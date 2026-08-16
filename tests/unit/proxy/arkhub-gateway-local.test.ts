import { describe, it, expect, afterEach } from "vitest";
import net from "net";
import {
  startArkhubLocalGateway,
  isArkhubLocalGatewayActive,
  setArkhubLocalGatewayActive,
  getArkhubLocalGatewayPort,
} from "../../../app/proxy/arkhub-gateway-local";

const servers: net.Server[] = [];
afterEach(() => {
  setArkhubLocalGatewayActive(false);
  for (const s of servers.splice(0)) s.close();
});

/** 组帧：[4B len][4B mainID][8B subID][body] */
function frame(mainID: number, subID: bigint, body: Buffer): Buffer {
  const f = Buffer.alloc(16 + body.length);
  f.writeUInt32BE(f.length, 0);
  f.writeUInt32BE(mainID, 4);
  f.writeBigUInt64BE(subID, 8);
  body.copy(f, 16);
  return f;
}

/** 连接本地网关，发一帧，收齐一帧响应 */
function roundTrip(port: number, payload: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const client = net.connect(port, "127.0.0.1", () => client.write(payload));
    let buf = Buffer.alloc(0);
    client.on("data", (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length >= 16 && buf.length >= buf.readUInt32BE(0)) {
        client.end();
        resolve(buf);
      }
    });
    client.on("error", reject);
  });
}

async function startServer(): Promise<number> {
  const server = (await startArkhubLocalGateway({ port: 0 }))!;
  servers.push(server);
  return (server.address() as net.AddressInfo).port;
}

describe("arkhub 本地网关应答器", () => {
  it("登录帧应返回 UserLoginResp（main=4 sub=0xfa2，code=100）", async () => {
    const port = await startServer();
    // UserLoginReq body: {1:'2222', 2:'secret', 3:1, 4:'dev'}
    const login = Buffer.concat([
      Buffer.from([0x0a, 0x04]),
      Buffer.from("2222"),
      Buffer.from([0x12, 0x06]),
      Buffer.from("secret"),
      Buffer.from([0x18, 0x01]),
      Buffer.from([0x22, 0x03]),
      Buffer.from("dev"),
    ]);
    const resp = await roundTrip(port, frame(4, BigInt(0x0fa1), login));
    expect(resp.readUInt32BE(4)).toBe(4);
    expect(resp.readBigUInt64BE(8)).toBe(BigInt(0x0fa2));
    // body 首字段 = code 100（0x08 0x64）
    expect(resp[16]).toBe(0x08);
    expect(resp[17]).toBe(100);
  });

  it("心跳帧应回 main=2 sub=0x0 的 16B 回显", async () => {
    const port = await startServer();
    const resp = await roundTrip(port, frame(1, BigInt(0), Buffer.alloc(8)));
    expect(resp.readUInt32BE(4)).toBe(2);
    expect(resp.readBigUInt64BE(8)).toBe(BigInt(0));
    expect(resp.length).toBe(16 + 16);
  });

  it("场景 hello 应返回合法 EnterSceneNotify（main=8 sub=0x2c89b38b37d3d）", async () => {
    const port = await startServer();
    // 先登录（记录 uid），再发场景 hello——场景帧应含自己的 PlayerSyncData（field1=uid）
    const login = Buffer.concat([
      Buffer.from([0x0a, 0x01]),
      Buffer.from("1"),
      Buffer.from([0x12, 0x01]),
      Buffer.from("x"),
      Buffer.from([0x18, 0x01]),
    ]);
    await roundTrip(port, frame(4, BigInt(0x0fa1), login));
    const resp = await roundTrip(
      port,
      frame(8, BigInt("0x18fb64de29cdb"), Buffer.from([0x08, 0x01])),
    );
    expect(resp.readUInt32BE(4)).toBe(8);
    expect(resp.readBigUInt64BE(8)).toBe(BigInt("0x2c89b38b37d3d"));
    // 场景 body 非空（含 HallInfo + PlayerSyncData + PlayerHallBrief）
    expect(resp.length).toBeGreaterThan(16 + 40);
    // 顶层 3 个 length-delimited 字段（field1/2/3）
    const body = resp.subarray(16);
    expect(body[0] >> 3).toBe(1);
    expect(body[0] & 7).toBe(2);
    expect(body[1]).toBeGreaterThan(0);
  });

  it("场景 hello 未登录时也返回合法帧（uid 空回退）", async () => {
    const port = await startServer();
    const resp = await roundTrip(
      port,
      frame(8, BigInt("0x18fb64de29cdb"), Buffer.from([0x08, 0x01])),
    );
    expect(resp.readUInt32BE(4)).toBe(8);
    expect(resp.length).toBeGreaterThan(16 + 40);
  });

  it("切场景（传送门）：请求带目标 map_id → ACK + 新场景 EnterSceneNotify", async () => {
    const port = await startServer();
    // 单连接全程（网关场景状态按连接维护——切场景状态不跨连接保留）
    const sock = net.connect(port, "127.0.0.1");
    let buf = Buffer.alloc(0);
    const pending: Array<(f: Buffer) => void> = [];
    sock.on("data", (d: Buffer) => {
      buf = Buffer.concat([buf, d]);
      while (buf.length >= 16) {
        const len = buf.readUInt32BE(0);
        if (buf.length < len) return;
        const f = buf.subarray(0, len);
        buf = buf.subarray(len);
        pending.shift()?.(f);
      }
    });
    const next = () =>
      new Promise<Buffer>((resolve) => pending.push(resolve));
    await new Promise<void>((r) => sock.once("connect", r));
    const sendFrame = (mainID: number, subID: bigint, body: Buffer) =>
      sock.write(frame(mainID, subID, body));
    const signedVarint = (v: number) => {
      let value = BigInt.asUintN(64, BigInt(v));
      const out: number[] = [];
      do {
        let byte = Number(value & 0x7fn);
        value >>= 7n;
        if (value !== 0n) byte |= 0x80;
        out.push(byte);
      } while (value !== 0n);
      return Buffer.from(out);
    };

    // 登录
    let p = next();
    sendFrame(4, BigInt(0x0fa1), Buffer.concat([
      Buffer.from([0x0a, 0x01]), Buffer.from("1"),
      Buffer.from([0x12, 0x01]), Buffer.from("x"),
      Buffer.from([0x18, 0x01]),
    ]));
    await p;
    // 场景 hello → TOWN（map -1520665757，varint e3f6f1aafaffffffff01）
    p = next();
    sendFrame(8, BigInt("0x18fb64de29cdb"), Buffer.from([0x08, 0x01]));
    const enter = await p;
    expect(enter.subarray(16).toString("hex").includes("e3f6f1aafaffffffff01")).toBe(true);
    // 切场景：body = {1:2, 2:<map_id=-820616879 CAPTURE 1>}
    // 网关连续回两帧（ACK + EnterSceneNotify）——先注册两个 next 再发包
    const pa = next();
    const ps = next();
    sendFrame(8, (BigInt("0x2c89b3") << BigInt(32)) | BigInt(0x38b3b60b),
      Buffer.concat([Buffer.from([0x08, 0x02, 0x10]), signedVarint(-820616879)]));
    const ack = await pa;
    // ACK：sub=0x38b3a5a8，body={1:9}
    expect((ack.readBigUInt64BE(8) & 0xffffffffn).toString(16)).toBe("38b3a5a8");
    expect(ack[16]).toBe(0x08);
    expect(ack[17]).toBe(9);
    // 随后 EnterSceneNotify：map_id = CAPTURE 1（-820616879，varint d1c2d9f8fcffffffff01）
    const scene = await ps;
    expect(scene.subarray(16).toString("hex").includes("d1c2d9f8fcffffffff01")).toBe(true);
    // 出生点应为捕抓区坐标（z=-6.85，LE float32）——修复：原统一用广场坐标导致传送后位置错误
    const capZ = Buffer.alloc(4);
    capZ.writeFloatLE(-6.85, 0);
    expect(scene.subarray(16).includes(capZ)).toBe(true);
    sock.end();
  });

  it("EnterSceneNotify 的 PlayerBrief 含 charId/skinId（广场玩家模型渲染所需）", async () => {
    const server = (await startArkhubLocalGateway({
      port: 0,
      resolvePlayerProfile: () => ({
        nickname: "博士2222",
        level: 120,
        charId: "char_1012_skadi2",
        skinId: "char_1012_skadi2#1",
      }),
    }))!;
    servers.push(server);
    const port = (server.address() as net.AddressInfo).port;
    const login = Buffer.concat([
      Buffer.from([0x0a, 0x04]),
      Buffer.from("2222"),
      Buffer.from([0x12, 0x06]),
      Buffer.from("secret"),
      Buffer.from([0x18, 0x01]),
    ]);
    await roundTrip(port, frame(4, BigInt(0x0fa1), login));
    const resp = await roundTrip(
      port,
      frame(8, BigInt("0x18fb64de29cdb"), Buffer.from([0x08, 0x01])),
    );
    // 顶层 f2 = PlayerSyncData，其 f1 = PlayerBrief，f1.f6/f1.f7 = charId/skinId
    const body = resp.subarray(16);
    // 解析顶层 f2（length-delimited，field 2）
    let p = 0;
    const readVarint = () => {
      let v = 0, s = 0;
      for (;;) {
        const b = body[p++];
        v |= (b & 0x7f) << s;
        if (!(b & 0x80)) break;
        s += 7;
      }
      return v;
    };
    while (p < body.length) {
      const tag = readVarint();
      const field = tag >> 3;
      const wire = tag & 7;
      if (wire === 2) {
        const len = readVarint();
        const chunk = body.subarray(p, p + len);
        p += len;
        if (field === 2) {
          // PlayerSyncData：解析其 f1（PlayerBrief）
          let q = 0;
          const rv = () => {
            let v = 0, s = 0;
            for (;;) {
              const b = chunk[q++];
              v |= (b & 0x7f) << s;
              if (!(b & 0x80)) break;
              s += 7;
            }
            return v;
          };
          const briefFields: Record<number, string> = {};
          while (q < chunk.length) {
            const t2 = rv();
            const f2 = t2 >> 3;
            const w2 = t2 & 7;
            if (w2 === 2) {
              const l2 = rv();
              if (f2 === 1) {
                // PlayerBrief 本体：解析其字段
                const brief = chunk.subarray(q, q + l2);
                let bq = 0;
                const bv = () => {
                  let v = 0, s = 0;
                  for (;;) {
                    const b = brief[bq++];
                    v |= (b & 0x7f) << s;
                    if (!(b & 0x80)) break;
                    s += 7;
                  }
                  return v;
                };
                while (bq < brief.length) {
                  const t3 = bv();
                  const f3 = t3 >> 3;
                  const w3 = t3 & 7;
                  if (w3 === 2) {
                    const l3 = bv();
                    if ([1, 2, 3, 6, 7].includes(f3)) {
                      briefFields[f3] = brief.subarray(bq, bq + l3).toString("utf8");
                    }
                    bq += l3;
                  } else if (w3 === 0) bv();
                  else break;
                }
              }
              q += l2;
            } else if (w2 === 0) rv();
            else break;
          }
          expect(briefFields[6]).toBe("char_1012_skadi2");
          expect(briefFields[7]).toBe("char_1012_skadi2#1");
          return;
        }
      } else if (wire === 0) readVarint();
      else break;
    }
    throw new Error("PlayerSyncData(f2) not found in EnterSceneNotify");
  });

  it("EnterSceneNotify 的 GuideFlags 为重复 f1 条目且含全部 hub 引导/区域标记（防引导重复）", async () => {
    const server = (await startArkhubLocalGateway({ port: 0 }))!;
    servers.push(server);
    const port = (server.address() as net.AddressInfo).port;
    const login = Buffer.concat([
      Buffer.from([0x0a, 0x01]),
      Buffer.from("1"),
      Buffer.from([0x12, 0x01]),
      Buffer.from("x"),
      Buffer.from([0x18, 0x01]),
    ]);
    await roundTrip(port, frame(4, BigInt(0x0fa1), login));
    const resp = await roundTrip(
      port,
      frame(8, BigInt("0x18fb64de29cdb"), Buffer.from([0x08, 0x01])),
    );
    const body = resp.subarray(16);
    // 用共享 cursor 的 protobuf 轻解析（返回 [field, wire, payload] 列表）
    const parse = (buf: Buffer): Array<[number, number, Buffer | number]> => {
      const out: Array<[number, number, Buffer | number]> = [];
      let p = 0;
      const rv = () => {
        let v = 0, s = 0;
        for (;;) {
          const b = buf[p++];
          v |= (b & 0x7f) << s;
          if (!(b & 0x80)) break;
          s += 7;
        }
        return v;
      };
      while (p < buf.length) {
        const tag = rv();
        const f = tag >> 3;
        const w = tag & 7;
        if (w === 2) {
          const len = rv();
          out.push([f, w, buf.subarray(p, p + len)]);
          p += len;
        } else if (w === 0) {
          out.push([f, w, rv()]);
        } else break;
      }
      return out;
    };

    // 顶层找 f2 (PlayerSyncData)
    let guideFlags: Buffer | null = null;
    for (const [f, w, payload] of parse(body)) {
      if (f === 2 && w === 2) {
        for (const [f2, w2, p2] of parse(payload as Buffer)) {
          if (f2 === 3 && w2 === 2) {
            guideFlags = p2 as Buffer;
          }
        }
      }
    }
    expect(guideFlags).not.toBeNull();
    // GuideFlags 内：f1 为重复条目 {1:key, 2:value}，f2 为时间戳
    const flags = new Map<string, number>();
    let tsFound = false;
    for (const [f, w, payload] of parse(guideFlags!)) {
      if (f === 2 && w === 0) tsFound = true;
      if (f === 1 && w === 2) {
        let key = "";
        let val = 0;
        for (const [f3, w3, p3] of parse(payload as Buffer)) {
          if (f3 === 1 && w3 === 2) key = (p3 as Buffer).toString("utf8");
          else if (f3 === 2 && w3 === 0) val = p3 as number;
        }
        flags.set(key, val);
      }
    }
    expect(tsFound).toBe(true);
    // 全部 hub 引导/区域标记应逐条下发（缺失 → 客户端每次进图重放引导对话）。
    // 取值对齐官服完成态：进度计数类（capture_catch_guide_01/02、arkdex_battle_guide）为 2，
    // 其余布尔标记为 1——取 1 会触发条件 ==1 的 AUTO 引导对话（mmkabi_01b 领奖帧无
    // 官服响应样本 → 客户端 9s 超时重试 → 对话无法结束），故 02 取完成态 2。
    const expected: Record<string, number> = {
      arkdex_battle_guide: 2,
      area_2_guard: 1,
      area_3_guard: 1,
      terminal_guide: 1,
      area_3_blcok: 1,
      terminal_guide_arkdex: 1,
      arkhub_login: 1,
      arkdex_mmkabi1: 1,
      capture_catch_guide_02: 2,
      pixel_unlock: 1,
      pixel_unlock_system: 1,
      area_2_block: 1,
      area_1_block: 1,
      capture_catch_guide_01: 2,
    };
    for (const [key, val] of Object.entries(expected)) {
      expect(flags.get(key)).toBe(val);
    }
  });

  it("启动后 isArkhubLocalGatewayActive 为 true（enterHall 据此指向本服）", async () => {
    await startServer();
    expect(isArkhubLocalGatewayActive()).toBe(true);
  });

  it("端口被占时自动避让到下一个空闲端口，getArkhubLocalGatewayPort 回报实际端口", async () => {
    // 先占用一个端口（与网关同样监听全部接口——Windows 上 127.0.0.1 占用不阻塞全局端口），
    // 再让本地网关以该端口为首选 → 应避让到下一个空闲端口
    const blocker = net.createServer();
    await new Promise<void>((r) => blocker.listen(0, r));
    const blockedPort = (blocker.address() as net.AddressInfo).port;
    const server = (await startArkhubLocalGateway({ port: blockedPort }))!;
    servers.push(server);
    const actualPort = (server.address() as net.AddressInfo).port;
    expect(actualPort).toBeGreaterThan(blockedPort);
    expect(getArkhubLocalGatewayPort()).toBe(actualPort);
    expect(isArkhubLocalGatewayActive()).toBe(true);
    blocker.close();
  });

  it("首选端口及全部避让端口被占时返回 null（本地网关不可用）", async () => {
    const blocker = net.createServer();
    await new Promise<void>((r) => blocker.listen(0, r));
    const port = (blocker.address() as net.AddressInfo).port;
    // maxPortTries=1：仅尝试首选端口，被占即放弃
    const result = await startArkhubLocalGateway({ port, maxPortTries: 1 });
    expect(result).toBeNull();
    expect(isArkhubLocalGatewayActive()).toBe(false);
    blocker.close();
  });

  describe("ARKDUEL/令牌网关帧（官服抓包对齐）", () => {
    async function openConn(port: number) {
      const sock = net.connect(port, "127.0.0.1");
      let buf = Buffer.alloc(0);
      const pending: Array<(f: Buffer) => void> = [];
      sock.on("data", (d: Buffer) => {
        buf = Buffer.concat([buf, d]);
        while (buf.length >= 16) {
          const len = buf.readUInt32BE(0);
          if (buf.length < len) return;
          const f = buf.subarray(0, len);
          buf = buf.subarray(len);
          pending.shift()?.(f);
        }
      });
      const next = () => new Promise<Buffer>((resolve) => pending.push(resolve));
      await new Promise<void>((r) => sock.once("connect", r));
      const sendFrame = (mainID: number, subID: bigint, body: Buffer) => sock.write(frame(mainID, subID, body));
      return { sock, next, sendFrame };
    }

    it("ARKDUEL 商店（0x28f5ba6f）→ 价格表（0x28f5229c，含 7 件道具）", async () => {
      const port = await startServer();
      const { sock, next, sendFrame } = await openConn(port);
      const p = next();
      const seq = Buffer.alloc(4);
      seq.writeUInt32BE(1, 0);
      sendFrame(8, (BigInt("0x2c89b3") << BigInt(32)) | BigInt(0x28f5ba6f), seq);
      const resp = await p;
      expect((resp.readBigUInt64BE(8) & 0xffffffffn).toString(16)).toBe("28f5229c");
      // [seq=1] {1:100, 3:{1:ts, 2:[7 items]}}
      const body = resp.subarray(16);
      expect(body.readUInt32BE(0)).toBe(1);
      expect(body[4]).toBe(0x08); // f1
      expect(body[5]).toBe(100); // code 100
      // 含 itemNumId 5004（标准诱引剂，varint 8c27）与价格 40（f3=1828）
      const hex = body.toString("hex");
      expect(hex).toContain("108c27");
      expect(hex).toContain("1828");
      // 稀有诱引剂 5006 价格 250（f3 varint = fa01）
      expect(hex).toContain("18fa01");
      sock.end();
    });

    it("ARKDUEL 战斗开始（0xb7c267d7）→ 敌方单位响应（0xb7c20f13 含 act1arkhub_14）", async () => {
      const port = await startServer();
      const { sock, next, sendFrame } = await openConn(port);
      const p = next();
      // [seq=2] {1: squad JSON}
      const body = Buffer.concat([
        Buffer.from([0x00, 0x00, 0x00, 0x02]),
        Buffer.from([0x0a, 0x02]),
        Buffer.from("{}"),
      ]);
      sendFrame(8, (BigInt("0x2c89b3") << BigInt(32)) | BigInt(0xb7c267d7), body);
      const resp = await p;
      expect((resp.readBigUInt64BE(8) & 0xffffffffn).toString(16)).toBe("b7c20f13");
      const hex = resp.subarray(16).toString("hex");
      expect(hex).toContain("6163743161726b6875625f3134"); // "act1arkhub_14"
      sock.end();
    });

    it("ARKDUEL 战斗结算（0xb7c204e8）→ code100 回显 + 结果推送", async () => {
      const port = await startServer();
      const { sock, next, sendFrame } = await openConn(port);
      // 战斗开始（记录 seq=2）
      let p = next();
      sendFrame(8, (BigInt("0x2c89b3") << BigInt(32)) | BigInt(0xb7c267d7),
        Buffer.concat([Buffer.from([0, 0, 0, 2]), Buffer.from([0x0a, 0x02]), Buffer.from("{}")]));
      await p;
      // 结算：[seq=3] {1:"battleId"}
      const pa = next();
      const pb = next();
      const pc = next();
      const finish = Buffer.concat([
        Buffer.from([0, 0, 0, 3]),
        Buffer.from([0x0a, 0x09]),
        Buffer.from("bid:12345"),
      ]);
      sendFrame(8, (BigInt("0x2c89b3") << BigInt(32)) | BigInt(0xb7c204e8), finish);
      const ack = await pa;
      expect((ack.readBigUInt64BE(8) & 0xffffffffn).toString(16)).toBe("b7c2b07e");
      const ackBody = ack.subarray(16);
      expect(ackBody.readUInt32BE(0)).toBe(2); // 回显战斗开始 seq
      expect(ackBody.subarray(4).toString("hex")).toContain("0864"); // f1=100
      expect(ackBody.subarray(4).toString()).toContain("bid:12345"); // battleId 回显
      // 结果推送
      const r1 = await pb;
      expect((r1.readBigUInt64BE(8) & 0xffffffffn).toString(16)).toBe("b7c26451");
      const r2 = await pc;
      expect((r2.readBigUInt64BE(8) & 0xffffffffn).toString(16)).toBe("b7c2d119");
      sock.end();
    });

    it("令牌刷新（0x31d603b3）→ 新令牌（0x31d60cf6）", async () => {
      const port = await startServer();
      const { sock, next, sendFrame } = await openConn(port);
      const p = next();
      // [seq=4] {1:ts, 2:旧令牌}
      const token = "c13ee8e6008018bc773b76b9eade06d7";
      const body = Buffer.concat([
        Buffer.from([0, 0, 0, 4]),
        Buffer.from([0x08, 0x80, 0xb2, 0xb1, 0x86, 0x1a]),
        Buffer.from([0x12, 0x20]),
        Buffer.from(token, "utf8"),
      ]);
      sendFrame(8, (BigInt("0x2c89b3") << BigInt(32)) | BigInt(0x31d603b3), body);
      const resp = await p;
      expect((resp.readBigUInt64BE(8) & 0xffffffffn).toString(16)).toBe("31d60cf6");
      const hex = resp.subarray(16).toString("hex");
      expect(hex).toContain("0864"); // f1=100
      expect(hex.length).toBeGreaterThan(40); // 含新令牌
      sock.end();
    });

    it("交互提交（0x38b3116d）mmkabi 领奖 → 奖励响应", async () => {
      const port = await startServer();
      const { sock, next, sendFrame } = await openConn(port);
      // 场景 hello（获取 flags——capture_catch_guide_02=2 完成态，mmkabi 引导不触发）
      let p = next();
      sendFrame(8, BigInt("0x18fb64de29cdb"), Buffer.from([0x08, 0x01]));
      const enter = await p;
      const keyHex = "636170747572655f63617463685f67756964655f3032";
      expect(enter.subarray(16).toString("hex")).toContain(keyHex + "1002");
      // 交互提交：[seq=4] {1:"arkhub_capture1_mmkabi_01b", 2:"get_reward"}
      p = next();
      const body = Buffer.concat([
        Buffer.from([0, 0, 0, 4]),
        Buffer.from([0x0a, 0x1a]),
        Buffer.from("arkhub_capture1_mmkabi_01b", "utf8"),
        Buffer.from([0x12, 0x0a]),
        Buffer.from("get_reward", "utf8"),
      ]);
      sendFrame(8, (BigInt("0x2c89b3") << BigInt(32)) | BigInt(0x38b3116d), body);
      const resp = await p;
      expect((resp.readBigUInt64BE(8) & 0xffffffffn).toString(16)).toBe("38b3116e");
      // 响应含奖励 arkdex_1_gold
      expect(resp.subarray(16).toString("hex")).toContain("61726b6465785f315f676f6c64");
      sock.end();
    });
  });
});
