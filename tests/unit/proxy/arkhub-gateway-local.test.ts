import { describe, it, expect, afterEach } from "vitest";
import net from "net";
import {
  startArkhubLocalGateway,
  isArkhubLocalGatewayActive,
  setArkhubLocalGatewayActive,
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

  it("启动后 isArkhubLocalGatewayActive 为 true（enterHall 据此指向本服）", async () => {
    await startServer();
    expect(isArkhubLocalGatewayActive()).toBe(true);
  });
});
