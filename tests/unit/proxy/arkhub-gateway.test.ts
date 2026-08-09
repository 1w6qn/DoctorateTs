import { describe, it, expect } from "vitest";
import net from "net";
import os from "os";
import path from "path";
import fs from "fs";
import {
  startArkhubGatewayProxy,
  adaptArkhubEnterHallResponse,
  isArkhubEnterHall,
  OFFICIAL_ARKHUB_GATEWAY_HOST,
  OFFICIAL_ARKHUB_GATEWAY_PORT,
} from "../../../app/proxy/arkhub-gateway";

/** 等待端口监听就绪 */
function listen(server: net.Server): Promise<void> {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
}

/** 等待一个 TCP 客户端完整往返（写数据→收够数据→关闭） */
function roundTrip(port: number, payload: Buffer): Promise<Buffer[]> {
  return new Promise((resolve, reject) => {
    const received: Buffer[] = [];
    const client = net.connect(port, "127.0.0.1", () => client.write(payload));
    client.on("data", (d) => {
      received.push(d);
      // 收够 payload 长度即主动关闭（兼容 echo 被拆成多段）
      const total = received.reduce((n, b) => n + b.length, 0);
      if (total >= payload.length) client.end();
    });
    client.on("error", reject);
    client.on("close", () => resolve(received));
  });
}

describe("adaptArkhubEnterHallResponse（enterHall 响应改写）", () => {
  it("改写 endpoint/port 为代理网关信息，其余字段不动", () => {
    const payload = {
      result: 0,
      endpoint: OFFICIAL_ARKHUB_GATEWAY_HOST,
      port: OFFICIAL_ARKHUB_GATEWAY_PORT,
      playerDataDelta: { modified: {}, deleted: {} },
    };
    const out = adaptArkhubEnterHallResponse(payload, { endpoint: "127.0.0.1", port: 30000 });
    expect(out).toEqual({
      result: 0,
      endpoint: "127.0.0.1",
      port: 30000,
      playerDataDelta: { modified: {}, deleted: {} },
    });
  });

  it("非网关形状（缺 endpoint/port）不改写，原对象返回", () => {
    const payload = { result: 1, msg: "x" };
    expect(adaptArkhubEnterHallResponse(payload, { endpoint: "127.0.0.1", port: 30000 })).toBe(payload);
  });

  it("非对象（Buffer/字符串）不改写", () => {
    const buf = Buffer.from("hello");
    expect(adaptArkhubEnterHallResponse(buf, { endpoint: "127.0.0.1", port: 30000 })).toBe(buf);
  });
});

describe("isArkhubEnterHall", () => {
  it("仅识别 /activity/arkhub/enterHall", () => {
    expect(isArkhubEnterHall("/activity/arkhub/enterHall")).toBe(true);
    expect(isArkhubEnterHall("/activity/arkhub/syncInfo")).toBe(false);
    expect(isArkhubEnterHall("/activity/arkhub/setSecretary")).toBe(false);
    expect(isArkhubEnterHall("/account/login")).toBe(false);
  });
});

describe("startArkhubGatewayProxy（30000 TCP 转发器）", () => {
  it("透传客户端↔目标字节流并记录 up/down/meta", async () => {
    // 本地 echo 服务器模拟官服网关
    const echo = net.createServer((sock) => sock.pipe(sock));
    await listen(echo);
    const echoPort = (echo.address() as net.AddressInfo).port;

    const recordRoot = path.join(os.tmpdir(), `arkhub-gw-test-${Date.now()}`);
    const server = await startArkhubGatewayProxy({
      port: 0, // 随机端口
      targetHost: "127.0.0.1",
      targetPort: echoPort,
      recordRoot,
    });
    expect(server).not.toBeNull();
    const proxyPort = (server!.address() as net.AddressInfo).port;

    try {
      // 客户端 → 代理 → echo → 代理 → 客户端
      const received = await roundTrip(proxyPort, Buffer.from("ping-1"));
      expect(Buffer.concat(received).toString()).toBe("ping-1");

      // 等异步落盘完成
      await new Promise((r) => setTimeout(r, 300));
      const dirs = fs.readdirSync(recordRoot);
      expect(dirs.length).toBe(1);
      const connDir = path.join(recordRoot, dirs[0]);
      expect(fs.readFileSync(path.join(connDir, "up.bin")).toString()).toBe("ping-1");
      expect(fs.readFileSync(path.join(connDir, "down.bin")).toString()).toBe("ping-1");
      const meta = JSON.parse(fs.readFileSync(path.join(connDir, "meta.json"), "utf-8"));
      expect(meta.upBytes).toBe(6);
      expect(meta.downBytes).toBe(6);
      expect(meta.targetAddr).toBe("127.0.0.1:" + echoPort);
    } finally {
      server!.close();
      echo.close();
      fs.rmSync(recordRoot, { recursive: true, force: true });
    }
  });

  it("端口被占用时返回 null（调用方应禁用 enterHall 改写）", async () => {
    const recordRoot = path.join(os.tmpdir(), "arkhub-gw-busy");
    // 两次启动都用相同的 listen 语义（server.listen(port) 双栈绑定），第二次必然 EADDRINUSE
    const first = await startArkhubGatewayProxy({
      port: 0,
      targetHost: "127.0.0.1",
      targetPort: 1,
      recordRoot,
    });
    expect(first).not.toBeNull();
    const usedPort = (first!.address() as net.AddressInfo).port;
    try {
      const second = await startArkhubGatewayProxy({
        port: usedPort,
        targetHost: "127.0.0.1",
        targetPort: 1,
        recordRoot,
      });
      expect(second).toBeNull();
    } finally {
      first!.close();
    }
  });
});
