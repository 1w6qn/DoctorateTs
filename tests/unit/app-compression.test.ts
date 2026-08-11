import { describe, it, expect, afterEach } from "vitest";
import express from "express";
import compression from "compression";
import { createServer, Server, request } from "http";
import { AddressInfo } from "net";
import { gunzipSync } from "zlib";

/**
 * 响应压缩中间件（B1）
 *
 * syncData 等大响应（user 全量数 MB）在客户端带 Accept-Encoding: gzip 时压缩传输，
 * 减小带宽且不改变响应内容（契约不变）。index.ts 已按同模式接线。
 * 注意用 http.request（不自动解压）拿原始字节，Node fetch 会自动解压 gzip。
 */
describe("compression 响应压缩（B1）", () => {
  let server: Server;

  afterEach(() => {
    server?.close();
  });

  async function startApp(): Promise<string> {
    const app = express();
    app.use(compression());
    app.get("/big", (_req, res) => {
      res.json({ user: { data: "x".repeat(200000) } });
    });
    server = createServer(app);
    await new Promise<void>((r) => server.listen(0, r));
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }

  function rawGet(
    url: string,
    headers: Record<string, string> = {},
  ): Promise<{ contentEncoding?: string; body: Buffer }> {
    return new Promise((resolve, reject) => {
      const req = request(url, { headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            contentEncoding: res.headers["content-encoding"] as string | undefined,
            body: Buffer.concat(chunks),
          }),
        );
      });
      req.on("error", reject);
      req.end();
    });
  }

  it("Accept-Encoding: gzip 时大 JSON 响应应压缩且解压后内容一致", async () => {
    const base = await startApp();
    const { contentEncoding, body } = await rawGet(`${base}/big`, {
      "Accept-Encoding": "gzip",
    });
    expect(contentEncoding).toBe("gzip");
    // 压缩后明显小于原文（200KB 重复串 → 远小）
    expect(body.length).toBeLessThan(1000);
    const inflated = JSON.parse(gunzipSync(body).toString("utf8"));
    expect(inflated).toEqual({ user: { data: "x".repeat(200000) } });
  });

  it("不带 Accept-Encoding 时不压缩（客户端无 gzip 支持时原样返回）", async () => {
    const base = await startApp();
    const { contentEncoding, body } = await rawGet(`${base}/big`);
    expect(contentEncoding).toBeUndefined();
    expect(body.length).toBeGreaterThan(200000);
  });
});
