import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as path from "path";
import * as fs from "fs";
import { createTrafficRecorder } from "../../../app/utils/traffic-recorder";

const RECORD_ROOT = "tmp";

function mockReq(originalUrl: string, method = "POST", body: any = {}) {
  return {
    method,
    originalUrl,
    headers: { "content-type": "application/json" },
    body,
    query: { platform: 2 },
  } as any;
}

function mockRes() {
  const res: any = {};
  let finishCb: () => void = () => {};
  res.send = vi.fn(function (this: any, data: any) {
    this._body = data;
    return this;
  });
  res.json = vi.fn(function (this: any, data: any) {
    this._body = data;
    return this;
  });
  // 模拟真实 Express：finish 在响应发出后才触发（send/json 之后手动调用 flush）
  res.on = vi.fn((event: string, cb: () => void) => {
    if (event === "finish") finishCb = cb;
  });
  res.flush = () => finishCb();
  return res;
}

describe("createTrafficRecorder（调试请求/响应记录）", () => {
  const cfgOn = { debug: { recordTraffic: true } };
  const cfgOff = { debug: { recordTraffic: false } };

  beforeEach(() => {
    // 清理 tmp/ 下测试产生的目录（只删本中间件前缀目录）
    for (const dir of ["account", "request_account", "u8", "request_u8"]) {
      const p = path.join(RECORD_ROOT, dir);
      if (fs.existsSync(p)) fs.rmSync(p, { recursive: true, force: true });
    }
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("recordTraffic=true 时记录 request 与 response 到 tmp/（对齐 test.ts 目录）", async () => {
    const handler = createTrafficRecorder(cfgOn);
    const req = mockReq("/account/syncData");
    const res = mockRes();
    const next = vi.fn();
    handler(req, res, next);
    expect(next).toHaveBeenCalled();
    res.send({ result: 0, ts: 123 });
    res.flush();
    // finish 回调是异步落盘的
    await new Promise((r) => setTimeout(r, 100));

    const files = fs.readdirSync(path.join(RECORD_ROOT, "account", "syncData"));
    expect(files.length).toBe(1);
    const resp = JSON.parse(fs.readFileSync(path.join(RECORD_ROOT, "account", "syncData", files[0]), "utf8"));
    expect(resp).toEqual({ result: 0, ts: 123 });

    const reqFiles = fs.readdirSync(path.join(RECORD_ROOT, "request_account", "syncData"));
    expect(reqFiles.length).toBe(1);
    const reqData = JSON.parse(fs.readFileSync(path.join(RECORD_ROOT, "request_account", "syncData", reqFiles[0]), "utf8"));
    expect(reqData.method).toBe("POST");
    expect(reqData.url).toBe("/account/syncData");
    expect(reqData.body).toEqual({});
    expect(reqData.query).toEqual({ platform: 2 });
  });

  it("recordTraffic=false（默认）时不写任何文件", async () => {
    const handler = createTrafficRecorder(cfgOff);
    const req = mockReq("/account/syncData");
    const res = mockRes();
    handler(req, res, () => {});
    res.send({ result: 0 });
    res.flush();
    await new Promise((r) => setTimeout(r, 100));
    expect(fs.existsSync(path.join(RECORD_ROOT, "account"))).toBe(false);
    expect(fs.existsSync(path.join(RECORD_ROOT, "request_account"))).toBe(false);
  });

  it("url 带 query 时目录只取路径部分", async () => {
    const handler = createTrafficRecorder(cfgOn);
    const req = mockReq("/u8/user/v1/getToken?appCode=abc&platform=2");
    const res = mockRes();
    handler(req, res, () => {});
    res.json({ result: 0 });
    res.flush();
    await new Promise((r) => setTimeout(r, 100));
    expect(fs.existsSync(path.join(RECORD_ROOT, "u8", "user", "v1", "getToken"))).toBe(true);
    expect(fs.existsSync(path.join(RECORD_ROOT, "request_u8", "user", "v1", "getToken"))).toBe(true);
  });

  it("res.json 同样被记录", async () => {
    const handler = createTrafficRecorder(cfgOn);
    const req = mockReq("/account/login");
    const res = mockRes();
    handler(req, res, () => {});
    res.json({ result: 0, uid: "1" });
    res.flush();
    await new Promise((r) => setTimeout(r, 100));
    const files = fs.readdirSync(path.join(RECORD_ROOT, "account", "login"));
    const resp = JSON.parse(fs.readFileSync(path.join(RECORD_ROOT, "account", "login", files[0]), "utf8"));
    expect(resp).toEqual({ result: 0, uid: "1" });
  });
});
