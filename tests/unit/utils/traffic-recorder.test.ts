import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import { createTrafficRecorder } from "../../../app/utils/traffic-recorder";

// 测试专用独立临时目录——绝不碰真实 tmp/（官服抓包目录，跑测试清空会导致参考数据丢失）
const RECORD_ROOT = path.join(os.tmpdir(), "traffic-recorder-test");

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
    // 清理测试专用临时目录（只影响本测试，不动 tmp/）
    if (fs.existsSync(RECORD_ROOT)) fs.rmSync(RECORD_ROOT, { recursive: true, force: true });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    if (fs.existsSync(RECORD_ROOT)) fs.rmSync(RECORD_ROOT, { recursive: true, force: true });
  });

  it("recordTraffic=true 时记录 request 与 response（独立临时目录，对齐 test.ts 目录结构）", async () => {
    const handler = createTrafficRecorder(cfgOn, RECORD_ROOT);
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
    const handler = createTrafficRecorder(cfgOff, RECORD_ROOT);
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
    const handler = createTrafficRecorder(cfgOn, RECORD_ROOT);
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
    const handler = createTrafficRecorder(cfgOn, RECORD_ROOT);
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

  it("非 JSON 请求带 rawBody 时以 base64 落盘（multipart 像素画上传等）", async () => {
    const handler = createTrafficRecorder(cfgOn, RECORD_ROOT);
    const req = mockReq("/activity/arkhub/savePixelArt");
    req.headers = { "content-type": 'multipart/form-data; boundary="C880D0B0"' };
    req.body = undefined;
    // 模拟 index.ts capture 模式捕获的原始 multipart 字节
    req.rawBody = Buffer.from('--C880D0B0\r\nContent-Disposition: form-data; name="file"\r\n\r\nPNGDATA\r\n--C880D0B0--\r\n');
    const res = mockRes();
    handler(req, res, () => {});
    res.send({ pixelArtId: 123 });
    res.flush();
    await new Promise((r) => setTimeout(r, 100));

    const reqFiles = fs.readdirSync(path.join(RECORD_ROOT, "request_activity", "arkhub", "savePixelArt"));
    const reqData = JSON.parse(fs.readFileSync(path.join(RECORD_ROOT, "request_activity", "arkhub", "savePixelArt", reqFiles[0]), "utf8"));
    // rawBody 原样 base64 编码，可还原为原始字节
    expect(reqData.rawBody).toBe(Buffer.from('--C880D0B0\r\nContent-Disposition: form-data; name="file"\r\n\r\nPNGDATA\r\n--C880D0B0--\r\n').toString("base64"));
    expect(Buffer.from(reqData.rawBody, "base64").toString("utf8")).toContain("PNGDATA");
  });

  it("JSON 请求（无 rawBody）不写 rawBody 字段", async () => {
    const handler = createTrafficRecorder(cfgOn, RECORD_ROOT);
    const req = mockReq("/account/login");
    const res = mockRes();
    handler(req, res, () => {});
    res.send({ result: 0 });
    res.flush();
    await new Promise((r) => setTimeout(r, 100));
    const reqFiles = fs.readdirSync(path.join(RECORD_ROOT, "request_account", "login"));
    const reqData = JSON.parse(fs.readFileSync(path.join(RECORD_ROOT, "request_account", "login", reqFiles[0]), "utf8"));
    expect(reqData.rawBody).toBeUndefined();
  });
});
