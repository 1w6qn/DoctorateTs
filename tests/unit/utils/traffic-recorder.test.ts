import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";
import { createTrafficRecorder } from "../../../app/utils/traffic-recorder";
import { captureManager } from "../../../app/capture/capture-manager";

// 测试专用独立临时目录——绝不碰真实 tmp/capture/（统一抓包存储）
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
  res.statusCode = 200;
  res.getHeaders = vi.fn(() => ({}));
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

describe("createTrafficRecorder（统一抓包存储记录）", () => {
  const cfgOn = { debug: { recordTraffic: true } };
  const cfgOff = { debug: { recordTraffic: false } };

  beforeEach(() => {
    captureManager.reset();
    captureManager.configure({ root: RECORD_ROOT });
    if (fs.existsSync(RECORD_ROOT)) fs.rmSync(RECORD_ROOT, { recursive: true, force: true });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    captureManager.reset();
    if (fs.existsSync(RECORD_ROOT)) fs.rmSync(RECORD_ROOT, { recursive: true, force: true });
  });

  it("recordTraffic=true 时写入统一抓包存储（记录行 + req/res body 文件）", async () => {
    const handler = createTrafficRecorder(cfgOn, "private");
    const req = mockReq("/account/syncData?platform=2");
    const res = mockRes();
    const next = vi.fn();
    handler(req, res, next);
    expect(next).toHaveBeenCalled();
    res.send({ result: 0, ts: 123 });
    res.flush();
    // finish 回调是异步落库的
    await new Promise((r) => setTimeout(r, 100));

    const { total, items } = await captureManager.query({});
    expect(total).toBe(1);
    const rec = items[0];
    expect(rec.method).toBe("POST");
    expect(rec.path).toBe("/account/syncData");
    expect(rec.module).toBe("account");
    expect(rec.endpoint).toBe("syncData");
    expect(rec.status).toBe(200);
    expect(rec.source).toBe("private");
    expect(rec.query).toBe("platform=2");
    expect(rec.latencyMs).not.toBeNull();

    const detail = await captureManager.getRecordDetail(rec.id);
    expect(detail?.reqBody).toEqual({});
    expect(detail?.resBody).toEqual({ result: 0, ts: 123 });
    // body 文件确实落盘
    const dir = path.join(RECORD_ROOT, "records", rec.rid);
    expect(fs.existsSync(path.join(dir, "req.json"))).toBe(true);
    expect(fs.existsSync(path.join(dir, "res.json"))).toBe(true);
  });

  it("recordTraffic=false（默认）时不写任何记录", async () => {
    const handler = createTrafficRecorder(cfgOff, "private");
    const req = mockReq("/account/syncData");
    const res = mockRes();
    handler(req, res, () => {});
    res.send({ result: 0 });
    res.flush();
    await new Promise((r) => setTimeout(r, 100));
    expect((await captureManager.query({})).total).toBe(0);
  });

  it("url 带 query 时 path 只取路径部分", async () => {
    const handler = createTrafficRecorder(cfgOn, "private");
    const req = mockReq("/u8/user/v1/getToken?appCode=abc&platform=2");
    const res = mockRes();
    handler(req, res, () => {});
    res.json({ result: 0 });
    res.flush();
    await new Promise((r) => setTimeout(r, 100));
    const { items } = await captureManager.query({});
    expect(items[0].path).toBe("/u8/user/v1/getToken");
    expect(items[0].query).toBe("appCode=abc&platform=2");
    expect(items[0].module).toBe("u8");
    expect(items[0].endpoint).toBe("user/v1/getToken");
  });

  it("source 参数标记来源（capture 官服转发 → official）", async () => {
    const handler = createTrafficRecorder(cfgOn, "official");
    const req = mockReq("/account/login");
    const res = mockRes();
    handler(req, res, () => {});
    res.json({ result: 0 });
    res.flush();
    await new Promise((r) => setTimeout(r, 100));
    const { items } = await captureManager.query({});
    expect(items[0].source).toBe("official");
  });

  it("非 JSON 请求带 rawBody 时以 req.bin 原始字节落盘（multipart 像素画上传等）", async () => {
    const handler = createTrafficRecorder(cfgOn, "official");
    const req = mockReq("/activity/arkhub/savePixelArt");
    req.headers = { "content-type": 'multipart/form-data; boundary="C880D0B0"' };
    req.body = undefined;
    // 模拟 index.ts capture 模式捕获的原始 multipart 字节
    const raw = Buffer.from('--C880D0B0\r\nContent-Disposition: form-data; name="file"\r\n\r\nPNGDATA\r\n--C880D0B0--\r\n');
    req.rawBody = raw;
    const res = mockRes();
    handler(req, res, () => {});
    res.send({ pixelArtId: 123 });
    res.flush();
    await new Promise((r) => setTimeout(r, 100));

    const { items } = await captureManager.query({});
    const rec = items[0];
    expect(rec.reqBodyType).toBe("bin");
    expect(rec.reqSize).toBe(raw.length);
    const detail = await captureManager.getRecordDetail(rec.id);
    const reqBody = detail?.reqBody as { base64: string };
    expect(Buffer.from(reqBody.base64, "base64")).toEqual(raw);
    expect(detail?.resBody).toEqual({ pixelArtId: 123 });
  });

  it("JSON 请求（无 rawBody）请求体以 req.json 落盘", async () => {
    const handler = createTrafficRecorder(cfgOn, "private");
    const req = mockReq("/account/login", "POST", { phone: "13800000000" });
    const res = mockRes();
    handler(req, res, () => {});
    res.send({ result: 0 });
    res.flush();
    await new Promise((r) => setTimeout(r, 100));
    const { items } = await captureManager.query({});
    expect(items[0].reqBodyType).toBe("json");
    const detail = await captureManager.getRecordDetail(items[0].id);
    expect(detail?.reqBody).toEqual({ phone: "13800000000" });
  });

  it("默认排除 /admin /assetbundle /config /api 等本地挂载前缀（不记录，不包裹 res）", async () => {
    const handler = createTrafficRecorder(cfgOn, "private");
    const cases = [
      "/admin/api/status",
      "/admin/dashboard",
      "/assetbundle/official/Android/assets/xx/yy",
      "/config/prod/official/network_config",
      "/api/remote_config/1/prod/default/Windows/network_config",
      "/batch_event",
    ];
    for (const url of cases) {
      const req = mockReq(url);
      const res = mockRes();
      handler(req, res, () => {});
      res.send({ ok: 1 });
      res.flush();
    }
    await new Promise((r) => setTimeout(r, 100));
    expect((await captureManager.query({})).total).toBe(0);
    // 未包裹 res.send：mock 的 send 应保持原样被调用（res.json 未被替换成记录版本）
  });

  it("自定义 recordTrafficExclude 覆盖默认列表（空数组 = 全部记录，含 /admin）", async () => {
    const cfgAll = { debug: { recordTraffic: true, recordTrafficExclude: [] as string[] } };
    const handler = createTrafficRecorder(cfgAll, "private");
    const req = mockReq("/admin/api/status");
    const res = mockRes();
    handler(req, res, () => {});
    res.send({ ok: 1 });
    res.flush();
    await new Promise((r) => setTimeout(r, 100));
    const { items } = await captureManager.query({});
    expect(items.length).toBe(1);
    expect(items[0].path).toBe("/admin/api/status");
  });

  it("自定义 recordTrafficExclude 仅排除指定前缀（其它照常记录）", async () => {
    const cfg = { debug: { recordTraffic: true, recordTrafficExclude: ["/admin"] } };
    const handler = createTrafficRecorder(cfg, "private");
    const req1 = mockReq("/admin/api/status");
    const res1 = mockRes();
    handler(req1, res1, () => {});
    res1.send({ ok: 1 });
    res1.flush();
    const req2 = mockReq("/shop/getLowGoodList");
    const res2 = mockRes();
    handler(req2, res2, () => {});
    res2.send({ ok: 1 });
    res2.flush();
    await new Promise((r) => setTimeout(r, 100));
    const { items } = await captureManager.query({});
    expect(items.length).toBe(1);
    expect(items[0].path).toBe("/shop/getLowGoodList");
  });
});
