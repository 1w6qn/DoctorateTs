import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as path from "path";
import * as os from "os";
import * as fs from "fs";
import { captureManager, splitPath } from "../../../app/capture/capture-manager";

// 测试专用独立临时目录——绝不碰真实 tmp/capture/
const TEST_ROOT = path.join(os.tmpdir(), "capture-manager-test");

function tempRoot(tag: string): string {
  return path.join(os.tmpdir(), `capture-manager-${tag}-${Date.now()}-${Math.floor(Math.random() * 1e5)}`);
}

describe("captureManager（统一抓包存储）", () => {
  beforeEach(() => {
    captureManager.reset();
    captureManager.configure({ root: TEST_ROOT });
  });

  afterEach(() => {
    captureManager.reset();
    if (fs.existsSync(TEST_ROOT)) fs.rmSync(TEST_ROOT, { recursive: true, force: true });
  });

  it("addRecord 写入 DB 行 + body 文件 + meta.json，并广播订阅事件", async () => {
    await captureManager.init();
    const seen: string[] = [];
    const unsub = captureManager.subscribe((r) => seen.push(r.rid));

    const rec = await captureManager.addRecord(
      {
        method: "POST",
        path: "/account/syncData",
        query: "platform=2",
        status: 200,
        latencyMs: 12.5,
        source: "private",
        reqHeaders: { "content-type": "application/json" },
        resHeaders: { "content-type": "application/json" },
      },
      {
        req: { kind: "json", data: { platform: 2 } },
        res: { kind: "json", data: { result: 0, user: { uid: "1" } } },
      },
    );
    expect(rec.id).toBeGreaterThan(0);
    expect(rec.rid).toMatch(/^R-\d+-\d{4}$/);
    expect(rec.module).toBe("account");
    expect(rec.endpoint).toBe("syncData");
    expect(rec.source).toBe("private");
    expect(seen).toEqual([rec.rid]);

    // body 文件
    const dir = path.join(TEST_ROOT, "records", rec.rid);
    expect(fs.existsSync(path.join(dir, "req.json"))).toBe(true);
    expect(fs.existsSync(path.join(dir, "res.json"))).toBe(true);
    expect(JSON.parse(fs.readFileSync(path.join(dir, "req.json"), "utf8"))).toEqual({ platform: 2 });
    expect(fs.existsSync(path.join(dir, "meta.json"))).toBe(true);
    const meta = JSON.parse(fs.readFileSync(path.join(dir, "meta.json"), "utf8"));
    expect(meta.path).toBe("/account/syncData");
    expect(meta.status).toBe(200);

    // 无显式会话 → 自动归入默认会话
    const sessions = await captureManager.listSessions();
    expect(sessions.length).toBe(1);
    expect(sessions[0].name).toMatch(/^自动-/);
    expect(sessions[0].recordCount).toBe(1);
    unsub();
  });

  it("bin body（原始字节）以 .bin 落盘；非 JSON 响应详情返回 base64", async () => {
    await captureManager.init();
    const raw = Buffer.from([0x89, 0x50, 0x4e, 0x47, 1, 2, 3]);
    const rec = await captureManager.addRecord(
      { path: "/activity/arkhub/savePixelArt", source: "official", status: 200 },
      { req: { kind: "bin", data: raw }, res: { kind: "bin", data: raw } },
    );
    const dir = path.join(TEST_ROOT, "records", rec.rid);
    expect(fs.readFileSync(path.join(dir, "req.bin"))).toEqual(raw);
    expect(fs.readFileSync(path.join(dir, "res.bin"))).toEqual(raw);
    expect(rec.reqBodyType).toBe("bin");
    expect(rec.reqSize).toBe(raw.length);

    const detail = await captureManager.getRecordDetail(rec.id);
    expect(detail?.reqBody).toEqual({ base64: raw.toString("base64"), size: raw.length, hexPreview: raw.subarray(0, 32).toString("hex") });
  });

  it("query 支持 path/status/source/q/时间范围过滤与分页", async () => {
    await captureManager.init();
    const ts = Date.now();
    await captureManager.addRecord(
      { ts: ts - 1000, method: "GET", path: "/config/prod/official/network_config", status: 200, source: "private" },
      { res: { kind: "json", data: { ok: 1 } } },
    );
    await captureManager.addRecord(
      { ts: ts, method: "POST", path: "/account/login", status: 401, source: "official", latencyMs: 5 },
      { res: { kind: "json", data: { result: 1 } } },
    );

    const byStatus = await captureManager.query({ status: 401 });
    expect(byStatus.total).toBe(1);
    expect(byStatus.items[0].path).toBe("/account/login");

    const byQ = await captureManager.query({ q: "network_config" });
    expect(byQ.total).toBe(1);

    const bySource = await captureManager.query({ source: "official" });
    expect(bySource.total).toBe(1);

    const byTime = await captureManager.query({ from: ts - 500, to: ts + 500 });
    expect(byTime.total).toBe(1);

    const byPath = await captureManager.query({ path: "/account/" });
    expect(byPath.total).toBe(1);

    const page = await captureManager.query({ limit: 1, offset: 0 });
    expect(page.items.length).toBe(1);
    expect(page.total).toBe(2);
  });

  it("会话生命周期：start/stop/delete（级联删记录与目录）", async () => {
    await captureManager.init();
    const sess = await captureManager.startSession("登录链路", "official");
    const rec = await captureManager.addRecord(
      { sessionId: sess.id, path: "/user/auth/v1/login", source: "official", status: 200 },
      { res: { kind: "json", data: { result: 0 } } },
    );
    expect(rec.sessionId).toBe(sess.id);
    const dir = path.join(TEST_ROOT, "records", rec.rid);
    expect(fs.existsSync(dir)).toBe(true);

    const stopped = await captureManager.stopSession(sess.id);
    expect(stopped).toBe(true);
    const sessions = await captureManager.listSessions();
    expect(sessions[0].endedAt).not.toBeNull();

    const deleted = await captureManager.deleteSession(sess.id);
    expect(deleted).toBe(1);
    await new Promise((r) => setTimeout(r, 50)); // 目录删除异步
    expect(fs.existsSync(dir)).toBe(false);
    expect((await captureManager.query({ sessionId: sess.id })).total).toBe(0);
  });

  it("deleteRecord 删除行与 body 目录；getRecordDetail 对缺失文件标记 missing", async () => {
    await captureManager.init();
    const rec = await captureManager.addRecord(
      { path: "/shop/getLowGoodList", source: "private", status: 200 },
      { res: { kind: "json", data: { goods: [] } } },
    );
    const dir = path.join(TEST_ROOT, "records", rec.rid);
    fs.rmSync(path.join(dir, "res.json")); // 模拟文件丢失
    const detail = await captureManager.getRecordDetail(rec.id);
    expect(detail?.missingFiles).toContain("res.json");
    expect(detail?.reqBody).toBeUndefined();

    const ok = await captureManager.deleteRecord(rec.id);
    expect(ok).toBe(true);
    await new Promise((r) => setTimeout(r, 50));
    expect(fs.existsSync(dir)).toBe(false);
    expect(await captureManager.getRecord(rec.id)).toBeNull();
  });

  it("clearAll 需要确认词；CLEAR 后清空全部（含默认会话）", async () => {
    await captureManager.init();
    await captureManager.addRecord({ path: "/a", source: "private" });
    await expect(captureManager.clearAll("no")).rejects.toThrow(/CLEAR/);
    const r = await captureManager.clearAll("CLEAR");
    expect(r.cleared).toBe(1);
    expect((await captureManager.stats()).total).toBe(0);
    expect((await captureManager.listSessions()).length).toBe(0);
  });

  it("gateway 记录：commitRecord 引用 up.bin/down.bin 并携带解析产物", async () => {
    await captureManager.init();
    const rid = "R-gw-0001";
    const dir = path.join(TEST_ROOT, "records", rid);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "up.bin"), Buffer.from("up-data"));
    fs.writeFileSync(path.join(dir, "down.bin"), Buffer.from("down-data"));
    fs.writeFileSync(path.join(dir, "parsed.json"), JSON.stringify({ frames: [] }));
    const rec = await captureManager.commitRecord(
      rid,
      {
        path: "/arkhub/gateway",
        source: "gateway",
        direction: "gateway-bidi",
        status: null,
        note: "gateway connection",
      },
      dir,
      { targetAddr: "127.0.0.1:30000", reason: "closed" },
    );
    expect(rec).not.toBeNull();
    expect(rec!.reqBodyFile).toBe("up.bin");
    expect(rec!.resBodyFile).toBe("down.bin");
    expect(rec!.reqSize).toBe(7);
    expect(rec!.direction).toBe("gateway-bidi");
    const meta = JSON.parse(fs.readFileSync(path.join(dir, "meta.json"), "utf8"));
    expect(meta.targetAddr).toBe("127.0.0.1:30000");
    expect(meta.reason).toBe("closed");
    expect(meta.gateway).toBeUndefined(); // commitRecord 无 bodies.gateway 时无 gateway 节
  });

  it("exportSession 产出 zip（含 index.json + body 文件）", async () => {
    await captureManager.init();
    const sess = await captureManager.startSession("导出测试", "private");
    await captureManager.addRecord(
      { sessionId: sess.id, path: "/a/b", source: "private", status: 200 },
      { res: { kind: "json", data: { x: 1 } } },
    );
    const out = await captureManager.exportSession(sess.id);
    expect(fs.existsSync(out.path)).toBe(true);
    expect(out.records).toBe(1);
    expect(out.size).toBeGreaterThan(0);
    const zip = await (await import("jszip")).default.loadAsync(fs.readFileSync(out.path));
    const names = Object.keys(zip.files);
    expect(names).toContain("index.json");
    expect(names.some((n) => n.endsWith("res.json"))).toBe(true);
  });

  it("未 init 时 addRecord 惰性初始化", async () => {
    // 不调用 init，直接 addRecord → ensureInit 生效
    const rec = await captureManager.addRecord({ path: "/x", source: "harness" });
    expect(rec.id).toBeGreaterThan(0);
    expect(captureManager.isReady()).toBe(true);
  });

  it("stats 汇总来源/状态码/按天", async () => {
    await captureManager.init();
    await captureManager.addRecord({ path: "/a", source: "private", status: 200 });
    await captureManager.addRecord({ path: "/b", source: "official", status: 401 });
    const s = await captureManager.stats();
    expect(s.total).toBe(2);
    expect(s.bySource).toEqual({ private: 1, official: 1 });
    expect(s.byStatus).toEqual({ "200": 1, "401": 1 });
    expect(s.byDay.length).toBeGreaterThan(0);
  });
});

describe("splitPath（module/endpoint 拆分）", () => {
  it("拆分首段与其余段", () => {
    expect(splitPath("/account/syncData")).toEqual({ module: "account", endpoint: "syncData" });
    expect(splitPath("/user/auth/v1/login")).toEqual({ module: "user", endpoint: "auth/v1/login" });
    expect(splitPath("/root")).toEqual({ module: "root", endpoint: "root" });
    expect(splitPath("")).toEqual({ module: null, endpoint: null });
    expect(splitPath("/u8/user/v1/getToken?appCode=abc")).toEqual({ module: "u8", endpoint: "user/v1/getToken" });
  });
});
