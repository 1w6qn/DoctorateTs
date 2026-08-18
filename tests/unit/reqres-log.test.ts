import { describe, it, expect, vi, afterEach } from "vitest";

// 临时 req/res 记录中间件单元测试
// 注意：reqres-log.ts 的 MODE 在模块加载时从 REQRES_LOG 读取——用 vi.resetModules 隔离
function loadModule(env: string) {
  vi.resetModules();
  process.env.REQRES_LOG = env;
  return import("@game/reqres-log");
}

afterEach(() => {
  delete process.env.REQRES_LOG;
});

describe("reqres-log 记录开关", () => {
  it("默认模式（rlv2）：仅记录 /rlv2/ 路径", async () => {
    const mod = await loadModule("rlv2");
    expect(mod.enabledFor("/rlv2/finishEvent")).toBe(true);
    expect(mod.enabledFor("/rlv2/createGame")).toBe(true);
    expect(mod.enabledFor("/other/route")).toBe(false);
    expect(mod.enabledFor("/admin/users")).toBe(false);
  });

  it("all 模式：记录全部路径", async () => {
    const mod = await loadModule("all");
    expect(mod.enabledFor("/rlv2/x")).toBe(true);
    expect(mod.enabledFor("/other")).toBe(true);
    expect(mod.enabledFor("/admin")).toBe(true);
  });

  it("关闭（0/false/off）：不记录", async () => {
    for (const off of ["0", "false", "off", ""]) {
      const mod = await loadModule(off);
      expect(mod.enabledFor("/rlv2/x")).toBe(false);
    }
  });

  it("自定义前缀模式", async () => {
    const mod = await loadModule("battle");
    expect(mod.enabledFor("/battle/start")).toBe(true);
    expect(mod.enabledFor("/rlv2/x")).toBe(false);
  });
});

describe("reqres-log 内容序列化", () => {
  it("对象 JSON 化 + 超长截断", async () => {
    const mod = await loadModule("rlv2");
    expect(mod.safeJson({ a: 1, b: "x" })).toBe('{"a":1,"b":"x"}');
    const big = "x".repeat(5000);
    const out = mod.safeJson({ data: big });
    expect(out).toContain("[截断");
    expect(out.length).toBeLessThan(4300);
  });

  it("字符串/空值/不可序列化容错", async () => {
    const mod = await loadModule("rlv2");
    expect(mod.safeJson("hello")).toBe("hello");
    expect(mod.safeJson(null)).toBe("null");
    expect(mod.safeJson(undefined)).toBe("undefined");
    const cyclic: any = {};
    cyclic.self = cyclic;
    expect(mod.safeJson(cyclic)).toContain("不可序列化");
  });
});
