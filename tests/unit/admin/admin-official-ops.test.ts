import { describe, it, expect, vi, beforeEach } from "vitest";

// mock 官服登录三步（不真实联网）
vi.mock("../../../scripts/official-api", () => ({
  GAME_API: "https://ak-gs-gf.hypergryph.com",
  getResVersion: vi.fn().mockResolvedValue({ resVersion: "r1", clientVersion: "c1" }),
  getToken: vi.fn().mockResolvedValue({ token: "t", uid: "10001" }),
  loginGame: vi.fn().mockResolvedValue({ secret: "s", seqnum: "1" }),
  getRandomDevices: vi.fn().mockReturnValue({ deviceId: "d1", deviceId2: "d2", deviceId3: "d3" }),
}));

import {
  OfficialSession,
  runOfficialAction,
  runOfficialCall,
  validateCgi,
} from "../../../app/admin/official-ops";

function fakeRes(body: any, seqnum: string | null = null) {
  return Promise.resolve({
    ok: true,
    status: 200,
    headers: { get: (k: string) => (k === "seqnum" ? seqnum : null) },
    json: vi.fn().mockResolvedValue(body),
  });
}

describe("OfficialSession", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("login 应完成三步登录并持有 uid/secret/seqnum", async () => {
    const s = new OfficialSession();
    await s.login("13800000000", "pwd");
    expect(s.uid).toBe("10001");
    expect(s.secret).toBe("s");
    expect(s.seqnum).toBe(1);
  });

  it("post 应带 secret/seqnum 头并按响应头更新 seqnum", async () => {
    const s = new OfficialSession();
    s.uid = "1";
    s.secret = "s";
    s.seqnum = 3;
    vi.stubGlobal("fetch", vi.fn().mockImplementation(() => fakeRes({ result: 0 }, "5")));
    const r = await s.post("/user/checkIn", {});
    expect(r.result).toBe(0);
    expect(s.seqnum).toBe(5);
    const [url, opts] = (fetch as any).mock.calls[0];
    expect(url).toBe("https://ak-gs-gf.hypergryph.com/user/checkIn");
    expect(opts.headers.secret).toBe("s");
    expect(opts.headers.seqnum).toBe("3");
    vi.unstubAllGlobals();
  });

  it("post 无 seqnum 响应头时应自增", async () => {
    const s = new OfficialSession();
    s.uid = "1";
    s.secret = "s";
    s.seqnum = 3;
    vi.stubGlobal("fetch", vi.fn().mockImplementation(() => fakeRes({})));
    await s.post("/user/checkIn", {});
    expect(s.seqnum).toBe(4);
    vi.unstubAllGlobals();
  });
});

describe("runOfficialAction", () => {
  it("status 应返回账号状态摘要", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(() =>
        fakeRes({
          user: {
            status: {
              nickName: "A", nickNumber: "1", uid: "10001", level: 60,
              ap: 10, maxAp: 135, gold: 999, androidDiamond: 5,
              socialPoint: 1, lggShard: 2, hggShard: 3,
            },
            checkIn: { canCheckIn: 1 },
          },
        }),
      ),
    );
    const r = await runOfficialAction("13800000000", "pwd", "status");
    expect(r.ok).toBe(true);
    expect(r.data).toMatchObject({ nickName: "A", level: 60, canCheckIn: 1, maxAp: 135 });
    vi.unstubAllGlobals();
  });

  it("signin 今日已签应返回 reason 且不调 checkIn", async () => {
    const fetchMock = vi.fn().mockImplementation(() =>
      fakeRes({ user: { status: {}, checkIn: { canCheckIn: 0 } } }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const r = await runOfficialAction("13800000000", "pwd", "signin");
    expect(r.ok).toBe(false);
    expect(r.reason).toContain("已签到");
    expect(fetchMock.mock.calls.some((c: any) => c[0].endsWith("/user/checkIn"))).toBe(false);
    vi.unstubAllGlobals();
  });

  it("signin 可签应调用 /user/checkIn", async () => {
    const fetchMock = vi.fn().mockImplementation((url: string) =>
      url.includes("syncData")
        ? fakeRes({ user: { status: {}, checkIn: { canCheckIn: 1 } } })
        : fakeRes({ result: 0 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const r = await runOfficialAction("13800000000", "pwd", "signin");
    expect(r.ok).toBe(true);
    expect(fetchMock.mock.calls.some((c: any) => c[0].endsWith("/user/checkIn"))).toBe(true);
    vi.unstubAllGlobals();
  });

  it("mails 应返回邮件计数", async () => {
    const fetchMock = vi.fn().mockImplementation((url: string) =>
      url.includes("syncData")
        ? fakeRes({ user: { status: {}, checkIn: { canCheckIn: 1 } } })
        : fakeRes({ result: [{ mailId: 1, hasItem: 1, state: 0 }, { mailId: 2, hasItem: 0, state: 1 }] }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const r = await runOfficialAction("13800000000", "pwd", "mails");
    expect(r.ok).toBe(true);
    expect(r.data).toMatchObject({ count: 2, unread: 1 });
    vi.unstubAllGlobals();
  });
});

describe("validateCgi / runOfficialCall", () => {
  it("validateCgi 应接受 /xxx/yyy 形式", () => {
    expect(validateCgi("/user/checkIn")).toBe("/user/checkIn");
    expect(validateCgi("/activity/loginOnly/getReward")).toBe("/activity/loginOnly/getReward");
  });

  it("validateCgi 应拒绝非法路径", () => {
    expect(() => validateCgi("user/checkIn")).toThrow(/非法的官服接口路径/);
    expect(() => validateCgi("/../etc/passwd")).toThrow(/非法的官服接口路径/);
    expect(() => validateCgi("")).toThrow(/非法的官服接口路径/);
  });

  it("runOfficialCall 应登录后调用指定 cgi 并返回完整响应", async () => {
    const fetchMock = vi.fn().mockImplementation((url: string) =>
      url.includes("/mail/getMetaInfoList")
        ? fakeRes({ result: [{ mailId: 1, hasItem: 1, state: 0 }] })
        : fakeRes({ user: { status: {}, checkIn: { canCheckIn: 1 } } }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const r = await runOfficialCall("13800000000", "pwd", "/mail/getMetaInfoList", { from: 0 });
    expect(r.cgi).toBe("/mail/getMetaInfoList");
    expect(r.result.result).toHaveLength(1);
    const [, opts] = fetchMock.mock.calls.find((c: any) => c[0].includes("/mail/getMetaInfoList"))!;
    expect(JSON.parse(opts.body)).toEqual({ from: 0 });
    vi.unstubAllGlobals();
  });
});
