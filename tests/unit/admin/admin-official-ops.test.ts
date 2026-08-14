import { describe, it, expect, vi, beforeEach } from "vitest";

// mock 官服登录三步（不真实联网）
vi.mock("../../../scripts/official-api", () => ({
  GAME_API: "https://ak-gs-gf.hypergryph.com",
  getResVersion: vi.fn().mockResolvedValue({ resVersion: "r1", clientVersion: "c1" }),
  getToken: vi.fn().mockResolvedValue({ token: "t", uid: "10001" }),
  loginGame: vi.fn().mockResolvedValue({ secret: "s", seqnum: "1" }),
  getRandomDevices: vi.fn().mockReturnValue({ deviceId: "d1", deviceId2: "d2", deviceId3: "d3" }),
}));
// 官服调用记录：mock 统一抓包存储（不写真实 tmp/capture/）
const cmMocks = vi.hoisted(() => ({
  addRecord: vi.fn().mockResolvedValue({ id: 1 }),
}));
vi.mock("@capture/capture-manager", () => ({
  captureManager: { addRecord: cmMocks.addRecord },
}));

// 网关 mock（不真实 TCP 连接；记录 connect/requestUploadToken/confirmSave 次数验证连接复用）
const gwMocks = vi.hoisted(() => ({
  connect: vi.fn().mockResolvedValue(undefined),
  requestUploadToken: vi.fn(),
  confirmSave: vi.fn().mockResolvedValue(undefined),
  deletePixelArt: vi.fn().mockResolvedValue(undefined),
  close: vi.fn(),
  GatewaySession: vi.fn(),
  randomGatewayDeviceId: vi.fn().mockReturnValue("device-1"),
}));
vi.mock("../../../app/admin/arkhub-gateway-client", () => ({
  GatewaySession: gwMocks.GatewaySession,
  randomGatewayDeviceId: gwMocks.randomGatewayDeviceId,
}));
gwMocks.GatewaySession.mockImplementation(function () {
  return {
    connect: gwMocks.connect,
    requestUploadToken: gwMocks.requestUploadToken,
    confirmSave: gwMocks.confirmSave,
    deletePixelArt: gwMocks.deletePixelArt,
    close: gwMocks.close,
  };
});

import {
  OfficialSession,
  runOfficialAction,
  runOfficialCall,
  runGachaSync,
  uploadPixelArt,
  uploadPixelArtBatch,
  getPixelArtList,
  deletePixelArt,
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

  it("post 应记录请求/响应到统一抓包存储（请求脱敏 secret）", async () => {
    cmMocks.addRecord.mockClear();
    const s = new OfficialSession();
    s.uid = "1";
    s.secret = "s";
    s.seqnum = 1;
    vi.stubGlobal("fetch", vi.fn().mockImplementation(() => fakeRes({ result: 0 })));
    await s.post("/user/checkIn", {});
    // 记录为 fire-and-forget，等待完成
    await new Promise((r) => setTimeout(r, 20));
    expect(cmMocks.addRecord).toHaveBeenCalledTimes(1);
    const [meta, bodies] = cmMocks.addRecord.mock.calls[0];
    expect(meta.path).toBe("/user/checkIn");
    expect(meta.source).toBe("ops");
    expect(meta.reqHeaders.secret).toBeUndefined(); // 脱敏
    expect(bodies.req).toEqual({ kind: "json", data: {} });
    expect(bodies.res.data.result).toBe(0);
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

  it("runGachaSync 应逐个抓取卡池详情，单个失败不中断", async () => {
    let gachaCalls = 0;
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (url.includes("/gacha/getPoolDetail")) {
        gachaCalls++;
        // 第 2 个池模拟失败（404）
        return gachaCalls === 2
          ? Promise.resolve({ ok: false, status: 404, headers: { get: () => null }, json: vi.fn() })
          : fakeRes({ detailInfo: { upCharInfo: { perCharList: [] }, gachaObjList: [] } });
      }
      return fakeRes({ user: { status: {} } });
    });
    vi.stubGlobal("fetch", fetchMock);
    const results = await runGachaSync("13800000000", "pwd", ["NORM_0_1_3", "BAD"]);
    expect(results).toHaveLength(2);
    expect(results[0].poolId).toBe("NORM_0_1_3");
    expect(results[0].detailInfo).toBeDefined();
    expect(results[1].poolId).toBe("BAD");
    expect(results[1].error).toBeDefined();
    vi.unstubAllGlobals();
  });
});

describe("uploadPixelArtBatch（复用登录 + 网关连接）", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    gwMocks.requestUploadToken.mockReset();
    gwMocks.requestUploadToken
      .mockResolvedValueOnce({ pixelArtId: 1001n, uploadToken: "tok1", expireTime: 0 })
      .mockResolvedValueOnce({ pixelArtId: 1002n, uploadToken: "tok2", expireTime: 0 });
  });

  it("批量应登录一次 + 网关连接一次并逐张上传", async () => {
    const fetchMock = vi.fn().mockImplementation(() =>
      fakeRes({ status: 200, pixelArtId: 1001 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const pixels = new Array(1728).fill(255);
    const results = await uploadPixelArtBatch("13800000000", "pwd", [Buffer.from(pixels), Buffer.from(pixels)]);
    expect(results).toHaveLength(2);
    expect(results[0]).toMatchObject({ index: 0, ok: true, pixelArtId: 1001n });
    expect(results[1]).toMatchObject({ index: 1, ok: true, pixelArtId: 1002n });
    // 网关连接只建一次（复用）
    expect(gwMocks.connect).toHaveBeenCalledTimes(1);
    expect(gwMocks.requestUploadToken).toHaveBeenCalledTimes(2);
    expect(gwMocks.confirmSave).toHaveBeenCalledTimes(2);
    expect(gwMocks.close).toHaveBeenCalledTimes(1);
    // HTTP 上传 2 次（multipart）
    const uploadCalls = fetchMock.mock.calls.filter((c: any[]) => String(c[0]).includes("savePixelArt"));
    expect(uploadCalls).toHaveLength(2);
    vi.unstubAllGlobals();
  });

  it("空列表应直接返回空数组且不建网关连接", async () => {
    const results = await uploadPixelArtBatch("13800000000", "pwd", []);
    expect(results).toEqual([]);
    expect(gwMocks.connect).not.toHaveBeenCalled();
  });

  it("单张失败不中断后续", async () => {
    const fetchMock = vi.fn().mockImplementation(() =>
      Promise.resolve({ ok: false, status: 500, headers: { get: () => null }, json: vi.fn() }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const results = await uploadPixelArtBatch("13800000000", "pwd", [Buffer.alloc(1728), Buffer.alloc(1728)]);
    expect(results[0].ok).toBe(false);
    expect(results[0].error).toContain("官服 HTTP 500");
    expect(results[1].ok).toBe(false);
    // 即使 HTTP 失败仍逐张尝试（token 已申请），连接复用于全部
    expect(gwMocks.connect).toHaveBeenCalledTimes(1);
    vi.unstubAllGlobals();
  });

  it("单张 uploadPixelArt 应透传批量结果", async () => {
    const fetchMock = vi.fn().mockImplementation(() =>
      fakeRes({ status: 200, pixelArtId: 1001 }),
    );
    vi.stubGlobal("fetch", fetchMock);
    gwMocks.requestUploadToken.mockReset();
    gwMocks.requestUploadToken.mockResolvedValue({ pixelArtId: 1001n, uploadToken: "tok", expireTime: 0 });
    const r = await uploadPixelArt("13800000000", "pwd", Buffer.alloc(1728));
    expect(r.pixelArtId).toBe(1001n);
    expect(r.uploadToken).toBe("tok");
    vi.unstubAllGlobals();
  });

  it("postMultipart 业务 statusCode 非 0/200 应判失败（防止缺张错位）", async () => {
    // HTTP 200 但业务 statusCode 400（savePixelArt "Invalid multipart payload format"）
    const fetchMock = vi.fn().mockImplementation(() =>
      fakeRes({ statusCode: 400, error: "Bad Request", message: "Invalid multipart payload format" }),
    );
    vi.stubGlobal("fetch", fetchMock);
    gwMocks.requestUploadToken.mockReset();
    gwMocks.requestUploadToken.mockResolvedValue({ pixelArtId: 1001n, uploadToken: "tok", expireTime: 0 });
    const results = await uploadPixelArtBatch("13800000000", "pwd", [Buffer.alloc(1728)]);
    expect(results[0].ok).toBe(false);
    expect(results[0].error).toContain("官服业务失败 statusCode=400");
    vi.unstubAllGlobals();
  });
});

describe("getPixelArtList / deletePixelArt", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("getPixelArtList 应从官服读取像素画并下载 .dat 解析（显式传 ID）", async () => {
    // 1728 字节像素数据（第 0 像素红色）
    const dat = Buffer.alloc(1728);
    dat[0] = 255; dat[1] = 0; dat[2] = 0;
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (String(url).includes("getPixelArt")) return fakeRes({ pixelArts: { "1001": { url: "https://oss.example/pixel_art_prod_1001.dat", isBanned: false } } });
      return Promise.resolve({ ok: true, status: 200, arrayBuffer: vi.fn().mockResolvedValue(dat) });
    });
    vi.stubGlobal("fetch", fetchMock);
    const list = await getPixelArtList("13800000000", "pwd", [1001]);
    expect(list).toHaveLength(1);
    expect(list[0].id).toBe("1001");
    expect(list[0].isBanned).toBe(false);
    expect(list[0].pixels).toHaveLength(1728);
    expect(list[0].pixels![0]).toBe(255);
    vi.unstubAllGlobals();
  });

  it("getPixelArtList 缺省 ID 应返回空数组（官服无列表接口，ID 须显式传入）", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const list = await getPixelArtList("13800000000", "pwd");
    expect(list).toEqual([]);
    expect(fetchMock).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it("deletePixelArt 应经网关删除并返回逐张结果", async () => {
    gwMocks.deletePixelArt.mockResolvedValue(undefined);
    const results = await deletePixelArt("13800000000", "pwd", [1001, 1002]);
    expect(results).toEqual([
      { id: "1001", ok: true },
      { id: "1002", ok: true },
    ]);
    expect(gwMocks.deletePixelArt).toHaveBeenCalledTimes(2);
    expect(gwMocks.deletePixelArt).toHaveBeenCalledWith(1001n);
    expect(gwMocks.connect).toHaveBeenCalledTimes(1);
    expect(gwMocks.close).toHaveBeenCalledTimes(1);
  });

  it("deletePixelArt 单张失败不中断", async () => {
    gwMocks.deletePixelArt
      .mockRejectedValueOnce(new Error("code=403"))
      .mockResolvedValueOnce(undefined);
    const results = await deletePixelArt("13800000000", "pwd", [1001, 1002]);
    expect(results[0]).toMatchObject({ id: "1001", ok: false });
    expect(results[0].error).toContain("code=403");
    expect(results[1]).toMatchObject({ id: "1002", ok: true });
  });

  it("deletePixelArt 空列表应返回空数组", async () => {
    const results = await deletePixelArt("13800000000", "pwd", []);
    expect(results).toEqual([]);
  });
});
