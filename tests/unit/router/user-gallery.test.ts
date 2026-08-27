import { describe, it, expect, vi, beforeEach } from "vitest";
import { join } from "node:path";

// 劫持 node:fs，避免缩略图落盘污染真实 data/user/gallery
const fsMock = vi.hoisted(() => ({
  writeFileSync: vi.fn(),
  mkdirSync: vi.fn(),
  unlinkSync: vi.fn(),
  existsSync: vi.fn(),
  readFileSync: vi.fn(),
}));
vi.mock("node:fs", () => fsMock);

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));
vi.mock("@utils/time", () => ({ now: () => 1234567890 }));

import { rootRouter } from "../../../app/game/domain/router/user";
import httpContext from "express-http-context2";
import { mockPlayerData } from "../../helpers";

function mockRes() {
  return { send: vi.fn(), type: vi.fn().mockReturnThis(), status: vi.fn().mockReturnThis(), json: vi.fn() };
}

describe("形艺特辑 gallery 编辑→展示闭环", () => {
  let player: any;
  let res: any;

  beforeEach(() => {
    vi.clearAllMocks();
    // 重置 fs mock 实现与一次性返回值队列，避免跨用例串扰
    fsMock.writeFileSync.mockReset();
    fsMock.mkdirSync.mockReset();
    fsMock.unlinkSync.mockReset();
    fsMock.existsSync.mockReset();
    fsMock.readFileSync.mockReset();
    player = mockPlayerData({
      status: { uid: "1" } as any,
    });
    res = mockRes();
    (httpContext.get as any).mockReturnValue(player);
  });

  async function call(req: any) {
    const r = mockRes();
    rootRouter(req, r, () => {});
    await new Promise((resolve) => setTimeout(resolve, 20));
    return r;
  }

  it("saveDiyMagazineV1：带 thumbnail 时将缩略图落盘为 {uid}_magazine_{leafId}.jpg", async () => {
    const r = await call({
      method: "POST",
      url: "/gallery/saveDiyMagazineV1",
      body: {
        magazine: { leafId: "leaf_1", charSkin: null, decorList: [{ id: "s1", type: 2, sub: 0, pos: [1, 1], scale: 1 }] },
        thumbnail: "data:image/jpeg;base64,aGVsbG8=",
      },
    });
    expect(fsMock.mkdirSync).toHaveBeenCalledWith("./data/user/gallery", { recursive: true });
    expect(fsMock.writeFileSync).toHaveBeenCalledWith(
      join("./data/user/gallery", "1_magazine_leaf_1.jpg"),
      expect.any(Buffer),
    );
    // base64 解码还原原始字节
    const buf = fsMock.writeFileSync.mock.calls[0][1] as Buffer;
    expect(buf.toString("utf8")).toBe("hello");
    expect(r.send).toHaveBeenCalled();
  });

  it("saveDiyMagazineV2：页面清空且无 thumbnail 时删除磁盘残留缩略图", async () => {
    fsMock.existsSync.mockReturnValueOnce(true);
    const r = await call({
      method: "POST",
      url: "/gallery/saveDiyMagazineV2",
      body: { magazine: { leafId: "leaf_1", charSkin: null, decorList: [] } },
    });
    expect(fsMock.existsSync).toHaveBeenCalledWith(join("./data/user/gallery", "1_magazine_leaf_1.jpg"));
    expect(fsMock.unlinkSync).toHaveBeenCalledWith(join("./data/user/gallery", "1_magazine_leaf_1.jpg"));
    expect(r.send).toHaveBeenCalled();
  });

  it("saveDiyMagazineV2：页面有内容但无 thumbnail 时不触发文件操作", async () => {
    const r = await call({
      method: "POST",
      url: "/gallery/saveDiyMagazineV2",
      body: { magazine: { leafId: "leaf_1", charSkin: "char_1", decorList: [] } },
    });
    expect(fsMock.writeFileSync).not.toHaveBeenCalled();
    expect(fsMock.unlinkSync).not.toHaveBeenCalled();
    expect(r.send).toHaveBeenCalled();
  });

  it("getThumbnailUrl：页面有内容时返回真实绝对 URL，空页面返回 null", async () => {
    // 预置 gallery：leaf_1 有内容，leaf_2 为空
    (player._playerdata.gallery as any) = {
      firstRewards: 0,
      leafMap: {
        leaf_1: { leafId: "leaf_1", charSkin: null, decorList: [{ id: "s1" }], getTs: 1, version: 0 },
        leaf_2: { leafId: "leaf_2", charSkin: null, decorList: [], getTs: 1, version: 0 },
      },
      magazineSquad: [],
      collectionRewards: {},
      stickerMap: {},
      offlineList: {},
    };
    const r = await call({
      method: "POST",
      url: "/gallery/getThumbnailUrl",
      body: { idList: ["leaf_1", "leaf_2"] },
      protocol: "http",
      get: () => "localhost:8080",
    });
    const response = r.send.mock.calls[0][0];
    expect(response.url).toEqual([
      "http://localhost:8080/gallery/jpg/1_magazine_leaf_1.jpg",
      null,
    ]);
  });

  it("GET /gallery/jpg：存在对应缩略图时回传真实 image/jpeg", async () => {
    fsMock.existsSync.mockReturnValueOnce(true);
    fsMock.readFileSync.mockReturnValue(Buffer.from("jpgdata"));
    const r = mockRes();
    rootRouter(
      { method: "GET", url: "/gallery/jpg/1_magazine_leaf_1.jpg" } as any,
      r,
      () => {},
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(fsMock.existsSync).toHaveBeenCalledWith(join("./data/user/gallery", "1_magazine_leaf_1.jpg"));
    expect(r.type).toHaveBeenCalledWith("image/jpeg");
    expect(r.send).toHaveBeenCalledWith(Buffer.from("jpgdata"));
  });

  it("GET /gallery/jpg：缩略图缺失时回退 1x1 透明占位 PNG", async () => {
    fsMock.existsSync.mockReturnValueOnce(false);
    const r = mockRes();
    rootRouter(
      { method: "GET", url: "/gallery/jpg/missing.jpg", params: { jpgName: "missing.jpg" } } as any,
      r,
      () => {},
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(r.type).toHaveBeenCalledWith("png");
    expect(r.send).toHaveBeenCalledWith(expect.any(Buffer));
  });

  it("changeMagazineSquad：JSON body 实际写入 gallery.magazineSquad（去重）", async () => {
    (player._playerdata.gallery as any) = { firstRewards: 0, leafMap: {}, magazineSquad: [], collectionRewards: {}, stickerMap: {}, offlineList: {} };
    const r = await call({
      method: "POST",
      url: "/gallery/changeMagazineSquad",
      headers: { "content-type": "application/json" },
      body: { magazineSquad: ["leaf_1", "leaf_2", "leaf_1"] },
    });
    expect(player._playerdata.gallery.magazineSquad).toEqual(["leaf_1", "leaf_2"]);
    expect(r.send).toHaveBeenCalled();
  });

  it("changeMagazineSquad：单叶 leafId 字段兼容写法", async () => {
    (player._playerdata.gallery as any) = { firstRewards: 0, leafMap: {}, magazineSquad: [], collectionRewards: {}, stickerMap: {}, offlineList: {} };
    await call({
      method: "POST",
      url: "/gallery/changeMagazineSquad",
      headers: { "content-type": "application/json" },
      body: { leafId: "leaf_3" },
    });
    expect(player._playerdata.gallery.magazineSquad).toEqual(["leaf_3"]);
  });

  it("changeMagazineSquad：官服字段 squad 写入当前陈列（修复前无匹配 → 不更新）", async () => {
    (player._playerdata.gallery as any) = { firstRewards: 0, leafMap: {}, magazineSquad: [], collectionRewards: {}, stickerMap: {}, offlineList: {} };
    // 官服抓包（R-1787473456620-0040）：请求体 {"squad":["leaf_default"]}
    const r = await call({
      method: "POST",
      url: "/gallery/changeMagazineSquad",
      headers: { "content-type": "application/json" },
      body: { squad: ["leaf_default", "leaf_default"] },
    });
    // 写入 + 去重，且响应 delta 携带 gallery.magazineSquad（客户端据此刷新"当前陈列"）
    expect(player._playerdata.gallery.magazineSquad).toEqual(["leaf_default"]);
    expect(r.send).toHaveBeenCalled();
  });

  it("saveDiyMagazineV2：multipart rawBody 能解析 json part 并写入 leafMap（不再 422）", async () => {
    const boundary = "BOUND";
    const raw = Buffer.concat([
      Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="json"\r\n\r\n`),
      Buffer.from(JSON.stringify({ magazine: { leafId: "leaf_m", charSkin: null, decorList: [{ id: "s1" }] } })),
      Buffer.from(`\r\n--${boundary}--\r\n`),
    ]);
    const r = await call({
      method: "POST",
      url: "/gallery/saveDiyMagazineV2",
      headers: { "content-type": `multipart/form-data; boundary="${boundary}"` },
      rawBody: raw,
    });
    expect(player._playerdata.gallery.leafMap).toBeDefined();
    expect(player._playerdata.gallery.leafMap["leaf_m"].decorList).toEqual([{ id: "s1" }]);
    expect(r.send).toHaveBeenCalled();
  });
});