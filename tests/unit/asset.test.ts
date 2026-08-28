import { describe, it, expect, vi, beforeEach } from "vitest";

const mockConfig = vi.hoisted(() => ({
  // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
  getItem(id: string) { return this.ItemTable?.items?.[id]; },
  itemName(id: string): string { return this.getItem(id)?.name ?? id; },
  makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
  charData(charId: string) { return this.CharacterTable?.[charId]; },
  stageData(stageId: string) { return this.StageTable?.stages?.[stageId]; },
  Host: "http://127.0.0.1",
  PORT: 8443,
  version: {
    resVersion: "25-05-20-12-36-22_4803e1",
    clientVersion: "2.5.60",
    windows: { resVersion: "26-07-30-09-00-07_win", clientVersion: "2.5.60" },
  },
  assets: { enableMods: false, downloadLocally: false, autoUpdate: true, downloadPeoxy: false },
  NetworkConfig: {},
}));

vi.mock("@utils/file", () => ({
  readJsonSync: vi.fn(() => mockConfig),
  exists: vi.fn().mockResolvedValue(false),
  size: vi.fn().mockResolvedValue(0),
}));
vi.mock("axios", () => ({
  default: { get: vi.fn().mockResolvedValue({ data: { abInfos: [] } }) },
}));
vi.mock("fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs/promises")>();
  return {
    ...actual,
    readFile: vi.fn(),
    writeFile: vi.fn().mockResolvedValue(undefined),
    mkdir: vi.fn().mockResolvedValue(undefined),
  };
});

import assetRouter from "../../app/ops/assets/asset";

function mockRes() {
  return {
    sendFile: vi.fn(),
    redirect: vi.fn(),
    send: vi.fn(),
    status: vi.fn().mockReturnThis(),
    setHeader: vi.fn(),
  };
}

describe("asset 资源路由", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConfig.assets.downloadPeoxy = false;
  });

  it("Windows 平台热更新列表路径应匹配并返回", async () => {
    const res = mockRes();
    await assetRouter(
      {
        method: "GET",
        url: "/official/Windows/assets/25-05-20-12-36-22_4803e1/hot_update_list.json",
        params: {
          platform: "Windows",
          assetsHash: "25-05-20-12-36-22_4803e1",
          fileName: "hot_update_list.json",
        },
      } as any,
      res as any,
      () => {},
    );
    await new Promise((r) => setTimeout(r, 30));
    expect(res.sendFile).toHaveBeenCalled();
  });

  it("Android 平台路径保持兼容", async () => {
    const res = mockRes();
    await assetRouter(
      {
        method: "GET",
        url: "/official/Android/assets/abc123/hot_update_list.json",
        params: { platform: "Android", assetsHash: "abc123", fileName: "hot_update_list.json" },
      } as any,
      res as any,
      () => {},
    );
    await new Promise((r) => setTimeout(r, 30));
    expect(res.sendFile).toHaveBeenCalled();
  });

  it("Windows 平台非热更新文件应重定向到 CDN（资源版本跟随客户端路径）", async () => {
    const res = mockRes();
    await assetRouter(
      {
        method: "GET",
        url: "/official/Windows/assets/26-07-30-09-00-07_win/char_pack.dat",
        params: { platform: "Windows", assetsHash: "26-07-30-09-00-07_win", fileName: "char_pack.dat" },
      } as any,
      res as any,
      () => {},
    );
    await new Promise((r) => setTimeout(r, 30));
    // downloadLocally=false → 重定向官服 CDN（CDN 平台跟随客户端请求的 platform + 客户端请求的版本）
    expect(res.redirect).toHaveBeenCalledWith(
      "https://ak.hycdn.cn/assetbundle/official/Windows/assets/26-07-30-09-00-07_win/char_pack.dat",
    );
  });

  it("代理模式应转发官服 CDN（支持 Range 头）", async () => {
    mockConfig.assets.downloadPeoxy = true;
    const headers = new Map([["content-type", "application/octet-stream"]]);
    vi.spyOn(globalThis, "fetch").mockResolvedValue({
      status: 206,
      arrayBuffer: async () => new ArrayBuffer(4),
      headers: { forEach: (cb: any) => headers.forEach((v, k) => cb(v, k)) },
    } as any);

    const res = mockRes();
    await assetRouter(
      {
        method: "GET",
        url: "/official/Windows/assets/26-07-30-09-00-07_win/char_pack.dat",
        headers: { range: "bytes=0-99" },
        params: { platform: "Windows", assetsHash: "26-07-30-09-00-07_win", fileName: "char_pack.dat" },
      } as any,
      res as any,
      () => {},
    );
    await new Promise((r) => setTimeout(r, 30));

    // 转发 CDN 状态码/头/body，且携带 Range 头
    expect(res.status).toHaveBeenCalledWith(206);
    expect(res.setHeader).toHaveBeenCalledWith("content-type", "application/octet-stream");
    expect(res.send).toHaveBeenCalled();
    // Range 转发给 CDN
    const fetchMock = vi.mocked(globalThis.fetch);
    expect(String((fetchMock.mock.calls[0][1] as any).headers.Range)).toBe("bytes=0-99");
  });
});
