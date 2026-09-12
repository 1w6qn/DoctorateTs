import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Request, Response as ExpressResponse } from "express";
import assetRouter from "../../app/ops/assets/asset";

/** excel 行形状（本文件用到的字段子集） */
interface ExcelRowMock {
  name?: string;
}

/** 配置替身视图：excel 门面方法 + 本文件读取/覆写的配置字段 */
interface AssetConfigMock {
  // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
  getItem(id: string): ExcelRowMock | undefined;
  itemName(id: string): string;
  makeItem(id: string, count: number, type?: string): { id: string; count: number; type?: string };
  charData(charId: string): ExcelRowMock | undefined;
  stageData(stageId: string): ExcelRowMock | undefined;
  // 本文件不提供的表显式占位（`undefined` 与「键不存在」在 `?.` 读取下运行时等价）
  ItemTable: { items?: Record<string, ExcelRowMock> } | undefined;
  CharacterTable: Record<string, ExcelRowMock> | undefined;
  StageTable: { stages?: Record<string, ExcelRowMock> } | undefined;
  Host: string;
  PORT: number;
  version: {
    resVersion: string;
    clientVersion: string;
    windows: { resVersion: string; clientVersion: string };
  };
  assets: { enableMods: boolean; downloadLocally: boolean; autoUpdate: boolean; downloadPeoxy: boolean };
  NetworkConfig: Record<string, string>;
}

const mockConfig = vi.hoisted(
  (): AssetConfigMock => ({
    // —— excel 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string): ExcelRowMock | undefined { return this.ItemTable?.items?.[id]; },
    itemName(id: string): string { return this.getItem(id)?.name ?? id; },
    makeItem(id: string, count: number, type?: string) { return type ? { id, count, type } : { id, count }; },
    charData(charId: string): ExcelRowMock | undefined { return this.CharacterTable?.[charId]; },
    stageData(stageId: string): ExcelRowMock | undefined { return this.StageTable?.stages?.[stageId]; },
    ItemTable: undefined,
    CharacterTable: undefined,
    StageTable: undefined,
    Host: "http://127.0.0.1",
    PORT: 8443,
    version: {
      resVersion: "25-05-20-12-36-22_4803e1",
      clientVersion: "2.5.60",
      windows: { resVersion: "26-07-30-09-00-07_win", clientVersion: "2.5.60" },
    },
    assets: { enableMods: false, downloadLocally: false, autoUpdate: true, downloadPeoxy: false },
    NetworkConfig: {},
  }),
);

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

/**
 * asset 路由的测试请求视图
 *
 * 只声明被测分支读到的四个成员（真实 express `Request` 可赋给它 → 单向可比）。
 */
interface MockReq {
  method: string;
  url: string;
  params: Record<string, string>;
  headers?: Record<string, string>;
}

/** asset 路由的测试响应视图：只声明被测分支调用的五个方法（真实 express `Response` 可赋给它） */
interface MockRes {
  sendFile: ExpressResponse["sendFile"];
  redirect: ExpressResponse["redirect"];
  send: ExpressResponse["send"];
  status: ExpressResponse["status"];
  setHeader: ExpressResponse["setHeader"];
}

/** asset 路由的请求形参类型（express Request） */
type RouterReq = Parameters<typeof assetRouter>[0];

/** fetch 响应替身视图：真实 `Response` 可赋给它（`headers.forEach` 三参回调可赋给两参签名） */
interface FetchResponseMock {
  status: number;
  arrayBuffer: () => Promise<ArrayBuffer>;
  headers: { forEach: (cb: (value: string, key: string) => void) => void };
}

/** fetch 调用参数视图：asset.ts 以普通对象字面量传 `headers.Range`（`RequestInit.headers` 是联合类型，无法直接索引） */
type FetchInitView = { headers: { Range?: string } };

function mockRes(): MockRes {
  return {
    sendFile: vi.fn(),
    redirect: vi.fn(),
    send: vi.fn(),
    status: vi.fn().mockReturnThis(),
    setHeader: vi.fn(),
  };
}

/** 以窄替身调用 asset 路由（`req`/`res` 单向断言，见 {@link MockReq}/{@link MockRes}） */
async function callRouter(req: MockReq, res: MockRes): Promise<void> {
  await assetRouter(req as RouterReq, res as ExpressResponse, () => {});
}

describe("asset 资源路由", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConfig.assets.downloadPeoxy = false;
  });

  it("Windows 平台热更新列表路径应匹配并返回", async () => {
    const res = mockRes();
    await callRouter(
      {
        method: "GET",
        url: "/official/Windows/assets/25-05-20-12-36-22_4803e1/hot_update_list.json",
        params: {
          platform: "Windows",
          assetsHash: "25-05-20-12-36-22_4803e1",
          fileName: "hot_update_list.json",
        },
      },
      res,
    );
    await new Promise((r) => setTimeout(r, 30));
    expect(res.sendFile).toHaveBeenCalled();
  });

  it("Android 平台路径保持兼容", async () => {
    const res = mockRes();
    await callRouter(
      {
        method: "GET",
        url: "/official/Android/assets/abc123/hot_update_list.json",
        params: { platform: "Android", assetsHash: "abc123", fileName: "hot_update_list.json" },
      },
      res,
    );
    await new Promise((r) => setTimeout(r, 30));
    expect(res.sendFile).toHaveBeenCalled();
  });

  it("Windows 平台非热更新文件应重定向到 CDN（资源版本跟随客户端路径）", async () => {
    const res = mockRes();
    await callRouter(
      {
        method: "GET",
        url: "/official/Windows/assets/26-07-30-09-00-07_win/char_pack.dat",
        params: { platform: "Windows", assetsHash: "26-07-30-09-00-07_win", fileName: "char_pack.dat" },
      },
      res,
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
    const fetchResponse: FetchResponseMock = {
      status: 206,
      arrayBuffer: async () => new ArrayBuffer(4),
      headers: { forEach: (cb) => headers.forEach((v, k) => cb(v, k)) },
    };
    vi.spyOn(globalThis, "fetch").mockResolvedValue(fetchResponse as Response);

    const res = mockRes();
    await callRouter(
      {
        method: "GET",
        url: "/official/Windows/assets/26-07-30-09-00-07_win/char_pack.dat",
        headers: { range: "bytes=0-99" },
        params: { platform: "Windows", assetsHash: "26-07-30-09-00-07_win", fileName: "char_pack.dat" },
      },
      res,
    );
    await new Promise((r) => setTimeout(r, 30));

    // 转发 CDN 状态码/头/body，且携带 Range 头
    expect(res.status).toHaveBeenCalledWith(206);
    expect(res.setHeader).toHaveBeenCalledWith("content-type", "application/octet-stream");
    expect(res.send).toHaveBeenCalled();
    // Range 转发给 CDN
    const fetchMock = vi.mocked(globalThis.fetch);
    expect(String((fetchMock.mock.calls[0][1] as FetchInitView).headers.Range)).toBe("bytes=0-99");
  });
});
