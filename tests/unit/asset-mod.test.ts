import { describe, it, expect, vi, beforeEach } from "vitest";
import { join } from "path";
import { crc32 } from "crc";

const mockConfig = vi.hoisted(() => ({
  Host: "http://127.0.0.1",
  PORT: 8443,
  version: {
    resVersion: "26-08-07-14-53-29_30b8f0",
    clientVersion: "2.7.61",
  },
  assets: {
    enableMods: true,
    downloadLocally: false,
    autoUpdate: true,
    downloadPeoxy: false,
  },
  NetworkConfig: {},
}));

vi.mock("@utils/file", () => ({
  readJsonSync: vi.fn(() => mockConfig),
  exists: vi.fn(),
  size: vi.fn(),
}));

vi.mock("axios", () => ({
  default: { get: vi.fn().mockResolvedValue({ data: { abInfos: [] } }) },
}));

vi.mock("fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("fs/promises")>();
  return {
    ...actual,
    readdir: vi.fn(),
    readFile: vi.fn(),
    writeFile: vi.fn().mockResolvedValue(undefined),
    mkdir: vi.fn().mockResolvedValue(undefined),
  };
});

// 损坏 zip 场景：openZipFile 拒绝（yauzl.open 报错）→ loadMods 逐文件跳过
vi.mock("yauzl", () => ({
  default: {
    open: vi.fn(
      (
        _path: string,
        _opts: unknown,
        cb: (err: Error | null) => void,
      ) => cb(new Error("mock: invalid zip")),
    ),
  },
  ZipFile: class {},
}));

import assetRouter from "../../app/asset";
import { getModsList, getModVersionSuffix } from "../../app/asset";
import { exists, size } from "@utils/file";
import { readdir, readFile } from "fs/promises";

/** asset.ts 的 mods 目录（app/.. / mods = 项目根 / mods） */
const modsDir = join(__dirname, "..", "..", "mods");

function manifestReq() {
  return {
    method: "GET",
    url: "/official/Android/assets/26-08-07-14-53-29_30b8f0/hot_update_list.json",
    params: {
      platform: "Android",
      assetsHash: "26-08-07-14-53-29_30b8f0",
      fileName: "hot_update_list.json",
    },
  } as any;
}

function mockRes() {
  return {
    sendFile: vi.fn(),
    redirect: vi.fn(),
    send: vi.fn(),
    status: vi.fn().mockReturnThis(),
    setHeader: vi.fn(),
  };
}

describe("asset mod（enableMods=true）", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockConfig.assets.enableMods = true;
  });

  it("mods 目录缺失时清单请求不 500，mod 列表为空", async () => {
    vi.mocked(readdir).mockRejectedValue(new Error("ENOENT"));
    vi.mocked(exists).mockResolvedValue(false);

    const res = mockRes();
    await assetRouter(manifestReq(), res, () => {});
    await new Promise((r) => setTimeout(r, 30));

    expect(res.sendFile).toHaveBeenCalled();
    expect(getModsList().mods).toHaveLength(0);
    expect(getModVersionSuffix()).toBe("");
  });

  it("损坏的 .dat（zip 解析失败）自动跳过，清单请求正常返回", async () => {
    vi.mocked(readdir).mockResolvedValue(["bad.dat"] as any);
    vi.mocked(readFile).mockResolvedValue(Buffer.from("not a zip") as any);
    vi.mocked(exists).mockResolvedValue(false);
    vi.mocked(size).mockResolvedValue(16);

    const res = mockRes();
    await assetRouter(manifestReq(), res, () => {});
    await new Promise((r) => setTimeout(r, 30));

    expect(res.sendFile).toHaveBeenCalled();
    expect(getModsList().mods).toHaveLength(0);
  });

  it("相对路径缓存命中时复用，并按 mods 目录解析绝对路径；resVersion 后缀稳定", async () => {
    const mods = ["a.dat", "b.dat"];
    const dat1 = Buffer.alloc(10);
    const dat2 = Buffer.alloc(11);
    vi.mocked(readdir).mockResolvedValue(mods as any);
    vi.mocked(readFile).mockImplementation(async (p: string) => {
      if (String(p).endsWith("mods.json")) {
        return JSON.stringify({
          file: {
            [join(modsDir, "a.dat")]: { size: 10, crc32: crc32(dat1) },
            [join(modsDir, "b.dat")]: { size: 11, crc32: crc32(dat2) },
          },
          mod: {
            mods: [
              { name: "activity/test.ab", hash: "h1", md5: "h1", totalSize: 10, abSize: 10 },
              { name: "scenes/x.ab", hash: "h2", md5: "h2", totalSize: 11, abSize: 11 },
            ],
            name: ["activity/test.ab", "scenes/x.ab"],
            path: ["a.dat", "b.dat"],
            download: ["activity_test.dat", "scenes_x.dat"],
          },
        });
      }
      if (String(p).endsWith("a.dat")) return dat1 as any;
      if (String(p).endsWith("b.dat")) return dat2 as any;
      return undefined;
    });
    // 仅 mods.json 缓存存在；资产版本目录视为不存在（走 axios 下载分支）
    vi.mocked(exists).mockImplementation(async (p: string) =>
      String(p).endsWith("mods.json"),
    );
    vi.mocked(size).mockResolvedValue(10);

    const res = mockRes();
    await assetRouter(manifestReq(), res, () => {});
    await new Promise((r) => setTimeout(r, 30));

    expect(res.sendFile).toHaveBeenCalled();
    expect(getModsList().mods).toHaveLength(2);
    // 相对文件名已按当前 mods 目录解析为绝对路径
    expect(getModsList().path[0]).toBe(join(modsDir, "a.dat"));
    expect(getModsList().path[1]).toBe(join(modsDir, "b.dat"));
    expect(getModsList().download).toEqual(["activity_test.dat", "scenes_x.dat"]);

    // 确定性后缀：非空且同 mod 集再次请求保持一致
    const s1 = getModVersionSuffix();
    expect(s1).not.toBe("");
    await assetRouter(manifestReq(), res, () => {});
    await new Promise((r) => setTimeout(r, 30));
    expect(getModVersionSuffix()).toBe(s1);
  });

  it("旧格式绝对路径缓存判失效（不命中）", async () => {
    vi.mocked(readdir).mockResolvedValue(["a.dat"] as any);
    vi.mocked(readFile).mockImplementation(async (p: string) => {
      if (String(p).endsWith("mods.json")) {
        return JSON.stringify({
          file: { [join(modsDir, "a.dat")]: { size: 10, crc32: 0 } },
          // 旧格式：path 为绝对路径（含盘符/分隔符）→ 应判失效
          mod: {
            mods: [],
            name: [],
            path: ["D:\\develop\\test\\mods\\a.dat"],
            download: [],
          },
        });
      }
      return Buffer.from("not a zip") as any;
    });
    vi.mocked(exists).mockImplementation(async (p: string) =>
      String(p).endsWith("mods.json"),
    );
    vi.mocked(size).mockResolvedValue(10);

    const res = mockRes();
    await assetRouter(manifestReq(), res, () => {});
    await new Promise((r) => setTimeout(r, 30));

    // 缓存未命中 → 走 zip 解析（yauzl mock 失败）→ 空列表（而非使用旧路径缓存）
    expect(getModsList().mods).toHaveLength(0);
  });
});
