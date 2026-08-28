import { describe, it, expect, vi, beforeEach } from "vitest";
import { join } from "path";
import { crc32 } from "crc";

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
    stat: vi.fn(),
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

import assetRouter from "@ops/assets/asset";
import { getModsList, getModVersionSuffix, refreshModsIfChanged, nextModBaseCid } from "@ops/assets/asset";
import { exists, size } from "@utils/file";
import { readdir, readFile, stat } from "fs/promises";

/** asset.ts 的 mods 目录（app/.. / mods = 项目根 / mods） */
const modsDir = join(__dirname, "..", "..", "mods");
/** 平台专属子目录（本组测试走 Android 平台） */
const androidModsDir = join(modsDir, "android");

/** 判断路径是否为平台专属子目录（用于 readdir mock 区分：平台目录视为不存在 → 走共享根目录） */
function isPlatformSubdir(p: string): boolean {
  return p.replace(/\\/g, "/").endsWith("/android");
}

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
    expect(getModsList("Android").mods).toHaveLength(0);
    expect(getModVersionSuffix("Android")).toBe("");
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
    expect(getModsList("Android").mods).toHaveLength(0);
  });

  it("相对路径缓存命中时复用，并按 mods 目录解析绝对路径；resVersion 后缀稳定", async () => {
    const mods = ["a.dat", "b.dat"];
    const dat1 = Buffer.alloc(10);
    const dat2 = Buffer.alloc(11);
    // 平台专属目录不存在（readdir ENOENT）→ 仅共享根目录有 mod
    vi.mocked(readdir).mockImplementation(async (d: string) => {
      if (isPlatformSubdir(String(d))) throw new Error("ENOENT");
      return mods as any;
    });
    vi.mocked(readFile).mockImplementation(async (p: string) => {
      if (String(p).endsWith("mods.Android.json")) {
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
    // 仅平台缓存文件存在；资产版本目录视为不存在（走 axios 下载分支）
    vi.mocked(exists).mockImplementation(async (p: string) =>
      String(p).endsWith("mods.Android.json"),
    );
    vi.mocked(size).mockResolvedValue(10);

    const res = mockRes();
    await assetRouter(manifestReq(), res, () => {});
    await new Promise((r) => setTimeout(r, 30));

    expect(res.sendFile).toHaveBeenCalled();
    expect(getModsList("Android").mods).toHaveLength(2);
    // 相对文件名已按当前 mods 目录解析为绝对路径
    expect(getModsList("Android").path[0]).toBe(join(modsDir, "a.dat"));
    expect(getModsList("Android").path[1]).toBe(join(modsDir, "b.dat"));
    expect(getModsList("Android").download).toEqual(["activity_test.dat", "scenes_x.dat"]);

    // 确定性后缀：非空且同 mod 集再次请求保持一致
    const s1 = getModVersionSuffix("Android");
    expect(s1).not.toBe("");
    await assetRouter(manifestReq(), res, () => {});
    await new Promise((r) => setTimeout(r, 30));
    expect(getModVersionSuffix("Android")).toBe(s1);
  });

  it("旧格式绝对路径缓存判失效（不命中）", async () => {
    vi.mocked(readdir).mockResolvedValue(["a.dat"] as any);
    vi.mocked(readFile).mockImplementation(async (p: string) => {
      if (String(p).endsWith("mods.Android.json")) {
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
      String(p).endsWith("mods.Android.json"),
    );
    vi.mocked(size).mockResolvedValue(10);

    const res = mockRes();
    await assetRouter(manifestReq(), res, () => {});
    await new Promise((r) => setTimeout(r, 30));

    // 缓存指纹不匹配 → 走 zip 解析（yauzl mock 失败）→ 空列表（而非使用旧路径缓存）
    expect(getModsList("Android").mods).toHaveLength(0);
  });

  it("nextModBaseCid：mod cid 越过 abInfos 与 packInfos 的最大值（防撞号回归）", () => {
    // 官方实测：abInfos cid 1..14981，packInfos cid 14982..15062
    const abInfos = Array.from({ length: 14981 }, (_, i) => ({ cid: i + 1 }));
    const packInfos = Array.from({ length: 81 }, (_, i) => ({ cid: 14982 + i }));
    expect(nextModBaseCid(abInfos, packInfos)).toBe(15063);
    // packInfos 缺省时退化为 abInfos 之后
    expect(nextModBaseCid(abInfos, [])).toBe(14982);
    // 空清单
    expect(nextModBaseCid([], [])).toBe(1);
  });

  it("平台专属目录 mod（mods/windows/）下发返回真实子目录路径（回归：曾被拼接为根路径 404）", async () => {
    vi.mocked(readdir).mockImplementation(async (d: string) => {
      const p = String(d).replace(/\\/g, "/");
      if (p.endsWith("/mods/windows")) return ["skinpack_char_4064_mlynar.dat"] as any;
      return [] as any; // 根目录无 mod → 平台目录唯一来源
    });
    vi.mocked(readFile).mockImplementation(async (p: string) => {
      const s = String(p);
      if (s.endsWith("mods.Windows.json")) {
        return JSON.stringify({
          file: {
            [join(modsDir, "windows", "skinpack_char_4064_mlynar.dat")]: { size: 100, crc32: crc32(Buffer.alloc(100)) },
          },
          mod: {
            mods: [{ name: "skinpack/char_4064_mlynar.ab", hash: "h", md5: "h", totalSize: 100, abSize: 200 }],
            name: ["skinpack/char_4064_mlynar.ab"],
            path: ["windows/skinpack_char_4064_mlynar.dat"],
            download: ["skinpack_char_4064_mlynar.dat"],
          },
        });
      }
      if (s.endsWith("skinpack_char_4064_mlynar.dat")) return Buffer.alloc(100) as any;
      return undefined as any;
    });
    vi.mocked(exists).mockImplementation(async (p: string) => {
      const s = String(p).replace(/\\/g, "/");
      return (
        s.endsWith("mods.Windows.json") ||
        s.endsWith("mods/windows/skinpack_char_4064_mlynar.dat")
      );
    });
    vi.mocked(size).mockResolvedValue(100);

    const req = {
      method: "GET",
      url: "/official/Windows/assets/26-08-07-10-51-39_26e0fc-8ddfbe/skinpack_char_4064_mlynar.dat",
      params: {
        platform: "Windows",
        assetsHash: "26-08-07-10-51-39_26e0fc-8ddfbe",
        fileName: "skinpack_char_4064_mlynar.dat",
      },
    } as any;
    const res = mockRes();
    await assetRouter(req, res, () => {});
    await new Promise((r) => setTimeout(r, 30));

    // 回归断言：sendFile 必须是 mods/windows/ 下的真实路径（旧代码拼成 mods/ 根 → ENOENT 404）
    expect(res.sendFile).toHaveBeenCalledWith(
      join(modsDir, "windows", "skinpack_char_4064_mlynar.dat"),
    );
    // 且不应误用根目录路径
    expect(res.sendFile).not.toHaveBeenCalledWith(
      join(modsDir, "skinpack_char_4064_mlynar.dat"),
    );
  });

  it("refreshModsIfChanged：mod 文件指纹变化时触发重载，未变化时跳过（运行时重打包热更新）", async () => {    // loadMods 走 zip 解析（yauzl mock 失败 → 空列表）；仅验证指纹驱动的重载触发
    let mtime = 1000;
    vi.mocked(readdir).mockImplementation(async (d: string) => {
      if (isPlatformSubdir(String(d))) throw new Error("ENOENT");
      return ["a.dat"] as any;
    });
    vi.mocked(stat).mockImplementation(async () => ({ mtimeMs: mtime, size: 10 }) as any);
    vi.mocked(exists).mockResolvedValue(false); // 平台缓存文件不存在
    vi.mocked(size).mockResolvedValue(10);
    vi.mocked(readFile).mockResolvedValue(Buffer.from("not a zip") as any);

    // 首次调用建立指纹基线 → 触发重载
    expect(await refreshModsIfChanged("Android")).toBe(true);
    // 指纹未变 → 不重载（避免每次版本请求重复扫描）
    expect(await refreshModsIfChanged("Android")).toBe(false);
    // mod 内容变更（mtime 变化）→ 再次触发重载
    mtime = 2000;
    expect(await refreshModsIfChanged("Android")).toBe(true);
    // 变更后趋于稳定 → 不再重载
    expect(await refreshModsIfChanged("Android")).toBe(false);
  });
});
