import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, rm, readFile } from "fs/promises";
import { join } from "path";
import os from "os";
import JSZip from "jszip";
import { packLuaBundle } from "../../../scripts/pack-lua-bundle";
import { extractLuaFromHotUpdate } from "../../../scripts/extract-lua-hot";

const enc = new TextEncoder();
const tempDirs: string[] = [];

/** 空参考目录：定位到临时目录下的不存在路径，避免测试读取真实 ArknightsGameData 参考映射 */
async function makeTempDirs(): Promise<{ downloads: string; out: string; ref: string }> {
  const downloads = await mkdtemp(join(os.tmpdir(), "lua-hot-dl-"));
  const out = await mkdtemp(join(os.tmpdir(), "lua-hot-out-"));
  const ref = join(downloads, "no-such-ref");
  tempDirs.push(downloads, out);
  return { downloads, out, ref };
}

/**
 * 构造一个 anon 资源 .dat：zip 包裹的 UnityFS bundle（对齐官方下载格式）。
 * @param datPath - 写出路径
 * @param assets - bundle 内 TextAsset 列表
 */
async function writeAnonDat(
  datPath: string,
  assets: { name: string; script: Uint8Array }[],
): Promise<void> {
  const zip = new JSZip();
  zip.file("anon/test.bin", Buffer.from(packLuaBundle(assets)));
  const buf = await zip.generateAsync({ type: "nodebuffer" });
  await writeFile(datPath, Buffer.from(buf));
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

describe("extract-lua-hot 官方热更 anon Lua 提取", () => {
  it("扫描 anon 资源并提取 Lua 明文", async () => {
    const { downloads, out, ref } = await makeTempDirs();
    // anon 资源 1：含 Lua + 非 Lua 资产
    await writeAnonDat(join(downloads, "anon_aaaa.dat"), [
      { name: "gamedata/[uc]lua/CollectionTimedTaskItem.lua", script: enc.encode("-- holder\n") },
      { name: "gamedata/other/not_lua.bin", script: enc.encode("\u0000") },
      { name: "some_table", script: enc.encode("{}") },
    ]);
    // anon 资源 2：裸 .lua 名（无前缀布局）
    await writeAnonDat(join(downloads, "anon_bbbb.dat"), [
      { name: "GlobalConfig.lua", script: enc.encode("GlobalConfig = {}\n") },
    ]);
    // 非 anon 前缀文件应被忽略
    await writeAnonDat(join(downloads, "character_table.dat"), [
      { name: "x.lua", script: enc.encode("-- x\n") },
    ]);

    const stats = await extractLuaFromHotUpdate({ downloadsDir: downloads, outDir: out, refDir: ref, fetch: false });

    expect(stats.scanned).toBe(2); // 仅 anon_* 文件
    expect(stats.written).toBe(2); // CollectionTimedTaskItem.lua + GlobalConfig.lua（忽略了非 lua 与 character_table.dat）
    expect(stats.downloaded).toBe(0);
    expect(await readFile(join(out, "CollectionTimedTaskItem.lua"), "utf8")).toBe("-- holder\n");
    expect(await readFile(join(out, "GlobalConfig.lua"), "utf8")).toBe("GlobalConfig = {}\n");
  });

  it("带 gamedata/[uc]lua/ 前缀时剥去前缀写相对路径", async () => {
    const { downloads, out, ref } = await makeTempDirs();
    await writeAnonDat(join(downloads, "anon_cccc.dat"), [
      { name: "gamedata/[uc]lua/nested/sub/Deep.lua", script: enc.encode("-- deep\n") },
    ]);

    await extractLuaFromHotUpdate({ downloadsDir: downloads, outDir: out, refDir: ref, fetch: false });

    expect(await readFile(join(out, "nested", "sub", "Deep.lua"), "utf8")).toBe("-- deep\n");
  });

  it("提供参考目录时自动还原平铺裸名到分层路径", async () => {
    const { downloads, out } = await makeTempDirs();
    // 构造参考目录（分层，像 ArknightsGameData）
    const ref = join(downloads, "ref");
    const refBase = join(ref, "base", "utils");
    await mkdir(refBase, { recursive: true });
    await writeFile(join(refBase, "RandomUtil.lua"), "# reference content\n");
    await mkdir(join(ref, "base", "timer"), { recursive: true });
    await writeFile(join(ref, "base", "timer", "TimerModel.lua"), "# ref timer\n");

    // 热更 anon 里的裸名不留前缀（官方格式）
    await writeAnonDat(join(downloads, "anon_dddd.dat"), [
      { name: "RandomUtil.lua", script: enc.encode("-- random\n") },
      { name: "noRefFile.lua", script: enc.encode("-- no ref\n") },
      { name: "base/timer/TimerModel.lua", script: enc.encode("-- timer\n") },
    ]);

    const stats = await extractLuaFromHotUpdate({ downloadsDir: downloads, outDir: out, refDir: ref, fetch: false });

    expect(stats.written).toBe(3);
    // RandomUtil.lua 被还原到 base/utils/（参考目录命中）
    expect(await readFile(join(out, "base", "utils", "RandomUtil.lua"), "utf8")).toBe("-- random\n");
    // 未命中参考目录的保留平铺
    expect(await readFile(join(out, "noRefFile.lua"), "utf8")).toBe("-- no ref\n");
    // 资产名本身带子目录（无 gamedata/ 前缀）时按其自身相对路径
    expect(await readFile(join(out, "base", "timer", "TimerModel.lua"), "utf8")).toBe("-- timer\n");
  });

  it("目录为空时返回零统计", async () => {
    const { downloads, out, ref } = await makeTempDirs();
    const stats = await extractLuaFromHotUpdate({ downloadsDir: downloads, outDir: out, refDir: ref, fetch: false });
    expect(stats.scanned).toBe(0);
    expect(stats.written).toBe(0);
  });
});