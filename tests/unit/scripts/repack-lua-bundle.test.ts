import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, rm } from "fs/promises";
import { join } from "path";
import os from "os";
import yauzl from "yauzl";
import { packLuaBundle } from "../../../scripts/pack-lua-bundle";
import { extractTextAssets } from "../../../scripts/vendor/unityfs";
import { patchDefinedFix, repackBuiltinLua } from "../../../scripts/repack-lua-bundle";

const enc = new TextEncoder();
const dec = new TextDecoder();

const tempDirs: string[] = [];

async function makeTempDirs(): Promise<{ src: string; out: string }> {
  const src = await mkdtemp(join(os.tmpdir(), "lua-repack-src-"));
  const out = await mkdtemp(join(os.tmpdir(), "lua-repack-out-"));
  tempDirs.push(src, out);
  return { src, out };
}

afterEach(async () => {
  await Promise.all(
    tempDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })),
  );
});

/** 构造与官方 DefinedFix.lua 结构一致的假清单 */
function fakeDefinedFix(): string {
  return [
    "local list = ",
    "{",
    '  "HotFixes/TestStubHotfixer",',
    '  "HotFixes/PCInputFontRegistryHotfixer",',
    "};",
    "return list;",
    "",
  ].join("\n");
}

/** 读回 .dat（zip），返回 { entryName, content } */
function readZip(path: string): Promise<{ entryName: string; content: Buffer }[]> {
  return new Promise((resolve, reject) => {
    const entries: { entryName: string; content: Buffer }[] = [];
    yauzl.open(path, { lazyEntries: true }, (err, zipFile) => {
      if (err) return reject(err);
      zipFile.on("entry", (entry) => {
        zipFile.openReadStream(entry, (err2, stream) => {
          if (err2) return reject(err2);
          const chunks: Buffer[] = [];
          stream.on("data", (c) => chunks.push(c));
          stream.on("end", () => {
            entries.push({ entryName: entry.fileName, content: Buffer.concat(chunks) });
            zipFile.readEntry();
          });
        });
      });
      zipFile.on("end", () => resolve(entries));
      zipFile.readEntry();
    });
  });
}

describe("repack-lua-bundle 内置 bundle 重打包（DefinedFix 引导）", () => {
  it("patchDefinedFix 注入 PluginBootHotfixer 到清单最前", () => {
    const patched = patchDefinedFix(fakeDefinedFix());
    expect(patched).toContain('  "Plugin/PluginBootHotfixer",');
    expect(patched).toContain('"HotFixes/TestStubHotfixer",');
    expect(patched).toContain('"HotFixes/PCInputFontRegistryHotfixer"');
    // 新条目在最前
    expect(patched.indexOf("Plugin/PluginBootHotfixer")).toBeLessThan(
      patched.indexOf("HotFixes/TestStubHotfixer"),
    );
  });

  it("patchDefinedFix 锚点缺失时抛错", () => {
    expect(() => patchDefinedFix("local x = 1\n")).toThrow(/未找到/);
  });

  it("端到端：重打包 → 覆盖 mod 含插件(Plugin 前缀) + 补丁后的 DefinedFix", async () => {
    const { src, out } = await makeTempDirs();

    // 假内置 bundle（含 DefinedFix.lua 与一个普通 lua）
    const builtinAssets = [
      { name: "gamedata/[uc]lua/Hotfixes/DefinedFix.lua", script: enc.encode(fakeDefinedFix()) },
      { name: "gamedata/[uc]lua/base/BaseModule.lua", script: enc.encode("-- base module\n") },
    ];
    const builtinBytes = packLuaBundle(builtinAssets);
    const builtinBin = join(src, "anon_7d91430e114d86fef7d3b3511151e12d.bin");
    await writeFile(builtinBin, Buffer.from(builtinBytes));

    // 假插件目录（含引导 hotfixer）
    const pluginDir = join(src, "plugin");
    await mkdir(pluginDir, { recursive: true });
    await writeFile(join(pluginDir, "PluginBootHotfixer.lua"), enc.encode("-- boot\n"));
    await writeFile(join(pluginDir, "EnemyHpPlugin.lua"), enc.encode("-- hp\n"));

    const result = await repackBuiltinLua(builtinBin, pluginDir, out);
    expect(result.dat.endsWith("anon_7d91430e114d86fef7d3b3511151e12d.dat")).toBe(true);

    const entries = await readZip(result.dat);
    expect(entries.map((e) => e.entryName)).toEqual(["anon/7d91430e114d86fef7d3b3511151e12d.bin"]);

    const list = extractTextAssets(new Uint8Array(entries[0].content));
    const names = list.map((a) => a.name);
    // 插件资产用 Plugin 大写前缀（与 require 路径一致）
    expect(names).toContain("gamedata/[uc]lua/Plugin/PluginBootHotfixer.lua");
    expect(names).toContain("gamedata/[uc]lua/Plugin/EnemyHpPlugin.lua");
    const df = list.find((a) => a.name.toLowerCase().endsWith("definedfix.lua"))!;
    expect(dec.decode(df.script)).toContain('"Plugin/PluginBootHotfixer",');
  });

  it("内置 bundle 无 DefinedFix 时抛错", async () => {
    const { src, out } = await makeTempDirs();
    const bytes = packLuaBundle([{ name: "gamedata/[uc]lua/x.lua", script: enc.encode("-- x\n") }]);
    const bin = join(src, "builtin.bin");
    await writeFile(bin, Buffer.from(bytes));
    const pluginDir = join(src, "plugin");
    await mkdir(pluginDir, { recursive: true });
    await writeFile(join(pluginDir, "A.lua"), enc.encode("-- a\n"));
    await expect(repackBuiltinLua(bin, pluginDir, out)).rejects.toThrow(/DefinedFix/);
  });
});