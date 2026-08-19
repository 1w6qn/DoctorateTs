import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, rm, readFile, readdir } from "fs/promises";
import { join } from "path";
import os from "os";
import { packLuaBundle } from "../../../scripts/pack-lua-bundle";
import { extractLuaBundle } from "../../../scripts/extract-lua-bundle";

const enc = new TextEncoder();

const tempDirs: string[] = [];

async function makeTempDirs(): Promise<{ src: string; out: string }> {
  const src = await mkdtemp(join(os.tmpdir(), "lua-extract-src-"));
  const out = await mkdtemp(join(os.tmpdir(), "lua-extract-out-"));
  tempDirs.push(src, out);
  return { src, out };
}

afterEach(async () => {
  await Promise.all(
    tempDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })),
  );
});

/** 构造与官方 DefinedFix.lua 结构一致的假清单（已注入插件 hotfixer 条目） */
function patchedDefinedFix(): string {
  return [
    "local list = ",
    "{",
    '  "Plugin/NetworkRedirectPlugin",',
    '  "HotFixes/TestStubHotfixer",',
    "};",
    "return list;",
    "",
  ].join("\n");
}

describe("extract-lua-bundle 内置 Lua bundle 提取", () => {
  it("提取 Lua 资产为明文文件，跳过插件资产并还原 DefinedFix 注入标记", async () => {
    const { src, out } = await makeTempDirs();

    // 假内置 bundle：官方 Lua + 已注入引导条目的 DefinedFix + 插件资产 + 非 Lua 资产
    const assets = [
      { name: "gamedata/[uc]lua/entry.lua", script: enc.encode("-- entry\n") },
      { name: "gamedata/[uc]lua/Hotfixes/DefinedFix.lua", script: enc.encode(patchedDefinedFix()) },
      { name: "gamedata/[uc]lua/base/BaseModule.lua", script: enc.encode("-- base\n") },
      { name: "gamedata/[uc]lua/plugin/NetworkRedirectPlugin.lua", script: enc.encode("-- redirect\n") },
      { name: "gamedata/[uc]lua/plugin/EnemyHpPlugin.lua", script: enc.encode("-- hp\n") },
      { name: "gamedata/[uc]lua/nested/sub/Deep.lua", script: enc.encode("-- deep\n") },
      { name: "gamedata/other/not_lua.bin", script: enc.encode("\u0000") }, // 非 Lua 资产
    ];
    const bin = join(src, "builtin.bin");
    await writeFile(bin, Buffer.from(packLuaBundle(assets)));

    const result = await extractLuaBundle(bin, out);

    // 统计：7 条总资产，写入 4 条（跳过 2 插件 + 1 非 Lua）；
    // DefinedFix 曾含注入标记（已还原），不计入 unchanged（官方原版数）
    expect(result.total).toBe(7);
    expect(result.written).toBe(4);
    expect(result.skipped).toBe(3);
    expect(result.unchanged).toBe(0);

    // entry.lua 与子目录文件已写出
    expect(await readFile(join(out, "entry.lua"), "utf8")).toBe("-- entry\n");
    expect(await readFile(join(out, "base", "BaseModule.lua"), "utf8")).toBe("-- base\n");
    expect(await readFile(join(out, "nested", "sub", "Deep.lua"), "utf8")).toBe("-- deep\n");

    // 插件资产被跳过（不写入参考目录）
    await expect(readFile(join(out, "plugin", "NetworkRedirectPlugin.lua"))).rejects.toThrow();

    // DefinedFix 注入标记被还原（与 collectReferenceLua 的 from-ref 重建期望一致）
    const df = await readFile(join(out, "Hotfixes", "DefinedFix.lua"), "utf8");
    expect(df).not.toContain("Plugin/NetworkRedirectPlugin");
    expect(df).toContain('"HotFixes/TestStubHotfixer"');
  });

  it("未注入的 DefinedFix 保持不变", async () => {
    const { src, out } = await makeTempDirs();
    const original = 'local list = { "HotFixes/A", };\n';
    const assets = [{ name: "gamedata/[uc]lua/Hotfixes/DefinedFix.lua", script: enc.encode(original) }];
    const bin = join(src, "builtin.bin");
    await writeFile(bin, Buffer.from(packLuaBundle(assets)));

    const result = await extractLuaBundle(bin, out);
    expect(result.unchanged).toBe(1);
    expect(await readFile(join(out, "Hotfixes", "DefinedFix.lua"), "utf8")).toBe(original);
  });

  it("非 .dat 且含嵌套目录的 .bin 也可正常提取", async () => {
    const { src, out } = await makeTempDirs();
    const assets = [
      { name: "gamedata/[uc]lua/a/b/c.lua", script: enc.encode("-- c\n") },
      { name: "gamedata/[uc]lua/x.lua", script: enc.encode("-- x\n") },
    ];
    const bin = join(src, "builtin.bin");
    await writeFile(bin, Buffer.from(packLuaBundle(assets)));

    await extractLuaBundle(bin, out);
    const files = await readdir(out, { recursive: true });
    expect(files).toContain("x.lua");
    expect(files).toContain(join("a", "b", "c.lua"));
  });
});
