import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, rm, readFile, stat, readdir } from "fs/promises";
import { join } from "path";
import os from "os";
import { buildMinForCurrentVersion } from "../../../scripts/pack-lua-min-current";

const enc = new TextEncoder();
const tempDirs: string[] = [];

async function makeDirs(): Promise<{ out: string; plugin: string }> {
  const out = await mkdtemp(join(os.tmpdir(), "lua-cur-out-"));
  const plugin = await mkdtemp(join(os.tmpdir(), "lua-cur-plugin-"));
  tempDirs.push(out, plugin);
  return { out, plugin };
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

describe("pack-lua-min-current 分平台最小 Lua 更新包", () => {
  it("Windows 离线：用 config windows resVersion 快照，构建最小包到 mods/windows，并移除旧 anon", async () => {
    const { out, plugin } = await makeDirs();
    await writeFile(join(plugin, "EnemyHpPlugin.lua"), enc.encode("-- hp\n"));
    await writeFile(join(plugin, "NetworkRedirectPlugin.lua"), enc.encode("-- redirect\n"));
    // 预置旧 anon（哈希命名）与非哈希 mod（皮肤，应保留）
    await mkdir(join(out, "windows"), { recursive: true });
    await writeFile(join(out, "windows", "anon_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.dat"), "old");
    await writeFile(join(out, "windows", "skinpack_x.dat"), "skin");
    await writeFile(join(out, "windows", ".placeholder"), "");

    const result = await buildMinForCurrentVersion(plugin, out, "Windows", true);

    // Windows 用 config.version.windows.resVersion；无下载桶时经已知 hash 兜底命中 6edf14bb
    expect(result.platform).toBe("Windows");
    expect(result.source).toBe("snapshot");
    expect(result.resVersion).toMatch(/^26-/);
    // config windows resVersion（client/resVersion 语义：日期+下划线后缀）
    expect(result.resVersion).toMatch(/^\d{2}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}_[0-9a-f]+$/);

    // 产物落在平台目录 mods/windows/
    const st = await stat(result.dat);
    expect(st.size).toBeGreaterThan(0);
    expect(result.dat).toContain(join("windows"));
    expect(result.bundleName).toMatch(/^anon\/[0-9a-f]{32}\.bin$/);

    // 覆盖目标为清单中真实 anon；patches[] 结构完整
    expect(result.replaceOf).toMatch(/^anon\//);
    expect(result.replaceOf).not.toBe("anon/7d91430e114d86fef7d3b3511151e12d.bin");
    expect(result.patches.length).toBeGreaterThan(0);
    expect(result.patch).toMatchObject(result.patches[0]);
    for (const p of result.patches) {
      expect(p.replaceOf).toMatch(/^anon\//);
      expect(p.name).toBe(result.bundleName);
      expect(p.md5).toMatch(/^[0-9a-f]{32}$/);
      expect(p.totalSize).toBeGreaterThan(0);
      expect(p.abSize).toBeGreaterThan(0);
    }

    // 旧 anon 被移除，皮肤/占位保留
    expect(result.removedOld).toContain("anon_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.dat");
    const files = await readdir(join(out, "windows"));
    expect(files).not.toContain("anon_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.dat");
    expect(files).toContain("skinpack_x.dat");
    expect(files).toContain(".placeholder");

    // 补丁描述 JSON（平台目录内）
    const patched = JSON.parse(await readFile(join(out, "windows", "lua-min-current.patch.json"), "utf8"));
    expect(patched.platform).toBe("Windows");
    expect(patched.resVersion).toBe(result.resVersion);
    expect(patched.patches).toHaveLength(result.patches.length);
    expect(patched.definedFixBundles).toContain(result.patch.replaceOf);
  });
});