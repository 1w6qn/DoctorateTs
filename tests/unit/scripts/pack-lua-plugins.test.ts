import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, rm } from "fs/promises";
import { join } from "path";
import os from "os";
import yauzl from "yauzl";
import { packLuaPlugins } from "../../../scripts/pack-lua-plugins";
import { extractTextAssets } from "../../../scripts/vendor/unityfs";

const tempDirs: string[] = [];

async function makeTempDirs(): Promise<{ src: string; out: string }> {
  const src = await mkdtemp(join(os.tmpdir(), "lua-plugins-src-"));
  const out = await mkdtemp(join(os.tmpdir(), "lua-plugins-out-"));
  tempDirs.push(src, out);
  return { src, out };
}

afterEach(async () => {
  await Promise.all(
    tempDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })),
  );
});

/** 读回 .dat（zip），返回 { entryName, content } 列表 */
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

describe("pack-lua-plugins 打包工具", () => {
  it("打包目录为 plugin_lua.dat，zip 单条目为 UnityFS bundle，可解回全部 Lua", async () => {
    const { src, out } = await makeTempDirs();
    const enc = new TextEncoder();
    await writeFile(join(src, "BasePlugin.lua"), Buffer.from(enc.encode("-- base\nreturn BasePlugin\n")));
    await writeFile(join(src, "EnemyHpPlugin.lua"), Buffer.from(enc.encode("-- hp\n")));

    const result = await packLuaPlugins(src, out);

    // 名字相对路径 + 排序
    expect(result.assets.map((a) => a.name)).toEqual(["BasePlugin.lua", "EnemyHpPlugin.lua"]);
    expect(result.dat.endsWith("plugin_lua.dat")).toBe(true);

    // zip 单条目，条目名 = bundle 名
    const entries = await readZip(result.dat);
    expect(entries.map((e) => e.entryName)).toEqual(["plugin_lua.bin"]);

    // .dat 内为 UnityFS bundle，可解回全部 Lua
    const list = extractTextAssets(new Uint8Array(entries[0].content));
    expect(list).toHaveLength(2);
    expect(list[0].name).toBe("BasePlugin.lua");
    expect(list[1].name).toBe("EnemyHpPlugin.lua");
  });

  it("空目录抛错", async () => {
    const { src, out } = await makeTempDirs();
    await expect(packLuaPlugins(src, out)).rejects.toThrow(/无 .lua 文件/);
  });
});