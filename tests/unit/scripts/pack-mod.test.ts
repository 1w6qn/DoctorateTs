import { describe, it, expect, afterEach } from "vitest";
import { mkdtemp, mkdir, writeFile, rm, readdir } from "fs/promises";
import { join } from "path";
import os from "os";
import yauzl from "yauzl";
import { packMod, toDownloadName } from "../../../scripts/pack-mod";

const tempDirs: string[] = [];

async function makeTempDirs(): Promise<{ src: string; out: string }> {
  const src = await mkdtemp(join(os.tmpdir(), "pack-mod-src-"));
  const out = await mkdtemp(join(os.tmpdir(), "pack-mod-out-"));
  tempDirs.push(src, out);
  return { src, out };
}

afterEach(async () => {
  await Promise.all(
    tempDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })),
  );
});

/** 用 yauzl 读回 .dat（zip），返回 { entryName, content } 列表 */
function readZip(path: string): Promise<{ entryName: string; content: string }[]> {
  return new Promise((resolve, reject) => {
    const entries: { entryName: string; content: string }[] = [];
    yauzl.open(path, { lazyEntries: true }, (err, zipFile) => {
      if (err) return reject(err);
      zipFile.on("entry", (entry) => {
        zipFile.openReadStream(entry, (err2, stream) => {
          if (err2) return reject(err2);
          const chunks: Buffer[] = [];
          stream.on("data", (chunk) => chunks.push(chunk));
          stream.on("end", () => {
            entries.push({
              entryName: entry.fileName,
              content: Buffer.concat(chunks).toString(),
            });
            zipFile.readEntry();
          });
        });
      });
      zipFile.on("end", () => resolve(entries));
      zipFile.readEntry();
    });
  });
}

describe("pack-mod 打包工具", () => {
  it("toDownloadName 与 asset.ts 命名约定一致（/ → _、去扩展名 + .dat）", () => {
    expect(toDownloadName("activity/[uc]act5fun.ab")).toBe("activity_[uc]act5fun.dat");
    expect(toDownloadName("scenes/activities/x/level_01.ab")).toBe(
      "scenes_activities_x_level_01.dat",
    );
    expect(toDownloadName("a/b#c.ab")).toBe("a_b__c.dat");
  });

  it("递归打包为 .dat 单条目 zip，条目名 = 相对 posix 路径，内容一致", async () => {
    const { src, out } = await makeTempDirs();
    await mkdir(join(src, "activity"), { recursive: true });
    await mkdir(join(src, "scenes", "map"), { recursive: true });
    await writeFile(join(src, "activity", "[uc]act1fun.ab"), Buffer.from("hello-mod"));
    await writeFile(join(src, "scenes", "map", "level_01.ab"), Buffer.from("scene-data"));

    const result = await packMod({ dir: src, out, clean: false });

    expect(result.packed).toBe(2);
    const names = result.files.map((f) => f.downloadName).sort();
    expect(names).toEqual(["activity_[uc]act1fun.dat", "scenes_map_level_01.dat"]);

    // 读回 zip：条目名与内容一致
    const entries = await readZip(join(out, "activity_[uc]act1fun.dat"));
    expect(entries.map((e) => e.entryName)).toEqual(["activity/[uc]act1fun.ab"]);
    expect(entries[0].content).toBe("hello-mod");

    const entries2 = await readZip(join(out, "scenes_map_level_01.dat"));
    expect(entries2.map((e) => e.entryName)).toEqual(["scenes/map/level_01.ab"]);
    expect(entries2[0].content).toBe("scene-data");
  });

  it("下载名冲突的文件被跳过（打包计数不含冲突项）", async () => {
    const { src, out } = await makeTempDirs();
    await mkdir(join(src, "activity"), { recursive: true });
    // 两个文件映射到同一下载名 activity_x.dat
    await writeFile(join(src, "activity", "x.ab"), Buffer.from("A"));
    await writeFile(join(src, "activity", "x"), Buffer.from("B"));

    const result = await packMod({ dir: src, out, clean: true });

    expect(result.packed).toBe(1);
    const dats = (await readdir(out)).filter((f) => f.endsWith(".dat"));
    expect(dats).toEqual(["activity_x.dat"]);
    const entries = await readZip(join(out, "activity_x.dat"));
    // 先扫到哪个文件不确定——内容与条目名应属于两者之一
    expect(entries.length).toBe(1);
    expect(entries[0].entryName).toMatch(/^activity\/x(\.ab)?$/);
  });

  it("clean=true 时清空输出目录旧 .dat 再打包", async () => {
    const { src, out } = await makeTempDirs();
    await writeFile(join(src, "keep.ab"), Buffer.from("K"));
    // 预置一个不属于本次源目录的旧 mod
    await writeFile(join(out, "stale.dat"), Buffer.from("old"));

    const result = await packMod({ dir: src, out, clean: true });

    expect(result.packed).toBe(1);
    const dats = (await readdir(out)).filter((f) => f.endsWith(".dat"));
    expect(dats).toEqual(["keep.dat"]);
  });
});
