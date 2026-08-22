/**
 * mod 打包工具：将 ArkUnpacker 解包出的资源目录打包为 mods/*.dat（zip）资源包
 *
 * 每个文件打成一个 .dat（zip，单条目），条目名 = 相对源目录的 posix 路径——
 * 与 app/asset.ts loadMods 的约定一致（zip 条目名即 mod 名，如 "activity/[uc]act5fun.ab"）。
 *
 * 用法：
 *   pnpm run pack:mod -- --dir <ArkUnpacker 解包目录> [--out <mods 目录>] [--clean]
 *   --dir    必填，源目录（递归）
 *   --out    输出目录（缺省 <项目根>/mods）
 *   --clean  打包前清空输出目录内的 *.dat（移除源中已删除的旧 mod）
 *
 * 打包后启用 mod 链路：data/config.json 的 assets.enableMods 置 true，重启服务。
 */
import { readdir, readFile, writeFile, mkdir, rm } from "fs/promises";
import { join, relative, basename, sep } from "path";
import JSZip from "jszip";
import { exists } from "../app/utils/file";
import { assetRegistry } from "../app/asset-registry/asset-service";

interface CliArgs {
  dir: string;
  out: string;
  clean: boolean;
}

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = { dir: "", out: join(__dirname, "..", "mods"), clean: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--dir") args.dir = argv[++i] ?? "";
    else if (arg === "--out") args.out = argv[++i] ?? "";
    else if (arg === "--clean") args.clean = true;
    else if (arg === "--help" || arg === "-h") {
      console.log(
        "用法: pnpm run pack:mod -- --dir <解包目录> [--out <mods目录>] [--clean]",
      );
      process.exit(0);
    }
  }
  return args;
}

/** 与 app/asset.ts 一致的下载名转换：/ → _，# → __，去扩展名 + .dat */
export function toDownloadName(relPosix: string): string {
  return relPosix.replace(/\//g, "_").replace(/#/g, "__").split(".")[0] + ".dat";
}

/** 递归收集目录下所有文件（跳过隐藏/占位文件） */
async function collectFiles(dir: string, out: string[]): Promise<void> {
  const entries = await readdir(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === ".placeholder" || entry.name.startsWith(".")) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      await collectFiles(full, out);
    } else {
      out.push(full);
    }
  }
}

export interface PackResult {
  packed: number;
  totalBytes: number;
  out: string;
  files: { rel: string; downloadName: string; bytes: number }[];
}

/**
 * 打包目录下所有文件为 mod 资源包（.dat 单条目 zip）。
 * @returns 打包汇总（供 CLI 打印与单测断言）
 */
export async function packMod(args: CliArgs): Promise<PackResult> {
  const { dir, out, clean } = args;
  const files: string[] = [];
  await collectFiles(dir, files);
  if (files.length === 0) {
    console.warn(`源目录无文件（${dir}），无 mod 可打包`);
    return { packed: 0, totalBytes: 0, out, files: [] };
  }

  await mkdir(out, { recursive: true });
  // 保留目录用占位文件（mods/ 被 .gitignore，仅 .placeholder 入 git）
  const placeholder = join(out, ".placeholder");
  if (!(await exists(placeholder))) {
    await writeFile(placeholder, "");
  }
  if (clean) {
    for (const name of await readdir(out)) {
      if (name !== ".placeholder" && name.endsWith(".dat")) {
        await rm(join(out, name), { force: true });
      }
    }
  }

  const seen = new Set<string>();
  const result: PackResult = { packed: 0, totalBytes: 0, out, files: [] };
  for (const file of files) {
    const relPosix = relative(dir, file).split(sep).join("/");
    const downloadName = toDownloadName(relPosix);
    if (seen.has(downloadName)) {
      console.warn(`冲突：${relPosix} 与其它文件映射到同一下载名 ${downloadName}，跳过`);
      continue;
    }
    seen.add(downloadName);

    const content = await readFile(file);
    const zip = new JSZip();
    // createFolders:false —— 避免 jsZip 为斜杠路径自动生成空目录条目（.dat 保持单条目，loadMods 只认文件条目）
    zip.file(relPosix, content, { createFolders: false });
    const buffer = await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" });

    await writeFile(join(out, downloadName), buffer);
    result.packed += 1;
    result.totalBytes += content.length;
    result.files.push({ rel: relPosix, downloadName, bytes: content.length });
  }
  return result;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  if (!args.dir) {
    console.error("缺少 --dir <解包目录>（ArkUnpacker 输出目录）");
    process.exit(1);
  }
  if (!(await exists(args.dir))) {
    console.error(`源目录不存在: ${args.dir}`);
    process.exit(1);
  }

  const { packed, totalBytes, out, files } = await packMod(args);
  for (const f of files) {
    console.log(`  ${f.rel} -> ${f.downloadName} (${f.bytes} B)`);
  }
  // 溯源：mod 生成留痕（mod 资产注册 + modify 事件）
  try {
    for (const f of files) {
      await assetRegistry.recordEvent({
        asset: { name: f.downloadName, category: "mod", source: args.dir, version: "mod", size: f.bytes },
        action: "modify",
        actor: "pack-mod",
        source: args.dir,
        sizeAfter: f.bytes,
        detail: { rel: f.rel },
      });
    }
  } catch { /* 溯源失败不阻断 */ }
  console.log(
    `\n打包完成：${packed} 个 mod -> ${out}（源共 ${totalBytes} B）。\n` +
      `启用：将 data/config.json 的 "assets" -> "enableMods" 置 true，重启服务后客户端热更自动拉取。`,
  );
}

// 仅在直接执行（tsx scripts/pack-mod.ts）时运行；被测试 import 时不自动执行
if (typeof require !== "undefined" && require.main === module) {
  main().catch((error) => {
    console.error("打包失败:", error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
