import * as fs from "fs";
import * as path from "path";

/**
 * CS 反编译源解析（`reference/com.hypergryph.arknights_<版本>.cs`）。
 *
 * 背景：`reference/` 被 gitignore，文件名内嵌客户端版本号，**每次客户端更新都会改名**。
 * 早期多处脚本硬编码 `..._2.7.61.cs`，客户端升到 2.7.71 后守卫静默失效
 * （类型生成被跳过、CS 枚举补充被禁用）。本模块提供唯一解析入口，
 * 按通配探测 + 版本号排序取最新，杜绝硬编码漂移。
 *
 * 解析优先级：显式传参 > `GENERATE_CS` 环境变量 > `reference/` 下最新签名文件。
 */

/**
 * 项目根目录。
 *
 * 注意：本文件位于 `scripts/lib/`，需上溯**两级**（`__dirname` → `scripts/lib` →
 * `scripts` → 项目根）。写成 `path.join(__dirname, "..")` 会指向 `scripts/`，
 * 导致 `reference/` 探测到 `scripts/reference` 而失败。
 */
export const PROJECT_ROOT = path.join(__dirname, "..", "..");

/** 签名文件名匹配（`com.hypergryph.arknights_2.7.71.cs`） */
export const CS_FILE_RE = /^com\.hypergryph\.arknights_.+\.cs$/;

/**
 * 在 `reference/` 下探测最新的 CS 签名文件。
 *
 * 排序策略：按文件名字典序升序取最后一个。版本号形如 `2.7.71`，在
 * 同等分段数下字典序与语义序一致（`2.10.x` 之类多段版本会在跨大版本时
 * 回退为 `2.9.x < 2.10.x`，属可接受）；需要精确时用显式 `--cs` 覆盖。
 *
 * @param opts.refDir - 覆盖 `reference/` 目录（默认项目根下 `reference/`）
 * @param opts.explicit - 显式指定的签名文件路径，传入且存在时直接返回
 * @returns 绝对路径；未找到返回 `null`
 */
export function resolveCsFile(opts?: { refDir?: string; explicit?: string }): string | null {
  const explicit = opts?.explicit ?? undefined;
  if (explicit) {
    const resolved = path.isAbsolute(explicit) ? explicit : path.join(process.cwd(), explicit);
    if (fs.existsSync(resolved)) return resolved;
  }

  const dir = opts?.refDir ?? path.join(PROJECT_ROOT, "reference");
  if (!fs.existsSync(dir)) return null;

  const candidates = fs
    .readdirSync(dir)
    .filter((f) => CS_FILE_RE.test(f))
    .sort();

  return candidates.length > 0 ? path.join(dir, candidates[candidates.length - 1]) : null;
}

/**
 * 与 {@link resolveCsFile} 相同，但找不到时抛出（供必须要有源才能工作的脚本使用）。
 *
 * @param opts - 同 {@link resolveCsFile}
 * @throws 未找到任何 `com.hypergryph.arknights_*.cs`
 */
export function requireCsFile(opts?: { refDir?: string; explicit?: string }): string {
  const file = resolveCsFile(opts);
  if (!file) {
    const dir = opts?.refDir ?? path.join(PROJECT_ROOT, "reference");
    throw new Error(
      `未找到 CS 反编译源：${dir} 下不存在 com.hypergryph.arknights_*.cs。` +
        `请先运行 \`pnpm run decompile\`，或用 --cs <path> / GENERATE_CS 显式指定。`,
    );
  }
  return file;
}

/** 从签名文件名（或完整路径）提取客户端版本号，如 `2.7.71`。 */
export function csVersionOf(csPath: string): string {
  const m = path.basename(csPath).match(/^com\.hypergryph\.arknights_(.+)\.cs$/);
  return m ? m[1] : "unknown";
}
