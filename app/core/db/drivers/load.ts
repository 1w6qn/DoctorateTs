/**
 * 可选驱动模块加载器
 *
 * MySQL / PostgreSQL 驱动（mysql2 / pg）声明为 `optionalDependencies`——未安装时
 * 对 `pnpm install` 不构成失败，对 SQLite 默认路径零影响。仅当配置显式选用该后端
 * 时才加载，加载失败抛出带安装指引的明确错误（而非晦涩的 MODULE_NOT_FOUND）。
 *
 * 说明：以变量承载模块名（而非字面量）——字面量会被 TypeScript 静态解析，驱动未安装
 * 时 `tsc` 直接报「Cannot find module」；变量形式让类型检查与驱动安装解耦，
 * 真正缺失在运行时（选用该后端时）才暴露，正是「可选」所需语义。
 */
import { logger } from "@utils/logger";

/**
 * 动态加载可选驱动模块
 * @param specifier - 模块说明符（如 `"mysql2/promise"`）
 * @param packageName - 包名（用于安装指引文案）
 * @param feature - 触发加载的功能名（用于错误上下文）
 * @returns 模块导出对象（CommonJS 默认导出自动解包）
 */
export async function loadOptionalDriver<T>(
  specifier: string,
  packageName: string,
  feature: string,
): Promise<T> {
  let mod: unknown;
  try {
    mod = await import(specifier);
  } catch (e) {
    const reason = e instanceof Error ? e.message : String(e);
    throw new Error(
      `${feature} 需要可选驱动 "${packageName}"，但当前未安装。` +
        `请执行：pnpm add ${packageName}（或 npm i ${packageName}）后重启。` +
        `原始错误：${reason}`,
    );
  }
  const anyMod = mod as { default?: unknown } & Record<string, unknown>;
  // tsx/Node ESM 互操作：CommonJS 包可能挂在 default 上
  const resolved =
    anyMod.default && typeof anyMod.default === "object"
      ? (anyMod.default as Record<string, unknown>)
      : anyMod;
  logger.debug("db", `可选驱动已加载：${specifier}`);
  return resolved as T;
}
