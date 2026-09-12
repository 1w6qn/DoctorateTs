/**
 * 物品事件直发扫描器（Items Direct Emit Scanner）
 *
 * 度量「绕过统一物品管道、直接 emit items:get/items:use 事件」的调用面：
 * `AGENTS.md` 约定物品增减必须经 `player.gainItem.setTarget(...).use()/handle()`
 * 管道（`app/game/kernel/inventory-pipeline.ts`），不直发 `items:*` 事件。
 * 本模块把该约定的违反量量化成可测指标，供棘轮守卫固化「只减不增」。
 *
 * 扫描口径与 tests/unit/architecture/inventory-pipeline-ratchet.test.ts 完全一致
 * （本文件即唯一判定来源，CLI 与守卫共用），基线刷新：`pnpm run items:direct -- --write`。
 */
import * as fs from "fs";
import * as path from "path";

/** 基线文档格式（tests/unit/architecture/inventory-pipeline-baseline.json） */
export interface ItemsDirectBaseline {
  /** 生成时间（ISO 8601，仅供人读，不参与判定） */
  generatedAt: string;
  /** 仓库相对路径 → 直发次数 */
  counts: Record<string, number>;
  /** 总次数（与 counts 逐项和自洽，防手写基线失真） */
  total: number;
}

/**
 * 豁免文件（仓库相对路径，唯二）
 *
 * - `inventory-pipeline.ts`：管道本体——它就是做这件事的地方；
 * - `inventory.ts`：`items:get`/`items:use` 的下游订阅者实现（事件 handler 本身）。
 */
export const EXEMPT_FILES = [
  "app/game/kernel/inventory-pipeline.ts",
  "app/game/kernel/inventory.ts",
] as const;

/** 直发事件名的匹配正则（items:get / items:use，单双引号皆可） */
const DIRECT_EMIT_RE = /_trigger\.emit\(\s*["']items:(?:get|use)["']/;

/**
 * 判定单行是否为物品事件直发
 *
 * 规则：
 * - 匹配 `_trigger.emit("items:get"|'items:use'`（无论是否 await，await 与否属时序问题，
 *   不改变「绕过管道」这一事实）；
 * - 跳过注释行——JSDoc/行注释里的示例代码不是调用点（如 inventory-pipeline.ts 的
 *   用法说明、battle.ts 的行内注释）。覆盖三种形态：行注释（双斜杠）、块注释续行
 *   （星号开头）、单行块注释（斜杠星号开头）。
 *
 * 已知边界（按行扫描的固有限制，刻意接受）：同一物理行「代码 + 尾随块注释」中的
 * 注释片段会计入；跨行的字符串字面量不含此模式。若未来出现误报/漏报，
 * 应升级为基于 AST 的扫描，而不是在本函数里加特例。
 * @param line - 源码单行
 * @returns 是否为直发调用行
 */
export function isDirectItemEmit(line: string): boolean {
  const trimmed = line.trim();
  if (
    trimmed.startsWith("*") ||
    trimmed.startsWith("//") ||
    trimmed.startsWith("/*")
  ) {
    return false;
  }
  return DIRECT_EMIT_RE.test(trimmed);
}

/**
 * 递归枚举目录下全部 .ts 文件
 * @param dir - 目录绝对路径
 * @returns 文件绝对路径数组
 */
export function collectTsFiles(dir: string): string[] {
  const out: string[] = [];
  if (typeof dir !== "string" || dir.length === 0) return out;
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const p = `${dir}/${e.name}`.replace(/\/+/g, "/");
    if (e.isDirectory()) out.push(...collectTsFiles(p));
    else if (e.isFile() && p.endsWith(".ts") && !p.endsWith(".d.ts")) out.push(p);
  }
  return out;
}

/**
 * 扫描 app/ 下的物品事件直发情况
 *
 * 覆盖全 `app/`（core/game/ops 都不该绕过管道），豁免 {@link EXEMPT_FILES}。
 * @param repoRoot - 仓库根绝对路径（POSIX 或 Windows 分隔符均可）
 * @returns 仓库相对路径（`/` 分隔）→ 直发次数（仅含 >0 的文件）
 */
export function scanDirectItemEmits(repoRoot: string): Record<string, number> {
  const counts: Record<string, number> = {};
  const appRoot = path.join(repoRoot, "app");
  for (const file of collectTsFiles(appRoot)) {
    const rel = path.relative(repoRoot, file).split(path.sep).join("/");
    if ((EXEMPT_FILES as readonly string[]).includes(rel)) continue;
    const n = fs
      .readFileSync(file, "utf-8")
      .split(/\r?\n/)
      .filter((l) => isDirectItemEmit(l)).length;
    if (n > 0) counts[rel] = n;
  }
  return counts;
}

/**
 * 棘轮比较：当前扫描结果 vs 基线
 * @param baseline - 基线（file → 次数）
 * @param current - 当前（file → 次数）
 * @returns 新增直发的文件、次数上升的文件、已清零（应收紧基线）的文件
 */
export function diffBaseline(
  baseline: Record<string, number>,
  current: Record<string, number>,
): { added: string[]; grown: string[]; migrated: string[] } {
  const added = Object.keys(current)
    .filter((f) => !(f in baseline))
    .sort();
  const grown = Object.keys(current)
    .filter((f) => f in baseline && current[f] > baseline[f])
    .map((f) => `${f}: ${baseline[f]} → ${current[f]}`)
    .sort();
  const migrated = Object.keys(baseline)
    .filter((f) => !(f in current))
    .sort();
  return { added, grown, migrated };
}

/**
 * 由扫描结果构造基线文档
 * @param counts - 扫描结果
 * @returns 基线文档（total 与逐项和自洽）
 */
export function buildBaseline(counts: Record<string, number>): ItemsDirectBaseline {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  return {
    generatedAt: new Date().toISOString(),
    counts: Object.fromEntries(Object.entries(counts).sort(([a], [b]) => a.localeCompare(b))),
    total,
  };
}
