/**
 * 类型债 CLI
 *
 * 用法：
 *   pnpm run type:debt              报告总量 + Top 违规文件
 *   pnpm run type:debt -- --write   刷新 type-debt-baseline.json（棘轮只紧不松）
 *   pnpm run type:debt -- --top 50  自定义报告条数
 *
 * `--write` 默认拒绝让任一文件计数或总量上升，必须先真正修掉类型债；
 * 确需例外时用 `--force`（会在输出中显式警告，便于评审发现）。
 * 扫描口径与 tests/unit/architecture/type-debt-ratchet.test.ts 完全一致
 * （共用 scripts/lib/type-debt-scan.ts）。
 */
import * as fs from "fs";
import * as path from "path";
import {
  buildBaseline,
  scanTypeDebt,
  totalOf,
  type TypeDebtBaseline,
  type TypeDebtCounts,
} from "./lib/type-debt-scan";

const REPO_ROOT = path.resolve(__dirname, "..");
const BASELINE_FILE = path.join(
  REPO_ROOT,
  "tests/unit/architecture/type-debt-baseline.json",
);
const args = process.argv.slice(2);
const topIndex = args.indexOf("--top");
const TOP_N = topIndex >= 0 ? Number(args[topIndex + 1]) || 25 : 25;

/**
 * 读取既有基线（不存在则返回 null）
 * @returns 基线文档或 null
 */
function readBaseline(): TypeDebtBaseline | null {
  if (!fs.existsSync(BASELINE_FILE)) return null;
  return JSON.parse(fs.readFileSync(BASELINE_FILE, "utf-8")) as TypeDebtBaseline;
}

/** 格式化计数为紧凑字符串 */
function fmt(c: TypeDebtCounts): string {
  return `any=${c.any} unknown=${c.unknown} object=${c.object}`;
}

/**
 * 计算违规项：新增文件与计数上升的文件
 * @param baseline - 基线
 * @param current - 当前扫描
 * @returns 新增文件列表与上升描述列表
 */
function violations(
  baseline: TypeDebtBaseline,
  current: Record<string, TypeDebtCounts>,
): { added: string[]; grown: string[] } {
  const added = Object.keys(current).filter((f) => !(f in baseline.counts));
  const grown: string[] = [];
  for (const [file, counts] of Object.entries(current)) {
    const base = baseline.counts[file];
    if (!base) continue;
    for (const key of ["any", "unknown", "object"] as const) {
      if (counts[key] > base[key]) grown.push(`${file}: ${key} ${base[key]} → ${counts[key]}`);
    }
  }
  return { added: added.sort(), grown: grown.sort() };
}

/** 打印报告 */
function report(): void {
  const current = scanTypeDebt(REPO_ROOT);
  const totals = totalOf(current);
  const baseline = readBaseline();

  console.log(`扫描文件数（含模糊类型）: ${Object.keys(current).length}`);
  console.log(`合计: ${fmt(totals)}`);
  if (baseline) {
    const before = baseline.totals;
    console.log(
      `基线: ${fmt(before)}   delta: any ${totals.any - before.any}, unknown ${
        totals.unknown - before.unknown
      }, object ${totals.object - before.object}`,
    );
    const { added, grown } = violations(baseline, current);
    if (added.length) console.log(`\n新增违规文件 (${added.length}):\n  ${added.join("\n  ")}`);
    if (grown.length) console.log(`\n计数上升 (${grown.length}):\n  ${grown.join("\n  ")}`);
    const cleared = Object.keys(baseline.counts)
      .filter((f) => !(f in current))
      .sort();
    if (cleared.length)
      console.log(`\n已清零（应从基线移除）(${cleared.length}):\n  ${cleared.join("\n  ")}`);
  }

  const worst = Object.entries(current)
    .map(([file, c]) => ({ file, c, score: c.any * 3 + c.unknown + c.object * 2 }))
    .sort((a, b) => b.score - a.score)
    .slice(0, TOP_N);
  console.log(`\nTop ${worst.length} 违规文件（权重 any×3 / unknown×1 / object×2）:`);
  for (const w of worst) console.log(`  ${String(w.score).padStart(4)}  ${w.file}  (${fmt(w.c)})`);
}

/** 刷新基线（棘轮只紧不松） */
function write(): void {
  const current = scanTypeDebt(REPO_ROOT);
  const baseline = readBaseline();
  const force = args.includes("--force");
  if (baseline && !force) {
    const { added, grown } = violations(baseline, current);
    const totals = totalOf(current);
    const totalGrown =
      totals.any > baseline.totals.any ||
      totals.unknown > baseline.totals.unknown ||
      totals.object > baseline.totals.object;
    if (added.length || grown.length || totalGrown) {
      console.error("拒绝写入：棘轮只允许收紧，检测到类型债上升。");
      if (added.length) console.error(`  新增文件:\n    ${added.join("\n    ")}`);
      if (grown.length) console.error(`  计数上升:\n    ${grown.join("\n    ")}`);
      if (totalGrown)
        console.error(`  总量上升: ${fmt(baseline.totals)} → ${fmt(totals)}`);
      process.exit(1);
    }
  } else if (baseline && force) {
    console.warn("⚠️  --force：允许类型债上升写入基线，请在评审中说明原因。");
  }
  const doc = buildBaseline(current);
  fs.writeFileSync(BASELINE_FILE, JSON.stringify(doc, null, 2) + "\n", "utf-8");
  console.log(`已写入 ${path.relative(REPO_ROOT, BASELINE_FILE)}：${fmt(doc.totals)}`);
}

if (args.includes("--write")) write();
else report();
