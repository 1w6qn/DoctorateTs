/**
 * 物品事件直发 CLI
 *
 * 用法：
 *   pnpm run items:direct              报告总量 + Top 违规文件
 *   pnpm run items:direct -- --write   刷新 inventory-pipeline-baseline.json（棘轮只紧不松）
 *   pnpm run items:direct -- --top 50  自定义报告条数
 *
 * `--write` 默认拒绝让任一文件计数或总量上升，必须先真正把调用迁到
 * `player.gainItem` 管道；确需例外时用 `--force`（会在输出中显式警告，便于评审发现）。
 * 扫描口径与 tests/unit/architecture/inventory-pipeline-ratchet.test.ts 完全一致
 * （共用 scripts/lib/items-pipeline-scan.ts）。
 */
import * as fs from "fs";
import * as path from "path";
import {
  buildBaseline,
  diffBaseline,
  scanDirectItemEmits,
  type ItemsDirectBaseline,
} from "./lib/items-pipeline-scan";

const REPO_ROOT = path.resolve(__dirname, "..");
const BASELINE_FILE = path.join(
  REPO_ROOT,
  "tests/unit/architecture/inventory-pipeline-baseline.json",
);
const args = process.argv.slice(2);
const topIndex = args.indexOf("--top");
const TOP_N = topIndex >= 0 ? Number(args[topIndex + 1]) || 25 : 25;

/** 读取既有基线（不存在则返回 null） */
function readBaseline(): ItemsDirectBaseline | null {
  if (!fs.existsSync(BASELINE_FILE)) return null;
  return JSON.parse(fs.readFileSync(BASELINE_FILE, "utf-8")) as ItemsDirectBaseline;
}

/** 打印报告 */
function report(): void {
  const current = scanDirectItemEmits(REPO_ROOT);
  const total = Object.values(current).reduce((a, b) => a + b, 0);
  const baseline = readBaseline();

  console.log(`扫描文件数（含直发）: ${Object.keys(current).length}`);
  console.log(`合计直发: ${total}`);
  if (baseline) {
    console.log(
      `基线: ${baseline.total}   delta: ${total - baseline.total}（负数=已收紧）`,
    );
    const { added, grown, migrated } = diffBaseline(baseline.counts, current);
    if (added.length) console.log(`\n新增违规文件 (${added.length}):\n  ${added.join("\n  ")}`);
    if (grown.length) console.log(`\n计数上升 (${grown.length}):\n  ${grown.join("\n  ")}`);
    if (migrated.length)
      console.log(`\n已清零（应从基线移除）(${migrated.length}):\n  ${migrated.join("\n  ")}`);
  }

  const worst = Object.entries(current)
    .sort((a, b) => b[1] - a[1])
    .slice(0, TOP_N);
  console.log(`\nTop ${worst.length} 直发文件:`);
  for (const [file, n] of worst) console.log(`  ${String(n).padStart(4)}  ${file}`);
}

/** 刷新基线（棘轮只紧不松） */
function write(): void {
  const current = scanDirectItemEmits(REPO_ROOT);
  const baseline = readBaseline();
  const force = args.includes("--force");
  const total = Object.values(current).reduce((a, b) => a + b, 0);
  if (baseline && !force) {
    const { added, grown } = diffBaseline(baseline.counts, current);
    const totalGrown = total > baseline.total;
    if (added.length || grown.length || totalGrown) {
      console.error("拒绝写入：棘轮只允许收紧，检测到物品直发上升。");
      if (added.length) console.error(`  新增文件:\n    ${added.join("\n    ")}`);
      if (grown.length) console.error(`  计数上升:\n    ${grown.join("\n    ")}`);
      if (totalGrown) console.error(`  总量上升: ${baseline.total} → ${total}`);
      process.exit(1);
    }
  } else if (baseline && force) {
    console.warn("⚠️  --force：允许物品直发上升写入基线，请在评审中说明原因。");
  }
  const doc = buildBaseline(current);
  fs.writeFileSync(BASELINE_FILE, JSON.stringify(doc, null, 2) + "\n", "utf-8");
  console.log(`已写入 ${path.relative(REPO_ROOT, BASELINE_FILE)}：合计 ${doc.total}`);
}

if (args.includes("--write")) write();
else report();
