/**
 * PlayerStatus / mutative patch 追踪性能基准脚本（工具，非生产代码）
 *
 * 目的：在 mutative 迁移落地后，验证状态引擎写密集场景的性能基线。
 * 场景：
 *   1. building/sync 类：update 内遍历 building.chars（真实存档 312 干员）写 ap/lastApAddTime，
 *      模拟 building.sync 的 _accrueCharAp —— 每个干员都被修改 → finish() 生成补丁。
 *   2. 通用 update：单点小修改。
 *   3. 空操作：create + 只读 + finish，量化 mutative 空跑开销。
 * 测量：create / recipe / finish(收集 patches) 分段耗时。
 *
 * 运行：pnpm exec tsx scripts/bench-playerstatus.ts [--iters N]
 */

import { performance } from "node:perf_hooks";
import { readFileSync, existsSync } from "node:fs";
import { create as mutCreate } from "mutative";
import { PlayerStatus } from "../app/game/manager/PlayerStatus";
import type { PlayerDataModel } from "../app/game/model/playerdata";

const args = process.argv.slice(2);
const itersStr = args.includes("--iters")
  ? args[args.indexOf("--iters") + 1]
  : "20";
const ITERS = Math.max(3, parseInt(itersStr, 10) || 20);

const DB = "data/user/databases/1.json";
if (!existsSync(DB)) {
  console.error(`[bench] 缺少存档 ${DB}，基准依赖真实 312 干员存档`);
  process.exit(1);
}

/** 中位数 */
function median(arr: number[]): number {
  const s = [...arr].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}
/** 汇总打印 */
function report(label: string, vals: number[]): void {
  const med = median(vals);
  const min = Math.min(...vals);
  const max = Math.max(...vals);
  console.log(`  ${label.padEnd(18)} median=${med.toFixed(2)}ms  min=${min.toFixed(2)}ms  max=${max.toFixed(2)}ms`);
}

/** 模拟 building.sync 的 _accrueCharAp：写每个干员的 ap / lastApAddTime */
function accrueCharAp(draft: any, nowMs: number): void {
  const chars = draft?.building?.chars;
  if (!chars) return;
  for (const key of Object.keys(chars)) {
    const ch = chars[key];
    if (ch && typeof ch === "object") {
      ch.ap = (ch.ap ?? 0) + 1;
      ch.lastApAddTime = nowMs;
    }
  }
}

async function run(): Promise<void> {
  const raw = JSON.parse(readFileSync(DB, "utf8")) as PlayerDataModel;
  const ps = new PlayerStatus(raw);

  const createTimes: number[] = [];
  const recipeTimes: number[] = [];
  const finishTimes: number[] = [];
  const overallTimes: number[] = [];
  let patchCount = 0;

  // building/sync 类：写 312 干员
  for (let i = 0; i < ITERS; i++) {
    const nowMs = Date.now();
    const t0 = performance.now();
    const [draft, finishDraft] = mutCreate(ps._playerdata, { enablePatches: true });
    const t1 = performance.now();
    accrueCharAp(draft, nowMs);
    const t2 = performance.now();
    const fr0 = performance.now();
    const [nxt, patches] = finishDraft();
    finishTimes.push(performance.now() - fr0);
    patchCount = patches.length;
    ps._playerdata = nxt;
    ps._changes = [];
    overallTimes.push(performance.now() - t0);
    createTimes.push(t1 - t0);
    recipeTimes.push(t2 - t1);
  }
  console.log(`[bench] engine=mutative iters=${ITERS} building.chars=312 patches/次≈${patchCount}`);
  console.log("  building/sync 类（写 312 干员）分段耗时：");
  report("create", createTimes);
  report("recipe(accrue)", recipeTimes);
  report("finish", finishTimes);
  report("整体(create+recipe+finish)", overallTimes);

  // 通用 update：单点小修改
  const genTimes: number[] = [];
  for (let i = 0; i < ITERS; i++) {
    const t0 = performance.now();
    const [draft, finishDraft] = mutCreate(ps._playerdata, { enablePatches: true });
    if (draft.status) draft.status.level = ((draft.status.level as number) || 1) + 1;
    const [nxt] = finishDraft();
    ps._playerdata = nxt;
    ps._changes = [];
    genTimes.push(performance.now() - t0);
  }
  console.log("  通用 update（单点 level+1）：");
  report("整体", genTimes);

  // 空操作：create + 只读 + finish，不写
  const noopTimes: number[] = [];
  for (let i = 0; i < ITERS; i++) {
    const t0 = performance.now();
    const [draft, finishDraft] = mutCreate(ps._playerdata, { enablePatches: true });
    void draft.building?.chars;
    const [nxt] = finishDraft();
    ps._playerdata = nxt;
    ps._changes = [];
    noopTimes.push(performance.now() - t0);
  }
  console.log("  隔离：空操作（create+只读+finish，无修改）：");
  report("整体", noopTimes);
}

run().catch((e) => {
  console.error("[bench] 失败:", e);
  process.exit(1);
});