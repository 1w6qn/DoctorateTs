/**
 * PlayerStatus / Immer patch 追踪性能基准脚本（探索用，非生产代码）
 *
 * 目的：为「Immer 替代方案探索」建立可复现的现状基线。
 * 场景：
 *   1. building/sync 类：update 内遍历 building.chars（真实存档 312 干员）写 ap/lastApAddTime，
 *      模拟 building.sync 的 _accrueCharAp —— 每个干员都被修改 → finishDraft 逐个 finalize。
 *   2. 通用 update：单点小修改。
 * 测量：createDraft / recipe / finishDraft(收集 patches) 分段耗时，以及走 PlayerStatus.update 的整体耗时。
 *
 * 运行：pnpm exec tsx scripts/bench-playerstatus.ts [--engine immer|mutative] [--iters N]
 */

import { performance } from "node:perf_hooks";
import { readFileSync, existsSync } from "node:fs";
import { createDraft, finishDraft, enablePatches, immerable } from "immer";
import { create as mutCreate, markSimpleObject } from "mutative";
import { PlayerStatus } from "../app/game/manager/PlayerStatus";
import type { PlayerDataModel } from "../app/game/model/playerdata";

// Immer v10 需显式启用 Patches 插件（生产入口 index.ts 亦调用，幂等）
enablePatches();

const args = process.argv.slice(2);
/** 引擎选择：现状 immer；mutative 为方案 C 对比（需先 pnpm add -D mutative） */
const engine = args.includes("--engine")
  ? args[args.indexOf("--engine") + 1]
  : "immer";
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
  // PlayerStatus import 时已执行 setAutoFreeze(false)
  const ps = new PlayerStatus(raw);

  const createTimes: number[] = [];
  const recipeTimes: number[] = [];
  const finishTimes: number[] = [];
  const overallTimes: number[] = [];
  let patchCount = 0;

  for (let i = 0; i < ITERS; i++) {
    const nowMs = Date.now();
    let t0 = performance.now();
    let draft: any;
    let t1 = t0;
    let t2 = t0;
    let t3 = t0;
    let newData: any;
    let finishTime = 0;
    if (engine === "mutative" || engine === "mutative-mark") {
      // mutative 两阶段：create(base, opts) → [draft, finish()]，enablePatches 收集补丁
      if (engine === "mutative-mark") markSimpleObject(ps._playerdata.building.chars);
      const [draftRes, finishRes] = mutCreate(ps._playerdata, { enablePatches: true });
      draft = draftRes;
      t1 = performance.now();
      accrueCharAp(draft, nowMs);
      t2 = performance.now();
      const fr0 = performance.now();
      const [nxt, patches, inv] = finishRes();
      finishTime = performance.now() - fr0;
      newData = nxt;
      patchCount = patches.length;
      ps._changes.push(patches as never);
      ps._inverseChanges.push(inv as never);
      t3 = performance.now();
    } else {
      // 方案 B：immer v10 已移除顶层 markRaw，改用 DRAFTABLE symbol 机制——
      // 设置 chars[immerable]=false 使其不可 draft → Immer 把 building.chars 当原始值，
      // createDraft 时浅拷贝引用、finalize 跳过整棵子树，写它不自动产生 patch。
      const markRawMode = engine === "immer-markraw";
      if (markRawMode) (ps._playerdata.building.chars as any)[immerable] = false;
      t0 = performance.now();
      draft = createDraft(ps._playerdata);
      t1 = performance.now();
      accrueCharAp(draft, nowMs);
      t2 = performance.now();
      const fr0 = performance.now();
      newData = finishDraft(draft, (patches) => {
        patchCount = patches.length;
        ps._changes.push(patches as never);
      });
      finishTime = performance.now() - fr0;
      t3 = performance.now();
      // markRaw 模式下 recipe 对 chars 的写不产生 patch，须手动提交整体（模拟 sync 的
      // forcePatch(["building","chars"], {...}) 或 markDirty），此处用 forcePatch 语义记录。
      if (markRawMode) {
        ps._changes.push([{ op: "replace", path: ["building", "chars"], value: ps._playerdata.building.chars }] as never);
        patchCount = 1;
      }
    }
    ps._playerdata = newData;
    ps._stateVersion++;
    const t4 = performance.now();
    overallTimes.push(t4 - t0);
    createTimes.push(t1 - t0);
    recipeTimes.push(t2 - t1);
    finishTimes.push(finishTime);
  }

  console.log(`[bench] engine=${engine} iters=${ITERS} building.chars=312 patches/次≈${patchCount}`);
  console.log("  building/sync 类（写 312 干员）分段耗时：");
  report("createDraft", createTimes);
  report("recipe(accrue)", recipeTimes);
  report("finishDraft", finishTimes);
  report("整体(create+recipe+finish)", overallTimes);

  // 通用 update：单点小修改
  const genTimes: number[] = [];
  for (let i = 0; i < ITERS; i++) {
    const t0 = performance.now();
    const draft = createDraft(ps._playerdata);
    if (draft.status) draft.status.level = ((draft.status.level as number) || 1) + 1;
    finishDraft(draft, (p) => ps._changes.push(p as never));
    ps._changes = [];
    genTimes.push(performance.now() - t0);
  }
  console.log("  通用 update（单点 level+1）：");
  report("整体", genTimes);

  // 隔离实验：空操作（createDraft + 只读 + finishDraft，不写）——量化 Immer finalize 的固有遍历开销
  const noopFinish: number[] = [];
  const noopOverall: number[] = [];
  for (let i = 0; i < ITERS; i++) {
    const t0 = performance.now();
    const draft = createDraft(ps._playerdata);
    // 只读一个深层字段，不写（模拟 recipe 内读但未改）
    void draft.building?.chars;
    const t1 = performance.now();
    finishDraft(draft, (p) => ps._changes.push(p as never));
    ps._changes = [];
    noopFinish.push(performance.now() - t1);
    noopOverall.push(performance.now() - t0);
  }
  console.log("  隔离：空操作（createDraft+只读+finishDraft，无修改）：");
  report("finishDraft", noopFinish);
  report("整体", noopOverall);

  // 决定性隔离：markRaw(chars) 后「只读 accrue」vs「写入 accrue」的 finishDraft，
  // 判断方案 B 的 166ms 到底来自「被修改干员的 draft finalize」还是「chars 子树本身」。
  const rawReadFinish: number[] = [];
  const rawWriteFinish: number[] = [];
  for (let i = 0; i < ITERS; i++) {
    (ps._playerdata.building.chars as any)[immerable] = false;
    const d1 = createDraft(ps._playerdata);
    const chars1 = d1.building?.chars;
    if (chars1) for (const k of Object.keys(chars1)) void chars1[k]?.ap; // 只读
    const tr0 = performance.now();
    finishDraft(d1, () => {});
    rawReadFinish.push(performance.now() - tr0);

    const d2 = createDraft(ps._playerdata);
    accrueCharAp(d2, Date.now()); // 写入
    const tw0 = performance.now();
    finishDraft(d2, () => {});
    rawWriteFinish.push(performance.now() - tw0);
  }
  console.log("  隔离：markRaw(chars) 只读 vs 写入 的 finishDraft：");
  report("只读 finishDraft", rawReadFinish);
  report("写入 finishDraft", rawWriteFinish);
}

run().catch((e) => {
  console.error("[bench] 失败:", e);
  process.exit(1);
});