/**
 * Immer finalize 补丁（npm postinstall 自动应用，幂等）
 *
 * 背景：本项目全局 setAutoFreeze(false)（medal/dungeon/rlv2 直接改 _playerdata）。
 * 关闭 autoFreeze 后 Immer finalize 有两个叠加问题，导致每次 player.update 都付出
 * 数十 ms 的全树遍历成本（任何路由都受影响，十连前每抽 ~90ms）：
 *
 * 1) 未修改 draft（recipe 里只读访问的大子树，如 draft.troop.chars）在 finalize 时
 *    不标记 finalized_/不递减 unfinalizedDrafts_ → 计数永不归零 → 深遍历无法早退。
 *    → 补丁：未修改 draft 同样标记并递减（计数准确，语义不变）。
 *
 * 2) 对「非 draft 的顶层子节点」，只要还有未处理 draft 就深遍历整棵子树（唯一作用
 *    是冻结 + 找嵌套在普通对象里的 draft；autoFreeze 关闭时冻结是 no-op）。
 *    → 补丁：autoFreeze 关闭时直接跳过非 draft 子节点（本项目存档为纯 JSON——
 *    无 Map/Set、无 draft 引用存入普通对象（已全量检索），安全）。
 *
 * 结果：update 开销从 O(变更路径之前的全部子树) 降到 O(实际修改的 draft 路径)，
 * 大部分接口 20ms 内。
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const TARGETS = [
  "node_modules/immer/dist/cjs/immer.cjs.development.js",
  "node_modules/immer/dist/immer.mjs",
  "node_modules/immer/dist/immer.legacy-esm.js",
];

/** 补丁 1：未修改 draft 也标记 finalized_ 并递减计数 */
const OLD1 = `  if (!state.modified_) {
    maybeFreeze(rootScope, state.base_, true);
    return state.base_;
  }`;
const NEW1 = `  if (!state.modified_) {
    if (!state.finalized_) {
      state.finalized_ = true;
      state.scope_.unfinalizedDrafts_--;
    }
    maybeFreeze(rootScope, state.base_, true);
    return state.base_;
  }`;

/** 补丁 2：autoFreeze 关闭时跳过非 draft 子节点的深遍历 */
const OLD2 = `    if (!rootScope.immer_.autoFreeze_ && rootScope.unfinalizedDrafts_ < 1) {
      return;
    }`;
const NEW2 = `    if (!rootScope.immer_.autoFreeze_) {
      return;
    }`;

const MARK1 = "state.scope_.unfinalizedDrafts_--;\n    }\n    maybeFreeze";
const MARK2 = "if (!rootScope.immer_.autoFreeze_) {\n      return;\n    }";

let patched = 0;
for (const rel of TARGETS) {
  const file = path.join(root, rel);
  if (!existsSync(file)) continue;
  let src = readFileSync(file, "utf8");
  const before = src;
  if (!src.includes(MARK1) && src.includes(OLD1)) {
    src = src.replace(OLD1, NEW1);
  }
  if (!src.includes(MARK2) && src.includes(OLD2)) {
    src = src.replace(OLD2, NEW2);
  }
  if (src !== before) {
    writeFileSync(file, src, "utf8");
    patched++;
    console.log(`[patch-immer] 已修补: ${rel}`);
  } else {
    console.log(`[patch-immer] 已应用或无需修改，跳过: ${rel}`);
  }
}
console.log(`[patch-immer] 完成，共修补 ${patched} 个文件`);
