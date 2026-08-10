/**
 * Immer finalize 补丁（npm postinstall 自动应用，幂等）
 *
 * 背景：本项目全局 setAutoFreeze(false)（medal/dungeon/rlv2 直接改 _playerdata）。
 * 关闭 autoFreeze 后 Immer finalize 的早退条件 `!autoFreeze_ && unfinalizedDrafts_ < 1`
 * 依赖所有 draft 归零——但「只读访问的未修改 draft」（如 recipe 里读 draft.troop.chars）
 * 走 `if (!state.modified_)` 分支时不会 decrement，导致计数永不归零 → 每次 update 对
 * 变更路径前的全部顶层子树深遍历（~60-90ms/次）。
 *
 * 补丁：未修改 draft 在 finalize 时同样标记 finalized_ 并递减 unfinalizedDrafts_，
 * 使计数准确 → 全部 draft 处理完后 finalize 正常早退，update 开销降到 O(变更路径前缀)。
 * 语义不变：早退只跳过非 draft 子树的深遍历（唯一作用是冻结/找嵌套 draft，而计数归零
 * 即代表已无未处理 draft）。
 *
 * ⚠️ 不要在这里加「autoFreeze 关闭时无条件跳过非 draft 子节点」的补丁——recipe 里
 * `draft.x = draft.y.filter(...)` 等会把 draft 引用存进普通数组/对象，跳过遍历会导致
 * 这些嵌套 draft 未 finalize → finishDraft 后 revoke 的 proxy 残留进 _playerdata →
 * 后续访问/JSON.stringify 抛 "Cannot perform 'get' on a proxy that has been revoked"。
 * （曾因此踩坑：building/deleteOrder 500 + save 失败，见 commit e65a0f9。）
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

/** 补丁：未修改 draft 也标记 finalized_ 并递减计数（早退条件才能准确触发） */
const OLD = `  if (!state.modified_) {
    maybeFreeze(rootScope, state.base_, true);
    return state.base_;
  }`;
const NEW = `  if (!state.modified_) {
    if (!state.finalized_) {
      state.finalized_ = true;
      state.scope_.unfinalizedDrafts_--;
    }
    maybeFreeze(rootScope, state.base_, true);
    return state.base_;
  }`;

const MARK = "state.scope_.unfinalizedDrafts_--;\n    }\n    maybeFreeze";

/** 还原被误加的「无条件跳过非 draft 子节点」补丁（会导致嵌套 draft 未 finalize → revoked proxy） */
const BAD = `    if (!rootScope.immer_.autoFreeze_) {
      return;
    }`;
const GOOD = `    if (!rootScope.immer_.autoFreeze_ && rootScope.unfinalizedDrafts_ < 1) {
      return;
    }`;

let patched = 0;
for (const rel of TARGETS) {
  const file = path.join(root, rel);
  if (!existsSync(file)) continue;
  let src = readFileSync(file, "utf8");
  const before = src;
  if (!src.includes(MARK) && src.includes(OLD)) {
    src = src.replace(OLD, NEW);
  }
  if (src.includes(BAD)) {
    src = src.replace(BAD, GOOD);
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
