/**
 * 可注入随机源（建议 15：全域随机源注入化）
 *
 * domain 纯函数/引擎统一经 `random()` 取随机数（默认 Math.random）；
 * 测试可经 `setRandSource` 注入固定序列/固定值，实现确定性复现，
 * 消除概率性断言 flaky（如 gacha-rank 的 2% 权重波动）。
 *
 * 约定：
 * - 业务代码只 import { random }，不直接调 Math.random；
 * - 默认源为动态读取 Math.random（兼容既有测试 vi.spyOn(Math, "random")）；
 * - 测试可经 setRandSource 注入固定序列（推荐），结束时 resetRandSource；
 * - 纯函数级 rand 参数注入（如 resolveGachaRank）优先于模块级注入。
 */

// 动态读取：每次调用取 Math.random 当前值，兼容既有 vi.spyOn(Math, "random") mock
let source: () => number = () => Math.random();

/** 注入随机源（测试用；fn 返回 [0,1) 均匀随机数） */
export function setRandSource(fn: () => number): void {
  source = fn;
}

/** 恢复默认（动态读取 Math.random） */
export function resetRandSource(): void {
  source = () => Math.random();
}

/** 取 [0,1) 随机数（经当前注入源） */
export function random(): number {
  return source();
}
