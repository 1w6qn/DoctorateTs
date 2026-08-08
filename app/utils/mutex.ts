/**
 * 按 key 的异步互斥锁（FIFO）
 *
 * 用于保证同一账号（uid）的请求串行执行，防止并发请求基于同一旧状态
 * 构建 Immer draft，导致后 finishDraft 的整体替换丢弃先到的变更
 * （delta 补丁已下发但状态丢失的不一致）。
 * 每个 key 独立维护一条 promise 链，先到先得（FIFO），延迟对低并发私服可接受。
 */

/** 各 key 的锁链尾部 promise（已完成 promise 残留无害：键数=账号数，有界） */
const chains = new Map<string, Promise<void>>();

/**
 * 按 key 获取互斥锁
 *
 * 返回释放函数，调用后解锁并唤醒下一个等待者。释放函数幂等：
 * 重复调用（如 res 的 finish/close 均触发）只真正释放一次。
 * @param key - 锁的键（uid 字符串）
 * @returns 释放函数（幂等）
 */
export async function acquireLock(key: string): Promise<() => void> {
  // 前一个持有者的释放标记（无在途锁时直接通过）
  const prev = chains.get(key) ?? Promise.resolve();
  let resolveNext!: () => void;
  const next = new Promise<void>((resolve) => {
    resolveNext = resolve;
  });
  // 将本请求接入锁链尾部：释放本锁后，prev.then(() => next) 才 resolve
  chains.set(key, prev.then(() => next));
  // 等待前一个持有者释放后才返回（此时才真正拿到锁）
  await prev;
  let released = false;
  return () => {
    if (released) return;
    released = true;
    resolveNext();
  };
}
