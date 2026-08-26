/**
 * 集成战略（rlv2）分区逻辑：银行存取（存款/取款）
 *
 * 由 RoguelikeV2Manager 拆分而来：函数首参 mgr 为管理器实例，
 * 类侧保留同名薄委派（见 logic.ts）。
 */
import type { RoguelikeV2Manager } from "./logic";


  /** 银行存钱（CS: RoguelikeBankInvestRequest）：bank.current/totalPut +1，record 取历史最高 */
export async function bankPut(mgr: RoguelikeV2Manager) : Promise<void> {
    const theme = mgr.current.game!.theme;
    if (!mgr.outer[theme]?.bank) return;
    // 修复：存钱应扣 1 金币——原实现不扣任何资源，可 put→withdraw 循环无限刷金币
    if ((mgr._status.property.gold ?? 0) < 1) return;
    mgr._status.property.gold -= 1;
    await mgr.update(async (draft) => {
      const bank = draft.outer[theme].bank;
      bank.current = (bank.current || 0) + 1;
      bank.totalPut = (bank.totalPut || 0) + 1;
      bank.record = Math.max(bank.record || 0, bank.current);
      bank.show = true;
    });
    mgr._status.status.bankPut += 1;
    await mgr._trigger.emit("rlv2:bankPut", [true]);
}

  /** 银行取钱（CS: RoguelikeBankWithdrawRequest { count }）：bank.current 减少，金币增加 */
export async function bankWithdraw(mgr: RoguelikeV2Manager, args: { count?: number }) : Promise<void> {
    const theme = mgr.current.game!.theme;
    const bank = mgr.outer[theme]?.bank;
    if (!bank) return;
    const count = Math.max(0, Math.min(args.count ?? 1, bank.current || 0));
    if (count <= 0) return;
    await mgr.update(async (draft) => {
      draft.outer[theme].bank.current -= count;
    });
    mgr._status.property.gold += count;
}
