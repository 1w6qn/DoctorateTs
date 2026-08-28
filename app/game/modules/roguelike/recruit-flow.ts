/**
 * 集成战略（rlv2）分区逻辑：招募流程（招募干员/激活票/关闭票/助战票列表与招募/存票/用票）
 *
 * 由 RoguelikeV2Manager 拆分而来：函数首参 mgr 为管理器实例，
 * 类侧保留同名薄委派（见 logic.ts）。
 */
import type { RoguelikeV2Manager } from "./logic";
import {
  PlayerRoguelikeV2,
  RoguelikeItemBundle,
  RoguelikeNodePosition,
  TorappuRoguelikeEventType,
} from "./rlv2";
import excel from "@excel/excel";

export async function activeRecruitTicket(mgr: RoguelikeV2Manager, args: { id: string }) {
    // 官方抓包：activeRecruitTicket 激活票并生成 RECRUIT pending 事件（客户端据此弹招募 UI），
    // 未生成事件 → 客户端无招募界面（"没有初始招募"）。激活后递归剩票无需再触发——客户端逐张激活。
    await mgr._trigger.emit("rlv2:recruit:active", [args.id]);
    const ticket = mgr.inventory?.recruit?.[args.id];
    if (ticket) {
      // 候选列表已生成（recruit.active 填充 list）→ 创建 RECRUIT 事件供客户端展示
      await mgr._trigger.emit("rlv2:event:create", [
        "RECRUIT",
        {
          tickets: args.id,
        },
      ]);
    }
}

export async function recruitChar(mgr: RoguelikeV2Manager, args: {
    ticketIndex: string;
    optionId: string;
  }) : Promise<PlayerRoguelikeV2.CurrentData.RecruitChar[]> {
    const { ticketIndex, optionId } = args;
    const ticket = mgr.inventory!.recruit[ticketIndex];
    // 一张票只能招募一次（官方语义）：票不存在 / 未打开(state=0) / 已放弃(state=3)
    // → 不可招募；已招募(state=2) 的票重复调用 → 幂等返回首次 result（非空，
    // 客户端不卡死）；仅 state=1（active）执行招募
    if (!ticket) return [];
    if (ticket.state !== 1) {
      return ticket.result ? [ticket.result] : [];
    }
    await mgr._trigger.emit("rlv2:recruit:done", [ticketIndex, optionId]);
    // 消费该票对应的 RECRUIT 事件（官服：招募完成后事件移除——
    // 否则残留 RECRUIT 进入 WAIT_MOVE，客户端报"系统发生未知故障"）
    const evIdx = mgr._status.pending.findIndex(
      (e) =>
        e.type === "RECRUIT" &&
        (e.content as any)?.recruit?.ticket === ticketIndex,
    );
    if (evIdx >= 0) mgr._status.pending.splice(evIdx, 1);
    // 票保留（state=2 终态）；inventory.recruit 由 finishEvent 初始阶段统一清空
    const result = mgr.inventory!.recruit[ticketIndex]?.result;
    return result ? [result] : [];
}

export async function closeRecruitTicket(mgr: RoguelikeV2Manager, args: { id: string }) : Promise<void> {
    const ticket = mgr.inventory!.recruit[args.id];
    if (!ticket) return;
    ticket.state = 3;
    ticket.list = [];
    // 票保留（state=3 终态）；inventory.recruit 由 finishEvent 初始阶段统一清空
    // （官服进入第一层 WAIT_MOVE 时 recruit={}）——若在此删除，客户端重复
    // close/后续请求读到空票会异常
}

export async function getTicketAssistList(mgr: RoguelikeV2Manager, args: {
    ticketIndex: string;
    profession: string;
  }) : Promise<void> {
    const ticket = mgr.inventory!.recruit[args.ticketIndex];
    if (!ticket) return;
    ticket.needAssist = false;
    ticket.assistList = ticket.assistList || {};
}

export async function recruitAssistChar(mgr: RoguelikeV2Manager, args: {
    ticketIndex: string;
    profession: string;
    assistUid: string;
    assistCharId: string;
  }) : Promise<void> {
    const ticket = mgr.inventory!.recruit[args.ticketIndex];
    if (!ticket) return;
    ticket.needAssist = false;
}

export async function stashRecruitTicket(mgr: RoguelikeV2Manager, args: { index: string }) : Promise<void> {
    const ticket = mgr.inventory!.recruit[args.index];
    if (!ticket) return;
    const inv = mgr.inventory! as any;
    // 留存上限（官方 stashRecruitLimit=3）
    if ((inv.stashRecruit || []).length >= (inv.stashRecruitLimit ?? 3)) return;
    // 转 _candle 变体（stashableTickets 映射），留存列表记录 id（官方 inventory.stashRecruit）
    const theme = mgr.current.game!.theme;
    const stashable = (excel.RoguelikeTopicTable.details[theme] as any)?.stashableTickets || {};
    const stashedId = stashable[ticket.id]?.stashedTicketId || `${ticket.id}_candle`;
    inv.stashRecruit = [...new Set([...(inv.stashRecruit || []), stashedId])];
    ticket.state = 3;
    ticket.list = [];
}

export async function useStashedTicket(mgr: RoguelikeV2Manager, args: { id: string }) : Promise<void> {
    const ticket = mgr.inventory!.recruit[args.id];
    const inv = mgr.inventory! as any;
    // 从留存列表移除（取回）
    if (inv.stashRecruit) {
      inv.stashRecruit = (inv.stashRecruit as string[]).filter(
        (sid) => !sid.includes(ticket?.id ?? "") && sid !== args.id,
      );
    }
    if (!ticket) return;
    ticket.state = 0;
    mgr._trigger.emit("rlv2:recruit:active", [args.id]);
    mgr._trigger.emit("rlv2:event:create", ["RECRUIT", { tickets: args.id }]);
}
