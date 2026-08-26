/**
 * 集成战略（rlv2）分区逻辑：战斗奖励选择（选奖励/结束奖励）
 *
 * 由 RoguelikeV2Manager 拆分而来：函数首参 mgr 为管理器实例，
 * 类侧保留同名薄委派（见 logic.ts）。
 */
import type { RoguelikeV2Manager } from "./logic";
import excel from "@excel/excel";

export async function chooseBattleReward(mgr: RoguelikeV2Manager, args: { index: number; sub: number }) {
    const rewardGrp =
      mgr._status.pending[0]?.content?.battleReward?.rewards.find(
        (r) => r.index == args.index,
      );
    // 防御：未知奖励组不 500
    if (!rewardGrp) return;
    // 修复：done 未校验 → 同一奖励组的每个 sub 都能领一遍（boss 双遗物全拿）；
    // 已选择过则拒绝
    if (rewardGrp.done) return;
    const reward = rewardGrp.items.find((r) => r.sub == args.sub);
    if (!reward) return;
    // 招募券奖励：仅入招募券库存（官服：战利品选券后券进券列表，由玩家自行激活）。
    // 原实现标记 RECRUIT_TICKET 走 getItem → 自动激活并弹 RECRUIT 事件 → 战斗中异常弹出招募界面。
    const theme = mgr.current.game!.theme;
    const item: any = { ...reward };
    if (excel.RoguelikeTopicTable.details[theme]?.recruitTickets?.[item.id]) {
      await mgr._trigger.emit("rlv2:recruit:gain", [item.id, "battle", 0]);
    } else {
      // await：getItem 为异步（gold/希望/零件实时入账），不 await 会先序列化旧状态（奖励不实时）
      await mgr._trigger.emit("rlv2:get:items", [[item]]);
    }

    rewardGrp.done = 1;
}

export async function finishBattleReward(mgr: RoguelikeV2Manager, args: {}) {
    // 指挥等级经验已在 battleFinish 即时入账（对齐官服：battleFinish 响应内已含升级后
    // exp/level）——此处不再重复发放，避免双重升级/希望增量（升级奖励异常根因）。
    mgr._status.pending.shift();
    await mgr.checkZoneEnd();
    mgr._status.state = "WAIT_MOVE";
}
