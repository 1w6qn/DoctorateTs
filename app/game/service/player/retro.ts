import { PlayerDataManager } from "@game/service/PlayerDataManager";
import { TypedEventEmitter } from "@game/service/events";
import excel from "@excel/excel";
import { ItemBundle } from "@excel/excel";

export class RetroManager {
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
  }

  async unlockRetroBlock(args: { retroId: string }) {
    await this._player.update(async (draft) => {
      draft.retro.coin -= 1;
      draft.retro.block[args.retroId].locked = 0;
      draft.retro.block[args.retroId].open = 1;
    });
  }

  async getRetroTrailReward(args: { retroId: string; rewardId: string }) {
    return await this._player.update(async (draft) => {
      const { retroId, rewardId } = args;
      const trailList = excel.RetroTable.retroTrailList[retroId]?.trailRewardList;
      const reward = trailList?.find((v) => v.trailRewardId === rewardId)
        ?.rewardItem;
      // 防御：未知 retro/奖励 id 不 500
      if (!reward) return [];
      // 修复：trail 惰性初始化（新 retro/旧存档缺条目时直接写 trail[retroId][rewardId]
      // 会 TypeError 500——模板只预置已知 retro，版本更新新增 retro 后必崩）
      const trail = (draft.retro.trail ??= {});
      if (!trail[retroId]) trail[retroId] = {};
      // 修复：已领取过的不再发放（原实现无幂等 → 可无限刷）
      if (trail[retroId][rewardId]) return [];
      trail[retroId][rewardId] = 1;
      await this._trigger.emit("items:get", [[reward]]);
      return [reward];
    });
  }

  async getRetroPassReward(args: { retroId: string; activityId: string }) {
    const { retroId } = args;
    // 修复：幂等——已领取过的通行证奖励不再发放（原实现无任何记录 → 可无限刷）
    if (this._player._playerdata.retro.rewardPerm?.includes(retroId)) {
      return [];
    }
    const rewards: ItemBundle[] = [];
    const retroActivities = excel.ActivityTable.activity;
    for (const [, activities] of Object.entries(retroActivities)) {
      for (const [id, activity] of Object.entries(activities as { [key: string]: any })) {
        if (id === args.activityId && "retroData" in activity) {
          const retroData = activity.retroData;
          if (retroData?.rewards) {
            const passReward = retroData.rewards.find((r: { id: string }) => r.id === retroId);
            if (passReward?.items) {
              rewards.push(...passReward.items);
            }
          }
        }
      }
    }
    if (rewards.length === 0) return rewards;
    // rewardPerm 未被业务使用，复用为已领取通行证奖励 id 记录
    await this._player.update(async (draft) => {
      if (!draft.retro.rewardPerm) draft.retro.rewardPerm = [];
      if (!draft.retro.rewardPerm.includes(retroId)) {
        draft.retro.rewardPerm.push(retroId);
      }
    });
    await this._trigger.emit("items:get", [rewards]);
    return rewards;
  }
}
