import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";
import excel from "@excel/excel";
import { ItemBundle } from "@excel/character_table";

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
      const reward = excel.RetroTable.retroTrailList[
        retroId
      ].trailRewardList.find((v) => v.trailRewardID === rewardId)!.rewardItem;
      draft.retro.trail[retroId][rewardId] = 1;
      await this._trigger.emit("items:get", [[reward]]);
      return [reward];
    });
  }

  async getRetroPassReward(args: { retroId: string; activityId: string }) {
    //TODO
    console.log(args);
    return [] as ItemBundle[];
  }
}
