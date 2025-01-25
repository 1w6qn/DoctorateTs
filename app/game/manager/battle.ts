import { accountManager } from "../manager/AccountManger";

import excel from "@excel/excel";
import { decryptBattleData } from "@utils/crypt";
import { now } from "@utils/time";
import { CommonStartBattleRequest } from "@game/model/battle";
import { TypedEventEmitter } from "@game/model/events";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { ItemBundle } from "@excel/character_table";
import { ConditionDesc } from "@excel/stage_table";

export class BattleManager {
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  constructor(_player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = _player;
    this._trigger = _trigger;
    this._trigger.on("battle:start", () => {
      this.start.bind(this);
    });
    this._trigger.on("battle:finish", () => {
      this.start.bind(this);
    });
  }

  async start([args]: [CommonStartBattleRequest]) {
    const { stageId } = args;
    const battleId = "1";
    const zoneId = excel.StageTable.stages[stageId].zoneId;
    let apFailReturn = excel.StageTable.stages[stageId].apFailReturn;
    const ts = now();
    let inApProtectPeriod = false;
    if (zoneId in excel.StageTable.apProtectZoneInfo) {
      inApProtectPeriod = excel.StageTable.apProtectZoneInfo[
        zoneId
      ].timeRanges.some((range) => ts >= range.startTs && ts <= range.endTs);
    }
    let isApProtect = 0;
    await this._player.update(async (draft) => {
      if (draft.dungeon.stages[stageId].noCostCnt == 1) {
        isApProtect = 1;
        apFailReturn = excel.StageTable.stages[stageId].apCost;
      }
      if (inApProtectPeriod) {
        isApProtect = 1;
      }
      if (args.usePracticeTicket == 1) {
        isApProtect = 0;
        apFailReturn = 0;
        draft.status.practiceTicket -= 1;
        draft.dungeon.stages[stageId].practiceTimes += 1;
      }
      draft.dungeon.stages[stageId].startTimes += 1;
      await accountManager.saveBattleInfo(draft.status.uid, battleId, {
        stageId,
      });
    });

    return {
      apFailReturn: apFailReturn,
      battleId: battleId,
      inApProtectPeriod: inApProtectPeriod,
      isApProtect: isApProtect,
      notifyPowerScoreNotEnoughIfFailed: false,
      result: 0,
    };
  }

  async finishStoryStage(args: { stageId: string }) {
    const { stageId } = args;
    const rewards: ItemBundle[] = [];
    const unlockStages: string[] = [];
    await this._player.update(async (draft) => {
      const stageState = draft.dungeon.stages[stageId].state;
      if (stageState !== 3) {
        draft.dungeon.stages[stageId].state = 3;

        const unlock_list: { [key: string]: ConditionDesc[] } = {};
        const stage_data = excel.StageTable.stages;
        for (const item of Object.keys(stage_data)) {
          unlock_list[item] = stage_data[item].unlockCondition;
        }

        //todo: 解锁关卡`

        rewards.push({
          type: "DIAMOND",
          id: "4002",
          count: 1,
        });
      }
    });
    await this._trigger.emit("items:get", [rewards]);
    return {
      result: 0,
      alert: [],
      rewards: rewards,
      unlockStages: unlockStages,
    };
  }

  async finish(args: {
    data: string;
    battleData: { isCheat: string; completeTime: number };
  }) {
    await this._player.update(async (draft) => {
      const battleData = decryptBattleData(args.data, draft.pushFlags.status);
      const battleInfo = accountManager.getBattleInfo(
        draft.status.uid,
        battleData.battleId,
      );
      await this._trigger.emit("CompleteStageAnyType", battleData);
      await this._trigger.emit("CompleteStage", {
        ...battleData,
        ...battleInfo,
      });
    });

    return {
      result: 0,
      apFailReturn: 0,
      expScale: 1.2,
      goldScale: 1.2,
      rewards: [],
      firstRewards: [],
      unlockStages: [],
      unusualRewards: [],
      additionalRewards: [],
      furnitureRewards: [],
      alert: [],
      suggestFriend: false,
      pryResult: [],
    };
  }

  async loadReplay(args: { stageId: string }): Promise<string> {
    return await accountManager.getBattleReplay(
      this._player._playerdata.status.uid,
      args.stageId,
    );
  }

  async saveReplay(args: {
    battleId: string;
    battleReplay: string;
  }): Promise<void> {
    const stageId = accountManager.getBattleInfo(
      this._player._playerdata.status.uid,
      args.battleId,
    )?.stageId;
    return await accountManager.saveBattleReplay(
      this._player._playerdata.status.uid,
      stageId!,
      args.battleReplay,
    );
  }
}
