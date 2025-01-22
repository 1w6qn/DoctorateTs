import {
  BaseProgress,
  MissionPlayerData,
  MissionPlayerState,
} from "../model/playerdata";
import excel from "@excel/excel";
import { ItemBundle } from "@excel/character_table";
import { PlayerCharacter } from "../model/character";
import { BattleData } from "../model/battle";
import { checkBetween, now } from "@utils/time";
import { EventMap, TypedEventEmitter } from "@game/model/events";
import { MissionData } from "@excel/mission_table";
import { PlayerDataManager } from "./PlayerDataManager";

export class MissionManager {
  missions: { [key: string]: MissionProgress[] };
  _trigger: TypedEventEmitter;
  _player: PlayerDataManager;

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    const playerdata = player._playerdata;
    playerdata.mission.missions["ACTIVITY"] = {};
    this.missions = Object.fromEntries(
      Object.entries(playerdata.mission.missions).map(([type, v]) => [
        type,
        Object.entries(v).map(([id, data]) => {
          return new MissionProgress(
            id,
            _trigger,
            this,
            type,
            data.progress[0].value ?? 0,
            data.state,
          );
        }),
      ]),
    );
    this._trigger = _trigger;
    this._trigger.on("refresh:weekly", this.weeklyRefresh.bind(this));
    this._trigger.on("refresh:daily", this.dailyRefresh.bind(this));
  }

  get dailyMissionPeriod(): string {
    const ts = now();
    const period = excel.MissionTable.dailyMissionPeriodInfo.find(
      (p) => p.startTime <= ts && p.endTime >= ts,
    );
    return period!.periodList.find((p) =>
      p.period.includes(new Date().getDay() + 1),
    )!.missionGroupId;
  }

  get dailyMissionRewardPeriod(): string {
    const ts = now();
    const period = excel.MissionTable.dailyMissionPeriodInfo.find(
      (p) => p.startTime <= ts && p.endTime >= ts,
    );
    return period!.periodList.find((p) =>
      p.period.includes(new Date().getDay() + 1),
    )!.rewardGroupId;
  }

  getMissionById(missionId: string): MissionProgress {
    const type = excel.MissionTable.missions[missionId].type;
    return this.missions[type].filter((m) => m.missionId == missionId)[0];
  }

  async dailyRefresh() {
    await this._player.update(async (draft) => {
      draft.mission.missionRewards.dailyPoint = 0;
      draft.mission.missionRewards.rewards["DAILY"] = {};
      for (const reward of Object.values(
        excel.MissionTable.periodicalRewards,
      )) {
        if (reward.groupId == this.dailyMissionRewardPeriod) {
          draft.mission.missionRewards.rewards["DAILY"][reward.id] = 0;
        }
      }
    });
    const missionIds =
      excel.MissionTable.missionGroups[this.dailyMissionPeriod].missionIds;
    this.missions["DAILY"] = await Promise.all(
      missionIds.map(
        (missionId) =>
          new MissionProgress(missionId, this._trigger, this, "DAILY"),
      ),
    );
  }

  async weeklyRefresh() {
    await this._player.update(async (draft) => {
      draft.mission.missionRewards.weeklyPoint = 0;
      draft.mission.missionRewards.rewards["WEEKLY"] = {};
    });
    this.missions["WEEKLY"] = [];
    for (const mission of Object.values(excel.MissionTable.missions).filter(
      (m) => m.type == "WEEKLY",
    )) {
      this.missions["WEEKLY"].push(
        new MissionProgress(mission.id, this._trigger, this, "WEEKLY"),
      );
    }
  }

  async confirmMission(args: { missionId: string }): Promise<ItemBundle[]> {
    const { missionId } = args;
    const items: ItemBundle[] = [];
    this.getMissionById(missionId).confirmed = true;
    await this._player.update(async (draft) => {
      switch (excel.MissionTable.missions[missionId].type) {
        case "DAILY":
          draft.mission.missionRewards.dailyPoint +=
            excel.MissionTable.missions[missionId].periodicalPoint;
          Object.entries(draft.mission.missionRewards.rewards["DAILY"]).forEach(
            ([k, v]) => {
              if (
                v == 0 &&
                draft.mission.missionRewards.dailyPoint >=
                  excel.MissionTable.periodicalRewards[k].periodicalPointCost
              ) {
                draft.mission.missionRewards.dailyPoint -=
                  excel.MissionTable.periodicalRewards[k].periodicalPointCost;
                items.push(...excel.MissionTable.periodicalRewards[k].rewards);
                //console.log(items)
                draft.mission.missionRewards.rewards["DAILY"][k] = 1;
              }
            },
          );
          break;
        case "WEEKLY":
          draft.mission.missionRewards.weeklyPoint +=
            excel.MissionTable.missions[missionId].periodicalPoint;
          break;
        default:
          break;
      }
    });

    this._trigger.emit("items:get", items);
    return items;
  }

  async confirmMissionGroup(args: { missionGroupId: string }) {
    const { missionGroupId } = args;
    const rewards = excel.MissionTable.missionGroups[missionGroupId].rewards;
    if (rewards) {
      this._trigger.emit("items:get", rewards);
    }
    await this._player.update(async (draft) => {
      draft.mission.missionGroups[missionGroupId] = 1;
    });
  }

  async autoConfirmMissions(args: { type: string }): Promise<ItemBundle[]> {
    const { type } = args;
    const items: ItemBundle[] = [];
    const missions = this.missions[type];
    const completedMissions = missions.filter(
      (m) => m.state == 2 && m.progress[0].value == m.progress[0].target,
    );
    for (const mission of completedMissions) {
      items.push(
        ...(await this.confirmMission({ missionId: mission.missionId })),
      );
    }
    return items;
  }

  async exchangeMissionRewards(args: { targetRewardsId: string }) {
    const { targetRewardsId } = args;
    const rewards =
      excel.MissionTable.periodicalRewards[targetRewardsId].rewards;
    this._trigger.emit("items:get", rewards);
    return rewards;
  }

  toJSON(): MissionPlayerData {
    return {
      missions: Object.fromEntries(
        Object.entries(this.missions).map(([type, v]) => [
          type,
          v.reduce(
            (acc, v) => ({ ...acc, [v.missionId]: v.toJSON() }),
            {} as { [k: string]: MissionPlayerState },
          ),
        ]),
      ),
      missionRewards: this._player._playerdata.mission.missionRewards,
      missionGroups: this._player._playerdata.mission.missionGroups,
    };
  }
}
export class MissionProgress implements MissionPlayerState {
  progress: BaseProgress[];
  missionId: string;
  _trigger: TypedEventEmitter;
  _manager: MissionManager;
  param!: string[];
  value: number;
  type: string;
  confirmed: boolean;

  constructor(
    missionId: string,
    _trigger: TypedEventEmitter,
    _manager: MissionManager,
    type: string,
    value = 0,
    state = -1,
  ) {
    this.missionId = missionId;
    this.value = value;
    this.progress = [];
    this._trigger = _trigger;
    this._manager = _manager;
    this.type = type;
    this.confirmed = state == 3;
    this.init();
    //this._trigger.on("mission:update", this.update.bind(this))
  }

  get state(): number {
    if (!("value" in this.progress[0])) {
      console.log(this.missionId);
      return 0;
    }
    if (
      this.progress[0].value >= (this.progress[0].target as number) &&
      this.confirmed
    ) {
      return 3;
    } else {
      const preMissionIds =
        excel.MissionTable.missions[this.missionId]?.preMissionIds;
      if (!preMissionIds) {
        return 2;
      }
      for (const i of preMissionIds) {
        if (this._manager.getMissionById(i).state != 3) {
          return 1;
        }
      }
      return 2;
    }
  }

  async init() {
    let template: keyof typeof MissionTemplates;
    let mission: MissionData;
    if (this.type == "ACTIVITY") {
      return;
    } else if (this.type == "OPENSERVER") {
      const group = excel.OpenServerTable.schedule.find((v) =>
        checkBetween(
          this._manager._player._playerdata.status.registerTs,
          v.startTs,
          v.endTs,
        ),
      )!.id;
      mission = excel.OpenServerTable.dataMap[group].openServerMissionData.find(
        (m) => m.id == this.missionId,
      )!;
    } else {
      mission = excel.MissionTable.missions[this.missionId];
    }
    if (mission) {
      if (mission.template in MissionTemplates) {
        template = mission.template as keyof typeof MissionTemplates;
        this.param = mission.param;
      } else {
        console.error(`Invalid template: ${mission.template}`);
        return;
      }
    } else {
      console.error(`Mission ID ${this.missionId} not found`);
      return;
    }
    //TODO:infer from variable
    const func = (args: unknown) => {
      return MissionTemplates[template]![this.param[0]].update(
        this,
        args as never,
      );
    };
    this._trigger.on(template, (args: unknown) => {
      MissionTemplates[template]![this.param[0]].update(this, args as never);
      //console.log(`[MissionManager] ${this.missionId} update ${this.progress[0].value}/${this.progress[0].target}`)
      if (this.progress[0].value >= this.progress[0].target!) {
        console.log(`[MissionManager] ${this.missionId} complete`);
        this._trigger.removeListener(template, func);
      }
    });
    MissionTemplates[template]![this.param[0]].init(this);
  }

  update() {}

  toJSON(): MissionPlayerState {
    return {
      state: this.state,
      progress: this.progress,
    };
  }
}

export const MissionTemplates: {
  [T in keyof Partial<EventMap>]: {
    [p: string]: {
      init: (mission: MissionProgress) => void;
      update: (mission: MissionProgress, ...args: EventMap[T]) => void;
    };
  };
} = {
  CompleteStageAnyType: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: BattleData) => {
        const { completeState } = args;
        if (completeState >= parseInt(mission.param[2])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  StageWithEnemyKill: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: () => {},
    },
    "1": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: BattleData) => {
        const { completeState } = args;
        if (completeState >= 2) {
          mission.progress[0].value += args.killCnt;
        }
      },
    },
    "2": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: BattleData) => {
        const enemies = mission.param[2].split("^");
        args.battleData.stats.enemyStats.forEach((stat) => {
          if (
            enemies.includes(stat.Key.enemyId) &&
            stat.Key.counterType == "HP_ZERO"
          ) {
            mission.progress[0].value += stat.Value;
          }
        });
      },
    },
    "3": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: () => {},
    },
    "5": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (
        mission: MissionProgress,
        args: BattleData & { stageId: string },
      ) => {
        const stages = mission.param[1].split("^");
        if (stages.includes(args.stageId) && args.completeState >= 2) {
          mission.progress[0].value += args.killCnt;
        }
      },
    },
    "6": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[3]),
        });
      },
      update: (
        mission: MissionProgress,
        args: BattleData & { stageId: string },
      ) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId)) {
          return;
        }
        if (args.completeState < parseInt(mission.param[3])) {
          return;
        }
        if (args.killCnt >= parseInt(mission.param[2])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  EnemyKillInAnyStage: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: BattleData) => {
        if (args.completeState < parseInt(mission.param[2])) {
          return;
        }
        mission.progress[0].value += args.killCnt;
      },
    },
  },

  StageWithAssistChar: {
    "1": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: () => {
        //TODO
      },
    },
  },

  UpgradeChar: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress) => {
        mission.progress[0].value += 1;
      },
    },
    "1": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { char: PlayerCharacter }) => {
        if (args.char.evolvePhase < parseInt(mission.param[2])) {
          return;
        }
        if (args.char.level >= parseInt(mission.param[3])) {
          mission.progress[0].value += 1;
        }
      },
    },
    "2": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { exp: number }) => {
        mission.progress[0].value += args.exp;
      },
    },
  },

  ReceiveSocialPoint: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { socialPoint: number }) => {
        mission.progress[0].value += args.socialPoint;
      },
    },
    "1": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress) => {
        mission.progress[0].value += 1;
      },
    },
  },

  BuyShopItem: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { type: string }) => {
        const shops = "LS^HS^ES".split("^");
        if (shops.includes(args.type)) {
          mission.progress[0].value += 1;
        }
      },
    },
    "1": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { type: string }) => {
        if (args.type == "SOCIAL") {
          mission.progress[0].value += 1;
        }
      },
    },
    "3": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (
        mission: MissionProgress,
        args: { type: string; socialPoint: number },
      ) => {
        if (args.type != "SOCIAL") {
          return;
        }
        mission.progress[0].value += args.socialPoint;
      },
    },
  },

  NormalGacha: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission: MissionProgress) => {
        mission.progress[0].value += 1;
      },
    },
  },

  GainIntimacy: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { count: number }) => {
        mission.progress[0].value += args.count;
      },
    },
  },
  ManufactureItem: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { item: ItemBundle }) => {
        if (args.item.id == mission.param[2]) {
          mission.progress[0].value += args.item.count;
        }
      },
    },
    "1": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { count: number }) => {
        mission.progress[0].value += args.count;
      },
    },
    "2": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { item: ItemBundle }) => {
        const items = mission.param[2].split("#");
        if (items.includes(args.item.id)) {
          mission.progress[0].value += 1;
        }
      },
    },
  },
  DeliveryOrder: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { count: number }) => {
        mission.progress[0].value += args.count;
      },
    },
    "1": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { count: number }) => {
        mission.progress[0].value += args.count;
      },
    },
  },
  RecoverCharBaseAp: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { count: number }) => {
        mission.progress[0].value += args.count;
      },
    },
  },
  VisitBuilding: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress) => {
        mission.progress[0].value += 1;
      },
    },
  },
  UpgradeSkill: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress) => {
        mission.progress[0].value += 1;
      },
    },
    "1": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { targetLevel: number }) => {
        mission.progress[0].value += args.targetLevel;
      },
    },
  },
  SquadFormation: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission: MissionProgress) => {
        const flag = false;
        //TODO
        mission.progress[0].value += flag ? 1 : 0;
      },
    },
  },
  CompleteStage: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (
        mission: MissionProgress,
        args: BattleData & { stageId: string },
      ) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId)) {
          return;
        }
        if (args.completeState >= 2) {
          mission.progress[0].value += 1;
        }
      },
    },
    "2": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission: MissionProgress, args: BattleData) => {
        if (args.completeState >= parseInt(mission.param[1])) {
          mission.progress[0].value += 1;
        }
      },
    },
    "3": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (
        mission: MissionProgress,
        args: BattleData & { isPractice: number },
      ) => {
        if (!args.isPractice) {
          return;
        }
        if (args.completeState >= 2) {
          mission.progress[0].value += 1;
        }
      },
    },
    "4": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (
        mission: MissionProgress,
        args: BattleData & { stageId: string },
      ) => {
        if (!args.stageId.includes("#f#")) {
          return;
        }
        if (args.completeState >= 3) {
          mission.progress[0].value += 1;
        }
      },
    },
  },
  UpgradePlayer: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { level: number }) => {
        mission.progress[0].value = args.level;
      },
    },
  },
  CompleteAnyStage: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (
        mission: MissionProgress,
        args: BattleData & { stageId: string },
      ) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId)) {
          return;
        }
        if (args.completeState >= parseInt(mission.param[2])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },
  HasChar: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { char: PlayerCharacter }) => {
        const data = excel.CharacterTable[args.char.charId];
        if (args.char.evolvePhase < parseInt(mission.param[2])) {
          return;
        }
        if (args.char.level < parseInt(mission.param[3])) {
          return;
        }
        if (
          data.rarity.slice(-1) != mission.param[4] &&
          mission.param[4] != "-1"
        ) {
          return;
        }
        if (data.profession != mission.param[5] && mission.param[5] != "ALL") {
          return;
        }
        mission.progress[0].value += 1;
      },
    },
    "1": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { char: PlayerCharacter }) => {
        const data = excel.CharacterTable[args.char.charId];
        if (args.char.evolvePhase < parseInt(mission.param[2])) {
          return;
        }
        if (args.char.level < parseInt(mission.param[3])) {
          return;
        }
        if (
          data.rarity.slice(-1) != mission.param[4] &&
          mission.param[4] != "-1"
        ) {
          return;
        }
        if (data.profession != mission.param[5] && mission.param[5] != "ALL") {
          return;
        }
        mission.progress[0].value += 1;
      },
    },
  },
  HasEquipment: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[3]),
        });
      },
      update: (mission: MissionProgress, args: { char: PlayerCharacter }) => {
        const data = excel.CharacterTable[args.char.charId];
        const rarities = mission.param[1].split("^");
        const levels = mission.param[2].split("^");
        if (args.char.evolvePhase < 2) {
          return;
        }
        if (!rarities.includes(data.rarity.slice(-1))) {
          return;
        }
        Object.values(args.char.equip!).forEach((e) => {
          if (levels.includes(e.level.toString())) {
            mission.progress[0].value += 1;
          }
        });
      },
    },
  },
  EvolveChar: {
    "1": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { char: PlayerCharacter }) => {
        if (args.char.evolvePhase >= parseInt(mission.param[2])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },
  DiyComfort: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: () => {
        //TODO
      },
    },
    "1": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: () => {
        //TODO
      },
    },
  },
  HasRoom: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: () => {
        //TODO
      },
    },
  },
  WorkshopSynthesis: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { item: ItemBundle }) => {
        if (args.item.id == mission.param[2]) {
          mission.progress[0].value += args.item.count;
        }
      },
    },
  },
  UpgradeSpecialization: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress) => {
        mission.progress[0].value += 1;
      },
    },
    "1": {
      init: (mission: MissionProgress) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission: MissionProgress, args: { targetLevel: number }) => {
        if (args.targetLevel >= parseInt(mission.param[1])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },
  BattleWithEnemyKill: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (
        mission: MissionProgress,
        args: BattleData & { stageId: string },
      ) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId)) {
          return;
        }
        if (args.killCnt >= mission.progress[0].value) {
          mission.progress[0].value = args.killCnt;
        }
      },
    },
  },
  CharIntimacy: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { favorPoint: number }) => {
        let percent: number;
        if (args.favorPoint == excel.FavorTable.maxFavor) {
          percent = 200;
        } else {
          percent = excel.FavorTable.favorFrames.find((_f, idx, table) => {
            return (
              args.favorPoint >= table[idx].level &&
              args.favorPoint < table[idx + 1].level
            );
          })!.data.percent;
        }
        if (percent >= parseInt(mission.param[2])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },
  CompleteBreakReward: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: () => {
        //TODO
      },
    },
  },
  StartInfoShare: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress) => {
        mission.progress[0].value += 1;
      },
    },
  },
  EditBusinessCard: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission: MissionProgress) => {
        mission.progress[0].value += 1;
      },
    },
  },
  SetAssistCharList: {
    "1": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress) => {
        mission.progress[0].value += 1;
      },
    },
  },
  ChangeSquadName: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress) => {
        mission.progress[0].value += 1;
      },
    },
  },
  StageWithReplay: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { isReplay: number }) => {
        if (args.isReplay) {
          mission.progress[0].value += 1;
        }
      },
    },
  },
  TakeOverReplay: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: BattleData) => {
        if (args.battleData.stats.autoReplayCancelled) {
          mission.progress[0].value += 1;
        }
      },
    },
  },
  CompleteCampaign: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (
        mission: MissionProgress,
        args: BattleData & { stageId: string },
      ) => {
        const stageType = excel.StageTable.stages[args.stageId].stageType;
        if (args.completeState < 2) {
          return;
        }
        if (stageType == "CAMPAIGN") {
          mission.progress[0].value += 1;
        }
      },
    },
  },
  SetBuildingAssist: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission: MissionProgress) => {
        mission.progress[0].value += 1;
      },
    },
  },
  BoostPotential: {
    "1": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress, args: { targetLevel: number }) => {
        if (args.targetLevel >= parseInt(mission.param[2])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },
  WorkshopExBonus: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress) => {
        mission.progress[0].value += 1;
      },
    },
  },
  BoostNormalGacha: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress) => {
        mission.progress[0].value += 1;
      },
    },
  },
  CompleteMainStage: {
    "1": {
      init: (mission: MissionProgress) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (
        mission: MissionProgress,
        args: BattleData & { stageId: string },
      ) => {
        if (args.stageId != mission.param[1]) {
          return;
        }
        if (args.completeState >= 2) {
          mission.progress[0].value += 1;
        }
      },
    },
  },
  SendClue: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission: MissionProgress) => {
        mission.progress[0].value += 1;
      },
    },
  },
  GainTeamChar: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: () => {
        //TODO
      },
    },
  },
  AccelerateOrder: {
    "0": {
      init: (mission: MissionProgress) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission: MissionProgress) => {
        mission.progress[0].value += 1;
      },
    },
  },
};
