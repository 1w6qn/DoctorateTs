import { accountManager } from "../manager/AccountManger";

import excel from "@excel/excel";
import { decryptBattleData } from "@utils/crypt";
import { now } from "@utils/time";
import { CommonStartBattleRequest } from "@game/model/battle";
import { TypedEventEmitter } from "@game/model/events";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { ItemBundle } from "@excel/character_table";
import { ConditionDesc, DisplayDetailRewards } from "@excel/stage_table";
import { divmod, randomChoice, randomChoices } from "@utils/random";
import { pick } from "lodash";

export class BattleManager {
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  constructor(_player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = _player;
    this._trigger = _trigger;
    this._trigger.on("battle:start", async([args]) => {
      await this.start(args);
    });
    this._trigger.on("battle:finish", async([args]) => {
      await this.finish(args);
    });
  }

  async start(args: CommonStartBattleRequest) {
    console.log("start battle", args);
    const { stageId, usePracticeTicket, squad } = args;
    const battleId = "1";
    const { zoneId, apCost, dangerLevel } = excel.StageTable.stages[stageId];
    let { apFailReturn } = excel.StageTable.stages[stageId];
    let notifyPowerScoreNotEnoughIfFailed = false;
    
    // Check zoneInfo of apProtect
    let inApProtectPeriod = false;
    if (zoneId in excel.StageTable.apProtectZoneInfo) {
      inApProtectPeriod = excel.StageTable.apProtectZoneInfo[
        zoneId
      ].timeRanges.some(
        (range) => now() >= range.startTs && now() <= range.endTs,
      );
    }
    let isApProtect = 0;
    await this._player.update(async (draft) => {
      if (draft.dungeon.stages[stageId].noCostCnt == 1) {
        isApProtect = 1;
        apFailReturn = apCost;
      }
      if (inApProtectPeriod) {
        isApProtect = 1;
      }
      // Add current stage
      if (stageId in draft.dungeon.stages) {
        draft.dungeon.stages[stageId].startTimes += 1;
      } else {
        draft.dungeon.stages[stageId] = {
          stageId: stageId,
          completeTimes: 0,
          startTimes: 0,
          practiceTimes: 0,
          state: 0,
          hasBattleReplay: 0,
          noCostCnt: stageId.includes("guide") ? 1 : 0,
        };
      }
      // Check if PracticeTicket is used
      if (apCost == 0 || usePracticeTicket) {
        isApProtect = 0;
        apFailReturn = 0;
      }
      if (usePracticeTicket) {
        draft.status.practiceTicket -= 1;
        draft.dungeon.stages[stageId].practiceTimes += 1;
      }
      // Check user powerScore
      squad.slots.forEach((char) => {
        if (!char) return;
        if (!dangerLevel || dangerLevel == "-") return;
        const { charInstId } = char;
        const stageLevel = parseInt(dangerLevel.slice(-2).replace(".", ""));
        const { level: charLevel, evolvePhase } = draft.troop.chars[charInstId];
        if (
          dangerLevel.startsWith("精英1") &&
          (evolvePhase < 1 || charLevel < stageLevel)
        ) {
          notifyPowerScoreNotEnoughIfFailed = true;
          return;
        } else if (
          dangerLevel.startsWith("精英2") &&
          (evolvePhase < 2 || charLevel < stageLevel)
        ) {
          notifyPowerScoreNotEnoughIfFailed = true;
          return;
        }
      });
      await accountManager.saveBattleInfo(draft.status.uid, battleId, {
        stageId,
        isPractice: usePracticeTicket,
      });
    });

    return {
      apFailReturn,
      battleId,
      inApProtectPeriod,
      isApProtect,
      notifyPowerScoreNotEnoughIfFailed,
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
    const { data } = args;
    const battleData = await decryptBattleData(
      data,
      this._player._playerdata.pushFlags.status,
    );
    const battleInfo = await accountManager.getBattleInfo(
      this._player.uid,
      battleData.battleId,
    );
    let goldScale = 0,
      expScale = 0,
      apFailReturn = 0;
    const suggestFriend = false;
    const unlockStages: string[] = [];
    const unlockStagesObject = [];
    const { apCost, expGain, goldGain } =
      excel.StageTable.stages[battleInfo.stageId];
    const { stageId, isPractice } = battleInfo;
    const displayDetailRewards =
      excel.StageTable.stages[stageId].stageDropInfo.displayDetailRewards;
    let [
      additionalRewards,
      unusualRewards,
      furnitureRewards,
      rewards,
    ]: ItemBundle[][] = [[], [], [], []];
    if (battleData.completeState === 3) {
      goldScale = 1.2;
      expScale = 1.2;
    } else if (battleData.completeState === 2) {
      goldScale = 1;
      expScale = 1;
    }
    await this._trigger.emit("items:get", [
      [
        {
          type: "AP_GAMEPLAY",
          id: "",
          count: -apCost,
        },
        {
          type: "EXP_PLAYER",
          id: "",
          count: expGain * expScale,
        },
        {
          type: "GOLD",
          id: "4001",
          count: goldGain * goldScale,
        },
      ],
    ]);
    await this._player.update(async (draft) => {
      const playerStage = draft.dungeon.stages[stageId];
      if (isPractice) {
        if (playerStage.state == 0) {
          playerStage.state = 1;
        }
        return;
      }
      if (battleData.completeState === 1) {
        if (playerStage.state == 0) {
          draft.dexNav.enemy.stage[stageId] = Object.keys(
            battleData.battleData.stats.enemyList,
          );
          playerStage.state = 1;
        }
        if (playerStage.noCostCnt) {
          apFailReturn = apCost;
          playerStage.noCostCnt -= 1;
        } else {
          apFailReturn = excel.StageTable.stages[stageId].apFailReturn;
        }
        await this._trigger.emit("items:get", [
          [
            {
              type: "AP_GAMEPLAY",
              id: "",
              count: apFailReturn,
            },
          ],
        ]);
      } else {
        let firstClear = false;
        if (
          (playerStage.state != 3 && battleData.completeState === 3) ||
          (playerStage.state == 3 && battleData.completeState === 4)
        ) {
          firstClear = true;
        }
        if (playerStage.state == 1 && battleData.completeState in [2, 3]) {
          if (stageId == "main_08-16") {
            //todo: amiya guard
          }
          // unlock recruit
          if (stageId == "main_00-02") {
            draft.recruit.normal.slots[0].state = 1;
            draft.recruit.normal.slots[1].state = 1;
          }
          //unlock stage
          const unlockList: { [key: string]: ConditionDesc[] } = {};
          for (const item of Object.keys(excel.StageTable.stages)) {
            unlockList[item] = excel.StageTable.stages[item].unlockCondition;
          }
          for (const item of Object.keys(unlockList)) {
            let passCondition = 0;
            if (unlockList[item].length == 0) {
              //todo
            } else {
              for (const condition of unlockList[item]) {
                if (condition.stageId in Object.keys(draft.dungeon.stages)) {
                  if (
                    draft.dungeon.stages[condition.stageId].state >=
                    condition.completeState
                  ) {
                    passCondition += 1;
                  }
                }
                if (stageId == condition.stageId) {
                  if (battleData.completeState >= condition.completeState) {
                    passCondition += 1;
                  }
                }
              }
              if (passCondition == unlockList[item].length) {
                const unlockStage = {
                  stageId: item,
                  practiceTimes: 0,
                  completeTimes: 0,
                  startTimes: 0,
                  state: 0,
                  hasBattleReplay: 0,
                  noCostCnt: 1,
                };
                for (const chr of ["#f#", "hard_", "tr_"]) {
                  if (item.includes(chr)) {
                    unlockStage.noCostCnt = 0;
                  }
                }
                if (!(item in Object.keys(draft.dungeon.stages))) {
                  if (
                    excel.StageTable.stages[stageId].stageType in
                      ["MAIN", "SUB"] &&
                    excel.StageTable.stages[item].stageType in ["MAIN", "SUB"]
                  ) {
                    draft.status.mainStageProgress = item;
                  }
                  draft.dungeon.stages[item] = unlockStage;
                  unlockStages.push(item);
                  unlockStagesObject.push(unlockStage);
                }
              }
            }
          }
        }
        if (firstClear) {
          for (const item of displayDetailRewards) {
            if (item.dropType in [1, 8]) {
              await this._trigger.emit("items:get", [
                [
                  {
                    type: item.type,
                    id: item.id,
                    count: 1,
                  },
                ],
              ]);
            }
          }
        }
        if (playerStage.state != 3 || battleData.completeState === 4) {
          draft.dungeon.stages[stageId].state = battleData.completeState;
        }
        [additionalRewards, unusualRewards, furnitureRewards, rewards] =
          await this.dropReward(
            displayDetailRewards,
            battleData.completeState,
            stageId,
          );
        if (goldGain * goldScale != 0) {
          rewards.push({
            type: "GOLD",
            id: "4001",
            count: goldGain * goldScale,
          });
        }
      }
    });

    await this._trigger.emit("CompleteStageAnyType", [battleData]);
    await this._trigger.emit("CompleteStage", [
      {
        ...battleData,
        ...battleInfo,
      },
    ]);
    if (isPractice) {
      return {};
    }
    return {
      apFailReturn,
      expScale,
      goldScale,
      rewards: [],
      firstRewards: [],
      unlockStages: [],
      unusualRewards: [],
      additionalRewards: [],
      furnitureRewards: [],
      alert: [],
      suggestFriend,
      pryResult: [],
    };
  }

  async dropReward(
    displayDetailRewards: DisplayDetailRewards[],
    completeState: number,
    stageId: string,
  ): Promise<ItemBundle[][]> {
    const additionalRewards: ItemBundle[] = [];
    const unusualRewards: ItemBundle[] = [];
    const furnitureRewards: ItemBundle[] = [];
    const rewards: ItemBundle[] = [];

    for (const item of displayDetailRewards) {
      const { occPercent, dropType, id: reward_id, type: reward_type } = item;
      let reward_count = 1;
      let reward_rarity = 0;
      let addPercent = 0;

      if (completeState === 3) {
        if (reward_type !== "CHAR") {
          reward_rarity =
            reward_type === "FURN"
              ? excel.BuildingData.customData.furnitures[reward_id].rarity
              : excel.ItemTable.items[reward_id].rarity;

          switch (reward_rarity) {
            case 0:
              reward_count += randomChoices([0, 1, 2], [70, 20, 10], 1)[0];
              addPercent = 15;
              break;
            case 1:
              reward_count += randomChoices([0, 1, 2], [85, 10, 5], 1)[0];
              addPercent = 10;
              break;
            case 2:
              addPercent = 5;
              break;
            default:
              addPercent = 0;
              break;
          }
        }
      } else if (completeState === 2) {
        if (reward_type !== "FURN" && reward_type !== "CHAR") {
          reward_rarity = excel.ItemTable.items[reward_id].rarity;
        }

        switch (reward_rarity) {
          case 0:
            reward_count += randomChoices([0, 1, 2], [80, 12, 8], 1)[0];
            break;
          case 1:
            reward_count += randomChoices([0, 1, 2], [97, 2, 1], 1)[0];
            break;
        }
      }

      if (stageId.toLowerCase().includes("act")) {
        addPercent += 12;
      } else {
        addPercent += randomChoices([-1, 0, 1], [5, 90, 5], 1)[0];
      }

      const handleMaterial = (stageId: string) => {
        const ToughSiege: { [key: string]: number } = {
          wk_toxic_1: 5,
          wk_toxic_2: 8,
          wk_toxic_3: 11,
          wk_toxic_4: 15,
          wk_toxic_5: 21,
        };
        const AerialThreat: { [key: string]: [number, number, number] } = {
          wk_fly_1: [3, 0, 0],
          wk_fly_2: [5, 0, 0],
          wk_fly_3: [1, 3, 0],
          wk_fly_4: [1, 1, 1.58],
          wk_fly_5: [1.49, 1.5, 2],
        };
        const ResourceSearch: { [key: string]: [number, number, number] } = {
          wk_armor_1: [1, 1, 2],
          wk_armor_2: [1, 3, 4],
          wk_armor_3: [0, 2.5, 5],
          wk_armor_4: [0, 7, 2],
          wk_armor_5: [0, 10, 2.99],
        };

        const stageData = AerialThreat[stageId] || ResourceSearch[stageId];
        if (stageData) {
          stageData.forEach((j, i) => {
            if (
              j === 0 ||
              (parseInt(stageId.slice(-1)) > 3 && reward_id === "3113")
            )
              return;
            const percent = Math.floor(divmod(j, 1)[1]);
            const drop_array = randomChoices(
              [0, 1],
              [percent, 1 - percent],
              1,
            )[0];
            let count = Math.floor(divmod(j, 1)[0]) + drop_array;

            if (completeState === 3) {
              if (reward_rarity === i + 1) {
                reward_count = count;
                if (
                  reward_type === "MATERIAL" &&
                  stageId === "wk_armor_3" &&
                  reward_id === "3401"
                ) {
                  reward_count = ResourceSearch[stageId][2];
                }
              }
            } else {
              if (
                reward_type === "MATERIAL" &&
                stageId === "wk_armor_3" &&
                reward_id === "3401"
              ) {
                count = ResourceSearch[stageId][2];
              }
              reward_count = Math.round(count / (1.5 * 1.2));
            }
          });
        } else if (stageId in ToughSiege) {
          if (completeState === 3) {
            reward_count = ToughSiege[stageId] + randomChoice([1, 0, -1]);
          } else {
            reward_count = Math.round(ToughSiege[stageId] / (2 * 1.2));
          }
        }
      };

      if (reward_type === "MATERIAL") handleMaterial(stageId);

      if (reward_type === "CARD_EXP") {
        const TacticalDrill: {
          [key: string]: [number, number, number, number];
        } = {
          wk_kc_1: [2.01, 3, 0, 0],
          wk_kc_2: [3.99, 4.99, 0, 0],
          wk_kc_3: [3, 1.73, 3, 0],
          wk_kc_4: [1.99, 3, 1.99, 1],
          wk_kc_5: [0, 1, 1, 3],
          wk_kc_6: [0, 0, 2, 4],
          "sub_02-03": [6.25, 0, 0, 0],
          "main_00-10": [4.27, 0, 0, 0],
          "main_03-05": [0, 5, 0, 0],
          "sub_02-10": [0, 4, 0, 0],
          "main_04-03": [0, 0, 2.74, 0],
          "main_07-11": [0, 0, 2.56, 0],
          "main_08-06": [0, 0, 2.65, 0],
          "sub_06-1-1": [0, 0, 2.82, 0],
          "main_09-09": [0, 0, 2.73, 0],
          "main_10-01": [0, 0, 3.38, 0],
          "tough_10-01": [0, 0, 3.17, 0],
          "main_11-01": [0, 0, 3.47, 0],
          "tough_11-01": [0, 0, 3.43, 0],
          "sub_04-3-3": [0, 0, 3.59, 0],
          "sub_05-3-2": [0, 0, 2.87, 0],
        };

        if (stageId in TacticalDrill) {
          TacticalDrill[stageId].forEach((j, i) => {
            const percent = Math.floor(divmod(j, 1)[1]);
            const drop_array = randomChoices(
              [0, 1],
              [percent, 1 - percent],
              1,
            )[0];
            const count = Math.floor(divmod(j, 1)[0]) + drop_array;
            if (completeState === 3 && reward_rarity === i + 1) {
              reward_count = count;
            } else {
              reward_count = Math.round(count / (1.5 * 1.2));
            }
          });
        }
      }

      if (reward_type === "GOLD") {
        const SpecialGold: { [key: string]: number } = {
          "main_01-01": 660, // 1-1
          "main_02-07": 1500, // 2-7
          "main_03-06": 2040, // 3-6
          "main_04-01": 2700, // 4-1
          "main_06-01": 1216, // 6-1
          "main_07-02": 1216, // 7-3
          "main_08-01": 2700, // R8-1
          "main_08-04": 1216, // R8-4
          "main_09-01": 2700, // Standard 9-2
          "main_09-02": 1216, // Standard 9-3
          "main_10-07": 3480, // Standard 10-8
          "tough_10-07": 3480, // Adverse 10-8
          "main_11-08": 3480, // Standard 11-9
          "tough_11-08": 3480, // Adverse 11-9
          "sub_02-02": 1020, // S2-2
          "sub_04-2-3": 3480, // S4-6
          "sub_05-1-2": 2700, // S5-2
          "sub_05-2-1": 1216, // S5-3
          "sub_05-3-1": 1216, // S5-5
          "sub_06-1-2": 1216, // S6-2
          "sub_06-2-2": 2700, // S6-4
          "sub_07-1-1": 2700, // S7-1
          "sub_07-1-2": 1216, // S7-2
          act18d0_05: 1644, // WD-5
          act17side_03: 1128, // SN-3
          act5d0_01: 1000, // CB-1
          act5d0_03: 1000, // CB-3
          act5d0_05: 2000, // CB-5
          act5d0_07: 2000, // CB-7
          act5d0_09: 3000, // CB-9
          act11d0_04: 1644, // TW-4
          act16d5_04: 1644, // WR-4
        };

        if (stageId in SpecialGold) {
          reward_count =
            completeState === 3
              ? SpecialGold[stageId]
              : Math.round(SpecialGold[stageId] / 1.2);
        }
      }

      const pushReward = () => {
        if (occPercent === 0 && dropType === 3) {
          unusualRewards.push({
            id: reward_id,
            type: reward_type,
            count: reward_count,
          });
        } else if (occPercent === 0 && dropType === 4) {
          const drop_array = randomChoices(
            [0, 1],
            [95 - addPercent, 5 + addPercent],
            1,
          )[0];
          if (drop_array)
            additionalRewards.push({
              id: reward_id,
              type: reward_type,
              count: reward_count + 1,
            });
        } else {
          if (reward_type === "FURN")
            furnitureRewards.push({
              id: reward_id,
              type: reward_type,
              count: reward_count,
            });
          else
            rewards.push({
              id: reward_id,
              type: reward_type,
              count: reward_count,
            });
        }
      };

      const handleOccPercent = (occPercent: number) => {
        if (occPercent === 0) {
          if (dropType === 1)
            displayDetailRewards = displayDetailRewards.filter(
              (i) => i !== item,
            );
          else if (dropType === 2)
            console.log(
              `- occPercent:0,dropType:2 -\n${JSON.stringify(item)}`,
              "debug",
            );
          else if (dropType === 8)
            displayDetailRewards = displayDetailRewards.filter(
              (i) => i !== item,
            );
          else pushReward();
        } else if (occPercent === 1) {
          if (dropType === 2) {
            console.log(
              `- occPercent:1,dropType:2 -\n${JSON.stringify(item)}`,
              "debug",
            );
            const drop_array = randomChoices(
              [0, 1],
              [25 - addPercent, 75 + addPercent],
              1,
            )[0];
            if (drop_array)
              rewards.push({
                id: reward_id,
                type: reward_type,
                count: reward_count,
              });
          }
        } else if (occPercent === 2) {
          if (dropType === 2) {
            console.log(
              `- occPercent:2,dropType:2 -\n${JSON.stringify(item)}`,
              "debug",
            );
            if (stageId.includes("pro_")) {
              const drop_array = randomChoices([0, 1], [50, 50], 1)[0];
              rewards.push({
                ...pick(displayDetailRewards[drop_array], ["id", "type"]),
                count: reward_count,
              });
            } else {
              const addWeights = 2;
              const drop_array = randomChoices(
                [0, 1],
                [60 - addPercent * addWeights, 40 + addPercent * addWeights],
                1,
              )[0];
              if (drop_array)
                rewards.push({
                  id: reward_id,
                  type: reward_type,
                  count: reward_count,
                });
            }
          }
        } else if (occPercent === 3) {
          if (dropType === 2) {
            console.log(
              `- occPercent:3,dropType:2 -\n${JSON.stringify(item)}`,
              "debug",
            );
            const drop_array = randomChoices(
              [0, 1],
              [85 - addPercent, 15 + addPercent],
              1,
            )[0];
            if (drop_array) pushReward();
          } else if (dropType === 4) {
            console.log(
              `- occPercent:3,dropType:4 -\n${JSON.stringify(item)}`,
              "debug",
            );
            const drop_array = randomChoices(
              [0, 1],
              [80 - addPercent, 20 + addPercent],
              1,
            )[0];
            if (drop_array)
              additionalRewards.push({
                id: reward_id,
                type: reward_type,
                count: reward_count,
              });
          }
        } else if (occPercent === 4) {
          if (dropType === 2) {
            console.log(
              `- occPercent:4,dropType:2 -\n${JSON.stringify(item)}`,
              "debug",
            );
            const drop_array = randomChoices(
              [0, 1],
              [97 - addPercent, 3 + addPercent],
              1,
            )[0];
            if (drop_array) pushReward();
          } else if (dropType === 3) {
            console.log(
              `- occPercent:4,dropType:3 -\n${JSON.stringify(item)}`,
              "debug",
            );
            const drop_array = randomChoices(
              [0, 1],
              [96 - addPercent, 4 + addPercent],
              1,
            )[0];
            if (drop_array)
              unusualRewards.push({
                id: reward_id,
                type: reward_type,
                count: reward_count,
              });
          } else if (dropType === 4) {
            console.log(
              `- occPercent:4,dropType:4 -\n${JSON.stringify(item)}`,
              "debug",
            );
            const drop_array = randomChoices(
              [1, 0],
              [(addPercent - 3) / 103, (100 - (addPercent - 3)) / 103],
              103,
            )[0];
            if (drop_array)
              additionalRewards.push({
                id: reward_id,
                type: reward_type,
                count: reward_count,
              });
          }
        } else {
          console.log(
            `[1;31mUnknown dropType: ${JSON.stringify(item)}[0;0m`,
            "info",
          );
        }
      };

      handleOccPercent(occPercent);
    }

    if (
      !additionalRewards.length &&
      !unusualRewards.length &&
      !rewards.length &&
      displayDetailRewards.length
    ) {
      return this.dropReward(displayDetailRewards, completeState, stageId);
    }
    await this._trigger.emit("items:get", [
      additionalRewards.concat(unusualRewards, furnitureRewards, rewards),
    ]);
    return [additionalRewards, unusualRewards, furnitureRewards, rewards];
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
    const { battleId, battleReplay } = args;
    const stageId = (
      await accountManager.getBattleInfo(
        this._player._playerdata.status.uid,
        battleId,
      )
    )?.stageId;
    return await accountManager.saveBattleReplay(
      this._player._playerdata.status.uid,
      stageId!,
      battleReplay,
    );
  }
}
