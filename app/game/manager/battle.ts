import { accountManager } from "../manager/AccountManager";

import excel from "@excel/excel";
import { decryptBattleData } from "@utils/crypt";
import { now } from "@utils/time";
import { CommonStartBattleRequest } from "@game/model/battle";
import { TypedEventEmitter } from "@game/model/events";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { ItemBundle } from "@excel/character_table";
import { ConditionDesc, DisplayDetailRewards } from "@excel/stage_table";
import { randomChoice, randomChoices } from "@utils/random";
import { rarityToIndex } from "@utils/rarity";
import { pick } from "lodash";
import { logger } from "@utils/logger";

/** 解锁条件完成度（PlayerBattleRank 字符串）→ 关卡 state 数值档位 */
const completeStateRank: Record<string, number> = { FAIL: 1, PASS: 2, COMPLETE: 3 };

/**
 * 各账号最近一次 battleStart 时的战斗加密锚点（pushFlags.status 快照）
 *
 * 客户端以「开始战斗时」的会话锚点时间戳加密战斗数据，而 pushFlags.status 会被每次
 * syncData 刷新为新的 now()——若战斗中途 syncData 推进了 status，battleFinish 直接用
 * 当前 status 解密会 key 漂移抛 bad decrypt。battleStart 快照后，finish 优先用存值解密。
 * 单账号私服场景下 uid 做 key 足够（覆盖最近一场战斗）。
 */
const battleLoginTimes = new Map<string, number>();

export class BattleManager {
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  constructor(_player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = _player;
    this._trigger = _trigger;
    this._trigger.on("battle:start", async([args]) => {
      await this.start(args);
    });
    this._trigger.on("battle:finish", async([args, cb]) => {
      const result = await this.finish(args);
      if (typeof cb === "function") cb(result);
    });
  }

  async start(args: CommonStartBattleRequest) {
    const { stageId, usePracticeTicket, squad } = args;
    // 唯一 battleId（时间戳 + 随机数），避免多场战斗互相覆盖 battleInfo/replay
    const battleId = `${now()}_${Math.floor(Math.random() * 100000)}`;
    const stage = excel.StageTable.stages[stageId];
    // 修复：未知关卡（数据版本错位/客户端请求未收录关卡）不 500——
    // 记录缺失 stageId 并返回最小战斗响应，客户端仍可本地游玩（结算由 finish 容错）
    if (!stage) {
      logger.warn(
        "battle",
        `quest/battleStart 未知关卡 ${stageId}（StageTable 无此关卡），返回最小 battleId`,
      );
      return {
        result: 0,
        battleId,
        apFailReturn: 0,
        isApProtect: 0,
        inApProtectPeriod: false,
        notifyPowerScoreNotEnoughIfFailed: false,
      };
    }
    const { zoneId, apCost, dangerLevel } = stage;
    let { apFailReturn } = stage;
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
      // 修复：新关卡（不在存档模板/后加活动关卡）在下方创建之前读取会 500——
      // 用可选链，创建块再按 guide 规则计算 noCostCnt
      if (draft.dungeon.stages[stageId]?.noCostCnt == 1) {
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
        // 修复：编队引用不存在的干员（已删/损坏存档）时不 500
        const charData = draft.troop.chars[charInstId];
        if (!charData) return;
        const { level: charLevel, evolvePhase } = charData;
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
      // 战斗加密锚点快照：客户端用「开始战斗时」的 pushFlags.status 加密，finish 用存值解密，
      // 避免中途 syncData 刷新 status 导致 key 漂移（bad decrypt）
      battleLoginTimes.set(draft.status.uid, draft.pushFlags.status);
      await accountManager.saveBattleInfo(draft.status.uid, battleId, {
        stageId,
        isPractice: usePracticeTicket,
        squad,
        // 助战好友信息（assistFriend 为 null 时不保存）
        ...(args.assistFriend ? { assistFriend: args.assistFriend } : {}),
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
          // 防御：数据表末尾字段名伪键（值 null）——stage.unlockCondition 读 null 崩溃
          const stage = stage_data[item];
          if (!stage || typeof stage !== "object") continue;
          unlock_list[item] = stage.unlockCondition as unknown as ConditionDesc[];
        }

        for (const item of Object.keys(unlock_list)) {
          let passCondition = 0;
          if (unlock_list[item].length == 0) {
            // 修复：`in Object.keys(...)` 恒 false → 无前置关卡每次把既有进度重置为 0
            if (!(item in draft.dungeon.stages)) {
              draft.dungeon.stages[item] = {
                stageId: item,
                practiceTimes: 0,
                completeTimes: 0,
                startTimes: 0,
                state: 0,
                hasBattleReplay: 0,
                noCostCnt: 1,
              };
              unlockStages.push(item);
            }
          } else {
            for (const condition of unlock_list[item]) {
              // 修复：同上 in 数组 bug；completeState 字符串已映射（此分支原本正确用
              // completeStateRank，但 173 行 in 数组恒 false 导致永不满足）
              if (condition.stageId in draft.dungeon.stages) {
                if (
                  draft.dungeon.stages[condition.stageId].state >=
                  completeStateRank[condition.completeState]
                ) {
                  passCondition += 1;
                }
              }
              if (stageId == condition.stageId) {
                if (3 >= completeStateRank[condition.completeState]) {
                  passCondition += 1;
                }
              }
            }
            if (passCondition == unlock_list[item].length) {
              if (!(item in draft.dungeon.stages)) {
                draft.dungeon.stages[item] = {
                  stageId: item,
                  practiceTimes: 0,
                  completeTimes: 0,
                  startTimes: 0,
                  state: 0,
                  hasBattleReplay: 0,
                  noCostCnt: 1,
                };
                unlockStages.push(item);
              }
            }
          }
        }

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
    // 解密锚点优先用 battleStart 快照（客户端用「开始战斗时」的锚点加密），
    // 防止战斗中途 syncData 刷新 pushFlags.status 导致 key 漂移（bad decrypt）
    const loginTime =
      battleLoginTimes.get(this._player.uid) ?? this._player._playerdata.pushFlags.status;
    const battleData = await decryptBattleData(data, loginTime);
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
    const firstRewards: ItemBundle[] = [];
    const { stageId, isPractice } = battleInfo;
    const stage = excel.StageTable.stages[stageId];
    // 修复：未知关卡（battleStart 已容错，battleInfo 里的 stageId 同样可能不在表内）——
    // 返回最小结算响应，避免 500
    if (!stage) {
      logger.warn(
        "battle",
        `quest/battleFinish 未知关卡 ${stageId}，返回空结算`,
      );
      return {
        result: 0,
        apFailReturn: 0,
        expScale: 0,
        goldScale: 0,
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
    const { apCost, expGain, goldGain } = stage;
    const displayDetailRewards =
      stage.stageDropInfo.displayDetailRewards;
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
    // 修复：演习（isPractice）不扣理智、不发基础奖励——原实现把 AP/EXP/GOLD 发放
    // 放在 isPractice 早退之前，演习既扣 AP 又发经验/金币
    if (!isPractice) {
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
    }
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
        if (playerStage.state == 1 && [2, 3].includes(battleData.completeState)) {
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
            // 防御：数据表末尾字段名伪键（值 null）——stage.unlockCondition 读 null 崩溃
            const stage = excel.StageTable.stages[item];
            if (!stage || typeof stage !== "object") continue;
            unlockList[item] = stage.unlockCondition as unknown as ConditionDesc[];
          }
          for (const item of Object.keys(unlockList)) {
            let passCondition = 0;
            if (unlockList[item].length == 0) {
              // 修复：`item in Object.keys(...)` 恒 false（测数组下标）→ 无前置关卡每次
              // 都把既有进度重置为 state 0；改为直接查对象键
              if (!(item in draft.dungeon.stages)) {
                draft.dungeon.stages[item] = {
                  stageId: item,
                  practiceTimes: 0,
                  completeTimes: 0,
                  startTimes: 0,
                  state: 0,
                  hasBattleReplay: 0,
                  noCostCnt: 1,
                };
                unlockStages.push(item);
              }
            } else {
              for (const condition of unlockList[item]) {
                // 修复：同上 in 数组 bug + completeState 为 "PASS"/"COMPLETE" 字符串，
                // 数字 >= 字符串 → NaN 恒 false → 条件关卡永不解锁；经 completeStateRank 映射
                if (condition.stageId in draft.dungeon.stages) {
                  if (
                    draft.dungeon.stages[condition.stageId].state >=
                    completeStateRank[condition.completeState]
                  ) {
                    passCondition += 1;
                  }
                }
                if (stageId == condition.stageId) {
                  if (
                    battleData.completeState >=
                    completeStateRank[condition.completeState]
                  ) {
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
                // 修复：原 `item in Object.keys(draft.dungeon.stages)` 对数组用 in
                // 恒 false → 已存在的关卡（含已通关）每次被整体覆盖为 state 0，
                // completeTimes/startTimes/noCostCnt 全被清零、关卡重新变锁定；
                // 改为直接查对象键（与上方无前置条件分支同款修复）
                if (!(item in draft.dungeon.stages)) {
                  if (
                    ["MAIN", "SUB"].includes(
                      excel.StageTable.stages[stageId].stageType,
                    ) &&
                    ["MAIN", "SUB"].includes(
                      excel.StageTable.stages[item].stageType,
                    )
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
            if ([1, 8].includes(item.dropType as unknown as number)) {
              firstRewards.push({
                type: item.type,
                id: item.id,
                count: 1,
              });
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
        // 胜利时累加通关次数（非练习）
        if ([2, 3].includes(battleData.completeState)) {
          draft.dungeon.stages[stageId].completeTimes += 1;
          // 出战后干员信赖结算（参战编队干员各 +1 favorPoint）
          if (battleInfo.squad) {
            for (const char of battleInfo.squad.slots) {
              if (char && draft.troop.chars[char.charInstId]) {
                const target = draft.troop.chars[char.charInstId];
                target.favorPoint = (target.favorPoint || 0) + 1;
                // 修复：勋章 CharFavorCount 事件从未 emit → 干员信赖勋章永不推进
                await this._trigger.emit("CharFavorCount", [
                  { favorPoint: target.favorPoint },
                ]);
                // 修复：任务 CharIntimacy 事件从未 emit → 干员信赖任务永不推进
                await this._trigger.emit("CharIntimacy", [
                  { favorPoint: target.favorPoint },
                ]);
              }
            }
          }
        }
        [additionalRewards, unusualRewards, furnitureRewards, rewards] =
          await this.dropReward(
            displayDetailRewards as unknown as DisplayDetailRewards[],
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
    // 修复：以下任务事件从未 emit → 相应任务模板永不推进；胜利结算统一补发。
    // 入账顺位在 update 之后（干员信赖 favorPoint 已在 recipe 内 +1）
    if (!isPractice && (battleData.completeState ?? 0) >= 2) {
      const stType = excel.StageTable.stages[stageId]?.stageType ?? "";
      await this._trigger.emit("CompleteAnyStage", [
        { ...battleData, stageId },
      ]);
      if (stType === "MAIN") {
        await this._trigger.emit("CompleteMainStage", [
          { ...battleData, stageId },
        ]);
      } else if (stType === "CAMPAIGN" || stType === "ACTIVITY") {
        await this._trigger.emit("CompleteCampaign", [
          { ...battleData, stageId },
        ]);
      }
      await this._trigger.emit("CostAp", [{ ap: apCost }]);
      // 修复：勋章 PassStageSome 事件从未 emit → 通关特定关卡勋章永不推进
      await this._trigger.emit("PassStageSome", [this._player]);
      const favorGained =
        battleInfo.squad?.slots?.filter(
          (s) => s && this._player._playerdata.troop.chars[s.charInstId],
        ).length ?? 0;
      if (favorGained > 0) {
        await this._trigger.emit("GainIntimacy", [{ count: favorGained }]);
      }
      // 修复：战斗击杀事件从未 emit → 击杀类任务永不推进（checkKilledCnt = 击杀总数）
      const killCnt = battleData.battleData?.stats?.checkKilledCnt ?? 0;
      await this._trigger.emit("EnemyKillInAnyStage", [
        { ...battleData, killCnt },
      ]);
      await this._trigger.emit("StageWithEnemyKill", [
        { ...battleData, stageId, killCnt },
      ]);
      await this._trigger.emit("BattleWithEnemyKill", [
        { ...battleData, stageId, killCnt },
      ]);
      // 修复：助战通关 → 助战任务事件 + 社交点来源（使用助战方 +30/日上限1、
      // 助战方 +20——原实现社交点无任何获取来源）
      const assistUid = battleInfo.assistFriend?.uid;
      if (assistUid) {
        await this._trigger.emit("StageWithAssistChar", [
          { ...battleData, assistFriend: battleInfo.assistFriend },
        ]);
        const usePt = excel.GameDataConst.useAssistSocialPt ?? 30;
        const maxUse = excel.GameDataConst.useAssistSocialPtMaxCount ?? 1;
        const todayKey = Math.floor(now() / 86400);
        // 使用方社交点：每日上限 maxUse 次（status.assistUsedDay 为私服字段，类型未声明用 any）
        const st = this._player._playerdata.status as any;
        const usedToday =
          st.assistUsedDay === todayKey ||
          st.assistUsedCount >= maxUse;
        if (!usedToday) {
          await this._player.update(async (draft) => {
            draft.status.socialPoint = (draft.status.socialPoint ?? 0) + usePt;
            const ds = draft.status as any;
            ds.assistUsedDay = todayKey;
            ds.assistUsedCount = (ds.assistUsedCount ?? 0) + 1;
          });
          await this._trigger.emit("ReceiveSocialPoint", [
            { socialPoint: usePt },
          ]);
        }
        // 助战方社交点（assistBeUsedSocialPt 档位表，取 1 档）
        const beUsedPt =
          excel.GameDataConst.assistBeUsedSocialPt?.["1"] ?? 20;
        if (assistUid !== this._player.uid) {
          try {
            const owner = await accountManager.getPlayerData(assistUid);
            await owner.update(async (draft) => {
              draft.status.socialPoint =
                (draft.status.socialPoint ?? 0) + beUsedPt;
            });
          } catch (e) {
            logger.warn(
              "battle",
              `助战方 ${assistUid} 社交点发放失败: ${(e as Error).message}`,
            );
          }
        }
      }
    }
    if (isPractice) {
      return {};
    }
    return {
      apFailReturn,
      expScale,
      goldScale,
      rewards,
      firstRewards,
      unlockStages,
      unusualRewards,
      additionalRewards,
      furnitureRewards,
      alert: [],
      suggestFriend,
      pryResult: [],
    };
  }

  async dropReward(
    displayDetailRewards: DisplayDetailRewards[],
    completeState: number,
    stageId: string,
    depth = 0,
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
          // 修复：rarity 为字符串 "TIER_N"（或 FURN 数字）——原 switch 用数字匹配
          // 恒进 default（addPercent=0），低稀有度 +count 加成永不生效；
          // 统一经 rarityToIndex 转 0~5
          const rawRarity =
            reward_type === "FURN"
              ? excel.BuildingData.customData.furnitures[reward_id]?.rarity
              : excel.ItemTable.items[reward_id]?.rarity;
          reward_rarity = rarityToIndex(rawRarity);

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
          reward_rarity = rarityToIndex(
            excel.ItemTable.items[reward_id]?.rarity,
          );
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
            // 修复：原 percent=floor(小数) 恒 0 → randomChoices 权重 [0,1] 恒选 +1；
            // 改为按小数部分概率 +1（数学期望 = 配置值 j）
            const jInt = Math.floor(j);
            const drop_array = Math.random() < j - jInt ? 1 : 0;
            let count = jInt + drop_array;

            if (completeState === 3) {
              if (reward_rarity === i) {
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
            // 修复：同 divmod 概率恒 +1 / 权重反向问题；按小数部分概率 +1
            const jInt = Math.floor(j);
            const drop_array = Math.random() < j - jInt ? 1 : 0;
            const count = jInt + drop_array;
            if (completeState === 3 && reward_rarity === i) {
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
          else if (dropType === 2) {
            // ALWAYS + NORMAL：必掉基础掉落（对照 Python quest.py 对应分支末尾产出）
            logger.debug(
              "BattleManager",
              `- occPercent:0,dropType:2 - ${JSON.stringify(item)}`,
            );
            pushReward();
          }
          else if (dropType === 8)
            displayDetailRewards = displayDetailRewards.filter(
              (i) => i !== item,
            );
          else pushReward();
        } else if (occPercent === 1) {
          if (dropType === 2) {
            logger.debug(
              "BattleManager",
              `- occPercent:1,dropType:2 - ${JSON.stringify(item)}`,
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
            logger.debug(
              "BattleManager",
              `- occPercent:2,dropType:2 - ${JSON.stringify(item)}`,
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
            logger.debug(
              "BattleManager",
              `- occPercent:3,dropType:2 - ${JSON.stringify(item)}`,
            );
            const drop_array = randomChoices(
              [0, 1],
              [85 - addPercent, 15 + addPercent],
              1,
            )[0];
            if (drop_array) pushReward();
          } else if (dropType === 4) {
            logger.debug(
              "BattleManager",
              `- occPercent:3,dropType:4 - ${JSON.stringify(item)}`,
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
            logger.debug(
              "BattleManager",
              `- occPercent:4,dropType:2 - ${JSON.stringify(item)}`,
            );
            const drop_array = randomChoices(
              [0, 1],
              [97 - addPercent, 3 + addPercent],
              1,
            )[0];
            if (drop_array) pushReward();
          } else if (dropType === 3) {
            logger.debug(
              "BattleManager",
              `- occPercent:4,dropType:3 - ${JSON.stringify(item)}`,
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
            logger.debug(
              "BattleManager",
              `- occPercent:4,dropType:4 - ${JSON.stringify(item)}`,
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
          logger.warn("BattleManager", `Unknown dropType: ${JSON.stringify(item)}`);
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
      // 防死循环：概率未中的条目永不移除，重试不会收敛；最多重试 10 轮后返回当前（可能为空）结果
      if (depth < 10) {
        return this.dropReward(displayDetailRewards, completeState, stageId, depth + 1);
      }
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
