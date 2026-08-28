/**
 * 经济/社交/采购类任务模板（信用/商店/寻访/活动币/龙门币消耗等）
 */
import type { MissionTemplateGroup } from "./types";

export const economyTemplates: MissionTemplateGroup = {

  /**
   * 获得社交点（助战信任点）
   *
   * @param param[0] 分支标识：
   *   0 —— 按累计收到的社交点 socialPoint 累加
   *   1 —— 事件触发一次 +1（如 daily_4815 param=[1,1]，周常=5次）
   * @param param[1] 目标值
   */
  ReceiveSocialPoint: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { socialPoint: number }) => {
        mission.progress[0].value += args.socialPoint;
      },
    },
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 购买商店物品（按分支细分商店来源）
   *
   * @param param[0] 分支标识：
   *   0 —— 购买任何商店（LS/HS/ES=物资/高层/标准商城）物品各计 1
   *   1 —— 购买信用交易所（SOCIAL）物品各计 1
   *   3 —— 购买信用交易所时按消费的社交点 socialPoint 累计
   * @param param[1] 目标值
   */
  BuyShopItem: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { type: string }) => {
        const shops = "LS^HS^ES".split("^");
        if (shops.includes(args.type)) {
          mission.progress[0].value += 1;
        }
      },
    },
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { type: string }) => {
        if (args.type == "SOCIAL") {
          mission.progress[0].value += 1;
        }
      },
    },
    "3": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { type: string; socialPoint: number }) => {
        if (args.type != "SOCIAL") {
          return;
        }
        mission.progress[0].value += args.socialPoint;
      },
    },
  },

  /**
   * 常规抽卡（公开招募）
   *
   * 每次抽取 +1。param[2] 为目标次数（如 daily_4818=[0,-1,3] 抽3次）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 无实际作用（常为 -1）
   * @param param[2] 目标抽取次数
   */
  NormalGacha: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 提升常规抽卡（公开招募）数量
   *
   * 每次抽取 +1，达 param[1] 完成。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标抽取次数
   */
  BoostNormalGacha: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * arkodc 奖励组收集（53sideActivity_1..9）
   *
   * param[1]=arkodc topic 活动 id，param[2]=目标奖励组 id 列表（逗号分隔，
   * 如 reward_tre_a 等宝箱/任务奖励），param[3]=目标收集数量。事件
   * ArkodcRewardGroupAtLeast 在 triggerInteraction 收集奖励后 emit，模板统计
   * topic.rewards 中已命中 param[2] 列表的数量作为进度。
   */
  ArkodcRewardGroupAtLeast: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[3]),
        });
      },
      update: (
        mission,
        args: { activityId: string; rewards: Record<string, number> },
      ) => {
        if (args.activityId !== mission.param[1]) return;
        const targets = mission.param[2].split(",");
        let count = 0;
        for (const t of targets) {
          if (args.rewards?.[t]) count += 1;
        }
        mission.progress[0].value = Math.max(
          mission.progress[0].value,
          count,
        );
      },
    },
  },

  // ==================== 通用活动战斗模板（DoctoratePy MissionTemplate 移植）====================
  // 名称与 ActivityTable.missionData.template 一致；update 从 battle 结算携带的
  // battleData.stats（enemyStats/charStats/skillTrigStats/extraBattleInfo）读取真实统计。
  // param[0]=type 位，语义对齐 DoctoratePy mission.py。

  /**
   * 累计获得活动货币（ActivityCoinGain，type0）
   * param[1]=activityId，param[2]=目标累计数，param[3]=活动币 itemId（如 act17side_token_compass）；
   * 事件由 inventory 获得目标币物品时发射，按 itemId 过滤累计
   */
  ActivityCoinGain: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: { itemId: string; count: number }) => {
        if (args.itemId !== mission.param[3]) return;
        mission.progress[0].value += args.count ?? 1;
      },
    },
  },

  /**
   * 累计消耗龙门币（CostGold，type0）
   * param[1]=目标累计消耗；升级/晋升/远征等耗币处 emit {goldCost}（此处由 char 升级/晋升触发）
   */
  CostGold: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { goldCost: number }) => {
        if (!Number.isFinite(args.goldCost)) return;
        mission.progress[0].value += args.goldCost;
      },
    },
  },

  /**
   * 干员升级与晋升中累计消耗龙门币（CostGoldPlus，type0）
   * param[1]=目标累计消耗；char 升级/晋升处 emit {goldCostPlus}
   */
  CostGoldPlus: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { goldCostPlus: number }) => {
        if (!Number.isFinite(args.goldCostPlus)) return;
        mission.progress[0].value += args.goldCostPlus;
      },
    },
  },
};
