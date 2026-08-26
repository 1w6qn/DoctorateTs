/**
 * 基建类任务模板（制造/订单/宿舍/加工室/线索等）
 */
import type { MissionTemplateGroup } from "./types";
import { ItemBundle } from "@excel/character_table";

export const buildingTemplates: MissionTemplateGroup = {

  /**
   * 制造站生产（按分支细分口径）
   *
   * @param param[0] 分支标识：
   *   0 —— 指定物品（param[2] itemId）累计生产数量
   *   1 —— 任意生产事件按产出 count 累加/计数（如 daily_4821=[1,1]）
   *   2 —— 指定物品集合（param[2] 以 # 分隔）任意命中 +1
   * @param param[1] 目标值
   * @param param[2] 指定物品 id 或 id 集合（分支 0/2 用）
   */
  ManufactureItem: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { item: ItemBundle }) => {
        if (args.item.id == mission.param[2]) {
          mission.progress[0].value += args.item.count;
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
      update: (mission, args: { count: number }) => {
        mission.progress[0].value += args.count;
      },
    },
    "2": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { item: ItemBundle }) => {
        const items = mission.param[2].split("#");
        if (items.includes(args.item.id)) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 贸易站订单交付
   *
   * 每次交付订单 count 累加，达 param[1] 完成。分支 0 / 1 行为一致
   * （如 daily_4822=[1,1]、周常=15/30/50/80 单）。
   * @param param[0] 分支标识（0 或 1，行为相同）
   * @param param[1] 目标交付订单量
   */
  DeliveryOrder: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { count: number }) => {
        mission.progress[0].value += args.count;
      },
    },
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { count: number }) => {
        mission.progress[0].value += args.count;
      },
    },
  },

  /**
   * 恢复干员基础体力
   *
   * 每次恢复体力 count 累加，达 param[1] 完成（如 daily_4826=[0,1]）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标恢复体力值
   */
  RecoverCharBaseAp: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { count: number }) => {
        mission.progress[0].value += args.count;
      },
    },
  },

  /**
   * 访问好友基建
   *
   * 每次访问 +1，达 param[1] 完成（如 weekly_732=[0,5]）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标访问次数
   */
  VisitBuilding: {
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
   * 基建舒适度提升（按分支细分）
   *
   * @param param[0] 分支标识：
   *   0 —— 按累计新增舒适度 comfort 累加（如 sub_85 param=[0,2000]）
   *   1 —— 直接以当前舒适度覆盖式进度（如 sub_113 param=[4000]）
   * @param param[1] 目标舒适度值
   */
  DiyComfort: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { comfort: number }) => {
        mission.progress[0].value += args.comfort || 0;
      },
    },
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { comfort: number }) => {
        mission.progress[0].value += args.comfort || 0;
      },
    },
  },

  /**
   * 基建房间建造（指定房间类型）
   *
   * 每次新增房间按 roomCount 累加，达 param[1] 完成。用于「建造 N 级某类型房间」
   * （如 sub_79 param=[0,1,2,POWER] 建造2级发电站）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标房间数
   * @param param[2] 房间等级（部分任务用）
   * @param param[3] 房间类型（如 POWER/MANUFACTURE/TRADING/WORKSHOP/CONTROL）
   */
  HasRoom: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { roomCount: number }) => {
        mission.progress[0].value += args.roomCount || 0;
      },
    },
  },

  /**
   * 车间合成物品
   *
   * 指定物品（param[2] itemId）合成时按产出数量累计，达 param[1] 完成。
   *   @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标合成数量
   * @param param[2] 指定产物 itemId
   */
  WorkshopSynthesis: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { item: ItemBundle }) => {
        if (args.item.id == mission.param[2]) {
          mission.progress[0].value += args.item.count;
        }
      },
    },
  },

  /**
   * 专精技能（升级专精等级）
   *
   * @param param[0] 分支标识：
   *   0 —— 每次专精事件 +1（如「专精任意技能 N 次」）
   *   1 —— 专精等级达到 param[1] 各计 1（如 sub_135 param=[1,1]、sub_137=[1,3]）
   * @param param[1] 目标值或目标专精等级
   */
  UpgradeSpecialization: {
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
    "1": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: { targetLevel: number }) => {
        if (args.targetLevel >= parseInt(mission.param[1])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },
  /**
   * 信息分享（截图/分享）
   *
   * 每次分享事件 +1，达 param[1] 完成。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标分享次数
   */
  StartInfoShare: {
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
    // 型1：线索分享类（target=param[1]，事件每次 +1）；对齐 DoctoratePy StartInfoShare type1
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
   * 设置基建助战（基建入驻助战位）
   *
   * 每次设置 +1，目标恒为 1。
   */
  SetBuildingAssist: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 车间额外产出
   *
   * 每次车间额外产出事件 +1，达 param[1] 完成。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标次数
   */
  WorkshopExBonus: {
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
   * 发送线索
   *
   * 每次发送线索 +1，达 param[1] 完成（社会/基建线索交流）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标发送次数
   */
  SendClue: {
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
   * 加速订单（基建加速制造/贸易）
   *
   * 每次加速订单 +1，目标恒为 1。
   */
  AccelerateOrder: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },
};
