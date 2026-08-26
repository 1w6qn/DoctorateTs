/**
 * ArkHub（像素美术馆/生物收集）活动任务模板
 */
import type { MissionTemplateGroup } from "./types";
import { userTimestamp } from "@utils/time";

export const arkhubTemplates: MissionTemplateGroup = {

  /** 引导任务：完成引导对话（param[2]=引导 flag，目标=1） */
  ArkhubMissionCompleted: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: { activityId: string; flag: string }) => {
        if (args.activityId !== mission.param[1]) return;
        if (args.flag !== mission.param[2]) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /** 每日物资：累计领取天数（param[2..3]=活动日期区间，param[4]=目标天数） */
  ArkhubDailyMissionCompleted: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[4]),
        });
      },
      update: (mission, args: { activityId: string; days: number }) => {
        if (args.activityId !== mission.param[1]) return;
        // 窗口门控（8/18 更新后任务：param[2] 起点 2026-08-18 16:00:00 前不推进）。
        // getTime() 为毫秒，需除以 1000 与 userTimestamp()（秒）对齐
        const start = Math.floor(
          new Date((mission.param[2] ?? "").replace(/\//g, "-")).getTime() / 1000,
        );
        const end = Math.floor(
          new Date((mission.param[3] ?? "").replace(/\//g, "-")).getTime() / 1000,
        );
        const ts = userTimestamp();
        if (Number.isNaN(start) || Number.isNaN(end) || !(ts >= start && ts <= end)) {
          return;
        }
        // 累计天数直接取当前值（服务端 ARK_HUB.dailySupplyDays 恒不小于历史值）
        mission.progress[0].value = Math.max(
          mission.progress[0].value,
          Math.min(args.days, mission.progress[0].target!),
        );
      },
    },
  },

  /** 收录生物种类：param[2]=目标 N，param[3]=collectionKey（arkhubMissionCollection1=全部 / 2=活动频繁） */
  ArkhubCreatureCollection: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (
        mission,
        args: { activityId: string; count: number; collectionKey: string },
      ) => {
        if (args.activityId !== mission.param[1]) return;
        if (args.collectionKey !== mission.param[3]) return;
        mission.progress[0].value = Math.max(
          mission.progress[0].value,
          Math.min(args.count, mission.progress[0].target!),
        );
      },
    },
  },

  /** 信息素诱引生物扫描（param[2]=目标次数，事件每次触发 +1） */
  ArkhubCreatureCaptured: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: { activityId: string }) => {
        if (args.activityId !== mission.param[1]) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /** 发起生物数据交换（param[2]=目标次数，事件每次触发 +1） */
  ArkhubCreatureExchange: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: { activityId: string }) => {
        if (args.activityId !== mission.param[1]) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /** 奇象拟合对战完成次数（param[2]=目标 N；count=ARK_HUB.duelCount 累计值） */
  ArkhubPassDexBattle: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: { activityId: string; count: number }) => {
        if (args.activityId !== mission.param[1]) return;
        mission.progress[0].value = Math.max(
          mission.progress[0].value,
          Math.min(args.count, mission.progress[0].target!),
        );
      },
    },
  },

  /** 发布画像数（param[2]=目标 N） */
  ArkhubPublishPixelArt: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: { activityId: string; count: number }) => {
        if (args.activityId !== mission.param[1]) return;
        mission.progress[0].value = Math.max(
          mission.progress[0].value,
          Math.min(args.count, mission.progress[0].target!),
        );
      },
    },
  },

  /** 收集画像数（param[2]=目标 N） */
  ArkhubCollectPixelArt: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: { activityId: string; count: number }) => {
        if (args.activityId !== mission.param[1]) return;
        mission.progress[0].value = Math.max(
          mission.progress[0].value,
          Math.min(args.count, mission.progress[0].target!),
        );
      },
    },
  },

  // ==================== act53side（arkodc）活动任务模板 ====================
};
