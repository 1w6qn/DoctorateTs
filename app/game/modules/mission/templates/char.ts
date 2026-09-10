/**
 * 干员与账号养成类任务模板（升级/精英化/潜能/编队等）
 */
import type { MissionTemplateGroup } from "./types";
import excel from "@excel/excel";
import { PlayerCharacter } from "../../../kernel/model";

export const charTemplates: MissionTemplateGroup = {

  /**
   * 干员养成升级（按分支细分养成口径）
   *
   * @param param[0] 分支标识：
   *   0 —— 任意干员养成事件 +1（周常「升级干员 N 次」）
   *   1 —— 干员精二达到 param[2]（evolvePhase）且等级达到 param[3] 各计 1
   *   2 —— 按累计获得的经验 exp 累加
   * @param param[1] 目标值
   * @param param[2] 精二阶段阈值（分支 1 用）
   * @param param[3] 等级阈值（分支 1 用）
   */
  UpgradeChar: {
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
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { char: PlayerCharacter }) => {
        if (args.char.evolvePhase < parseInt(mission.param[2])) {
          return;
        }
        if (args.char.level >= parseInt(mission.param[3])) {
          mission.progress[0].value += 1;
        }
      },
    },
    "2": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { exp: number }) => {
        mission.progress[0].value += args.exp;
      },
    },
  },

  /**
   * 获得干员信赖值
   *
   * 每次获得信赖 count 累加，达 param[1] 完成（如 daily_4819=[0,5]）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标信赖值总量
   */
  GainIntimacy: {
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
   * 升级技能（按分支细分口径）
   *
   * @param param[0] 分支标识：
   *   0 —— 每次技能升级事件 +1
   *   1 —— 按累计升级目标等级 targetLevel 累加
   * @param param[1] 目标值
   */
  UpgradeSkill: {
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
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { targetLevel: number }) => {
        mission.progress[0].value += args.targetLevel;
      },
    },
  },

  /**
   * 编队/阵容配置
   *
   * 每次编队事件 +1，达 param[2] 完成。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 无实际作用
   * @param param[2] 目标编队次数
   */
  SquadFormation: {
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
   * 升级玩家等级
   *
   * 进度直接取当前玩家等级 level（覆盖式）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标玩家等级
   */
  UpgradePlayer: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { level: number }) => {
        mission.progress[0].value = args.level;
      },
    },
  },

  /**
   * 拥有符合筛选条件的干员
   *
   * 每满足条件的干员 +1。分支 0 / 1 行为一致。用于「拥有某精二/等级/稀有度/职业干员」任务
   * （如 sub_10010 param=[0,30,-1,SNIPER]）。
   * @param param[0] 分支标识（0 或 1，行为相同）
   * @param param[1] 目标干员数量
   * @param param[2] 精二阶段下限（evolvePhase）
   * @param param[3] 等级下限
   * @param param[4] 稀有度（-1=不限）
   * @param param[5] 职业（ALL=不限，如 SNIPER/TANK/PIONEER）
   */
  HasChar: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { char: PlayerCharacter }) => {
        const data = excel.charData(args.char.charId)!;
        if (args.char.evolvePhase < parseInt(mission.param[2])) {
          return;
        }
        if (args.char.level < parseInt(mission.param[3])) {
          return;
        }
        if (
          data.rarity.toString() != mission.param[4] &&
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
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { char: PlayerCharacter }) => {
        const data = excel.charData(args.char.charId)!;
        if (args.char.evolvePhase < parseInt(mission.param[2])) {
          return;
        }
        if (args.char.level < parseInt(mission.param[3])) {
          return;
        }
        if (
          data.rarity.toString() != mission.param[4] &&
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
  /**
   * 拥有符合条件（稀有度 + 模组等级）的已解锁模组
   *
   * 精二（evolvePhase>=2）干员，其稀有度命中 param[1]（^ 分隔），每有一个模组等级
   * 命中 param[2]（^ 分隔，模组等级列表）各计 1，达 param[3] 完成。
   * 用于「模组任务」（如 sub_20001 param=[0,4^5^6,1^2^3,1]）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 干员稀有度列表（^ 分隔）
   * @param param[2] 模组等级列表（^ 分隔）
   * @param param[3] 目标模组数量
   */
  HasEquipment: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[3]),
        });
      },
      update: (mission, args: { char: PlayerCharacter }) => {
        const data = excel.charData(args.char.charId)!;
        const rarities = mission.param[1].split("^");
        const levels = mission.param[2].split("^");
        if (args.char.evolvePhase < 2) {
          return;
        }
        if (!rarities.includes(data.rarity.toString())) {
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

  /**
   * 干员精二
   *
   * 干员精二阶段达到 param[2] 各计 1，达 param[1] 完成。
   * 用于「精二 N 名干员」（如 sub_73 param=[1,3,1] 精二3名）。
   * @param param[0] 恒为 "1"（分支标识）
   * @param param[1] 目标精二干员数
   * @param param[2] 目标精二阶段（evolvePhase）
   */
  EvolveChar: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { char: PlayerCharacter }) => {
        if (args.char.evolvePhase >= parseInt(mission.param[2])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 干员信赖（羁绊）达到指定百分比
   *
   * 按干员当前信赖百分比 percent（最大 200%=满信赖）判定，达到 param[2]% 各计 1，
   * 达 param[1] 完成。用于「信任 N 名干员达到 XX%」。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标干员数
   * @param param[2] 目标信赖百分比阈值（0-200）
   */
  CharIntimacy: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { favorPoint: number }) => {
        let percent: number;
        if (args.favorPoint == excel.FavorTable.maxFavor) {
          percent = 200;
        } else {
          percent = (
            excel.FavorTable.favorFrames.find((_f, idx, table) => {
              return (
                args.favorPoint >= table[idx].level &&
                args.favorPoint < table[idx + 1].level
              );
            })!.data as { percent: number }
          ).percent;
        }
        if (percent >= parseInt(mission.param[2])) {
          mission.progress[0].value += 1;        }
      },
    },
  },

  /**
   * 完成剧情/破镜奖励
   *
   * 每次完成奖励事件 +1，目标恒为 1。用于一次性剧情奖励任务。
   */
  CompleteBreakReward: {
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
   * 编辑名片
   *
   * 每次编辑名片 +1，目标恒为 1。
   */
  EditBusinessCard: {
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
   * 设置助战干员列表
   *
   * 每次设置助战 +1，达 param[1] 完成。
   * @param param[0] 恒为 "1"（分支标识）
   * @param param[1] 目标设置次数
   */
  SetAssistCharList: {
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
   * 修改编队/小队名称
   *
   * 每次改名 +1，达 param[1] 完成。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标改名次数
   */
  ChangeSquadName: {
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
   * 提升潜能（潜能等级达阈值）
   *
   * 干员潜能提升后 targetLevel 达到 param[2] 各计 1，达 param[1] 完成。
   * @param param[0] 恒为 "1"（分支标识）
   * @param param[1] 目标干员数
   * @param param[2] 目标潜能等级
   */
  BoostPotential: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { targetLevel: number }) => {
        if (args.targetLevel >= parseInt(mission.param[2])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 势力全员收集（GainTeamChar）
   *
   * 修复（2026-09-09，S2）：数据实参为 [branch, 目标势力数]——guide_43「获得1个势力的
   * 全部成员」= ["0","1"]、guide_48「获得3个势力的全部成员」= ["0","3"]；原实现把目标
   * 硬编码为 1（guide_48 一次即完成）且全仓无 emit 站点。现在每次「新达成一个势力的全员
   * 收集」计 1（事件由 character 模块在获得干员时判定后补发）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标势力数
   */
  GainTeamChar: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1] ?? "1") || 1,
        });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },
};
