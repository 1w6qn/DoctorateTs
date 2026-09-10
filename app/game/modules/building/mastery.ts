/**
 * 技能专精（训练室）数据引擎（纯函数，无 IO）
 *
 * 官方机制（prts.wiki 训练室页 + excel character_table，2026-08-25 全量对齐）：
 * - 专精条件：精英 2 + 技能 7 级；单技能最高专精三；专精等级上限 = 训练室等级
 * - 专精配置：character_table[charId].skills[i].levelUpCostCond[M1/M2/M3]——
 *   lvlUpTime（基础训练秒数：专一 28800=8h / 专二 57600=16h / 专三 86400=24h）、
 *   levelUpCost（材料）、unlockCond（解锁前置）
 * - 训练速度：基础 1 + 协助位非涣散 +5% + 教官 train_* 技能（接线侧合成）
 */
import excel from "@excel/excel";

import { phaseRank } from "./buff-parse";

/** 专精档位材料/时长配置 */
export interface SpecCond {
  /** 基础训练时长（秒） */
  lvlUpTime: number;
  /** 训练材料（MATERIAL） */
  costs: { id: string; count: number; type: string }[];
  /** 该档位的精英化前置（levelUpCostCond[].unlockCond.phase，缺省 0 表示无额外要求） */
  phaseNeed: number;
}

/**
 * 读取专精档位配置：levelUpCostCond 下标 0/1/2 对应专一/二/三
 * （与 char.ts _masterCond 同源语义，此处为基建侧纯函数版本）。
 * @param charId - 干员 ID
 * @param skillIndex - 技能槽位索引
 * @param targetSpecLevel - 目标专精等级（1/2/3）
 * @returns 配置；干员/技能/档位缺失返回 null
 */
export function getSpecCond(
  charId: string,
  skillIndex: number,
  targetSpecLevel: number,
): SpecCond | null {
  const skill = (excel.CharacterTable as Record<string, any>)?.[charId]?.skills?.[
    skillIndex
  ];
  const cond = skill?.levelUpCostCond?.[targetSpecLevel - 1];
  if (!cond) return null;
  return {
    lvlUpTime: cond.lvlUpTime ?? 28800,
    costs: cond.levelUpCost ?? [],
    phaseNeed: phaseRank(cond.unlockCond?.phase),
  };
}

/** 协助位基础训练加速（非涣散干员，官方 +5%） */
export const SPEC_ASSIST_BASE_BONUS = 0.05;
