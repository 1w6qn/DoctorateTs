/**
 * 宿舍特殊技能分类引擎（纯函数，无 IO）
 *
 * 官方机制（prts.wiki 宿舍页 + building_data.buffs，2026-08-25 全量对齐）：
 * 宿舍恢复技能按作用域分四类（此前实现把全部宿舍技能当全体恢复叠加 →
 * 自身恢复/单体恢复被错发给全宿舍，恢复速度虚高）：
 * - all：全体恢复（dorm_rec_all* / dorm_powToRecAll / dorm_hireToRecAll 等，同种取最高）
 * - self：仅自身恢复（dorm_rec_oneself*）
 * - single：单体恢复——作用于宿舍内除施放者外心情未满的某干员，近似取
 *   心情最低者（dorm_rec_single*，同种取最高）
 * - shared：均分恢复（小酌怡情 dorm_rec_all&single：总计 0.8/时均分给心情未满成员）
 *
 * 未建模（excel 无对应 buff 或需额外存档字段，记录为已知限制）：
 * - 自律（恢复源隔离）/嗜睡/慵懒：当前数据表无匹配 buff
 * - 患难之交（dorm_exchangeAp 心情互换）：需宿舍进驻顺序追踪，后续立项
 */
import { buffGroupKey, parseDescTags } from "./buff";
import type { BuildingBuffLike } from "./buff-parse";

/** 宿舍技能分类 */
export type DormBuffCategory = "all" | "self" | "single" | "shared";

/**
 * 按 buffId 前缀判定宿舍技能作用域。
 * @param buffId - buff ID（如 dorm_rec_all[010]）
 */
export function classifyDormBuff(buffId: string): DormBuffCategory {
  if (/^dorm_rec_all&single/.test(buffId)) return "shared";
  if (/^dorm_rec_single/.test(buffId)) return "single";
  if (/^dorm_rec_oneself/.test(buffId)) return "self";
  return "all";
}

/** 按作用域拆分后的宿舍技能（效率字段语义：点/小时） */
export interface DormBuffSplit {
  /** 全体恢复（作用于宿舍全员） */
  all: { group: string; value: number }[];
  /** 自身恢复（仅施放者） */
  self: { group: string; value: number }[];
  /** 单体恢复（心情最低目标） */
  single: { group: string; value: number }[];
  /** 均分恢复总量（分给心情未满成员） */
  shared: { group: string; value: number }[];
}

/**
 * 拆分干员的宿舍技能列表为四类，解析每档数值（点/小时）：
 * - 常规宿舍技能取 <@cc.vup> 无 % 数值（buff 语境为心情恢复原值）
 * - dorm_rec_single&oneself 双数值：首个 = 单体目标、次个 = 自身
 * 同技能多档（buffId 去 [] 后缀分组）由调用方取最高。
 */
export function splitDormBuffs(buffs: BuildingBuffLike[]): DormBuffSplit {
  const out: DormBuffSplit = { all: [], self: [], single: [], shared: [] };
  for (const b of buffs ?? []) {
    const id: string = b?.buffId ?? "";
    const group = buffGroupKey(id);
    if (/^dorm_rec_single&oneself/.test(id)) {
      const vals = parseDescTags(b?.description)
        .filter((t) => t.tag === "vup")
        .map((t) => t.value);
      out.single.push({ group, value: vals[0] ?? 0 });
      out.self.push({ group, value: vals[1] ?? 0 });
      continue;
    }
    const cat = classifyDormBuff(id);
    // 数值：efficiency 优先（部分数据直接给值），否则描述 vup 原值（点/小时）
    let value = 0;
    if (typeof b?.efficiency === "number" && b.efficiency > 0) {
      value = b.efficiency / 100;
    } else {
      const vup = parseDescTags(b?.description).find((t) => t.tag === "vup");
      value = vup?.value ?? 0;
    }
    out[cat].push({ group, value });
  }
  return out;
}

/** 列表内同技能分组取最高后求和（官方"同种效果取最高"） */
export function sumByGroupMax(entries: { group: string; value: number }[]): number {
  const best = new Map<string, number>();
  for (const e of entries ?? []) {
    best.set(e.group, Math.max(best.get(e.group) ?? 0, e.value));
  }
  return [...best.values()].reduce((s, v) => s + v, 0);
}
