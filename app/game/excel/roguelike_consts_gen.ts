/**
 * RoguelikeConsts 转换器（从官方 excel 派生，替代 data/rlv2.json）
 *
 * 原 data/rlv2.json（excel.RoguelikeConsts）是游离在官方热更管线之外的手工维护文件。
 * 本模块改为在启动时直接由官方 excel 表派生，因此：
 * - outbuff：遍历官方 `customizeData[theme].developments`（rogue_1..3）
 *   / `customizeData[theme].commonDevelopment.developments`（rogue_4..6），
 *   由每条开发的 `buffDisplayInfo`（displayType/displayForm/displayNum）确定性映射
 *   为 RoguelikeBuff；`buffDisplayInfo` 为空（或 legacy 存在怪癖）的分队开发项，
 *   按 RAWRULES 表逐条显式给出（内容为旧 rlv2.json 维护值，完整保留行为）。
 * - modebuff：官方 excel 无此表（难度敌人全局调整，源自 odpy 脚本），内嵌为常量。
 * - recruitGrps：官方 `details[theme].recruitGrps` 全量，直接引用。
 *
 * 产物经 scripts/verify-rlv2-migration.ts 与旧 data/rlv2.json 逐项断言一致，
 * 保证本次迁移行为零变更。
 */

import type { RoguelikeBuff } from "@excel/excel";
import type { RoguelikeConst } from "@excel/excel";

/** buildRoguelikeConsts 所需的官方表最小结构（customizeData 六主题 + details[].recruitGrps） */
export interface RoguelikeTopicTableInput {
  customizeData: Record<string, any>;
  details?: Record<string, { recruitGrps?: Record<string, any> }>;
}

/** 单条 buffDisplayInfo（displayType/displayForm/displayNum） */
interface DisplayInfo {
  displayType: string;
  displayForm: string | number;
  displayNum: number;
}

/**
 * 构造一个 blackboard 条目，形如旧 rlv2.json：仅包含实际存在的字段。
 * 缺失的数值/字符串字段被省略（与旧数据逐字节一致，运行时不读取缺省 key）。
 */
function bb(key: string, value?: number, valueStr?: string | null): Record<string, unknown> {
  const e: Record<string, unknown> = { key };
  if (value !== undefined) e.value = value;
  if (valueStr !== undefined) e.valueStr = valueStr;
  return e;
}

/** 构造单个 RoguelikeBuff */
function buff(key: string, blackboard: Record<string, unknown>[]): RoguelikeBuff {
  return { key, blackboard: blackboard as any };
}

/** immediate_reward：发放一类初始资源/物品 */
function immReward(id: string, count: number): RoguelikeBuff {
  return buff("immediate_reward", [bb("id", undefined, id), bb("count", count)]);
}

/** 我方单位属性百分比加成（display_bat_attack/def/max_hp + PERCENTAGE） */
function charAttrMul(attr: string, percent: number): RoguelikeBuff {
  return buff("char_attribute_mul", [bb(attr, percent / 100)]);
}

/** 战斗获取指挥经验加成（display_exp + PERCENTAGE） */
function upReward(theme: string, percent: number): RoguelikeBuff {
  return buff("up_reward", [
    bb("id", undefined, `${theme}_exp`),
    bb("up", percent / 100),
    bb("mask", undefined, "battle"),
  ]);
}

/** 外援节点奖励/货币获取效率增加（display_grow_point + PERCENTAGE） */
function bpRewardIncrease(n: number): RoguelikeBuff {
  return buff("bp_reward_increase", [bb("value", n)]);
}

/** 可同时部署人数 +value（display_bat_char_limit） */
function levelCharLimitAdd(n: number): RoguelikeBuff {
  return buff("level_char_limit_add", [bb("value", n)]);
}

/**
 * 由单个 buffDisplayInfo 生成 RoguelikeBuff（每个 displayType 是确定性语义）。
 *
 * @returns 生成的 buff；纯展示型 displayType（display_hp/display_temp_hp 等）返回 null，
 *   在组合中被跳过，不产生服务端 buff。
 */
function fromDisplayInfo(theme: string, info: DisplayInfo): RoguelikeBuff | null {
  const n = info.displayNum;
  const isPercent = info.displayForm === "PERCENTAGE";
  switch (info.displayType) {
    case "display_bat_attack":
      return isPercent ? charAttrMul("atk", n) : null;
    case "display_bat_def":
      return isPercent ? charAttrMul("def", n) : null;
    case "display_bat_max_hp":
      return isPercent ? charAttrMul("max_hp", n) : null;
    case "display_gold":
      return immReward(`${theme}_gold`, n);
    case "display_squad_capacity":
      return immReward(`${theme}_squad_capacity`, n);
    case "display_pro":
      return immReward(`${theme}_shield`, n);
    case "display_bat_conceive":
      return immReward(`${theme}_fragment_I_1`, n);
    case "display_bur":
      return immReward(`${theme}_max_weight`, n);
    case "display_exp":
      return isPercent ? upReward(theme, n) : null;
    case "display_bat_char_limit":
      return levelCharLimitAdd(n);
    case "display_grow_point":
      return isPercent ? bpRewardIncrease(n) : null;
    // 纯展示项：仅简介展示，不产生服务端 buff
    case "display_hp":
    case "display_temp_hp":
    case "display_dice_point":
    case "display_key_point":
    case "display_divinationkit":
      return null;
    default:
      // 未登记 displayType：保守忽略（黄金断言会覆盖全部已知类型，确保无遗漏）
      return null;
  }
}

/**
 * 逐条显式规则：旧 rlv2.json 中 buffDisplayInfo 为空、或 legacy 存在字段怪癖的开发项。
 *
 * 这些开发项无法由 buffDisplayInfo 推导（官方表对该处开发仅给描述文本，无结构化 buff），
 * 内容为旧数据维护值，按 buffId 精确保留以保证行为不变（文本见 rawDesc 注释）。
 * 未列入者（buffDisplayInfo 为空且旧数据为空）按空 buff 处理。
 */
const RAWRULES: { [themeBuffId: string]: RoguelikeBuff[] } = {
  // 探险中会出现“思维边界”节点
  "rogue_4.rogue_4_outbuff_7": [buff("unlock_node", [bb("node", undefined, "PORTAL")])],
  // 探险中会出现“先行一步”节点
  "rogue_4.rogue_4_outbuff_8": [buff("unlock_node", [bb("node", undefined, "EXPEDITION")])],
  // 探险中会出现“失与得”节点
  "rogue_4.rogue_4_outbuff_9": [buff("unlock_node", [bb("node", undefined, "SACRIFICE")])],
  // 指挥分队：目标生命上限+5（文本）/ 魂灵书签获取效率+2% / 初始源石锭+2
  "rogue_4.rogue_4_difficulty_1": [
    immReward("rogue_4_gold", 2),
    bpRewardIncrease(2),
  ],
  // 先行一步节点派遣的队员可以带回1个构想
  "rogue_4.rogue_4_outbuff_23": [
    buff("expedition_extra_random_reward", [
      bb("id", undefined, "rogue_4_fragment_I_1"),
      bb("min", 1),
      bb("max", 1),
    ]),
  ],
  // 后勤分队：初始源石锭+30（文本，旧数据不作为发放）/ 魂灵书签获取效率+2% / 额外出售两个商品
  "rogue_4.rogue_4_difficulty_2": [
    bpRewardIncrease(2),
    buff("inc_outerbuff_shop_slot_unlock", [bb("count", 2)]),
  ],
  // 矛头分队：攻击力+20%（文本）/ 魂灵书签获取效率+2% / 4、5、6星临界值+1
  "rogue_4.rogue_4_difficulty_3": [
    bpRewardIncrease(2),
    buff("char_weight_rarity", [bb("rarity", 3), bb("value", 1)]),
    buff("char_weight_rarity", [bb("rarity", 4), bb("value", 1)]),
    buff("char_weight_rarity", [bb("rarity", 5), bb("value", 1)]),
  ],
  // 完美作战时，额外掉落一缕思绪
  "rogue_4.rogue_4_outbuff_50": [
    buff("battle_extra_drop", [
      bb("id", undefined, "pool_fragment_1"),
      bb("count", 1),
      bb("perfect", 1),
    ]),
  ],
  // 4星、5星负荷干员提升的临界值+1
  "rogue_4.rogue_4_outbuff_52": [
    buff("char_weight_rarity", [bb("rarity", 3), bb("value", 1)]),
    buff("char_weight_rarity", [bb("rarity", 4), bb("value", 1)]),
  ],
  // legacy 怪癖：该 char_attribute_mul 的 max_hp 条目多带了 valueStr:null（其余主题同型无此字段）
  "rogue_4.rogue_4_outbuff_1": [
    buff("char_attribute_mul", [{ key: "max_hp", value: 0.01, valueStr: null } as any]),
  ],
};

/** modebuff 常量（官方 excel 无此表，源自 odpy 难度敌人全局调整，保持旧值不变） */
const MODEBUFF: { [theme: string]: { [grade: string]: RoguelikeBuff[] } } = {
  rogue_1: {},
  rogue_2: {
    "0": [],
    "1": [buff("global_buff_normal", [bb("key", undefined, "rogue_2_ep_damage_scale"), bb("ep_damage_scale", 1.15)])],
    "2": [],
    "3": [buff("enemy_attribute_add", [bb("magic_resistance", 10)])],
    "4": [],
    "5": [
      buff("global_buff_normal", [bb("key", undefined, "enemy_atk_down"), bb("atk", 1.15), bb("selector.enemy_level_type", undefined, "BOSS")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_def_down"), bb("def", 1.15), bb("selector.enemy_level_type", undefined, "BOSS")]),
    ],
    "6": [],
    "7": [buff("global_buff_normal", [bb("key", undefined, "enemy_move_speed_down"), bb("move_speed", 1.15)])],
    "8": [buff("global_buff_normal", [bb("key", undefined, "rogue_2_ep_damage_scale"), bb("ep_damage_scale", 1.3)])],
    "9": [buff("global_buff_normal", [bb("key", undefined, "enemy_attack_speed_down"), bb("attack_speed", 15)])],
    "10": [],
    "11": [buff("global_buff_normal", [bb("key", undefined, "enemy_max_hp_down"), bb("max_hp", 1.2), bb("selector.enemy_level_type", undefined, "ELITE|BOSS")])],
    "12": [buff("enemy_attribute_add", [bb("magic_resistance", 20)])],
    "13": [buff("global_buff_normal", [bb("key", undefined, "rogue_2_ep_damage_scale"), bb("ep_damage_scale", 1.45)])],
    "14": [buff("level_char_limit_add", [bb("value", -1)])],
    "15": [
      buff("global_buff_normal", [bb("key", undefined, "enemy_atk_down"), bb("atk", 1.2), bb("selector.enemy_level_type", undefined, "ELITE|BOSS")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_def_down"), bb("def", 1.2), bb("selector.enemy_level_type", undefined, "ELITE|BOSS")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_max_hp_down"), bb("max_hp", 1.2), bb("selector.enemy_level_type", undefined, "ELITE|BOSS")]),
    ],
  },
  rogue_3: {
    "0": [],
    "1": [],
    "2": [],
    "3": [],
    "4": [buff("global_buff_normal", [bb("key", undefined, "enemy_atk_down"), bb("atk", 1.1), bb("selector.enemy_level_type", undefined, "ELITE")])],
    "5": [
      buff("global_buff_normal", [bb("key", undefined, "enemy_atk_down"), bb("atk", 1.05), bb("selector.enemy_level_type", undefined, "NORMAL")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_max_hp_down"), bb("max_hp", 1.05), bb("selector.enemy_level_type", undefined, "NORMAL")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_atk_down"), bb("atk", 1.15), bb("selector.enemy_level_type", undefined, "ELITE")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_max_hp_down"), bb("max_hp", 1.05), bb("selector.enemy_level_type", undefined, "ELITE")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_atk_down"), bb("atk", 1.05), bb("selector.enemy_level_type", undefined, "BOSS")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_max_hp_down"), bb("max_hp", 1.05), bb("selector.enemy_level_type", undefined, "BOSS")]),
    ],
    "6": [],
    "7": [
      buff("global_buff_normal", [bb("key", undefined, "enemy_def_down"), bb("def", 1.1), bb("selector.enemy_level_type", undefined, "NORMAL")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_def_down"), bb("def", 1.1), bb("selector.enemy_level_type", undefined, "ELITE")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_def_down"), bb("def", 1.1), bb("selector.enemy_level_type", undefined, "BOSS")]),
    ],
    "8": [
      buff("global_buff_normal", [bb("key", undefined, "enemy_damage_resistance[inf]"), bb("damage_resistance", 0.05), bb("selector.enemy_level_type", undefined, "NORMAL")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_damage_resistance[inf]"), bb("damage_resistance", 0.05), bb("selector.enemy_level_type", undefined, "ELITE")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_damage_resistance[inf]"), bb("damage_resistance", 0.05), bb("selector.enemy_level_type", undefined, "BOSS")]),
    ],
    "9": [buff("level_char_limit_add", [bb("value", -1)])],
    "10": [
      buff("global_buff_normal", [bb("key", undefined, "enemy_atk_down"), bb("atk", 1.15), bb("selector.enemy_level_type", undefined, "NORMAL")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_max_hp_down"), bb("max_hp", 1.05), bb("selector.enemy_level_type", undefined, "NORMAL")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_atk_down"), bb("atk", 1.25), bb("selector.enemy_level_type", undefined, "ELITE")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_max_hp_down"), bb("max_hp", 1.05), bb("selector.enemy_level_type", undefined, "ELITE")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_atk_down"), bb("atk", 1.15), bb("selector.enemy_level_type", undefined, "BOSS")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_max_hp_down"), bb("max_hp", 1.05), bb("selector.enemy_level_type", undefined, "BOSS")]),
    ],
    "11": [
      buff("global_buff_normal", [bb("key", undefined, "enemy_damage_resistance[inf]"), bb("damage_resistance", 0.05), bb("selector.enemy_level_type", undefined, "NORMAL")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_damage_resistance[inf]"), bb("damage_resistance", 0.05), bb("selector.enemy_level_type", undefined, "ELITE")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_damage_resistance[inf]"), bb("damage_resistance", 0.1), bb("selector.enemy_level_type", undefined, "BOSS")]),
    ],
    "12": [],
    "13": [
      buff("global_buff_normal", [bb("key", undefined, "enemy_damage_resistance[inf]"), bb("damage_resistance", 0.05), bb("selector.enemy_level_type", undefined, "NORMAL")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_damage_resistance[inf]"), bb("damage_resistance", 0.1), bb("selector.enemy_level_type", undefined, "ELITE")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_damage_resistance[inf]"), bb("damage_resistance", 0.15), bb("selector.enemy_level_type", undefined, "BOSS")]),
    ],
    "14": [
      buff("global_buff_normal", [bb("key", undefined, "enemy_atk_down"), bb("atk", 1.15), bb("selector.enemy_level_type", undefined, "NORMAL")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_def_down"), bb("def", 1.15), bb("selector.enemy_level_type", undefined, "NORMAL")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_max_hp_down"), bb("max_hp", 1.1), bb("selector.enemy_level_type", undefined, "NORMAL")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_atk_down"), bb("atk", 1.25), bb("selector.enemy_level_type", undefined, "ELITE")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_def_down"), bb("def", 1.15), bb("selector.enemy_level_type", undefined, "ELITE")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_max_hp_down"), bb("max_hp", 1.1), bb("selector.enemy_level_type", undefined, "ELITE")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_atk_down"), bb("atk", 1.15), bb("selector.enemy_level_type", undefined, "BOSS")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_def_down"), bb("def", 1.15), bb("selector.enemy_level_type", undefined, "BOSS")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_max_hp_down"), bb("max_hp", 1.1), bb("selector.enemy_level_type", undefined, "BOSS")]),
    ],
    "15": [
      buff("global_buff_normal", [bb("key", undefined, "enemy_atk_down"), bb("atk", 1.25), bb("selector.enemy_level_type", undefined, "NORMAL")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_def_down"), bb("def", 1.25), bb("selector.enemy_level_type", undefined, "NORMAL")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_max_hp_down"), bb("max_hp", 1.2), bb("selector.enemy_level_type", undefined, "NORMAL")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_atk_down"), bb("atk", 1.35), bb("selector.enemy_level_type", undefined, "ELITE")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_def_down"), bb("def", 1.25), bb("selector.enemy_level_type", undefined, "ELITE")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_max_hp_down"), bb("max_hp", 1.2), bb("selector.enemy_level_type", undefined, "ELITE")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_atk_down"), bb("atk", 1.25), bb("selector.enemy_level_type", undefined, "BOSS")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_def_down"), bb("def", 1.25), bb("selector.enemy_level_type", undefined, "BOSS")]),
      buff("global_buff_normal", [bb("key", undefined, "enemy_max_hp_down"), bb("max_hp", 1.2), bb("selector.enemy_level_type", undefined, "BOSS")]),
    ],
  },
  rogue_4: { "1": [] },
  rogue_5: {},
  rogue_6: {},
};

/** 提取某主题 customizeData 的 developments（rogue_1..3 顶层，rogue_4..6 在 commonDevelopment） */
function themeDevelopments(theme: string, customizeData: any): { [key: string]: any } {
  const cd = customizeData?.[theme];
  if (!cd) return {};
  if (theme === "rogue_4" || theme === "rogue_5" || theme === "rogue_6") {
    return cd.commonDevelopment?.developments ?? {};
  }
  return cd.developments ?? {};
}

/**
 * 由官方 excel 派生整个 RoguelikeConsts（6 主题）。
 *
 * @param topicTable - 已加载的官方 RoguelikeTopicTable
 * @returns 与旧 data/rlv2.json 结构一致、逐字节等价的 RoguelikeConsts
 */
export function buildRoguelikeConsts(topicTable: RoguelikeTopicTableInput): { [theme: string]: RoguelikeConst } {
  const result: { [theme: string]: RoguelikeConst } = {};
  const themes = Object.keys(topicTable.customizeData ?? {});
  for (const theme of themes) {
    const devs = themeDevelopments(theme, topicTable.customizeData);
    const outbuff: { [key: string]: RoguelikeBuff[] } = {};
    for (const buffId of Object.keys(devs)) {
      const dev = devs[buffId];
      const overrideKey = `${theme}.${buffId}`;
      let bufs: RoguelikeBuff[] = RAWRULES[overrideKey];
      if (!bufs) {
        const infos = dev.buffDisplayInfo as DisplayInfo[] | undefined;
        bufs =
          infos && infos.length > 0
            ? infos
                .map((info) => fromDisplayInfo(theme, info))
                .filter((b): b is RoguelikeBuff => b !== null)
            : [];
      }
      outbuff[buffId] = bufs;
    }
    const recruitGrps: { [key: string]: any } = topicTable.details?.[theme]?.recruitGrps ?? {};
    result[theme] = {
      outbuff,
      modebuff: MODEBUFF[theme] ?? {},
      recruitGrps,
    };
  }
  return result;
}