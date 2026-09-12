/**
 * 集成战略（Roguelike）主题表归一化
 *
 * 官方 `roguelike_topic_table` 经热更管线转换后有两处与服务端消费契约不一致，
 * 均属「不报错的静默失效」——查询 miss 或枚举比对失败后按空处理：
 *
 * 1. **主题键**：`details` / `modules` / `topics` 用 `rogue_1..rogue_6`，而 `customizeData`
 *    用客户端内部键 `rl01..rl06`。消费点全按 `rogue_N` 取数（科技树 unlockBuff、
 *    RoguelikeConsts 派生、分队升级可见性），键不一致即全部 miss。
 * 2. **展示枚举**：`buffDisplayInfo[].displayForm` 在数据里是数值 0/1未转字符串，
 *    而 CS 枚举 `RoguelikeTopicDevTokenDisplayForm`（StringEnumConverter）为
 *    `ABSOLUTE_VAL = 0 / PERCENTAGE = 1`；派生逻辑按 `=== "PERCENTAGE"` 判定，
 *    数值形态一律判为「非百分比」→ 属性类节点（atk/def/max_hp/exp/grow_point）的
 *    科技树 buff 被整体丢弃。
 *
 * 配对依据（2026-09-11 实测校验）：
 * - rl01..rl06 与 rogue_1..rogue_6 同序号一一对应——`customizeData.rl01.difficulties[].modeDifficulty`
 *   为数值 1..6，与 `details.rogue_1.difficulties[].modeDifficulty` 的 EASY..CHALLENGE 同序同义；
 *   `topics.rogue_1.medalGroupId = medalGroupRogue01` 亦同序号。
 * - displayForm：数据取值仅 {0, 1}，与上述 CS 枚举一一对应。
 *
 * 两个函数均幂等（已归一化则不改），`details` 缺该主题（异常数据）时跳过。
 */
import type { RoguelikeTopicTable } from "./types_excel_gen";

/** buffDisplayInfo 展示项（官方线格式；displayForm 可能为未转枚举的数值） */
interface DisplayInfoEntry {
  /** 展示类型（如 display_bat_attack，已转字符串） */
  displayType?: string;
  /** 展示数值 */
  displayNum?: number;
  /** 展示形式（ABSOLUTE_VAL / PERCENTAGE，或未转的 0/1） */
  displayForm?: string | number;
}

/** 科技树节点（仅声明归一化需要触碰的字段） */
interface DevelopmentNode {
  buffDisplayInfo?: DisplayInfoEntry[];
}

/** customizeData 单主题条目 */
interface CustomizeEntry {
  developments?: Record<string, DevelopmentNode>;
  commonDevelopment?: { developments?: Record<string, DevelopmentNode> };
  developmentTokens?: Record<string, DisplayInfoEntry>;
}

/** 数值 → CS 枚举名（RoguelikeTopicDevTokenDisplayForm） */
const DISPLAY_FORM_BY_VALUE: Record<number, string> = {
  0: "ABSOLUTE_VAL",
  1: "PERCENTAGE",
};

/**
 * 归一化主题键（customizeData 的 rlNN → rogue_N）
 *
 * @param table - RoguelikeTopicTable 结构（需 customizeData + details）
 */
export function normalizeRoguelikeTopicKeys(
  table: Pick<RoguelikeTopicTable, "customizeData" | "details">,
): void {
  const customize = table?.customizeData;
  const details = table?.details;
  if (!customize || !details) return;
  for (const key of Object.keys(customize)) {
    const matched = /^rl0*(\d+)$/.exec(key);
    if (!matched) continue;
    const theme = `rogue_${parseInt(matched[1], 10)}`;
    if (!details[theme]) continue;
    if (customize[theme] === undefined) customize[theme] = customize[key];
    delete customize[key];
  }
}

/**
 * 归一化科技树展示项的 displayForm（数值 0/1 → ABSOLUTE_VAL / PERCENTAGE）
 *
 * 覆盖 `developments`（rogue_1..3）、`commonDevelopment.developments`（rogue_4..6）
 * 与 `developmentTokens`。
 * @param table - RoguelikeTopicTable 结构（需 customizeData）
 */
export function normalizeRoguelikeDisplayForm(
  table: Pick<RoguelikeTopicTable, "customizeData">,
): void {
  const customize = table?.customizeData as
    | Record<string, CustomizeEntry>
    | undefined;
  if (!customize) return;
  const fix = (entry: DisplayInfoEntry | undefined): void => {
    if (!entry || typeof entry.displayForm !== "number") return;
    entry.displayForm = DISPLAY_FORM_BY_VALUE[entry.displayForm] ?? entry.displayForm;
  };
  for (const themeEntry of Object.values(customize)) {
    if (!themeEntry) continue;
    const developmentMaps = [
      themeEntry.developments,
      themeEntry.commonDevelopment?.developments,
    ];
    for (const developments of developmentMaps) {
      if (!developments) continue;
      for (const node of Object.values(developments)) {
        for (const info of node?.buffDisplayInfo ?? []) fix(info);
      }
    }
    for (const token of Object.values(themeEntry.developmentTokens ?? {})) fix(token);
  }
}

/**
 * RoguelikeTopicTable 全量归一化（主题键 + 展示枚举），在 excel 加载与 RoguelikeConsts
 * 派生前各调用一次（幂等，可重复调用）。
 * @param table - RoguelikeTopicTable 结构
 */
export function normalizeRoguelikeTopicTable(
  table: Pick<RoguelikeTopicTable, "customizeData" | "details">,
): void {
  normalizeRoguelikeTopicKeys(table);
  normalizeRoguelikeDisplayForm(table);
}
