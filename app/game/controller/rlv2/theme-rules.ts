/**
 * 集成战略主题规则注册表（rlv2 theme rules）
 *
 * 背景：黑流树海（rogue_6）的节点类型数值、层行动力、场景前缀、首领关卡等常量原先散落在
 * controller/rlv2.ts、modules/grid_zone.ts、modules/scrap.ts 等 7 个文件中，以字面量与
 * `theme === "rogue_6"` 分支形式存在，改一处需同步多处。本文件把「主题相关的数据」集中为
 * 单一事实来源，供各管理器查表；「主题相关的行为」仍留在各自管理器内（避免上帝对象）。
 *
 * 本文件**不 import 任何 rlv2 管理器**，以免与 grid_zone/rlv2 形成循环依赖：
 * grid_zone.ts 从此处 re-export `ROGUE6_NODE`，故既有 `import { ROGUE6_NODE } from "./modules/grid_zone"`
 * 的调用方无需改动。
 */

/** 黑流树海主题 id（无相地图 + 废品 + 天气三模块） */
export const BLACKSTREAM_THEME = "rogue_6";

/**
 * 是否为黑流树海主题。
 * 用于表达「该机制仅黑流树海存在」的语义门（如零件箱、行动力、误入奇境）。
 * @param theme 主题 id（current.game.theme）
 * @returns 是黑流树海返回 true
 */
export function isBlackstream(theme: string | undefined): boolean {
  return theme === BLACKSTREAM_THEME;
}

/**
 * 黑流树海节点类型数值（官方 details.rogue_6.nodeTypeData 的键，21 项实测全覆盖）。
 *
 * 数值即官方 `RoguelikeEventType` 位标志枚举（types_excel_gen.ts）的值——按枚举声明顺序
 * 2^n 展开后与 nodeTypeData 的键逐一吻合，据此可确证每个节点的官方语义：
 *   PORTAL(8192)=误入奇境、STORY(32768)/STORY_HIDDEN(65536)=命运所指、DUEL(262144)=狭路相逢、
 *   SCRAP_SHOP(2097152)=秘境行商、DOOR(4194304)=曲折密道、FINAL(8388608)=险路尽头、
 *   EVACUATE(16777216)=险路小径、EMPLOY(33554432)=应急助力、LIGHT(67108864)=羽瞰点、
 *   BATTLE_SAVAGE(134217728)="居民"据点、EMPTY(268435456)=林间空地、BATTLE_SHOP(4096)=诡意行商。
 * 与标准主题的 TorappuRoguelikeEventType 部分重叠但语义不同（如 4096 在标准主题是 BATTLE_SHOP
 * 通用商店），故单独成表；客户端地图按此数值渲染节点图标与名称。
 */
export const ROGUE6_NODE = {
  /** 作战（BATTLE_NORMAL） */
  BATTLE_NORMAL: 1,
  /** 紧急作战（BATTLE_ELITE） */
  BATTLE_ELITE: 2,
  /** 险路恶敌（BATTLE_BOSS，层首领） */
  BATTLE_BOSS: 4,
  /** 安全的角落（REST） */
  REST: 16,
  /** 不期而遇（INCIDENT） */
  INCIDENT: 32,
  /** 得偿所愿（WISH） */
  WISH: 512,
  /** 失与得（SACRIFICE） */
  SACRIFICE: 1024,
  /** 先行一步（EXPEDITION，三结局远征入口） */
  EXPEDITION: 2048,
  /** 诡意行商（BATTLE_SHOP） */
  SHOP: 4096,
  /** 误入奇境（PORTAL，进入隐藏层 未萌生的摇篮） */
  MIRAGE: 8192,
  /** 命运所指（STORY，二结局 / 调谐仪式入口） */
  PROPHECY: 32768,
  /** 命运所指·隐藏变体（STORY_HIDDEN，nodeTypeData 与 32768 同名同描述） */
  PROPHECY_HIDDEN: 65536,
  /** 狭路相逢（DUEL） */
  FACE_OFF: 262144,
  /** 秘境行商（SCRAP_SHOP） */
  SECRET_SHOP: 2097152,
  /** 曲折密道（DOOR，传送） */
  TUNNEL: 4194304,
  /** 险路尽头（FINAL，黑池；构造模板终点） */
  VISIBLE_END: 8388608,
  /** 险路小径（EVACUATE，提前进入下一区域的捷径） */
  VISIBLE_PATH: 16777216,
  /** 应急助力（EMPLOY，雇佣商店） */
  EMERGENCY_AID: 33554432,
  /** 羽瞰点（LIGHT，视野 2 格） */
  RAIN_VIEW: 67108864,
  /** “居民”据点（BATTLE_SAVAGE） */
  RESIDENT: 134217728,
  /** 林间空地（EMPTY，空节点 / 起点） */
  GLADE: 268435456,
} as const;

/**
 * 黑流树海商店类节点（官方 nodeTypeData subName == "商店"）：
 * 诡意行商 / 秘境行商 / 应急助力。进入这些节点生成 BATTLE_SHOP 事件。
 */
export const ROGUE6_SHOP_NODES: readonly number[] = [
  ROGUE6_NODE.SHOP,
  ROGUE6_NODE.SECRET_SHOP,
  ROGUE6_NODE.EMERGENCY_AID,
];

/**
 * 黑流树海战斗类节点：作战 / 紧急作战 / 险路恶敌 / “居民”据点。
 * “居民”据点归入战斗类的依据：官方枚举名为 `BATTLE_SAVAGE`（134217728），且
 * modules.rogue_6.gridZone.moduleConsts.savageBubble = rogue_6_bubble_01
 * （gridZone 节点内容字段亦名 `savage`）；节点描述"平静的生活被打破，也难怪它们怒火中烧"
 * 与路标档案馆"居民据点"11 件收藏品奖励池一致（战斗奖励）。
 */
export const ROGUE6_BATTLE_NODES: readonly number[] = [
  ROGUE6_NODE.BATTLE_NORMAL,
  ROGUE6_NODE.BATTLE_ELITE,
  ROGUE6_NODE.BATTLE_BOSS,
  ROGUE6_NODE.RESIDENT,
];

/**
 * 黑流树海初始默认点亮的特殊节点（show=true），其余节点初始不点亮：
 * - GLADE（林间空地/起点）
 * - BATTLE_BOSS（险路恶敌）与 VISIBLE_END（险路尽头）——各层终点/首领
 * - TUNNEL（曲折密道）、RAIN_VIEW（羽瞰点）——传送/视野机制锚点
 * 其余节点生成时 show=false；抵达时沿地图边点亮可达路径首次节点（见 grid_zone.moveTo）。
 */
export const ROGUE6_INITIALLY_LIT_NODES: readonly number[] = [
  ROGUE6_NODE.GLADE,
  ROGUE6_NODE.BATTLE_BOSS,
  ROGUE6_NODE.VISIBLE_END,
  ROGUE6_NODE.TUNNEL,
  ROGUE6_NODE.RAIN_VIEW,
];

/**
 * 地图节点 visibility（官方枚举 PlayerNodeForesightType 的数值）：
 * - NORMAL=0：已揭示/可见，显示真实节点
 * - HIDE_INVISIBLE=1：隐藏不可见（未揭示的节点或事件，显名"未知事件"）
 * - HIDE_BATTLE=2：隐藏战斗（战斗节点被遮蔽，显名"未知战斗"）
 * - PRESAGE=3：预言/预兆（特殊揭示）
 * 到达状态不在此表达，由 gridZone 节点 state（GridMapZoneNodeStatus.FINISHED=2）承载。
 */
export const ROGUE6_FORESIGHT = {
  NORMAL: 0,
  HIDE_INVISIBLE: 1,
  HIDE_BATTLE: 2,
  PRESAGE: 3,
} as const;

/**
 * 黑流树海"可反复进入"的节点类型（经过后不变成林间空地）：
 * 商店类（诡意行商/秘境行商/应急助力）、林间空地、险路尽头、险路小径、曲折密道。
 * 其余节点被玩家"经过"后（玩家移走）其地图节点类型改写为林间空地 GLADE，
 * 表示已探索/不可再次进入原事件。见 grid_zone.moveTo 中被经过节点的衰减处理。
 */
export const ROGUE6_REVISITABLE_NODES: readonly number[] = [
  ...ROGUE6_SHOP_NODES,
  ROGUE6_NODE.GLADE,
  ROGUE6_NODE.VISIBLE_END,
  ROGUE6_NODE.VISIBLE_PATH,
  ROGUE6_NODE.TUNNEL,
];

/**
 * 各层（1 起）初始行动力：Ⅰ..Ⅴ = 5/6/7/8/8（官方探索文本）。
 * 索引 0 占位；超出索引（Ⅵ 层 / 隐藏层）由构造模板的 action 字段决定。
 */
export const ROGUE6_ZONE_ACTION: readonly number[] = [0, 5, 6, 7, 8, 8];

/** 【生命游戏】"翅膀"节点：点亮后 Ⅰ 层初始行动力 +1（RAW_TEXT_EFFECT"进入第一层时，行动力+1"） */
export const ROGUE6_WING_OUTBUFF = "rogue_6_outbuff_37";

/**
 * 【生命游戏】"喙"节点：点亮后先行一步派出的干员归来时会带回随机加工品。
 * 与"翅膀"同为科技树标记节点（outbuff effect 数组为空，语义由代码解释）。
 * 该 outbuff id 由用户指定（官方数据的科技树节点名集中无字面"喙"，此为其检索键）。
 */
export const ROGUE6_BEAK_OUTBUFF = "rogue_6_outbuff_33";

/**
 * "无法携带至下一区域"的移动加工品（官方 moveScrapData.scrapDesc 原文含
 * "无法被携带至下一区域"）：进入下一层/新区域时被移除；进入/离开特殊层（portal）
 * 时豁免（官方误入奇境描述"进入和离开特殊层时，不会使无法携带至下一层的加工品损坏"）。
 */
export const ROGUE6_NON_PORTABLE_SCRAPS: readonly string[] = [
  "rogue_6_scrap_M_04",
  "rogue_6_scrap_M_07",
];

/** 二结局·维度重构的首领关卡（窥视箱中 → 混沌源阶理论） */
export const ROGUE6_END2_BOSS_STAGE = "ro6_b_5";

/** 二结局专属收藏品：沙盘α（线人事件获得）/ 沙盘β（Ⅰ-Ⅲ 层行商上架） */
export const ROGUE6_END2_RELICS = {
  sandboxAlpha: "rogue_6_relic_final_1",
  sandboxBeta: "rogue_6_relic_final_2",
} as const;

/** 三结局·纠缠调和的放行收藏品：怦然信标（= gameConst.expedEndingRelic） */
export const ROGUE6_END3_RELIC = "rogue_6_relic_final_3";

/**
 * 黑流树海节点类型 → 官方 enter 场景前缀（`scene_ro6_{prefix}*_enter`）。
 *
 * 依据（官方 details.rogue_6 数据实测：nodeTypeData 的 name/description、choiceScenes 的
 * title/description、choices 的 type，以及 RoguelikeEventType 枚举名）：
 * - REST(安全的角落 "食物和水也很充足，别一直紧绷着神经了") → `rest`
 *   （金色凝滞：坐下休息 +生命上限 / 采样金色泉水 +可携带干员）
 * - INCIDENT(不期而遇 "新朋友、老对头......奇遇") → `normal`（沉寂之屋等 5 幕）
 *   + `bat`（思乡心切等 6 幕，含"遭遇一场特殊的战斗"选项）
 * - WISH(得偿所愿 "许愿的形式千奇百怪") → `wish`（无人商店）+ `relic`
 *   （血衣之下 / 擒与缚，选项均为"获得收藏品"；与路标档案馆得偿所愿池 78 件收藏品一致）
 * - SACRIFICE(失与得) → `sacrifice`（回滚文明，选项 type=SACRIFICE）
 * - EXPEDITION(先行一步) → `scout`（未涉足之树，选项 type=EXPEDITION；三结局入口）
 * - FACE_OFF(狭路相逢 = 枚举 DUEL，"猎物与猎手的对话") → `sala`
 *   （原始娱乐 / 掠夺成性：胜者拦路，选项"应战/争夺"= 遭遇一场特殊的战斗）
 * - EMERGENCY_AID(应急助力 = 枚举 EMPLOY，subName=商店，"人手不嫌多，朋友不嫌少") → `hire`
 *   （临时中介所：兜售可雇佣的动物；对应 customizeData.rogue_6.employShopDialogData）
 * - VISIBLE_END(险路尽头 = 枚举 FINAL) → `final`（场景标题即"险路尽头"，描述为黑池；
 *   选项含 ZONE_END"进入下一区域"、USE_STASHED_TICKET"召集同伴"）
 * - VISIBLE_PATH(险路小径 = 枚举 **EVACUATE**，"嘘，不要把这个秘密告诉别人") → `evacuate`
 *   （三重身：选项 ZONE_END"离开——保留行动力，进入下一区域"，即提前进层的捷径）
 *
 * 未列入的节点类型：
 * - RESIDENT("居民"据点 = 枚举 BATTLE_SAVAGE)：走战斗分支（见 ROGUE6_BATTLE_NODES），
 *   `res` 前缀场景（桑尼的邀请等）在官方数据中无法确证归属于该节点类型，不做映射。
 * - TUNNEL(曲折密道，subName=传送) / RAIN_VIEW(羽瞰点，subName=视野) / GLADE(林间空地)：
 *   官方 subName 明示为地图机制而非事件场景——曲折密道与羽瞰点分别为传送与视野
 *   （视野 +1 格已在 GRID_ZONE 模块实现），林间空地"无事发生便是最动人的温柔"即空节点。
 */
export const ROGUE6_NODE_SCENE_PREFIX: {
  readonly [nodeType: number]: readonly string[];
} = {
  [ROGUE6_NODE.REST]: ["rest"],
  [ROGUE6_NODE.INCIDENT]: ["normal", "bat"],
  [ROGUE6_NODE.WISH]: ["wish", "relic"],
  [ROGUE6_NODE.SACRIFICE]: ["sacrifice"],
  [ROGUE6_NODE.EXPEDITION]: ["scout"],
  [ROGUE6_NODE.FACE_OFF]: ["sala"],
  [ROGUE6_NODE.EMERGENCY_AID]: ["hire"],
  [ROGUE6_NODE.VISIBLE_END]: ["final"],
  [ROGUE6_NODE.VISIBLE_PATH]: ["evacuate"],
};

/**
 * 重掷节点（rollNodeData.groups[].nodeType）字符串 → 节点数值。
 * 标准主题（rogue_1..5）与黑流树海共用一张表：前者取 TorappuRoguelikeEventType 语义，
 * 后者的 SHOP/BATTLE_SHOP/PROPHECY 等数值以 rogue_6 nodeTypeData 为准。
 * 实测 details.rogue_6.rollNodeData 仅 zone_portal_normal_5_1..3（隐藏层）配置，
 * groups 为 INCIDENT/BATTLE_NORMAL/BATTLE_ELITE/BATTLE_SHOP/WISH。
 */
export const ROLL_NODE_TYPE_VALUES: { readonly [name: string]: number } = {
  BATTLE_NORMAL: ROGUE6_NODE.BATTLE_NORMAL,
  BATTLE_ELITE: ROGUE6_NODE.BATTLE_ELITE,
  BATTLE_BOSS: ROGUE6_NODE.BATTLE_BOSS,
  SHOP: 8,
  REST: ROGUE6_NODE.REST,
  INCIDENT: ROGUE6_NODE.INCIDENT,
  TREASURE: 64,
  ENTERTAINMENT: 128,
  UNKNOWN: 256,
  WISH: ROGUE6_NODE.WISH,
  SACRIFICE: ROGUE6_NODE.SACRIFICE,
  EXPEDITION: ROGUE6_NODE.EXPEDITION,
  BATTLE_SHOP: ROGUE6_NODE.SHOP,
  PORTAL: ROGUE6_NODE.MIRAGE,
  MISSION: 16384,
  STORY: ROGUE6_NODE.PROPHECY,
  STORY_HIDDEN: ROGUE6_NODE.PROPHECY_HIDDEN,
  ALCHEMY: 131072,
  DUEL: ROGUE6_NODE.FACE_OFF,
  SCRAP_SHOP: ROGUE6_NODE.SECRET_SHOP,
  DOOR: ROGUE6_NODE.TUNNEL,
  FINAL: ROGUE6_NODE.VISIBLE_END,
  EVACUATE: ROGUE6_NODE.VISIBLE_PATH,
  EMPLOY: ROGUE6_NODE.EMERGENCY_AID,
  LIGHT: ROGUE6_NODE.RAIN_VIEW,
  BATTLE_SAVAGE: ROGUE6_NODE.RESIDENT,
  EMPTY: ROGUE6_NODE.GLADE,
};
