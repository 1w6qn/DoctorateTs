/**
 * act44side（「墟」）情报屋（Informant）状态机
 *
 * 玩法：玩家经营情报小报摊，每个营业日 3 位顾客到访；对话二选一调整顾客的
 * 信任（trust）/兴味（attention），客户端判定耐心耗尽后请求结算；按
 * `income = basicIncome × incomeRate` 记收益，当日总收入在 RESULT 态累加进
 * `milestone.point`（里程碑奖励经通用 /activity/rewardMilestone 领取）。
 *
 * 协议依据：官服抓包（tmp/capture，2026-10 会话，activityId=act44sre，
 * 已导出 tmp/act44side-captures.json）。注意 live 协议字段与 2.7.61 反编译
 * playerdata 类型不一致（server 形状为 game/tagId/customerLine/keeperLine、
 * insight 缩写键、无 patience 字段），本模块以抓包为准：
 *
 * activity.TYPE_ACT44SIDE[<activityId>] = {
 *   coin, favorList, informantPt,
 *   milestone: { point, got: string[] },
 *   businessDay, unlockedCustomers: {id:1}, unlockedTags: {id:1},
 *   isNew, outerOpen,
 *   game: InformantGame | null   // 收摊后为 null
 * }
 *
 * 兼容性：live 客户端发送 activityId=act44sre，而本仓库 excel
 * typeAct44Side 键为 act44side（版本偏移）。excel 解析「请求 id 优先 →
 * 兜底唯一条目」；玩家状态缺失时按默认形状自愈创建。
 *
 * 私服近似（官方 RNG 无法逐字节对齐，明示偏差）：successRate 为两维超出
 * min 的归一化均值截断 [0,100]，success 按 rate 掷点；incomeRate ∈ [3.0,4.5]；
 * basicIncome ∈ {360,480,600}。每日 insight 定值由 (activityId, businessDay)
 * 种子伪随机导出（抓包验证同一营业日内三顾客同值），无需落盘。
 */
import excel from "@excel/excel";
import type { Act44SideData } from "@excel/excel";
import { logger } from "@utils/logger";
import type { Draft } from "mutative";
import type { PlayerDataModel } from "../../../kernel/playerdata";
import { asRecord } from "../shared/activity-json";

/** InformantState 数值语义（官服 PlayerAct44SideActivity.InformantState） */
export const InformantState = {
  ENTRY: 0,
  CHOICE: 1,
  CHOICE_END: 2,
  BEFORE_SINGLE_RESULT: 3,
  SINGLE_RESULT: 4,
  RESULT: 5,
} as const;

/** 每营业日顾客数（抓包：customerList 固定 3 槽） */
const CUSTOMERS_PER_DAY = 3;
/** 每位顾客可用洞悉次数（抓包：insightTimes 初始 3） */
const INSIGHT_TIMES_PER_CUSTOMER = 3;

/** 对话进行中的顾客交易数据（live 形状，无 patience 字段） */
export interface InformantTradeInfo {
  trust: number;
  attention: number;
  choices: string[];
  lastChoice: string | null;
}

/** 单位顾客结算记录（live 形状：success 为布尔） */
export interface InformantSettleEntry {
  customerId: string;
  tagId: string;
  success: boolean;
  successRate: number;
  incomeRate: number;
  income: number;
}

/** 洞悉提示（live 缩写键：RE=推荐目标值，MAX=该顾客可达上限） */
export interface InformantInsight {
  trustRE: number;
  trustMAX: number;
  attentionRE: number;
  attentionMAX: number;
}

/** 单场营业会话状态 */
export interface InformantGame {
  state: number;
  customerList: number[];
  curCustomer: number;
  newsId: string;
  customerId: string;
  round: number;
  boom: boolean;
  tagId: string;
  basicIncome: number;
  customerLine: string | null;
  keeperLine: string | null;
  insightTimes: number;
  insight: InformantInsight | null;
  tradeInfo: InformantTradeInfo;
  settle: InformantSettleEntry[];
}

/** TYPE_ACT44SIDE 运行时顶层形状（与官服抓包一致） */
export interface Act44SideRuntimeState {
  coin: number;
  favorList: string[];
  informantPt: number;
  milestone: { point: number; got: string[] };
  businessDay: number;
  unlockedCustomers: { [customerId: string]: number };
  unlockedTags: { [tagId: string]: number };
  isNew: boolean;
  outerOpen: boolean;
  game: InformantGame | null;
}

/**
 * 大小写不敏感解析 excel activity 字典键（键名随数据版本大小写多变，
 * 沿用 unlockActivity.activityDictKey 经验）
 *
 * @returns typeAct44Side 字典（无数据时返回空对象）
 */
function resolveAct44Dict(): Record<string, Act44SideData> {
  const dict = excel.ActivityTable.activity;
  const key = Object.keys(dict).find(
    (k) => k.replace(/_/g, "").toLowerCase() === "typeact44side",
  );
  return asRecord<Act44SideData>(key ? dict[key] : undefined);
}

/**
 * 解析活动 excel 数据：请求 id 优先，兜底唯一条目
 *
 * live 客户端发 act44sre 而仓库 excel 键为 act44side——版本偏移下二者共用同份玩法配置。
 * @param activityId - 客户端请求的活动 ID
 * @returns 活动 excel 数据（无任何数据时 undefined）
 */
export function resolveAct44Data(activityId?: string): Act44SideData | undefined {
  const dict = resolveAct44Dict();
  if (activityId && dict[activityId]) return dict[activityId];
  const ids = Object.keys(dict);
  if (ids.length === 0) return undefined;
  if (activityId && ids.length > 1) {
    logger.warn("Act44side", `excel 无 ${activityId} 数据且存在多条目，取第一条`);
  }
  return dict[ids[0]];
}

/**
 * djb2 字符串哈希（每日种子成分）
 * @param s - 输入字符串
 * @returns 32 位无符号哈希
 */
function strHash(s: string): number {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) >>> 0;
  return h;
}

/**
 * mulberry32 伪随机数生成器（确定性，供每日定值导出）
 * @param seed - 随机种子
 * @returns 返回 [0,1) 随机数的函数
 */
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * 从数组随机取一个元素
 * @param arr - 非空数组
 * @returns 随机元素；空数组返回 undefined
 */
function pick<T>(arr: T[]): T | undefined {
  if (arr.length === 0) return undefined;
  return arr[Math.floor(Math.random() * arr.length)];
}

/**
 * 导出指定营业日的洞悉定值（同一天内所有顾客共享，抓包验证）
 * @param activityId - 活动 ID（种子成分）
 * @param businessDay - 营业日（种子成分）
 * @returns 洞悉提示数值
 */
export function dayInsight(activityId: string, businessDay: number): InformantInsight {
  const rnd = mulberry32(strHash(activityId) ^ (businessDay * 0x9e3779b9));
  const trustMAX = 80 + Math.floor(rnd() * 41); // 80..120
  const attentionMAX = 80 + Math.floor(rnd() * 41);
  return {
    trustRE: Math.max(1, Math.round(trustMAX * 0.55)),
    trustMAX,
    attentionRE: Math.max(1, Math.round(attentionMAX * 0.55)),
    attentionMAX,
  };
}

/**
 * 构造 TYPE_ACT44SIDE 默认顶层状态（无进行中营业会话）
 * @param favorList - 信赖加成干员列表（播种方传入）
 * @returns 默认状态
 */
export function defaultAct44State(favorList: string[] = []): Act44SideRuntimeState {
  return {
    coin: 0,
    favorList,
    informantPt: 0,
    milestone: { point: 0, got: [] },
    businessDay: 1,
    unlockedCustomers: {},
    unlockedTags: {},
    isNew: false,
    outerOpen: true,
    game: null,
  };
}

/**
 * 取玩家活动状态，缺失时按默认形状自愈创建（live activityId 与仓库 excel 键
 * 存在版本偏移，不能依赖播种覆盖全部请求 id）
 *
 * @param draft - player.update 的 draft
 * @param activityId - 客户端请求的活动 ID（缺省回退 excel 唯一条目键）
 * @returns 玩家活动状态（draft 内引用，可直接变异）
 */
export function ensureAct44State(
  draft: Draft<PlayerDataModel>,
  activityId?: string,
): { state: Act44SideRuntimeState; data?: Act44SideData } {
  const data = resolveAct44Data(activityId);
  const dict = draft.activity;
  dict.TYPE_ACT44SIDE = dict.TYPE_ACT44SIDE || {};
  const store = dict.TYPE_ACT44SIDE;
  const id = activityId || Object.keys(resolveAct44Dict())[0] || "act44side";
  const existing = store[id];
  if (!existing || typeof existing !== "object") {
    store[id] = defaultAct44State();
  }
  // 自愈旧形状/缺字段（如仅播种了通用 TYPE_ACT 三件套的历史存档）
  const base = defaultAct44State();
  const state = store[id] as Act44SideRuntimeState;
  if (state.coin === undefined) state.coin = base.coin;
  if (state.favorList === undefined) state.favorList = base.favorList;
  if (state.informantPt === undefined) state.informantPt = base.informantPt;
  if (state.milestone === undefined) state.milestone = base.milestone;
  if (state.businessDay === undefined) state.businessDay = base.businessDay;
  if (state.unlockedCustomers === undefined) {
    state.unlockedCustomers = base.unlockedCustomers;
  }
  if (state.unlockedTags === undefined) state.unlockedTags = base.unlockedTags;
  if (state.isNew === undefined) state.isNew = base.isNew;
  if (state.outerOpen === undefined) state.outerOpen = base.outerOpen;
  if (state.game === undefined) state.game = base.game;
  return { state, data };
}

/**
 * 按关卡进度自愈同步 TYPE_ACT44SIDE 活动状态（情报屋入口解锁前置）
 *
 * 官方语义（抓包实证）：活动状态由进度事件创建——官服在领任务/商店购买时即出现
 * `{coin}` 级状态，首次 startGame 前已存在；客户端情报屋入口 Status 计算要求
 * `activity.TYPE_ACT44SIDE[actId]` 非空，缺失时恒为 LOCKED（即使 AT-TR-1 已通关）。
 * 本仓库此前仅在窗口内/forceOpen 播种或玩法路由内自愈——窗口外玩家推进
 * act44side 关卡链（ST-1→TR-1→…）时状态缺失 → 入口无法随关卡进度解锁。
 *
 * 在关卡进度写入点调用：命中 TYPE_ACT44SIDE 活动 id 前缀的关卡即 setdefault
 * 自愈创建；非本类关卡为 no-op。
 *
 * @param draft - player.update 的 draft
 * @param stageId - 本次写入的关卡 id；缺省时扫描 dungeon.stages 全部键（播种后自愈）
 */
export function syncAct44SideEntry(draft: Draft<PlayerDataModel>, stageId?: string): void {
  const basicInfo = excel.ActivityTable?.basicInfo ?? {};
  const candidates = Object.keys(basicInfo).filter(
    (id) => basicInfo[id]?.type === "TYPE_ACT44SIDE",
  );
  if (candidates.length === 0) return;
  const touched = stageId
    ? [stageId]
    : Object.keys(draft.dungeon?.stages ?? {});
  for (const sid of touched) {
    const actId = candidates.find((id) => sid.startsWith(`${id}_`));
    if (actId) {
      if (draft.activity.TYPE_ACT44SIDE?.[actId]) return;
      ensureAct44State(draft, actId);
      logger.info("Informant", `关卡进度触发情报屋活动状态自愈：${actId}（${sid}）`);
      return;
    }
    // 修复（2026-08-25）：复刻活动关卡（act<NN>sre_*）——live 客户端 activityId 为
    // act44sre（抓包 tmp/act44side-captures.json 实证 94 处），而 excel basicInfo 仅
    // 收录原活动 act44side。原实现只匹配 `act44side_` 前缀 → 复刻玩家通关
    // act44sre_tr01 后状态不自愈 → 客户端情报屋入口 Status 计算
    // TYPE_ACT44SIDE["act44sre"] 缺失 → 恒 LOCKED → 小游戏没有解锁。
    // 按「act<NN>side → act<NN>sre」推导复刻 id 并自愈其状态（ensureAct44State
    // 内部 resolveAct44Data 兜底唯一条目，玩法配置共用原活动）。
    const rerunId = candidates
      .map((id) => (id.endsWith("side") ? `${id.slice(0, -4)}sre` : undefined))
      .find((id) => !!id && sid.startsWith(`${id}_`));
    if (rerunId) {
      if (draft.activity.TYPE_ACT44SIDE?.[rerunId]) return;
      ensureAct44State(draft, rerunId);
      logger.info("Informant", `关卡进度触发情报屋活动状态自愈：${rerunId}（${sid}）`);
      return;
    }
  }
}

/**
 * 在台词映射中挑一个 key：按候选前缀依序匹配（数据内大小写不一致，
 * 如 policeman_lowPatience_01 与 fans_LowPatience_01 并存），命中集合内随机
 *
 * @param map - customerDialogMap / keeperDialogMap
 * @param prefixes - 依序尝试的前缀（首个命中集合非空即用）
 * @returns 台词 key；全未命中返回 null
 */
function pickDialogKey(map: Record<string, string> | undefined, prefixes: string[]): string | null {
  if (!map) return null;
  for (const prefix of prefixes) {
    const hits = Object.keys(map).filter((k) => k.startsWith(prefix));
    const chosen = pick(hits);
    if (chosen) return chosen;
  }
  return null;
}

/**
 * 发一位顾客：从池子抽顾客与标签、定 basicIncome 与进场台词
 *
 * 特殊池取 constData.specialCustomerListId（缺失回退 isSp 顾客）；普通池排除
 * 特殊顾客与教程顾客 citizen_beginner。
 *
 * @param data - 活动 excel 数据
 * @param slot - 顾客槽位（0=特殊位）
 * @returns 顾客/标签/收入基数字段
 */
function dealCustomer(data: Act44SideData | undefined, slot: number) {
  const customers = Object.values(data?.customerDataMap ?? {});
  const specialIds = data?.constData?.specialCustomerListId?.filter((id) =>
    customers.some((c) => c.id === id),
  );
  const specialPool =
    specialIds && specialIds.length > 0
      ? customers.filter((c) => specialIds.includes(c.id))
      : customers.filter((c) => c.isSp);
  const normalPool = customers.filter((c) => !c.isSp && c.id !== "citizen_beginner");
  const isSpecialSlot = slot === 0;
  const pool = isSpecialSlot && specialPool.length > 0 ? specialPool : normalPool;
  const customer = pick(pool);

  const tags = Object.values(data?.tagDataMap ?? {});
  const spTag = tags.find((t) => t.isSp) ?? { id: "special" };
  const normalTags = tags.filter((t) => !t.isSp);
  const tag = isSpecialSlot && spTag ? spTag : pick(normalTags) ?? spTag;

  // 抓包观测值集合 {360,480,600}；私服从同集合随机
  const basicIncome = pick([360, 480, 600]) ?? 360;
  return {
    customerId: customer?.id ?? "",
    tagId: tag?.id ?? "",
    isSp: isSpecialSlot && specialPool.length > 0,
    basicIncome,
  };
}

/**
 * 开启新营业日（startGame）：保留顶层字段，重建 game 会话并发出槽位 0 顾客
 *
 * @param draft - player.update 的 draft
 * @param activityId - 客户端请求的活动 ID
 */
export function informantStartGame(draft: Draft<PlayerDataModel>, activityId?: string): void {
  const { state, data } = ensureAct44State(draft, activityId);
  const day = state.businessDay;
  const newsIds = Object.keys(data?.newsDataMap ?? {}).sort();
  const newsId = newsIds.length > 0 ? newsIds[(day - 1) % newsIds.length] : "";

  const deal = dealCustomer(data, 0);
  const customerList = new Array<number>(CUSTOMERS_PER_DAY).fill(0);
  customerList[0] = deal.isSp ? 1 : 0;

  state.game = {
    state: InformantState.ENTRY,
    customerList,
    curCustomer: 0,
    newsId,
    customerId: deal.customerId,
    round: 0,
    boom: false,
    tagId: deal.tagId,
    basicIncome: deal.basicIncome,
    customerLine: null,
    keeperLine: null,
    insightTimes: INSIGHT_TIMES_PER_CUSTOMER,
    insight: null,
    tradeInfo: { trust: 0, attention: 0, choices: [], lastChoice: null },
    settle: [],
  };
  logger.debug("Act44side", `开日 day=${day} 顾客=${deal.customerId} 标签=${deal.tagId}`);
}

/**
 * 进入 CHOICE：发一对不同选项与当前耐心档位的顾客台词（ENTRY→CHOICE 与
 * CHOICE_END→CHOICE 复用）
 *
 * @param game - 营业会话（原地变异）
 * @param data - 活动 excel 数据
 */
function enterChoice(game: InformantGame, data?: Act44SideData): void {
  const choiceIds = Object.keys(data?.choiceDataMap ?? {});
  const first = pick(choiceIds);
  const rest = choiceIds.filter((id) => id !== first);
  const second = pick(rest);
  game.tradeInfo.choices = first && second ? [first, second] : first ? [first] : [];
  game.tradeInfo.lastChoice = null;
  game.keeperLine = null;
  // 耐心台词分档：round 0 进场；前半 highPatience、后半 LowPatience
  //（阈值取 constData.patienceRCRoundNum，缺省 4；抓包 r>=4 即低耐心档）
  const threshold = Math.max(1, data?.constData?.patienceRCRoundNum ?? 4);
  const phasePrefixes =
    game.round === 0
      ? [`${game.customerId}_entrance`]
      : game.round < threshold
        ? [`${game.customerId}_highPatience`]
        : [`${game.customerId}_LowPatience`, `${game.customerId}_lowPatience`];
  game.customerLine = pickDialogKey(data?.customerDialogMap, phasePrefixes);
  game.state = InformantState.CHOICE;
}

/**
 * 推进状态机（nextState）：请求携带客户端当前态，服务端据此转移
 *
 * 转移表（官服抓包还原）：
 * - ENTRY(0)→CHOICE(1)：发选项对与台词
 * - CHOICE_END(2)→CHOICE(1)：round+1，新选项对与新台词
 * - CHOICE(1)→SINGLE_RESULT(4)：结算当前顾客（settle 追加 + 洞悉填充 + 结果台词）
 * - SINGLE_RESULT(4)→ENTRY(0)/RESULT(5)：还有顾客则发下一位；三位齐则日结算
 *   （milestone.point += Σ settle.income）
 * - RESULT(5)→收摊：businessDay+1、解锁已服务顾客与非特殊标签、game=null
 * - BEFORE_SINGLE_RESULT(3)：抓包未出现，不支持（保持原状并告警）
 *
 * @param draft - player.update 的 draft
 * @param activityId - 客户端请求的活动 ID
 * @param reqState - 客户端报告的当前状态
 */
export function informantNextState(draft: Draft<PlayerDataModel>, activityId?: string, reqState?: number): void {
  const { state, data } = ensureAct44State(draft, activityId);
  const game = state.game;
  if (!game) {
    logger.debug("Act44side", "nextState 无进行中会话，忽略");
    return;
  }
  if (reqState !== undefined && reqState !== game.state) {
    logger.debug("Act44side", `nextState 状态不匹配 req=${reqState} cur=${game.state}，按当前态处理`);
  }
  switch (game.state) {
    case InformantState.ENTRY:
      enterChoice(game, data);
      break;
    case InformantState.CHOICE_END:
      game.round += 1;
      enterChoice(game, data);
      break;
    case InformantState.CHOICE:
      settleCurrentCustomer(game, data, activityId, state.businessDay);
      game.state = InformantState.SINGLE_RESULT;
      break;
    case InformantState.SINGLE_RESULT:
      if (game.curCustomer < CUSTOMERS_PER_DAY - 1) {
        advanceToNextCustomer(game, data);
      } else {
        closeDaySession(game, state);
        game.state = InformantState.RESULT;
      }
      break;
    case InformantState.RESULT:
      finishBusinessDay(state, game, data);
      break;
    default:
      logger.warn("Act44side", `不支持的状态转移 state=${game.state}`);
      break;
  }
}

/**
 * 结算当前顾客：按信任/兴味相对阈值的归一化均值计成功率，掷点判成功；
 * income = round(basicIncome × incomeRate)；追加 settle 并填结果台词与洞悉
 *
 * @param game - 营业会话（原地变异）
 * @param data - 活动 excel 数据
 * @param activityId - 活动 ID（洞悉种子成分）
 * @param businessDay - 营业日（洞悉种子成分）
 */
function settleCurrentCustomer(
  game: InformantGame,
  data: Act44SideData | undefined,
  activityId?: string,
  businessDay = 1,
): void {
  const consts = data?.constData;
  const trustMin = consts?.trustMin ?? 30;
  const trustMax = consts?.trustMax ?? 180;
  const attentionMin = consts?.attentionMin ?? 30;
  const attentionMax = consts?.attentionMax ?? 180;
  const { trust, attention } = game.tradeInfo;
  const rawRate =
    (50 * (trust - trustMin)) / Math.max(1, trustMax - trustMin) +
    (50 * (attention - attentionMin)) / Math.max(1, attentionMax - attentionMin);
  const successRate = Math.max(0, Math.min(100, Math.round(rawRate)));
  const success = Math.random() * 100 < successRate;
  const incomeRate = Math.round((3 + 1.2 * (successRate / 100) + Math.random() * 0.3) * 10) / 10;
  const income = Math.round(game.basicIncome * incomeRate);

  game.settle.push({
    customerId: game.customerId,
    tagId: game.tagId,
    success,
    successRate,
    incomeRate,
    income,
  });
  // 结果台词：成功按占优维度夸奖；失败按信任符号抱怨（负信任=耐心抱怨，
  // 非负但未达标=信任抱怨）；key 未命中时退化为普通成交行
  const resultPrefixes = success
    ? [attention >= trust ? "shopkeeper_highAttention" : "shopkeeper_highTrust"]
    : [trust < 0 ? "shopkeeper_lowPatience" : "shopkeeper_lowTrust"];
  game.keeperLine = pickDialogKey(data?.keeperDialogMap, [
    ...resultPrefixes,
    "shopkeeper_normalDeal",
  ]);
  game.insight = dayInsight(activityId || "act44side", businessDay);
}

/**
 * SINGLE_RESULT→下一位顾客：curCustomer+1 并重置会话内顾客相关字段
 *（settle 保留累计）
 *
 * @param game - 营业会话（原地变异）
 * @param data - 活动 excel 数据
 */
function advanceToNextCustomer(game: InformantGame, data?: Act44SideData): void {
  game.curCustomer += 1;
  const deal = dealCustomer(data, game.curCustomer);
  game.customerList[game.curCustomer] = deal.isSp ? 1 : 0;
  game.customerId = deal.customerId;
  game.tagId = deal.tagId;
  game.basicIncome = deal.basicIncome;
  game.round = 0;
  game.boom = false;
  game.customerLine = null;
  game.keeperLine = null;
  game.insightTimes = INSIGHT_TIMES_PER_CUSTOMER;
  game.insight = null;
  game.tradeInfo = { trust: 0, attention: 0, choices: [], lastChoice: null };
  game.state = InformantState.ENTRY;
}

/**
 * 日结算（RESULT 进入时）：milestone.point += Σ settle.income（抓包验证：
 * 1224 + (2160+1776+2304) = 7464）
 *
 * @param game - 营业会话
 * @param state - 活动顶层状态（point 原地累加）
 */
function closeDaySession(game: InformantGame, state: Act44SideRuntimeState): void {
  const totalIncome = game.settle.reduce((sum, s) => sum + s.income, 0);
  state.milestone.point += totalIncome;
}

/**
 * 收摊（RESULT→收摊）：businessDay+1；解锁本次服务过的全部顾客与
 * 非特殊标签（抓包：特殊顾客 policeman 入解锁表，special 标签不入）；清空 game
 *
 * @param state - 活动顶层状态（原地变异）
 * @param game - 营业会话（读取 settle 后置 null）
 * @param data - 活动 excel 数据
 */
function finishBusinessDay(
  state: Act44SideRuntimeState,
  game: InformantGame,
  data?: Act44SideData,
): void {
  for (const entry of game.settle) {
    if (entry.customerId) state.unlockedCustomers[entry.customerId] = 1;
    const tagIsSp = data?.tagDataMap?.[entry.tagId]?.isSp ?? entry.tagId === "special";
    if (entry.tagId && !tagIsSp) state.unlockedTags[entry.tagId] = 1;
  }
  state.businessDay += 1;
  state.isNew = false;
  state.outerOpen = true;
  state.game = null;
  logger.debug("Act44side", `收摊 day→${state.businessDay} point=${state.milestone.point}`);
}

/**
 * 选择对话（selectChoice）：按 excel choiceDataMap 把 trustValue/attentionValue
 * 累加进 tradeInfo（抓包验证 dialogue_c=-8/+24 与表一致），记录 lastChoice，
 * 置店主回应台词，进入 CHOICE_END
 *
 * @param draft - player.update 的 draft
 * @param activityId - 客户端请求的活动 ID
 * @param index - 选项下标（tradeInfo.choices 的 0/1）
 */
export function informantSelectChoice(draft: Draft<PlayerDataModel>, activityId?: string, index?: number): void {
  const { state, data } = ensureAct44State(draft, activityId);
  const game = state.game;
  if (!game || game.state !== InformantState.CHOICE) {
    logger.debug("Act44side", `selectChoice 状态非 CHOICE（${game?.state}），忽略`);
    return;
  }
  const choiceId = game.tradeInfo.choices[index ?? -1];
  const choice = choiceId ? data?.choiceDataMap?.[choiceId] : undefined;
  if (!choice) {
    logger.warn("Act44side", `selectChoice 非法下标 index=${index}`);
    return;
  }
  game.tradeInfo.trust += choice.trustValue ?? 0;
  game.tradeInfo.attention += choice.attentionValue ?? 0;
  game.tradeInfo.lastChoice = choice.id;
  game.tradeInfo.choices = [];
  // 店主回应：shopkeeper_dialogue<X>_NN（X=选项字母），未命中退化普通成交行
  const letter = (choice.id.match(/dialogue_([a-zA-Z])/)?.[1] ?? "A").toUpperCase();
  game.keeperLine = pickDialogKey(data?.keeperDialogMap, [
    `shopkeeper_dialogue${letter}`,
    "shopkeeper_normalDeal",
  ]);
  game.state = InformantState.CHOICE_END;
}

/**
 * 使用洞悉（useInsight）：CHOICE 态且剩余次数 >0 时消耗一次并填入当日洞悉定值。
 * 抓包未覆盖该接口（当日会话内未使用），语义按客户端 UI 类推：展示推荐值/上限提示
 *
 * @param draft - player.update 的 draft
 * @param activityId - 客户端请求的活动 ID
 */
export function informantUseInsight(draft: Draft<PlayerDataModel>, activityId?: string): void {
  const { state } = ensureAct44State(draft, activityId);
  const game = state.game;
  if (!game || game.state !== InformantState.CHOICE) {
    logger.debug("Act44side", `useInsight 状态非 CHOICE（${game?.state}），忽略`);
    return;
  }
  if (game.insightTimes <= 0) {
    logger.debug("Act44side", "useInsight 次数耗尽，忽略");
    return;
  }
  game.insightTimes -= 1;
  game.insight = dayInsight(activityId || "act44side", state.businessDay);
}
