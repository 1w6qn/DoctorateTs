/**
 * 危机合约静态数据视图（data/crisis、data/crisisV2）与服务端存档赛季视图
 *
 * 两类形状都不在客户端闭包里：
 *
 * 1. **静态 JSON**（`data/crisis/<season>.json`、`data/crisisV2/<season>.json`）
 *    是只读资产，生成类型里没有对应接口。此处按本模块消费面声明——一律用 `type`
 *    别名（interface 无隐式索引签名，无法赋给响应契约 `PlayerDataDelta` 的
 *    `{ [key: string]: unknown }`）。
 *
 * 2. **玩家存档**：生成类型 `PlayerCrisisSeason` 的 permanent/temporary/sInfo 是
 *    `ServerPayload`（两层非递归兜底），而服务端实际访问到第三层
 *    （`permanent.challenge.taskList[id].rts`）。存档内禁用 `JsonValue`
 *    （mutative `Draft` 会 TS2589），故按 `building/logic/ext-types.ts` 的本地视图
 *    范式就地声明，并用「是对象」运行期判定收窄：判定通过时**原样返回引用**（不复制），
 *    写入照常经 draft 落盘。
 */
import type { Draft } from "mutative";
import type { ServerPayload } from "@excel/json-value";
import type {
  PlayerCrisisSocialInfo,
  PlayerCrisisV2Season_BasicMapInfo,
  PlayerCrisisV2Season_PermanentMapInfo,
  PlayerDataModel,
} from "../../kernel/playerdata";

/* ==================== 静态 JSON：危机合约 V1（data/crisis） ==================== */

/** V1 符文风险条目（`data.stageRune[stageId][runeId]`；服务端只读 points） */
export type CrisisV1StageRuneJson = {
  id?: string;
  points?: number;
  mutexGroupKey?: string | null;
  description?: string;
};

/** V1 赛季信息（`data.seasonInfo[*]`；服务端只读 seasonId） */
export type CrisisV1SeasonInfoJson = { seasonId?: string };

/** V1 赛季临时数据（`playerDataDelta.modified.crisis.season[*].temporary`） */
export type CrisisV1TemporaryJson = {
  schedule: string;
  nst: number;
  point: number;
  challenge: {
    taskList: { [taskId: string]: { fts: number; rts: number } };
    topPoint: number;
    pointList: { [key: string]: number };
  };
};

/** V1 静态文件内的赛季模板条目（服务端仅覆盖 temporary） */
export type CrisisV1SeasonJson = { temporary?: CrisisV1TemporaryJson };

/** `data/crisis/<season>.json` 的服务端读取视图 */
export type CrisisV1File = {
  ts: number;
  data: {
    seasonInfo?: CrisisV1SeasonInfoJson[];
    stageRune?: { [stageId: string]: { [runeId: string]: CrisisV1StageRuneJson } };
  };
  playerDataDelta: {
    modified: {
      crisis: {
        lst?: number;
        nst?: number;
        training: { nst?: number };
        season: { [seasonId: string]: CrisisV1SeasonJson };
      };
    };
    deleted: { [key: string]: boolean };
  };
};

/* ==================== 静态 JSON：危机合约 V2（data/crisisV2） ==================== */

/** V2 节点数据（`info.mapDetailDataMap[mapId].nodeDataMap[slot]`） */
export type CrisisV2NodeDataJson = {
  runeId?: string | null;
  slotPackId?: string | null;
  mutualExclusionGroup?: string | null;
};

/** V2 符文数据（`runeDataMap[runeId]`；实测 2619 条全部含 score/dimension） */
export type CrisisV2RuneDataJson = {
  runeId?: string;
  score: number;
  dimension: number;
};

/** V2 指标集数据（`bagDataMap[slotPackId]`；服务端读 dimension/rewardScore） */
export type CrisisV2BagDataJson = {
  dimension: number;
  rewardScore: number;
};

/** V2 挑战节点（`challengeNodeDataMap[key]`；服务端读 missionType/missionParamList） */
export type CrisisV2ChallengeNodeJson = {
  missionType?: string;
  missionParamList?: string[];
};

/** V2 地图详情（只声明服务端读取的四个子表） */
export type CrisisV2MapDetailJson = {
  nodeDataMap?: { [slot: string]: CrisisV2NodeDataJson };
  runeDataMap?: { [runeId: string]: CrisisV2RuneDataJson };
  bagDataMap?: { [slotPackId: string]: CrisisV2BagDataJson };
  challengeNodeDataMap?: { [key: string]: CrisisV2ChallengeNodeJson };
};

/** V2 地图关卡（`info.mapStageDataMap[mapId]`；服务端只读 stageType） */
export type CrisisV2MapStageJson = { stageType?: string };

/** V2 `info` 视图（服务端读取面） */
export type CrisisV2InfoJson = {
  seasonId?: string;
  mapStageDataMap?: { [mapId: string]: CrisisV2MapStageJson };
  mapDetailDataMap?: { [mapId: string]: CrisisV2MapDetailJson };
};

/** `data/crisisV2/<season>.json` 的服务端读取视图 */
export type CrisisV2File = {
  ts: number;
  info: CrisisV2InfoJson;
  playerDataDelta: {
    modified: { [key: string]: ServerPayload };
    deleted: { [key: string]: boolean };
  };
};

/* ==================== 玩家存档：V1 赛季视图 ==================== */

/** V1 赛季 permanent 存档视图（生成模型为 `ServerPayload`） */
export type CrisisV1PermanentView = {
  rune?: { [runeId: string]: number };
  point?: number;
  challenge?: {
    taskList?: { [taskId: string]: { fts?: number; rts?: number } };
    topPoint?: number;
    pointList?: { [key: string]: number };
  };
};

/** V1 赛季 temporary 存档视图 */
export type CrisisV1TemporaryView = {
  schedule?: string;
  nst?: number;
  point?: number;
  challenge?: CrisisV1PermanentView["challenge"];
};

/** V1 赛季 sInfo 存档视图 */
export type CrisisV1SInfoView = {
  assistCnt?: number;
  maxPnt?: number;
};

/**
 * V1 赛季存档视图
 *
 * 各字段可选 + permanent/temporary/sInfo 与 `ServerPayload` 联合，使生成类型
 * `PlayerCrisisSeason` 可直接赋值（无需断言）。
 */
export type CrisisV1SeasonView = {
  coin?: number;
  tCoin?: number;
  permanent?: ServerPayload | CrisisV1PermanentView;
  temporary?: ServerPayload | CrisisV1TemporaryView;
  sInfo?: ServerPayload | CrisisV1SInfoView;
};

/** V1 赛季 permanent 的「已补齐」视图（`ensureCrisisV1Season` 保证各子块存在） */
export type CrisisV1PermanentReady = {
  rune: { [runeId: string]: number };
  point: number;
  challenge: {
    taskList: { [taskId: string]: { fts?: number; rts?: number } };
    topPoint: number;
    pointList: { [key: string]: number };
  };
};

/** V1 赛季的「已补齐」视图（`ensureCrisisV1Season` 返回值） */
export type CrisisV1SeasonReady = {
  coin?: number;
  tCoin?: number;
  permanent: CrisisV1PermanentReady;
  temporary?: ServerPayload | CrisisV1TemporaryView;
  sInfo?: ServerPayload | CrisisV1SInfoView;
};

/**
 * `draft.crisis.season` 的赛季字典视图
 *
 * `PlayerCrisisSeason` 可直接赋给 `CrisisV1SeasonView`（字段可选化），故本断言两侧
 * 必然兼容；仅用于把「整赛季可能缺失」的运行时事实带进类型（下标返回 `| undefined`）。
 * @param draft - 玩家数据草稿
 * @returns 赛季字典视图
 */
export function crisisV1SeasonsView(
  draft: Draft<PlayerDataModel>,
): { [seasonId: string]: CrisisV1SeasonView | undefined } {
  return draft.crisis.season as { [seasonId: string]: CrisisV1SeasonView | undefined };
}

/**
 * 取 `draft.crisis.season[seasonId]`（赛季字典整体缺失时返回 undefined）
 *
 * 与既有 `(draft.crisis.season as any)?.[seasonId]` 的运行期语义一致：整块缺失不抛。
 * @param draft - 玩家数据草稿
 * @param seasonId - 赛季 id
 * @returns 赛季视图
 */
export function crisisV1SeasonView(
  draft: Draft<PlayerDataModel>,
  seasonId: string,
): CrisisV1SeasonView | undefined {
  const seasons:
    | { [seasonId: string]: CrisisV1SeasonView | undefined }
    | undefined = draft.crisis.season;
  return seasons?.[seasonId];
}

/**
 * `ServerPayload` → permanent 视图收窄
 *
 * 生成模型把 permanent 兜底为 `ServerPayload`（两层非递归），而服务端访问第三层
 * （`challenge.taskList[id]`）。运行期判定「是对象」后按声明视图使用；判定通过时返回
 * 原引用（不复制），写入随 draft 落盘。非对象返回新空对象（只读取值路径安全）。
 * @param value - 存档中的 permanent 值
 * @returns permanent 视图
 */
export function asCrisisV1Permanent(
  value: ServerPayload | CrisisV1PermanentView | undefined,
): CrisisV1PermanentView {
  return isObjectView<CrisisV1PermanentView>(value) ? value : {};
}

/**
 * 运行期判定值是否为对象（用于把 `ServerPayload` 收窄到调用方声明的视图）
 * @param value - 待判定值
 * @returns 是否为对象
 */
function isObjectView<T>(value: ServerPayload | T | undefined): value is T {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/* ==================== 玩家存档：V2 赛季视图 ==================== */

/** V2 赛季 permanent 存档视图（生成模型字段全部可选化） */
export type CrisisV2PermanentView = Partial<PlayerCrisisV2Season_PermanentMapInfo>;

/** V2 赛季 temporary（轮换测试地）条目视图 */
export type CrisisV2BasicMapView = Partial<PlayerCrisisV2Season_BasicMapInfo>;

/** V2 赛季存档视图（字段可选化，使生成类型 `PlayerCrisisV2Season` 可直接赋值） */
export type CrisisV2SeasonView = {
  coin?: number;
  permanent?: CrisisV2PermanentView;
  temporary?: { [mapId: string]: CrisisV2BasicMapView };
  social?: PlayerCrisisSocialInfo;
};

/** V2 赛季 permanent 的「已补齐」形状（`ensureCrisisV2Season` 逐个补齐生成模型声明字段） */
export type CrisisV2PermanentReady = PlayerCrisisV2Season_PermanentMapInfo;

/** V2 赛季的「已补齐」视图（`ensureCrisisV2Season` 返回值） */
export type CrisisV2SeasonReady = {
  coin?: number;
  permanent: CrisisV2PermanentReady;
  temporary: { [mapId: string]: CrisisV2BasicMapView };
  social?: PlayerCrisisSocialInfo;
};

/**
 * `draft.crisisV2.seasons` 的赛季字典视图
 *
 * `PlayerCrisisV2Season` 可直接赋给 `CrisisV2SeasonView`（字段可选化），故断言两侧兼容；
 * 用于把「整赛季可能缺失」带入类型（下标返回 `| undefined`）。
 * @param draft - 玩家数据草稿
 * @returns 赛季字典视图
 */
export function crisisV2SeasonsView(
  draft: Draft<PlayerDataModel>,
): { [seasonId: string]: CrisisV2SeasonView | undefined } {
  return draft.crisisV2.seasons as { [seasonId: string]: CrisisV2SeasonView | undefined };
}
