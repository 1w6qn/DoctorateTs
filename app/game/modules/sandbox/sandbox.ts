/**
 * 沙盒（生息演算）协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中 Torappu.UI.SandboxPerm 命名空间的
 * SandboxV2 / SandboxV3 / SandboxPerm 系列 Request/Response 类；字段以 CS 类为准。
 * 本服务端多数 handler 为占位实现（返回 202 或空增量），未读取的请求字段以空接口表示；
 * 响应仅返回 playerDataDelta 时类型即 PlayerDeltaResponse。
 */
import { PlayerDeltaResponse } from "../../kernel/http/common";

/* ===== 公共响应基类 ===== */

/** 沙盒通用纯增量响应（服务端仅返回 playerDataDelta 时的别名） */
export type SandboxDeltaResponse = PlayerDeltaResponse;

/* ===== 主题切换 / 固定 ===== */

/** 切换沙盒主题请求（CS: SandboxPermChangeTopicRequest） */
export interface SandboxPermChangeTopicRequest {
  topicId: string;
}

/** 切换沙盒主题响应（CS: SandboxPermChangeTopicResponse） */
export interface SandboxPermChangeTopicResponse extends PlayerDeltaResponse {
  result: number;
}

/** 固定沙盒主题请求（CS: SandboxPermPinTopicRequest） */
export interface SandboxPermPinTopicRequest {
  topicId: string;
}

/** 固定沙盒主题响应（CS: SandboxPermPinTopicResponse；服务端直接返回 202 无响应体） */
export type SandboxPermPinTopicResponse = PlayerDeltaResponse;

/* ===== 沙盒 V2 请求 ===== */

/** 沙盒V2创建游戏请求（CS: SandboxV2CreateGameRequest） */
export interface SandboxV2CreateGameRequest {
  topicId: string;
}

/** 沙盒V2战斗开始请求（CS: SandboxV2BattleStartRequest） */
export interface SandboxV2BattleStartRequest {
  topicId: string;
  nodeId: string;
  squadIdx: number;
}

/** 沙盒V2战斗结束请求（CS: SandboxV2BattleFinishRequest : CommonFinishBattleRequest，含 topicId / sandboxV2Data；服务端不读取） */
export interface SandboxV2BattleFinishRequest {}

/** 沙盒V2进食请求（CS: SandboxV2DineRequest） */
export interface SandboxV2DineRequest {
  topicId: string;
  charInstId: number;
  foodInstId: string;
}

/** 沙盒V2烹饪饮品请求（CS: SandboxV2CookDrinkRequest；material/food 为 SandboxV2CookDrinkItem { id, count }） */
export interface SandboxV2CookDrinkRequest {
  topicId: string;
  material: SandboxV2CookDrinkItem[];
  food: SandboxV2CookDrinkItem[];
}

/** 沙盒V2烹饪饮品材料项（CS: SandboxV2CookDrinkItem） */
export interface SandboxV2CookDrinkItem {
  id: string;
  count: number;
}

/** 沙盒V2烹饪食物请求（CS: SandboxV2CookFoodRequest） */
export interface SandboxV2CookFoodRequest {
  topicId: string;
  main: string[];
  sub: string[];
  count: number;
}

/** 沙盒V2设置编队请求（CS: SandboxV2SetSquadRequest；slots 为 RequestSquadSlot[]） */
export interface SandboxV2SetSquadRequest {
  topicId: string;
  index: number;
  slots: unknown[];
  tools: string[];
}

/** 沙盒V2结算游戏请求（CS: SandboxV2SettleGameRequest） */
export interface SandboxV2SettleGameRequest {
  topicId: string;
}

/** 沙盒V2基地建造保存请求（服务端自定义，无 CS 对应类；handler 不读取 body） */
export interface SandboxV2HomeBuildSaveRequest {}

/** 沙盒V2月度战斗开始请求（CS: SandboxV2MonthBattleStartRequest） */
export interface SandboxV2MonthBattleStartRequest {
  topicId: string;
  squadIdx: number;
  monthRushId: string;
}

/** 沙盒V2月度战斗结束请求（CS: SandboxV2BattleFinishRequest : CommonFinishBattleRequest；服务端不读取） */
export interface SandboxV2MonthBattleFinishRequest {}

/** 沙盒V2探索模式请求（CS: SandboxV2ExploreModeRequest） */
export interface SandboxV2ExploreModeRequest {
  topicId: string;
  mode: number;
}

/** 沙盒V2事件选择请求（CS: SandboxV2EventChoiceRequest） */
export interface SandboxV2EventChoiceRequest {
  topicId: string;
  nodeId: string;
  eventId: string;
  choiceId: string;
}

/** 沙盒V2炼金术请求（CS: SandboxV2AlchemyRequest） */
export interface SandboxV2AlchemyRequest {
  topicId: string;
  recipeId: string;
  count: number;
}

/** 沙盒V2基地升级请求（CS: SandboxV2BasementUpgradeRequest） */
export interface SandboxV2BasementUpgradeRequest {
  topicId: string;
}

/** 沙盒V2建造请求（CS: SandboxV2ConstructOperationRequest；operation 为 JArray） */
export interface SandboxV2ConstructOperationRequest {
  topicId: string;
  nodeId: string;
  operation: unknown[];
  catchedAnimals: { [key: string]: { [key: string]: number } };
}

/** 沙盒V2烹饪（合成）请求（CS: SandboxV2CraftRequest） */
export interface SandboxV2CraftRequest {
  topicId: string;
  itemId: string;
  count: number;
  autoSquad: number;
}

/** 沙盒V2放弃行动点请求（CS: SandboxV2DiscardApRequest） */
export interface SandboxV2DiscardApRequest {
  topicId: string;
}

/** 沙盒V2进入挑战请求（CS: SandboxV2StartChallengeRequest） */
export interface SandboxV2StartChallengeRequest {
  topicId: string;
}

/** 沙盒V2退出挑战请求（CS: SandboxV2ChallengeExitRequest） */
export interface SandboxV2ChallengeExitRequest {
  topicId: string;
}

/** 沙盒V2提取请求（服务端自定义，无 CS 对应类；handler 不读取 body） */
export interface SandboxV2ExtractRequest {}

/** 沙盒V2获取挑战奖励请求（CS: SandboxV2GetChallengeRewardRequest） */
export interface SandboxV2GetChallengeRewardRequest {
  topicId: string;
  rewardIds: string[];
}

/** 沙盒V2引导加载请求（CS: SandboxV2GuideLoadRequest） */
export interface SandboxV2GuideLoadRequest {
  topicId: string;
}

/** 沙盒V2加载（读档）请求（CS: SandboxV2LoadArchiveRequest） */
export interface SandboxV2LoadArchiveRequest {
  topicId: string;
}

/** 沙盒V2进入下一天请求（CS: SandboxV2NextDayRequest） */
export interface SandboxV2NextDayRequest {
  topicId: string;
}

/** 沙盒V2移除补给请求（CS: SandboxV2RemoveSupplyRequest） */
export interface SandboxV2RemoveSupplyRequest {
  topicId: string;
  charInstId: number;
}

/** 沙盒V2裂隙关闭请求（CS: SandboxV2RiftCloseRequest） */
export interface SandboxV2RiftCloseRequest {
  topicId: string;
}

/** 沙盒V2裂隙创建请求（CS: SandboxV2RiftCreateRequest） */
export interface SandboxV2RiftCreateRequest {
  topicId: string;
}

/** 沙盒V2裂隙设置难度请求（CS: SandboxV2RiftSetDifficultyRequest） */
export interface SandboxV2RiftSetDifficultyRequest {
  topicId: string;
  difficulty: string;
}

/** 沙盒V2裂隙设置队伍请求（CS: SandboxV2RiftSetTeamRequest） */
export interface SandboxV2RiftSetTeamRequest {
  topicId: string;
  team: string;
}

/** 沙盒V2裂隙结算请求（CS: SandboxV2RiftSettleRequest） */
export interface SandboxV2RiftSettleRequest {
  topicId: string;
}

/** 沙盒V2设置补给请求（CS: SandboxV2SetSupplyRequest） */
export interface SandboxV2SetSupplyRequest {
  topicId: string;
  charList: number[];
}

/** 沙盒V2结算挑战请求（CS: SandboxV2ChallengeSettleRequest） */
export interface SandboxV2ChallengeSettleRequest {
  topicId: string;
}

/** 沙盒V2结算天数请求（CS: SandboxV2SettleDayRequest） */
export interface SandboxV2SettleDayRequest {
  topicId: string;
}

/** 沙盒V2商店购买请求（CS: SandboxV2ShopBuyRequest） */
export interface SandboxV2ShopBuyRequest {
  topicId: string;
  index: number;
  count: number;
}

/** 沙盒V2开始任务请求（服务端自定义，无 CS 对应类；handler 不读取 body） */
export interface SandboxV2StartMissionRequest {}

/** 沙盒V2切换模式请求（服务端自定义，CS 仅有 SandboxV3SwitchModeRequest；handler 不读取 body） */
export interface SandboxV2SwitchModeRequest {}

/** 沙盒V2解锁科技请求（CS: SandboxV2ScienceUnlockRequest） */
export interface SandboxV2ScienceUnlockRequest {
  topicId: string;
  techId: string;
}

/* ===== 沙盒 V2 竞速请求 ===== */

/** 沙盒竞速战斗结束请求（CS: SandboxV2RacingBattleFinishRequest : CommonFinishBattleRequest，含 topicId / racingData；服务端不读取） */
export interface SandboxV2RacingBattleFinishRequest {}

/** 沙盒竞速战斗开始请求（CS: SandboxV2RacingBattleStartRequest） */
export interface SandboxV2RacingBattleStartRequest {
  topicId: string;
  nodeId: string;
  instId: string;
}

/** 沙盒竞速学习天赋请求（CS: SandboxV2RacingLearnTalentRequest） */
export interface SandboxV2RacingLearnTalentRequest {
  topicId: string;
  instId: string;
}

/** 沙盒竞速注册请求（CS: SandboxV2RacingRegisterRequest） */
export interface SandboxV2RacingRegisterRequest {
  topicId: string;
  instId: string;
}

/** 沙盒竞速释放请求（CS: SandboxV2RacingReleaseRequest） */
export interface SandboxV2RacingReleaseRequest {
  topicId: string;
  instIds: string[];
  tmp: number;
}

/** 沙盒竞速保存标记请求（CS: SandboxV2RacingSaveMarkRequest） */
export interface SandboxV2RacingSaveMarkRequest {
  topicId: string;
  instId: string;
  mark: number;
}

/* ===== 沙盒 V3 请求 ===== */

/** 沙盒V3切换模式请求（CS: SandboxV3SwitchModeRequest） */
export interface SandboxV3SwitchModeRequest {
  topicId: string;
  modeId: string;
}

/** 沙盒V3生产刷新请求（CS: SandboxV3RefreshHarvestRequest） */
export interface SandboxV3RefreshHarvestRequest {
  topicId: string;
}

/** 沙盒V3生产收取请求（CS: SandboxV3HarvestRequest） */
export interface SandboxV3HarvestRequest {
  topicId: string;
}

/** 沙盒V3基地进入请求（CS: SandboxV3EnterBaseRequest） */
export interface SandboxV3EnterBaseRequest {
  topicId: string;
}

/** 沙盒V3基地商店购买请求（CS: SandboxV3BaseShopBuyRequest） */
export interface SandboxV3BaseShopBuyRequest {
  topicId: string;
  goodId: string;
  count: number;
}

/** 沙盒V3基地保存请求（CS 仅存在 SandboxV3BuildSaveResponse，无请求类；handler 不读取 body） */
export interface SandboxV3BuildSaveRequest {}

/** 沙盒V3基地商店出售请求（CS: SandboxV3BaseShopSellRequest） */
export interface SandboxV3BaseShopSellRequest {
  topicId: string;
  itemId: string;
  count: number;
}

/** 沙盒V3基地升级请求（CS: SandboxV3HomeUpgradeRequest） */
export interface SandboxV3HomeUpgradeRequest {
  topicId: string;
}

/** 沙盒V3创建游戏请求（CS: SandboxV3CreateGameRequest；服务端仅读取 topicId） */
export interface SandboxV3CreateGameRequest {
  topicId: string;
  nodeId: string;
  difficultyId: string;
}

/** 沙盒V3放弃游戏请求（CS: SandboxV3GiveUpGameRequest） */
export interface SandboxV3GiveUpGameRequest {
  topicId: string;
}

/** 沙盒V3战斗开始请求（CS: SandboxV3BattleStartRequest） */
export interface SandboxV3BattleStartRequest {
  topicId: string;
}

/** 沙盒V3战斗结束请求（CS: SandboxV3BattleFinishRequest : CommonFinishBattleRequest，含 topicId / sandboxV3Data；服务端不读取） */
export interface SandboxV3BattleFinishRequest {}

/** 沙盒V3更改防御请求（CS: SandboxV3ChangeDefendRequest；服务端仅读取 topicId） */
export interface SandboxV3ChangeDefendRequest {
  topicId: string;
  zoneId: string;
  operate: number;
  chars: number[];
}

/** 沙盒V3选择乐队请求（CS: SandboxV3ChooseBandRequest） */
export interface SandboxV3ChooseBandRequest {
  topicId: string;
  bandId: string;
}

/** 沙盒V3每日招募请求（CS: SandboxV3DayPassRecruitRequest；ownChar 为 RequestSquadSlot，thirdChar 为 SandboxV3DayPassRecruitThirdCharData） */
export interface SandboxV3DayPassRecruitRequest {
  topicId: string;
  ownChar: unknown;
  thirdChar: SandboxV3DayPassRecruitThirdCharData;
}

/** 沙盒V3每日招募第三人数据（CS: SandboxV3DayPassRecruitThirdCharData） */
export interface SandboxV3DayPassRecruitThirdCharData {
  charId: string;
  skillIndex: number;
  currentEquip: string;
}

/** 沙盒V3进食请求（CS: SandboxV3EatFoodRequest） */
export interface SandboxV3EatFoodRequest {
  topicId: string;
  charInstId: number;
  cookbook: string;
  sub: string[];
}

/** 沙盒V3事件选择请求（CS: SandboxV3EventChoiceRequest） */
export interface SandboxV3EventChoiceRequest {
  topicId: string;
  choiceId: string;
  charList: number[];
}

/** 沙盒V3获取每日招募列表请求（CS: SandboxV3GetDayPassRecruitListRequest） */
export interface SandboxV3GetDayPassRecruitListRequest {
  topicId: string;
  refresh: number;
}

/** 沙盒V3进入下一天请求（CS: SandboxV3NextDayRequest） */
export interface SandboxV3NextDayRequest {
  topicId: string;
}

/** 沙盒V3初始化招募请求（CS: SandboxV3InitRecruitRequest；ownChars 为 RequestSquadSlot[]） */
export interface SandboxV3InitRecruitRequest {
  topicId: string;
  ownChars: unknown[];
  assistFriend: unknown;
}

/** 沙盒V3结算游戏请求（CS: SandboxV3SettleGameRequest） */
export interface SandboxV3SettleGameRequest {
  topicId: string;
}

/** 沙盒V3商店购买请求（CS: SandboxV3ShopBuyRequest） */
export interface SandboxV3ShopBuyRequest {
  topicId: string;
  index: number;
  count: number;
}

/** 沙盒V3商店购买招募请求（CS: SandboxV3ShopBuyRecruitRequest） */
export interface SandboxV3ShopBuyRecruitRequest {
  topicId: string;
}

/** 沙盒V3商店刷新请求（CS: SandboxV3ShopRefreshRequest） */
export interface SandboxV3ShopRefreshRequest {
  topicId: string;
}

/** 沙盒V3商店出售请求（CS: SandboxV3ShopSellRequest） */
export interface SandboxV3ShopSellRequest {
  topicId: string;
  itemId: string;
  count: number;
}

/** 沙盒V3解锁科技请求（CS: SandboxV3UnlockTechRequest） */
export interface SandboxV3UnlockTechRequest {
  topicId: string;
  techId: string;
}

/* ===== 沙盒 V2 响应 ===== */

/** 沙盒V2创建游戏响应（CS: SandboxV2CreateGameResponse） */
export type SandboxV2CreateGameResponse = PlayerDeltaResponse;

/** 沙盒V2战斗开始响应（CS: SandboxV2BattleStartResponse : CommonStartBattleResponse；服务端省略 battleId 等协议字段） */
export type SandboxV2BattleStartResponse = PlayerDeltaResponse;

/** 沙盒V2战斗结束响应（CS: SandboxV2BattleFinishResponse : CommonFinishBattleResponse；服务端省略结果字段） */
export type SandboxV2BattleFinishResponse = PlayerDeltaResponse;

/** 沙盒V2进食响应（CS: SandboxV2DineResponse） */
export type SandboxV2DineResponse = PlayerDeltaResponse;

/** 沙盒V2烹饪饮品响应（CS: SandboxV2CookDrinkResponse） */
export type SandboxV2CookDrinkResponse = PlayerDeltaResponse;

/** 沙盒V2烹饪食物响应（CS: SandboxV2CookFoodResponse） */
export type SandboxV2CookFoodResponse = PlayerDeltaResponse;

/** 沙盒V2设置编队响应（CS: SandboxV2SetSquadResponse） */
export type SandboxV2SetSquadResponse = PlayerDeltaResponse;

/** 沙盒V2结算游戏响应（CS: SandboxV2SettleGameResponse） */
export type SandboxV2SettleGameResponse = PlayerDeltaResponse;

/** 沙盒V2基地建造保存响应（服务端自定义，仅返回增量） */
export type SandboxV2HomeBuildSaveResponse = PlayerDeltaResponse;

/** 沙盒V2月度战斗开始响应（CS: SandboxV2MonthBattleStartResponse : CommonStartBattleResponse；服务端省略协议字段） */
export type SandboxV2MonthBattleStartResponse = PlayerDeltaResponse;

/** 沙盒V2月度战斗结束响应（CS: SandboxV2MonthBattleFinishResponse : CommonFinishBattleResponse；服务端省略结果字段） */
export type SandboxV2MonthBattleFinishResponse = PlayerDeltaResponse;

/** 沙盒V2探索模式响应（CS 无对应响应类，仅返回增量） */
export type SandboxV2ExploreModeResponse = PlayerDeltaResponse;

/** 沙盒V2事件选择响应（CS: SandboxV2EventChoiceResponse；服务端省略 success/items/finish） */
export type SandboxV2EventChoiceResponse = PlayerDeltaResponse;

/** 沙盒V2炼金术响应（CS: SandboxV2AlchemyResponse） */
export type SandboxV2AlchemyResponse = PlayerDeltaResponse;

/** 沙盒V2基地升级响应（CS: SandboxV2BasementUpgradeResponse） */
export type SandboxV2BasementUpgradeResponse = PlayerDeltaResponse;

/** 沙盒V2建造响应（CS: SandboxV2ConstructOperationResponse） */
export type SandboxV2ConstructOperationResponse = PlayerDeltaResponse;

/** 沙盒V2烹饪（合成）响应（CS: SandboxV2CraftResponse） */
export type SandboxV2CraftResponse = PlayerDeltaResponse;

/** 沙盒V2放弃行动点响应（CS: SandboxV2DiscardApResponse） */
export type SandboxV2DiscardApResponse = PlayerDeltaResponse;

/** 沙盒V2进入挑战响应（CS: SandboxV2StartChallengeResponse） */
export type SandboxV2StartChallengeResponse = PlayerDeltaResponse;

/** 沙盒V2退出挑战响应（CS: SandboxV2ChallengeExitResponse） */
export type SandboxV2ChallengeExitResponse = PlayerDeltaResponse;

/** 沙盒V2提取响应（服务端自定义，无 CS 对应类） */
export type SandboxV2ExtractResponse = PlayerDeltaResponse;

/** 沙盒V2获取挑战奖励响应（CS: SandboxV2GetChallengeRewardResponse） */
export type SandboxV2GetChallengeRewardResponse = PlayerDeltaResponse;

/** 沙盒V2引导加载响应（CS: SandboxV2GuideLoadResponse） */
export type SandboxV2GuideLoadResponse = PlayerDeltaResponse;

/** 沙盒V2加载（读档）响应（CS: SandboxV2LoadArchiveResponse） */
export type SandboxV2LoadArchiveResponse = PlayerDeltaResponse;

/** 沙盒V2进入下一天响应（CS: SandboxV2NextDayResponse） */
export type SandboxV2NextDayResponse = PlayerDeltaResponse;

/** 沙盒V2移除补给响应（CS: SandboxV2RemoveSupplyResponse） */
export type SandboxV2RemoveSupplyResponse = PlayerDeltaResponse;

/** 沙盒V2裂隙关闭响应（CS: SandboxV2RiftCloseResponse） */
export type SandboxV2RiftCloseResponse = PlayerDeltaResponse;

/** 沙盒V2裂隙创建响应（CS: SandboxV2RiftCreateResponse） */
export type SandboxV2RiftCreateResponse = PlayerDeltaResponse;

/** 沙盒V2裂隙设置难度响应（CS: SandboxV2RiftSetDifficultyResponse） */
export type SandboxV2RiftSetDifficultyResponse = PlayerDeltaResponse;

/** 沙盒V2裂隙设置队伍响应（CS: SandboxV2RiftSetTeamResponse） */
export type SandboxV2RiftSetTeamResponse = PlayerDeltaResponse;

/** 沙盒V2裂隙结算响应（CS: SandboxV2RiftSettleResponse） */
export type SandboxV2RiftSettleResponse = PlayerDeltaResponse;

/** 沙盒V2设置补给响应（CS: SandboxV2SetSupplyResponse） */
export type SandboxV2SetSupplyResponse = PlayerDeltaResponse;

/** 沙盒V2结算挑战响应（CS: SandboxV2ChallengeSettleResponse） */
export type SandboxV2ChallengeSettleResponse = PlayerDeltaResponse;

/** 沙盒V2结算天数响应（CS: SandboxV2SettleDayResponse） */
export type SandboxV2SettleDayResponse = PlayerDeltaResponse;

/** 沙盒V2商店购买响应（CS: SandboxV2ShopBuyResponse） */
export type SandboxV2ShopBuyResponse = PlayerDeltaResponse;

/** 沙盒V2开始任务响应（服务端自定义，无 CS 对应类） */
export type SandboxV2StartMissionResponse = PlayerDeltaResponse;

/** 沙盒V2切换模式响应（服务端自定义，CS 仅有 SandboxV3SwitchModeResponse） */
export type SandboxV2SwitchModeResponse = PlayerDeltaResponse;

/** 沙盒V2解锁科技响应（CS: SandboxV2ScienceUnlockResponse） */
export type SandboxV2ScienceUnlockResponse = PlayerDeltaResponse;

/* ===== 沙盒 V2 竞速响应 ===== */

/** 沙盒竞速战斗结束响应（CS: SandboxV2RacingBattleFinishResponse : CommonFinishBattleResponse；服务端省略协议字段） */
export type SandboxV2RacingBattleFinishResponse = PlayerDeltaResponse;

/** 沙盒竞速战斗开始响应（CS: SandboxV2RacingBattleStartResponse : CommonStartBattleResponse；服务端省略协议字段） */
export type SandboxV2RacingBattleStartResponse = PlayerDeltaResponse;

/** 沙盒竞速学习天赋响应（CS: SandboxV2RacingLearnTalentResponse；服务端省略 instId/talent） */
export type SandboxV2RacingLearnTalentResponse = PlayerDeltaResponse;

/** 沙盒竞速注册响应（CS: SandboxV2RacingRegisterResponse；服务端省略 name） */
export type SandboxV2RacingRegisterResponse = PlayerDeltaResponse;

/** 沙盒竞速释放响应（CS: SandboxV2RacingReleaseResponse） */
export type SandboxV2RacingReleaseResponse = PlayerDeltaResponse;

/** 沙盒竞速保存标记响应（CS: SandboxV2RacingSaveMarkResponse；服务端省略 instId/mark） */
export type SandboxV2RacingSaveMarkResponse = PlayerDeltaResponse;

/* ===== 沙盒 V3 响应 ===== */

/** 沙盒V3切换模式响应（CS: SandboxV3SwitchModeResponse） */
export type SandboxV3SwitchModeResponse = PlayerDeltaResponse;

/** 沙盒V3生产刷新响应（CS: SandboxV3RefreshHarvestResponse） */
export type SandboxV3RefreshHarvestResponse = PlayerDeltaResponse;

/** 沙盒V3生产收取响应（CS: SandboxV3HarvestResponse） */
export type SandboxV3HarvestResponse = PlayerDeltaResponse;

/** 沙盒V3基地进入响应（CS: SandboxV3EnterBaseResponse） */
export type SandboxV3EnterBaseResponse = PlayerDeltaResponse;

/** 沙盒V3基地商店购买响应（CS: SandboxV3BaseShopBuyResponse；服务端省略 items） */
export type SandboxV3BaseShopBuyResponse = PlayerDeltaResponse;

/** 沙盒V3基地保存响应（CS: SandboxV3BuildSaveResponse） */
export type SandboxV3BuildSaveResponse = PlayerDeltaResponse;

/** 沙盒V3基地商店出售响应（CS: SandboxV3BaseShopSellResponse） */
export type SandboxV3BaseShopSellResponse = PlayerDeltaResponse;

/** 沙盒V3基地升级响应（CS: SandboxV3HomeUpgradeResponse；服务端省略 items） */
export type SandboxV3HomeUpgradeResponse = PlayerDeltaResponse;

/** 沙盒V3创建游戏响应（CS: SandboxV3CreateGameResponse） */
export type SandboxV3CreateGameResponse = PlayerDeltaResponse;

/** 沙盒V3放弃游戏响应（CS: SandboxV3GiveUpGameResponse） */
export type SandboxV3GiveUpGameResponse = PlayerDeltaResponse;

/** 沙盒V3战斗开始响应（CS: SandboxV3BattleStartResponse : CommonStartBattleResponse；服务端省略协议字段） */
export type SandboxV3BattleStartResponse = PlayerDeltaResponse;

/** 沙盒V3战斗结束响应（CS: SandboxV3BattleFinishResponse : CommonFinishBattleResponse；服务端省略结果字段） */
export type SandboxV3BattleFinishResponse = PlayerDeltaResponse;

/** 沙盒V3更改防御响应（CS: SandboxV3ChangeDefendResponse） */
export type SandboxV3ChangeDefendResponse = PlayerDeltaResponse;

/** 沙盒V3选择乐队响应（CS: SandboxV3ChooseBandResponse） */
export type SandboxV3ChooseBandResponse = PlayerDeltaResponse;

/** 沙盒V3每日招募响应（CS: SandboxV3DayPassRecruitResponse） */
export type SandboxV3DayPassRecruitResponse = PlayerDeltaResponse;

/** 沙盒V3进食响应（CS: SandboxV3EatFoodResponse） */
export type SandboxV3EatFoodResponse = PlayerDeltaResponse;

/** 沙盒V3事件选择响应（CS: SandboxV3EventChoiceResponse；服务端省略 items/finish） */
export type SandboxV3EventChoiceResponse = PlayerDeltaResponse;

/** 沙盒V3获取每日招募列表响应（CS: SandboxV3GetDayPassRecruitListResponse；服务端省略 subProfessionList/tempCharList/rookieCharList） */
export type SandboxV3GetDayPassRecruitListResponse = PlayerDeltaResponse;

/** 沙盒V3进入下一天响应（CS: SandboxV3NextDayResponse） */
export type SandboxV3NextDayResponse = PlayerDeltaResponse;

/** 沙盒V3初始化招募响应（CS: SandboxV3InitRecruitResponse） */
export type SandboxV3InitRecruitResponse = PlayerDeltaResponse;

/** 沙盒V3结算游戏响应（CS: SandboxV3SettleGameResponse；服务端省略 score/reward/detail） */
export type SandboxV3SettleGameResponse = PlayerDeltaResponse;

/** 沙盒V3商店购买响应（CS: SandboxV3ShopBuyResponse；服务端省略 items） */
export type SandboxV3ShopBuyResponse = PlayerDeltaResponse;

/** 沙盒V3商店购买招募响应（CS: SandboxV3ShopBuyRecruitResponse） */
export type SandboxV3ShopBuyRecruitResponse = PlayerDeltaResponse;

/** 沙盒V3商店刷新响应（CS: SandboxV3ShopRefreshResponse） */
export type SandboxV3ShopRefreshResponse = PlayerDeltaResponse;

/** 沙盒V3商店出售响应（CS: SandboxV3ShopSellResponse；服务端省略 items） */
export type SandboxV3ShopSellResponse = PlayerDeltaResponse;

/** 沙盒V3解锁科技响应（CS: SandboxV3UnlockTechResponse） */
export type SandboxV3UnlockTechResponse = PlayerDeltaResponse;
