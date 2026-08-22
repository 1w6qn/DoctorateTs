/**
 * 沙盒（生息演算）请求 zod schema
 *
 * 对应 protocol/sandbox.ts 的 Request 类型（参考 CS 2.7.61 协议类），
 * 供 router/sandbox.ts 经 validateBody 做运行时校验：缺失必填字段 /
 * 类型不符时返回 HTTP 4xx，避免非法 body 传入控制器抛 500。
 *
 * 约定（与 rlv2.schema.ts 一致）：
 * - z.any() 表示"键必须存在、值类型不深检"（如 material/ownChar 这类复杂嵌套对象，
 *   仅保证出现，避免对客户端完整结构误伤）。
 * - .optional() 表示服务端不读或抓包确认可不传的字段。
 * - 空请求体用 z.object({})。
 * - 主题切换/固定及多数 V2 占位端点为 stub（handler 不读取 body），字段标为可选，
 *   避免对既有跳过的请求误伤；V3 中 handler 实际读取的 topicId/techId 标为必填。
 */
import { z } from "zod";

/* ===== 主题切换 / 固定（stub，服务端不读 body） ===== */

/** 切换沙盒主题（CS: SandboxPermChangeTopicRequest { topicId }）；stub 不读，标为可选 */
export const changeTopicSchema = z.object({
  topicId: z.string().optional(),
});

/** 固定沙盒主题（CS: SandboxPermPinTopicRequest { topicId }）；stub 不读，标为可选 */
export const pinTopicSchema = z.object({
  topicId: z.string().optional(),
});

/* ===== 沙盒 V2 ===== */

/** 沙盒V2创建游戏（CS: SandboxV2CreateGameRequest { topicId }）；stub 不读，标为可选 */
export const v2CreateGameSchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V2战斗开始（CS: SandboxV2BattleStartRequest { topicId, nodeId, squadIdx }）；stub 不读，标为可选 */
export const v2BattleStartSchema = z.object({
  topicId: z.string().optional(),
  nodeId: z.string().optional(),
  squadIdx: z.number().optional(),
});

/** 沙盒V2战斗结束（CS: SandboxV2BattleFinishRequest，服务端不读取） */
export const v2BattleFinishSchema = z.object({});

/** 沙盒V2进食（CS: SandboxV2DineRequest { topicId, charInstId, foodInstId }）；stub 不读，标为可选 */
export const v2DineSchema = z.object({
  topicId: z.string().optional(),
  charInstId: z.number().optional(),
  foodInstId: z.string().optional(),
});

/** 沙盒V2烹饪饮品（CS: SandboxV2CookDrinkRequest { topicId, material, food }）；material/food 为复杂数组，用 z.any() */
export const v2CookDrinkSchema = z.object({
  topicId: z.string().optional(),
  material: z.any().optional(),
  food: z.any().optional(),
});

/** 沙盒V2烹饪食物（CS: SandboxV2CookFoodRequest { topicId, main, sub, count }）；stub 不读，标为可选 */
export const v2CookFoodSchema = z.object({
  topicId: z.string().optional(),
  main: z.array(z.string()).optional(),
  sub: z.array(z.string()).optional(),
  count: z.number().optional(),
});

/** 沙盒V2设置编队（CS: SandboxV2SetSquadRequest { topicId, index, slots, tools }）；slots 为复杂数组，用 z.any() */
export const v2SetSquadSchema = z.object({
  topicId: z.string().optional(),
  index: z.number().optional(),
  slots: z.any().optional(),
  tools: z.array(z.string()).optional(),
});

/** 沙盒V2结算游戏（CS: SandboxV2SettleGameRequest { topicId }）；stub 不读，标为可选 */
export const v2SettleGameSchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V2基地建造保存（服务端自定义，无 CS 对应类；handler 不读取 body） */
export const v2HomeBuildSaveSchema = z.object({});

/** 沙盒V2月度战斗开始（CS: SandboxV2MonthBattleStartRequest { topicId, squadIdx, monthRushId }）；stub 不读，标为可选 */
export const v2MonthBattleStartSchema = z.object({
  topicId: z.string().optional(),
  squadIdx: z.number().optional(),
  monthRushId: z.string().optional(),
});

/** 沙盒V2月度战斗结束（服务端不读取） */
export const v2MonthBattleFinishSchema = z.object({});

/** 沙盒V2探索模式（CS: SandboxV2ExploreModeRequest { topicId, mode }）；stub 不读，标为可选 */
export const v2ExploreModeSchema = z.object({
  topicId: z.string().optional(),
  mode: z.number().optional(),
});

/** 沙盒V2事件选择（CS: SandboxV2EventChoiceRequest { topicId, nodeId, eventId, choiceId }）；stub 不读，标为可选 */
export const v2EventChoiceSchema = z.object({
  topicId: z.string().optional(),
  nodeId: z.string().optional(),
  eventId: z.string().optional(),
  choiceId: z.string().optional(),
});

/** 沙盒V2炼金术（CS: SandboxV2AlchemyRequest { topicId, recipeId, count }）；stub 不读，标为可选 */
export const v2AlchemySchema = z.object({
  topicId: z.string().optional(),
  recipeId: z.string().optional(),
  count: z.number().optional(),
});

/** 沙盒V2基地升级（CS: SandboxV2BasementUpgradeRequest { topicId }）；stub 不读，标为可选 */
export const v2BaseUpgradeSchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V2建造（CS: SandboxV2ConstructOperationRequest { topicId, nodeId, operation, catchedAnimals }）；operation/catchedAnimals 为复杂结构，用 z.any() */
export const v2BuildSchema = z.object({
  topicId: z.string().optional(),
  nodeId: z.string().optional(),
  operation: z.any().optional(),
  catchedAnimals: z.any().optional(),
});

/** 沙盒V2烹饪（合成）（CS: SandboxV2CraftRequest { topicId, itemId, count, autoSquad }）；stub 不读，标为可选 */
export const v2CookSchema = z.object({
  topicId: z.string().optional(),
  itemId: z.string().optional(),
  count: z.number().optional(),
  autoSquad: z.number().optional(),
});

/** 沙盒V2放弃行动点（CS: SandboxV2DiscardApRequest { topicId }）；stub 不读，标为可选 */
export const v2DiscardApSchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V2进入挑战（CS: SandboxV2StartChallengeRequest { topicId }）；stub 不读，标为可选 */
export const v2EnterChallengeSchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V2退出挑战（CS: SandboxV2ChallengeExitRequest { topicId }）；stub 不读，标为可选 */
export const v2ExitChallengeSchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V2提取（服务端自定义，无 CS 对应类；handler 不读取 body） */
export const v2ExtractSchema = z.object({});

/** 沙盒V2获取挑战奖励（CS: SandboxV2GetChallengeRewardRequest { topicId, rewardIds }）；stub 不读，标为可选 */
export const v2GetChallengeRewardSchema = z.object({
  topicId: z.string().optional(),
  rewardIds: z.array(z.string()).optional(),
});

/** 沙盒V2引导加载（CS: SandboxV2GuideLoadRequest { topicId }）；stub 不读，标为可选 */
export const v2GuideLoadSchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V2加载（读档）（CS: SandboxV2LoadArchiveRequest { topicId }）；stub 不读，标为可选 */
export const v2LoadSchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V2进入下一天（CS: SandboxV2NextDayRequest { topicId }）；stub 不读，标为可选 */
export const v2NextDaySchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V2移除补给（CS: SandboxV2RemoveSupplyRequest { topicId, charInstId }）；stub 不读，标为可选 */
export const v2RemoveSupplySchema = z.object({
  topicId: z.string().optional(),
  charInstId: z.number().optional(),
});

/** 沙盒V2裂隙关闭（CS: SandboxV2RiftCloseRequest { topicId }）；stub 不读，标为可选 */
export const v2RiftCloseSchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V2裂隙创建（CS: SandboxV2RiftCreateRequest { topicId }）；stub 不读，标为可选 */
export const v2RiftCreateSchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V2裂隙设置难度（CS: SandboxV2RiftSetDifficultyRequest { topicId, difficulty }）；stub 不读，标为可选 */
export const v2RiftSetDifficultySchema = z.object({
  topicId: z.string().optional(),
  difficulty: z.string().optional(),
});

/** 沙盒V2裂隙设置队伍（CS: SandboxV2RiftSetTeamRequest { topicId, team }）；stub 不读，标为可选 */
export const v2RiftSetTeamSchema = z.object({
  topicId: z.string().optional(),
  team: z.string().optional(),
});

/** 沙盒V2裂隙结算（CS: SandboxV2RiftSettleRequest { topicId }）；stub 不读，标为可选 */
export const v2RiftSettleSchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V2设置补给（CS: SandboxV2SetSupplyRequest { topicId, charList }）；stub 不读，标为可选 */
export const v2SetSupplySchema = z.object({
  topicId: z.string().optional(),
  charList: z.array(z.number()).optional(),
});

/** 沙盒V2结算挑战（CS: SandboxV2ChallengeSettleRequest { topicId }）；stub 不读，标为可选 */
export const v2SettleChallengeSchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V2结算天数（CS: SandboxV2SettleDayRequest { topicId }）；stub 不读，标为可选 */
export const v2SettleDaySchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V2商店购买（CS: SandboxV2ShopBuyRequest { topicId, index, count }）；stub 不读，标为可选 */
export const v2ShopBuySchema = z.object({
  topicId: z.string().optional(),
  index: z.number().optional(),
  count: z.number().optional(),
});

/** 沙盒V2开始任务（服务端自定义，无 CS 对应类；handler 不读取 body） */
export const v2StartMissionSchema = z.object({});

/** 沙盒V2切换模式（服务端自定义，CS 仅有 V3 类；handler 不读取 body） */
export const v2SwitchModeSchema = z.object({});

/** 沙盒V2解锁科技（CS: SandboxV2ScienceUnlockRequest { topicId, techId }）；stub 不读，标为可选 */
export const v2UnlockTechSchema = z.object({
  topicId: z.string().optional(),
  techId: z.string().optional(),
});

/* ===== 沙盒 V2 竞速 ===== */

/** 沙盒竞速战斗结束（CS: SandboxV2RacingBattleFinishRequest，服务端不读取） */
export const racingBattleFinishSchema = z.object({});

/** 沙盒竞速战斗开始（CS: SandboxV2RacingBattleStartRequest { topicId, nodeId, instId }）；stub 不读，标为可选 */
export const racingBattleStartSchema = z.object({
  topicId: z.string().optional(),
  nodeId: z.string().optional(),
  instId: z.string().optional(),
});

/** 沙盒竞速学习天赋（CS: SandboxV2RacingLearnTalentRequest { topicId, instId }）；stub 不读，标为可选 */
export const racingLearnTalentSchema = z.object({
  topicId: z.string().optional(),
  instId: z.string().optional(),
});

/** 沙盒竞速注册（CS: SandboxV2RacingRegisterRequest { topicId, instId }）；stub 不读，标为可选 */
export const racingRegisterSchema = z.object({
  topicId: z.string().optional(),
  instId: z.string().optional(),
});

/** 沙盒竞速释放（CS: SandboxV2RacingReleaseRequest { topicId, instIds, tmp }）；stub 不读，标为可选 */
export const racingReleaseSchema = z.object({
  topicId: z.string().optional(),
  instIds: z.array(z.string()).optional(),
  tmp: z.number().optional(),
});

/** 沙盒竞速保存标记（CS: SandboxV2RacingSaveMarkRequest { topicId, instId, mark }）；stub 不读，标为可选 */
export const racingSaveMarkSchema = z.object({
  topicId: z.string().optional(),
  instId: z.string().optional(),
  mark: z.number().optional(),
});

/** 沙盒V2竞速小游戏 stub（/v2/racing/*，统一 handler 不读取 body） */
export const v2RacingStubSchema = z.object({});

/* ===== 沙盒 V3 ===== */

/** 沙盒V3切换模式（CS: SandboxV3SwitchModeRequest { topicId, modeId }）；stub 不读，标为可选 */
export const v3SwitchModeSchema = z.object({
  topicId: z.string().optional(),
  modeId: z.string().optional(),
});

/** 沙盒V3生产刷新（CS: SandboxV3RefreshHarvestRequest { topicId }）；handler 读取 topicId，标为必填 */
export const v3ProductionRefreshSchema = z.object({
  topicId: z.string(),
});

/** 沙盒V3生产收取（CS: SandboxV3HarvestRequest { topicId }）；handler 读取 topicId，标为必填 */
export const v3ProductionHarvestSchema = z.object({
  topicId: z.string(),
});

/** 沙盒V3基地进入（CS: SandboxV3EnterBaseRequest { topicId }）；stub 不读，标为可选 */
export const v3HomeEnterSchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V3基地商店购买（CS: SandboxV3BaseShopBuyRequest { topicId, goodId, count }）；stub 不读，标为可选 */
export const v3HomeShopBuySchema = z.object({
  topicId: z.string().optional(),
  goodId: z.string().optional(),
  count: z.number().optional(),
});

/** 沙盒V3基地保存（CS 仅存在 SandboxV3BuildSaveResponse，无请求类；handler 不读取 body） */
export const v3HomeSaveSchema = z.object({});

/** 沙盒V3基地商店出售（CS: SandboxV3BaseShopSellRequest { topicId, itemId, count }）；stub 不读，标为可选 */
export const v3HomeShopSellSchema = z.object({
  topicId: z.string().optional(),
  itemId: z.string().optional(),
  count: z.number().optional(),
});

/** 沙盒V3基地升级（CS: SandboxV3HomeUpgradeRequest { topicId }）；stub 不读，标为可选 */
export const v3HomeUpgradeSchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V3创建游戏（CS: SandboxV3CreateGameRequest { topicId, nodeId, difficultyId }）；handler 读取 topicId，标为必填 */
export const v3CreateGameSchema = z.object({
  topicId: z.string(),
  nodeId: z.string().optional(),
  difficultyId: z.string().optional(),
});

/** 沙盒V3放弃游戏（CS: SandboxV3GiveUpGameRequest { topicId }）；handler 读取 topicId，标为必填 */
export const v3GiveUpGameSchema = z.object({
  topicId: z.string(),
});

/** 沙盒V3战斗开始（CS: SandboxV3BattleStartRequest { topicId }）；stub 不读，标为可选 */
export const v3BattleStartSchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V3战斗结束（CS: SandboxV3BattleFinishRequest，服务端不读取） */
export const v3BattleFinishSchema = z.object({});

/** 沙盒V3更改防御（CS: SandboxV3ChangeDefendRequest { topicId, zoneId, operate, chars }）；handler 读取 topicId，标为必填 */
export const v3ChangeDefendSchema = z.object({
  topicId: z.string(),
  zoneId: z.string().optional(),
  operate: z.number().optional(),
  chars: z.array(z.number()).optional(),
});

/** 沙盒V3选择乐队（CS: SandboxV3ChooseBandRequest { topicId, bandId }）；stub 不读，标为可选 */
export const v3ChooseBandSchema = z.object({
  topicId: z.string().optional(),
  bandId: z.string().optional(),
});

/** 沙盒V3每日招募（CS: SandboxV3DayPassRecruitRequest { topicId, ownChar, thirdChar }）；ownChar/thirdChar 为复杂对象，用 z.any() */
export const v3DailyRecruitSchema = z.object({
  topicId: z.string().optional(),
  ownChar: z.any().optional(),
  thirdChar: z.any().optional(),
});

/** 沙盒V3进食（CS: SandboxV3EatFoodRequest { topicId, charInstId, cookbook, sub }）；stub 不读，标为可选 */
export const v3EatFoodSchema = z.object({
  topicId: z.string().optional(),
  charInstId: z.number().optional(),
  cookbook: z.string().optional(),
  sub: z.array(z.string()).optional(),
});

/** 沙盒V3事件选择（CS: SandboxV3EventChoiceRequest { topicId, choiceId, charList }）；stub 不读，标为可选 */
export const v3EventChoiceSchema = z.object({
  topicId: z.string().optional(),
  choiceId: z.string().optional(),
  charList: z.array(z.number()).optional(),
});

/** 沙盒V3获取每日招募列表（CS: SandboxV3GetDayPassRecruitListRequest { topicId, refresh }）；stub 不读，标为可选 */
export const v3GetDailyRecruitListSchema = z.object({
  topicId: z.string().optional(),
  refresh: z.number().optional(),
});

/** 沙盒V3进入下一天（CS: SandboxV3NextDayRequest { topicId }）；stub 不读，标为可选 */
export const v3NextDaySchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V3初始化招募（CS: SandboxV3InitRecruitRequest { topicId, ownChars, assistFriend }）；ownChars/assistFriend 为复杂结构，用 z.any() */
export const v3InitRecruitSchema = z.object({
  topicId: z.string().optional(),
  ownChars: z.any().optional(),
  assistFriend: z.any().optional(),
});

/** 沙盒V3结算游戏（CS: SandboxV3SettleGameRequest { topicId }）；stub 不读，标为可选 */
export const v3SettleGameSchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V3商店购买（CS: SandboxV3ShopBuyRequest { topicId, index, count }）；stub 不读，标为可选 */
export const v3ShopBuySchema = z.object({
  topicId: z.string().optional(),
  index: z.number().optional(),
  count: z.number().optional(),
});

/** 沙盒V3商店购买招募（CS: SandboxV3ShopBuyRecruitRequest { topicId }）；stub 不读，标为可选 */
export const v3ShopBuyRecruitSchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V3商店刷新（CS: SandboxV3ShopRefreshRequest { topicId }）；stub 不读，标为可选 */
export const v3ShopRefreshSchema = z.object({
  topicId: z.string().optional(),
});

/** 沙盒V3商店出售（CS: SandboxV3ShopSellRequest { topicId, itemId, count }）；stub 不读，标为可选 */
export const v3ShopSellSchema = z.object({
  topicId: z.string().optional(),
  itemId: z.string().optional(),
  count: z.number().optional(),
});

/** 沙盒V3解锁科技（CS: SandboxV3UnlockTechRequest { topicId, techId }）；handler 读取 topicId/techId，标为必填 */
export const v3UnlockTechSchema = z.object({
  topicId: z.string(),
  techId: z.string(),
});