/**
 * 关卡（quest）请求 zod schema
 *
 * 对应 protocol/quest.ts 的 Request 类型（部分复用 model/battle.ts 的
 * CommonStartBattleRequest，参考 CS 2.7.61 协议类），供 router/quest.ts
 * 经 validateBody 做运行时校验：缺失必填字段 / 类型不符时返回 HTTP 4xx，
 * 避免非法 body 传入控制器抛 500。
 *
 * 约定：
 * - 复杂嵌套对象（slots/squad/continuous/assistFriend/battleData）用 z.json()，
 *   仅保证键存在、不深检，避免对客户端完整结构误伤。
 * - .optional() 表示服务端不读或抓包确认可不传的字段。
 */
import { z } from "zod";

/** 编队请求（CS: SquadFormationRequest { squadId, slots, changeSkill? }） */
export const squadFormationSchema = z.object({
  squadId: z.number(),
  // slots 为 PlayerSquadItem[]——handler 只做 Array.isArray 判定后整段写入
  // troop.squads[squadId].slots（不读元素字段），故按被读层级收紧到「JSON 数组」
  slots: z.array(z.json()),
  changeSkill: z.number().optional(),
});

/** 编队重命名请求（CS: SquadRenameRequest { squadId, name }） */
export const changeSquadNameSchema = z.object({
  squadId: z.number(),
  name: z.string(),
});

/** 获取助战列表请求（CS: GetFriendAssistCharListRequest { profession, askRefresh?, currSquadId? }） */
export const getAssistListSchema = z.object({
  profession: z.string(),
  askRefresh: z.number().optional(),
  currSquadId: z.string().optional(),
});

/**
 * 战斗开始请求（CS: CommonStartBattleRequest；squad/continuous/assistFriend 为嵌套对象）
 * 三者整包转发给 battle.start（由 kernel/battle 读取内层字段），故用 z.json() 原样透传，
 * 不用精确 schema——否则 zod 会剥掉未声明的内层字段改变开战数据。
 */
export const battleStartSchema = z.object({
  isRetro: z.number(),
  pray: z.number(),
  battleType: z.number(),
  continuous: z.json(),
  usePracticeTicket: z.number(),
  stageId: z.string(),
  squad: z.json(),
  assistFriend: z.json(),
  isReplay: z.number(),
  startTs: z.number(),
});

/** 战斗结算请求（CS: CommonFinishBattleRequest { data, battleData }；battleData 完整战报透传给 battle.finish） */
export const battleFinishSchema = z.object({
  data: z.string(),
  battleData: z.json(),
});

/** 获取战斗回放请求（CS: LoadBattleReplayRequest { stageId }） */
export const getBattleReplaySchema = z.object({
  stageId: z.string(),
});

/** 保存战斗回放请求（CS: SaveBattleReplayRequest { battleId, battleReplay }） */
export const saveBattleReplaySchema = z.object({
  battleId: z.string(),
  battleReplay: z.string(),
});

/** 继续战斗请求（服务端自定义，无请求体字段） */
export const battleContinueSchema = z.object({});

/** 完成剧情关卡请求（CS: SpecialStoryStageRewardRequest { stageId }） */
export const finishStoryStageSchema = z.object({
  stageId: z.string(),
});

/** 编辑六星干员标记请求（CS: UI.Stage.EditStageSixStarTagRequest { stageId, selected }；selected 行情可为数字/字符串 id） */
export const editStageSixStarTagSchema = z.object({
  stageId: z.string(),
  selected: z.array(z.union([z.string(), z.number()])),
});

/** 获取特殊关卡（牛关）奖励请求（CS: SpecialStoryStageRewardRequest { stageId }） */
export const getCowLevelRewardSchema = z.object({
  stageId: z.string(),
});

/** 获取主线记录奖励请求（CS: ZoneRecordRewardRequest { stageId: string[] }） */
export const getMainlineRecordRewardsSchema = z.object({
  stageId: z.array(z.string()),
});

/** 获取主线缓存请求（CS: GetMainlineCacheRequest，无字段） */
export const getMainlineCacheSchema = z.object({});

/** 解锁关卡迷雾请求（服务端自定义，CS 无请求类；{ stageId }） */
export const unlockStageFogSchema = z.object({
  stageId: z.string(),
});

/** 解锁隐藏关卡请求（服务端自定义 { stageId }） */
export const unlockHideStageSchema = z.object({
  stageId: z.string(),
});

/** 确认六星奖励请求（服务端抓包 { groupId?, rewardIds? }，两者均可选） */
export const confirmSixStarRewardSchema = z.object({
  groupId: z.string().optional(),
  rewardIds: z.array(z.string()).optional(),
});