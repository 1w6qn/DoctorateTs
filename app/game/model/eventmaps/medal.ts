/**
 * 勋章领域事件映射（Medal）
 *
 * 集中定义勋章系统的领域事件：
 * - 勋章生命周期：完成 / 解锁 / 奖励领取
 * - 勋章追踪模板事件（template 语义的事件名），由各玩法动作 emit，
 *   MedalManager 的勋章模板按 template 名订阅
 */
import type { PlayerDataManager } from "@game/manager/PlayerDataManager";
import type { PlayerCharacter } from "@game/model/character";

/**
 * 勋章领域事件映射
 */
export type EventMapMedal = {
  /** 勋章完成事件 */
  "medal:complete": [{ medalId: string }];
  /** 勋章解锁事件 */
  "medal:unlock": [{ medalId: string }];
  /** 勋章奖励领取事件 */
  "medal:reward": [{ medalId: string }];

  /** 玩家等级提升（勋章追踪） */
  PlayerLevel: [{ level: number }];
  /** 加入游戏天数（勋章追踪） */
  JoinGameDays: [{ registerTs: number }];
  /** 角色数量（勋章追踪） */
  CharNum: [{ curCharInstId: number }];
  /** 招募次数（勋章追踪） */
  RecruitCount: [];
  /** 关卡完成情况（勋章追踪） */
  PassStageSome: [PlayerDataManager];
  /** 任务完成情况（勋章追踪） */
  MissionCompleteSome: [{ count: number }];
  /** 累计获得指定活动材料（勋章追踪，act53side TotalSimpleTokenCount：param[3]=材料列表） */
  TotalSimpleTokenCount: [{ itemId: string; count: number }];
  /** 累计获得活动货币（ActivityCoinGain：param[1]=activityId，param[2]=目标，param[3]=活动币 itemId） */
  ActivityCoinGain: [{ itemId: string; count: number }];
  /** 累计消耗龙门币（CostGold：param[1]=目标；升级/晋升耗币 emit {goldCost}） */
  CostGold: [{ goldCost: number }];
  /** 干员升级与晋升累计消耗龙门币（CostGoldPlus：param[1]=目标） */
  CostGoldPlus: [{ goldCostPlus: number }];
  /** 通关关卡且满足条件次数（勋章追踪，act53side PassStageWithSimpleCountMore；enemyStats=当关各敌人击杀计数） */
  PassStageWithSimpleCountMore: [
    {
      stageId: string;
      completeState: number;
      enemyStats?: { Key: { enemyId: string; counterType: string }; Value: number }[];
    },
  ];
  /** arkodc 变量序列达标（勋章追踪，act53side ArkodcVarSeqAtLeast：读 topic.varSeqs） */
  ArkodcVarSeqAtLeast: [{ activityId: string; varSeqs: Record<string, number> }];
  /** 干员精英化次数（勋章追踪，补声明——medal.ts CharEvolveCount 模板监听） */
  CharEvolveCount: [{ char: PlayerCharacter }];
  /** 干员信赖档位（勋章追踪，补声明——medal.ts CharFavorCount 模板监听） */
  CharFavorCount: [{ favorPoint: number }];
  /** 获得干员（勋章追踪，补声明——medal.ts GotChars 模板监听） */
  GotChars: [{ char: PlayerCharacter }];
  /** 累计签到次数（勋章追踪，补声明——medal.ts TotalCheckinCount 模板监听） */
  TotalCheckinCount: [];
  /** 技能升级次数（勋章追踪，补声明——medal.ts CharSkillCount 模板监听） */
  CharSkillCount: [{ targetLevel: number }];
  /** 潜能提升次数（勋章追踪，补声明——medal.ts CharPotential 模板监听） */
  CharPotential: [{ targetLevel: number }];
  /** 基建放置建筑（勋章追踪） */
  Sbv2PlaceBuilding: [];
  /** 基建通关裂隙（勋章追踪） */
  Sbv2PassRiftLevel: [{ level: number }];
  /** 基建通关裂隙次数（勋章追踪） */
  Sbv2PassRiftCount: [];
  /** 基建捕获动物（勋章追踪） */
  Sbv2CatchAnimal: [];
  /** 基建解锁科技（勋章追踪） */
  Sbv2UnlockTech: [];
  /** 基建生存天数（勋章追踪） */
  Sbv2SurviveDays: [{ days: number }];
  /** 基建击杀Boss（勋章追踪） */
  Sbv2KillBoss: [];
  /** 肉鸽V2通关节点（勋章追踪） */
  Rlv2PassNode: [];
  /** 肉鸽V2通行证等级（勋章追踪） */
  Rlv2BpLevel: [{ level: number }];
  /** 永久升级（勋章追踪） */
  PermUpgrade: [];
  /** 使用炼金（勋章追踪） */
  UseAlchemy: [];
  /** 肉鸽V2招募（勋章追踪） */
  Rlv2Recruit: [];
  /** 肉鸽V2获得队伍奖励（勋章追踪） */
  Rlv2GetTeamReward: [];
  /** 肉鸽V2结局收集（勋章追踪） */
  Rlv2EndingCollect: [{ ending: string }];
  /** 肉鸽V2收集遗物（勋章追踪） */
  Rlv2CollectRelic: [{ relicId: string }];
  /** 肉鸽V2使用指定角色完成战斗（勋章追踪） */
  Rlv2FinishBattleWithSpecChar: [{ charId: string }];
  /** 肉鸽V2指定难度通关结局（勋章追踪） */
  Rlv2EndingWithModeGrade: [{ ending: string; grade: number }];
  /** 肉鸽V2解锁乐队（勋章追踪） */
  Rlv2UnlockBand: [];
  /** 肉鸽V2图腾共鸣（勋章追踪） */
  Rlv2TotemResonance: [];
  /** 肉鸽V2完成节点任务（勋章追踪） */
  Rlv2CompleteNodeMission: [];
  /** 肉鸽V2获得胶囊（勋章追踪） */
  Rlv2GainCapsule: [];
  /** 基建家具主题数量（勋章追踪） */
  BuildingGotFurnitureThemeCount: [{ count: number }];
  /** 基建制造产品次数（勋章追踪） */
  BuildingManufactureProductTimes: [{ count: number }];
  /** 基建工坊合成（勋章追踪） */
  BuildingWorkshopSynthesisGroupByID: [{ groupId: string }];
  /** 限时获取角色（勋章追踪） */
  GotCharsBeforeTime: [{ charId: string }];
  /** 活动代币消耗（勋章追踪） */
  ActivityCoinCost: [{ coinType: string; cost: number }];
  /** 活动里程碑点数（勋章追踪） */
  ActivityMilestonePoint: [{ point: number }];
  /** 限时获取物品（勋章追踪） */
  GotItemBeforeTime: [{ itemId: string }];
  /** 危机合约维度分数总计（勋章追踪） */
  CrisisV2DimScoreTotal: [{ score: number }];
  /** 危机合约解锁节点（勋章追踪，每局通关 +1） */
  CrisisV2NodeSome: [];
  /** 危机合约维度分数达标（勋章追踪，峰值得分） */
  CrisisV2DimScoreSome: [{ score: number }];
  /** 危机合约V2使用助战（勋章追踪） */
  CrisisV2UseAssist: [{ used: number }];
  /** 危机合约分数达标（勋章追踪，峰值得分） */
  CrisisStageScoreSome: [{ score: number }];
  /** 危机合约完成任务（勋章追踪） */
  CrisisTaskSome: [{ count: number }];
  /** 危机合约解锁永久符文（勋章追踪） */
  CrisisUnlockPermRuneSome: [{ count: number }];
  /** 危机合约使用助战（勋章追踪） */
  CrisisUseAssist: [{ used: number }];
  /** 危机合约临时派遣结算（CrisisTempClearSome：每结算局 +1） */
  CrisisTempClearSome: [{ count: number }];
  /** 危机合约限时达成得分（CrisisStageScoreBeforeTime：峰值 score） */
  CrisisStageScoreBeforeTime: [{ score: number }];
  /** 重构符文关卡得分（RecalRuneStageScoreSome：峰值 score；由 recal battleFinish 发） */
  RecalRuneStageScoreSome: [{ score: number }];
};