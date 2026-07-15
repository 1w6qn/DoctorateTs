/**
 * 游戏事件系统接口定义
 * 
 * 定义了游戏中所有事件类型及其参数，用于模块间的解耦通信。
 * 基于 Emittery 实现类型安全的事件发布/订阅机制。
 */

import { ItemBundle } from "@excel/character_table";
import { GachaResult } from "@game/model/gacha";
import { BattleData, CommonStartBattleRequest } from "@game/model/battle";
import {
  PlayerRoguelikeV2,
  RoguelikeBuff,
  RoguelikeItemBundle,
} from "@game/model/rlv2";
import { PlayerCharacter } from "@game/model/character";
import { RoguelikeV2Controller } from "@game/controller/rlv2";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import Emittery from "emittery";

/**
 * 事件映射类型
 * 
 * 定义所有游戏事件的名称和参数类型。
 * 键为事件名称，值为事件参数数组。
 */
export type EventMap = {
  /** 保存事件 - 触发数据持久化 */
  save: [];
  /** 游戏修复事件 - 触发游戏数据修复 */
  "game:fix": [];
  /** 状态时间刷新事件 - 刷新时间相关状态 */
  "status:refresh:time": [];
  /** 月度刷新事件 - 触发月度数据刷新 */
  "refresh:monthly": [];
  /** 周度刷新事件 - 触发周度数据刷新 */
  "refresh:weekly": [];
  /** 每日刷新事件 - 触发每日数据刷新 */
  "refresh:daily": [number];
  /** 关卡更新事件 - 关卡进度更新 */
  "stage:update": [];
  /** 角色获取事件 - 获取新角色 */
  "char:get": [string, { from: string }?, ((res: GachaResult) => void)?];
  /** 角色升级事件 - 角色等级提升 */
  "char:levelUp": [number];
  /** 角色初始化事件 - 新角色初始化 */
  "char:init": [PlayerCharacter];
  /** 物品使用事件 - 消耗物品 */
  "items:use": [ItemBundle[]];
  /** 物品获取事件 - 获得物品 */
  "items:get": [ItemBundle[]];
  /** 玩家升级事件 - 玩家等级提升 */
  "player:levelUp": [];
  /** 基建角色初始化事件 - 基建角色初始化 */
  "building:char:init": [PlayerCharacter];
  /** 战斗保存事件 - 保存战斗信息 */
  "save:battle": [string, { stageId: string; isPractice: number }];
  /** 战斗开始事件 - 开始战斗 */
  "battle:start": [CommonStartBattleRequest];
  /** 战斗结束事件 - 战斗完成 */
  "battle:finish": [
    {
      data: string;
      battleData: { isCheat: string; completeTime: number };
    },
  ];
  /** 背景获取事件 - 获取背景 */
  "background:get": [string];
  /** 背景解锁事件 - 解锁背景 */
  "background:unlock": [{ bgID: string }];
  /** 背景条件更新事件 - 更新背景解锁条件 */
  "background:condition:update": [string, string, number];
  /** 家园主题获取事件 - 获取家园主题 */
  "homeTheme:get": [string];
  /** 家园主题条件更新事件 - 更新家园主题条件 */
  "homeTheme:condition:update": [
    {
      themeId: string;
      conditionId: string;
      target: number;
    },
  ];
  /** 家园主题解锁事件 - 解锁家园主题 */
  "homeTheme:unlock": [{ themeId: string }];
  /** 招募标签刷新事件 - 刷新招募标签 */
  "recruit:refresh:tags": [{ slotId: number }];
  /** 开服活动登录事件 - 开服活动登录奖励 */
  "openserver:chain:login": [number];

  // RLV2 (肉鸽V2) 相关事件
  /** 肉鸽V2初始化事件 */
  "rlv2:init": [RoguelikeV2Controller];
  /** 肉鸽V2模块初始化事件 */
  "rlv2:module:init": [];
  /** 肉鸽V2创建事件 */
  "rlv2:create": [RoguelikeV2Controller];
  /** 肉鸽V2继续事件 */
  "rlv2:continue": [];
  /** 肉鸽V2移动事件 */
  "rlv2:move": [];
  /** 肉鸽V2获取物品事件 */
  "rlv2:get:items": [RoguelikeItemBundle[]];
  /** 肉鸽V2升级事件 */
  "rlv2:levelUp": [number];
  /** 肉鸽V2招募获取事件 */
  "rlv2:recruit:gain": [string, string, number];
  /** 肉鸽V2招募激活事件 */
  "rlv2:recruit:active": [string];
  /** 肉鸽V2招募完成事件 */
  "rlv2:recruit:done": [string, string];
  /** 肉鸽V2角色获取事件 */
  "rlv2:char:get": [PlayerRoguelikeV2.CurrentData.RecruitChar];
  /** 肉鸽V2选择初始招募组事件 */
  "rlv2:choose_init_recruit_set": [string[]];
  /** 肉鸽V2遗物获取事件 */
  "rlv2:relic:gain": [RoguelikeItemBundle];
  /** 肉鸽V2遗物回收事件 */
  "rlv2:relic:recycle": [string];
  /** 肉鸽V2遗物放置事件 */
  "rlv2:relic:put": [string];
  /** 肉鸽V2事件创建事件 */
  "rlv2:event:create": [string, object];
  /** 肉鸽V2buff应用事件 */
  "rlv2:buff:apply": [[...RoguelikeBuff[]]];
  /** 肉鸽V2区域新事件 */
  "rlv2:zone:new": [number];
  /** 肉鸽V2战斗开始事件 */
  "rlv2:battle:start": [string];
  /** 肉鸽V2战斗结束事件 */
  "rlv2:battle:finish": [
    {
      battleLog: string;
      data: string;
      battleData: BattleData;
    },
  ];
  /** 肉鸽V2银行存入事件 */
  "rlv2:bankPut": [boolean];
  /** 肉鸽V2银行取出事件 */
  "rlv2:bank:withdraw": [];
  /** 肉鸽V2灾祸抽象事件 */
  "rlv2:disaster:abstract": [];
  /** 肉鸽V2灾祸生成事件 */
  "rlv2:disaster:generate": [];
  /** 肉鸽V2节点附着事件 */
  "rlv2:node:attach": [string[], string[]];
  /** 肉鸽V2节点升级事件 */
  "rlv2:node:upgrade": [string];
  /** 肉鸽V2碎片获取事件 */
  "rlv2:fragment:gain": [string];
  /** 肉鸽V2碎片设置队伍携带事件 */
  "rlv2:fragment:set_troop_carry": [string[]];
  /** 肉鸽V2碎片使用灵感事件 */
  "rlv2:fragment:use_inspiration": [string];
  /** 肉鸽V2碎片改变类型权重事件 */
  "rlv2:fragment:change_type_weight": [RoguelikeBuff];
  /** 肉鸽V2碎片最大权重增加事件 */
  "rlv2:fragment:max_weight:add": [number];
  /** 肉鸽V2碎片使用事件 */
  "rlv2:fragment:use": [string, number];
  /** 肉鸽V2碎片丢失事件 */
  "rlv2:fragment:lose": [string];

  // 任务相关事件
  /** 完成任意类型关卡 */
  CompleteStageAnyType: [BattleData];
  /** 关卡击杀敌人 */
  StageWithEnemyKill: [BattleData & { stageId: string }];
  /** 任意关卡击杀敌人 */
  EnemyKillInAnyStage: [BattleData];
  /** 使用助战角色通关 */
  StageWithAssistChar: [BattleData & { assistFriend: any }];
  /** 升级角色 */
  UpgradeChar: [{ char: PlayerCharacter; exp: number }];
  /** 获得社交点数 */
  ReceiveSocialPoint: [{ socialPoint: number }];
  /** 购买商店物品 */
  BuyShopItem: [{ type: string; socialPoint: number }];
  /** 普通抽卡 */
  NormalGacha: [];
  /** 获得信赖度 */
  GainIntimacy: [{ count: number }];
  /** 制造物品 */
  ManufactureItem: [{ item: ItemBundle; count: number }];
  /** 交付订单 */
  DeliveryOrder: [{ count: number }];
  /** 恢复角色理智 */
  RecoverCharBaseAp: [{ count: number }];
  /** 访问基建 */
  VisitBuilding: [];
  /** 升级技能 */
  UpgradeSkill: [{ targetLevel: number }];
  /** 编队 */
  SquadFormation: [];
  /** 完成关卡 */
  CompleteStage: [BattleData & { stageId: string; isPractice: number }];
  /** 升级玩家 */
  UpgradePlayer: [{ level: number }];
  /** 完成任意关卡 */
  CompleteAnyStage: [BattleData & { stageId: string }];
  /** 拥有角色 */
  HasChar: [{ char: PlayerCharacter }];
  /** 拥有装备 */
  HasEquipment: [{ char: PlayerCharacter }];
  /** 精二角色 */
  EvolveChar: [{ char: PlayerCharacter }];
  /** 舒适度DIY */
  DiyComfort: [{ comfort: number }];
  /** 拥有房间 */
  HasRoom: [{ roomCount: number }];
  /** 工坊合成 */
  WorkshopSynthesis: [{ item: ItemBundle }];
  /** 专精升级 */
  UpgradeSpecialization: [{ targetLevel: number }];
  /** 战斗击杀敌人 */
  BattleWithEnemyKill: [BattleData & { stageId: string }];
  /** 角色信赖度 */
  CharIntimacy: [{ favorPoint: number }];
  /** 完成突破奖励 */
  CompleteBreakReward: [];
  /** 开启信息分享 */
  StartInfoShare: [];
  /** 编辑名片 */
  EditBusinessCard: [];
  /** 设置助战角色列表 */
  SetAssistCharList: [];
  /** 更改队伍名称 */
  ChangeSquadName: [];
  /** 关卡回放 */
  StageWithReplay: [{ isReplay: number }];
  /** 接管回放 */
  TakeOverReplay: [BattleData];
  /** 完成活动关卡 */
  CompleteCampaign: [BattleData & { stageId: string }];
  /** 设置基建助手 */
  SetBuildingAssist: [];
  /** 潜能提升 */
  BoostPotential: [{ targetLevel: number }];
  /** 工坊额外加成 */
  WorkshopExBonus: [];
  /** 普通抽卡提升 */
  BoostNormalGacha: [];
  /** 完成主线关卡 */
  CompleteMainStage: [BattleData & { stageId: string }];
  /** 发送线索 */
  SendClue: [];
  /** 获得组队角色 */
  GainTeamChar: [];
  /** 加速订单 */
  AccelerateOrder: [];
  /** 消耗理智 */
  CostAp: [{ ap: number }];
  /** 肉鸽V2结算游戏 */
  Rlv2SettleGame: [{ data: PlayerRoguelikeV2 }];
  /** 肉鸽V2结算游戏次数 */
  Rlv2SettleGameTimes: [];

  // 勋章相关事件
  /** 勋章完成事件 */
  "medal:complete": [{ medalId: string }];
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
  /** 危机合约解锁节点（勋章追踪） */
  CrisisV2NodeSome: [];
  /** 危机合约维度分数达标（勋章追踪） */
  CrisisV2DimScoreSome: [{ score: number }];
  /** 危机合约使用助战（勋章追踪） */
  CrisisV2UseAssist: [];
  /** 危机合约分数达标（勋章追踪） */
  CrisisStageScoreSome: [{ score: number }];
  /** 危机合约完成任务（勋章追踪） */
  CrisisTaskSome: [];
  /** 危机合约解锁永久符文（勋章追踪） */
  CrisisUnlockPermRuneSome: [];
  /** 危机合约使用助战（勋章追踪） */
  CrisisUseAssist: [];
};

/**
 * 类型化事件发射器类
 * 
 * 继承自 Emittery，提供类型安全的事件发布和订阅功能。
 */
export class TypedEventEmitter extends Emittery<EventMap> {}