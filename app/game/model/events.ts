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
  /** 干员升级事件 - 干员等级提升 */
  "char:levelUp": [{ charId: string; level: number }];
  /** 干员精英化事件 - 干员精英化 */
  "char:evolve": [{ charId: string; phase: number }];
  /** 干员技能升级事件 - 干员技能升级 */
  "char:skillUp": [{ charId: string; skillIndex: number; level: number }];
  /** 干员潜能提升事件 - 干员潜能提升 */
  "char:potential": [{ charId: string; potential: number }];
  /** 角色初始化事件 - 新角色初始化 */
  "char:init": [PlayerCharacter];
  /** 物品使用事件 - 消耗物品 */
  "items:use": [ItemBundle[]];
  /** 物品获取事件 - 获得物品 */
  "items:get": [ItemBundle[]];
  /** 获得物品事件 - 获得物品 */
  "item:get": [{ items: ItemBundle[] }];
  /** 使用物品事件 - 使用物品 */
  "item:use": [{ items: ItemBundle[] }];
  /** 玩家等级提升事件 - 玩家等级提升 */
  "player:levelUp": [{ level: number }];
  /** 玩家登录事件 - 玩家登录 */
  "player:login": [{ playerId: string }];
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
  /** 战斗完成事件 - 战斗完成 */
  "battle:complete": [{ stageId: string; result: string }];
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
  /** 肉鸽V2节点完成事件 */
  "rlv2:node:complete": [{ nodeId: string }];
  /** 肉鸽V2游戏结束事件 */
  "rlv2:game:end": [{ score: number; rank: string }];
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
  /** 任务完成事件 */
  "mission:complete": [{ missionId: string }];
  /** 任务进度更新事件 */
  "mission:update": [{ missionId: string; progress: number }];
  /** 任务奖励领取事件 */
  "mission:reward": [{ missionId: string; items: ItemBundle[] }];
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

  // 日志相关事件
  /** 事件日志事件 - 记录事件日志 */
  "log:event": [{ eventName: string; timestamp: number }];
};

/**
 * 类型化事件发射器类
 * 
 * 继承自 Emittery，提供类型安全的事件发布和订阅功能。
 */
export class TypedEventEmitter extends Emittery<EventMap> {}

/**
 * 事件优先级枚举
 *
 * 定义事件的优先级，用于事件调度和处理顺序控制。
 */
export enum Priority {
  HIGH = 0,
  MEDIUM = 1,
  LOW = 2,
}

/**
 * 事件中间件接口
 *
 * 用于在事件触发前/后执行自定义逻辑，可用于日志、校验、拦截等场景。
 */
export interface EventMiddleware<T extends keyof EventMap> {
  before?(
    eventName: T,
    args: EventMap[T]
  ): void | boolean | Promise<void | boolean>;
  after?(eventName: T, args: EventMap[T]): void | Promise<void>;
}

/**
 * 事件验证器类型
 *
 * 用于在事件触发前验证参数合法性，返回 false 则阻止事件触发。
 */
export type EventValidator<T extends keyof EventMap> = (
  args: EventMap[T]
) => boolean;

/**
 * 优先级监听器存储结构
 *
 * 外层 Map 的键为事件名称，内层 Map 的键为优先级，值为该优先级下的监听器集合。
 */
type PriorityListenerMap = Map<string, Map<Priority, Set<Function>>>;

/**
 * 事件总线类
 *
 * 继承自 TypedEventEmitter，在 Emittery 基础上扩展优先级监听器管理能力。
 * 支持 HIGH / MEDIUM / LOW 三种优先级，事件派发时按优先级顺序依次执行：
 * HIGH → MEDIUM → LOW，同一优先级内的监听器按注册顺序执行。
 *
 * 保留对 Emittery 原有 API（on / off / emit 等）的完全兼容性，
 * 未指定优先级的监听器继续通过 Emittery 内部机制处理。
 */
export class EventBus extends TypedEventEmitter {
  /**
   * 优先级监听器存储
   *
   * 以事件名为键，值为该事件不同优先级的监听器映射。
   */
  private priorityListeners: PriorityListenerMap = new Map();

  /**
   * 中间件存储
   *
   * 按注册顺序存储所有事件中间件，在事件派发前后执行。
   */
  private middlewares: EventMiddleware<keyof EventMap>[] = [];

  /**
   * 日志开关
   *
   * 默认为关闭状态，需要通过 enableLogging() 主动开启。
   */
  private loggingEnabled: boolean = false;

  /**
   * 验证器存储
   *
   * 以事件名为键，值为该事件注册的验证器集合。
   */
  private validators: Map<string, EventValidator<keyof EventMap>> = new Map();

  /**
   * 严格验证模式开关
   *
   * 默认为 false。开启后，验证失败会阻止事件派发；
   * 关闭时仅输出警告日志，不阻止事件。
   */
  private strictValidation: boolean = false;

  /**
   * 注册带优先级的事件监听器
   *
   * 覆盖父类 Emittery 的 on 方法，默认使用 MEDIUM 优先级。
   *
   * @param eventName 事件名称
   * @param listener  监听器函数
   * @param priority  优先级，默认为 {@link Priority.MEDIUM}
   */
  // @ts-expect-error Emittery 父类签名包含复杂泛型（数组事件名、predicate 等），
  // 此处收窄为单一事件名 + 优先级参数，行为上向后兼容。
  on<T extends keyof EventMap>(
    eventName: T,
    listener: (...args: EventMap[T]) => void,
    priority: Priority = Priority.MEDIUM
  ): void {
    this.addPriorityListener(eventName, listener as Function, priority);
  }

  /**
   * 移除带优先级的事件监听器
   *
   * 若未指定 priority，则在所有优先级中查找并移除匹配的监听器。
   *
   * @param eventName 事件名称
   * @param listener  要移除的监听器函数
   * @param priority  可选，指定要移除的优先级
   */
  // @ts-expect-error 同 on，签名收窄。
  off<T extends keyof EventMap>(
    eventName: T,
    listener: (...args: EventMap[T]) => void,
    priority?: Priority
  ): void {
    const listenerMap = this.priorityListeners.get(eventName as string);
    if (!listenerMap) return;

    const target = listener as Function;

    if (priority !== undefined) {
      const set = listenerMap.get(priority);
      if (set) {
        set.delete(target);
        if (set.size === 0) {
          listenerMap.delete(priority);
        }
      }
    } else {
      for (const [, set] of listenerMap) {
        set.delete(target);
      }
    }

    if (listenerMap.size === 0) {
      this.priorityListeners.delete(eventName as string);
    }
  }

  /**
   * 发射事件
   *
   * 先按 HIGH → MEDIUM → LOW 的顺序依次执行带优先级的监听器
   * （同一优先级内按注册顺序执行），随后调用父类 Emittery 的 emit
   * 以保持与原有 API 的完全兼容。
   *
   * @param eventName 事件名称
   * @param args      事件参数
   */
  async emit<T extends keyof EventMap>(
    eventName: T,
    ...args: EventMap[T]
  ): Promise<void> {
    const startTime = this.loggingEnabled ? performance.now() : 0;

    const validator = this.validators.get(eventName as string);
    if (validator) {
      const passed = validator(args);
      if (!passed) {
        console.warn(
          `[EventBus] Validation failed for event: ${eventName} args: ${JSON.stringify(args)}`
        );
        if (this.strictValidation) {
          if (this.loggingEnabled) {
            const duration = (performance.now() - startTime).toFixed(3);
            console.log(
              `[EventBus] emit: ${eventName} args: ${JSON.stringify(args)} time: ${duration}ms (blocked by validation)`
            );
          }
          return;
        }
      }
    }

    for (const mw of this.middlewares) {
      if (mw.before) {
        const result = await mw.before(eventName, args);
        if (result === false) {
          if (this.loggingEnabled) {
            const duration = (performance.now() - startTime).toFixed(3);
            console.log(
              `[EventBus] emit: ${eventName} args: ${JSON.stringify(args)} time: ${duration}ms (blocked)`
            );
          }
          return;
        }
      }
    }

    const listenerMap = this.priorityListeners.get(eventName as string);
    if (listenerMap) {
      const orderedPriorities: Priority[] = [
        Priority.HIGH,
        Priority.MEDIUM,
        Priority.LOW,
      ];
      for (const priority of orderedPriorities) {
        const set = listenerMap.get(priority);
        if (!set) continue;
        for (const listener of Array.from(set)) {
          await (listener as (...a: unknown[]) => void)(...(args as unknown[]));
        }
      }
    }
    await Emittery.prototype.emit.call(
      this,
      eventName,
      args[0]
    );

    for (const mw of this.middlewares) {
      if (mw.after) {
        await mw.after(eventName, args);
      }
    }

    if (this.loggingEnabled) {
      const duration = (performance.now() - startTime).toFixed(3);
      console.log(
        `[EventBus] emit: ${eventName} args: ${JSON.stringify(args)} time: ${duration}ms`
      );
    }
  }

  /**
   * 订阅事件，返回取消订阅函数
   *
   * 便于使用 `const unsub = bus.subscribe('x', fn); unsub();` 的模式。
   *
   * @param eventName 事件名称
   * @param listener  监听器函数
   * @param priority  优先级，默认为 {@link Priority.MEDIUM}
   * @returns 取消订阅函数，调用后将移除该监听器
   */
  subscribe<T extends keyof EventMap>(
    eventName: T,
    listener: (...args: EventMap[T]) => void,
    priority: Priority = Priority.MEDIUM
  ): () => void {
    this.on(eventName, listener, priority);
    return () => this.off(eventName, listener, priority);
  }

  /**
   * 注册一次性监听器
   *
   * 监听器首次触发后会自动移除。
   *
   * @param eventName 事件名称
   * @param listener  监听器函数
   * @param priority  优先级，默认为 {@link Priority.MEDIUM}
   */
  // @ts-expect-error Emittery 父类 once 返回 Promise 且签名不同，此处重新定义。
  once<T extends keyof EventMap>(
    eventName: T,
    listener: (...args: EventMap[T]) => void,
    priority: Priority = Priority.MEDIUM
  ): void {
    const wrapper = ((...args: unknown[]) => {
      this.off(eventName, wrapper as (...a: EventMap[T]) => void, priority);
      (listener as (...a: unknown[]) => void)(...args);
    }) as (...args: EventMap[T]) => void;
    this.on(eventName, wrapper, priority);
  }

  /**
   * 注册事件中间件
   *
   * 中间件可在事件派发前（before）和派发后（after）执行自定义逻辑，
   * before 返回 false 可阻止事件继续传播。
   * 中间件按注册顺序执行。
   *
   * @param middleware 事件中间件
   */
  useMiddleware<T extends keyof EventMap>(
    middleware: EventMiddleware<T>
  ): void {
    this.middlewares.push(
      middleware as EventMiddleware<keyof EventMap>
    );
  }

  enableLogging(): void {
    this.loggingEnabled = true;
  }

  disableLogging(): void {
    this.loggingEnabled = false;
  }

  /**
   * 启用或关闭严格验证模式
   *
   * 开启后，验证失败会阻止事件继续派发；关闭时仅输出警告日志。
   *
   * @param enabled 是否开启严格模式
   */
  setStrictValidation(enabled: boolean): void {
    this.strictValidation = enabled;
  }

  /**
   * 当前是否处于严格验证模式
   */
  isStrictValidation(): boolean {
    return this.strictValidation;
  }

  /**
   * 为指定事件添加验证器
   *
   * 事件派发前会先调用验证器校验参数合法性。
   * 若验证器返回 false，根据严格模式决定是否阻止事件派发。
   *
   * @param eventName 事件名称
   * @param validator 验证器函数
   */
  addValidator<T extends keyof EventMap>(
    eventName: T,
    validator: EventValidator<T>
  ): void {
    this.validators.set(eventName as string, validator as EventValidator<keyof EventMap>);
  }

  /**
   * 移除指定事件的验证器
   *
   * @param eventName 事件名称
   */
  removeValidator<T extends keyof EventMap>(eventName: T): void {
    this.validators.delete(eventName as string);
  }

  /**
   * 构建当前 EventBus 对应的验证中间件
   *
   * 返回的中间件会读取当前 validators 与 strictValidation 状态，
   * 可通过 {@link useMiddleware} 注册到同一 EventBus 或其他总线实例上。
   */
  createValidationMiddleware(): EventMiddleware<keyof EventMap> {
    return createValidationMiddleware(this.validators, this.strictValidation);
  }

  getListenerCount(eventName?: keyof EventMap): number {
    let count = 0;

    if (eventName) {
      const listenerMap = this.priorityListeners.get(eventName as string);
      if (listenerMap) {
        for (const [, set] of listenerMap) {
          count += set.size;
        }
      }
      count += super.listenerCount(eventName);
    } else {
      for (const [, listenerMap] of this.priorityListeners) {
        for (const [, set] of listenerMap) {
          count += set.size;
        }
      }
      count += super.listenerCount();
    }

    return count;
  }

  getRegisteredEvents(): string[] {
    const eventSet = new Set<string>();

    for (const [eventName] of this.priorityListeners) {
      eventSet.add(eventName);
    }

    return Array.from(eventSet);
  }

  /**
   * 添加一个带优先级的监听器到内部存储
   *
   * @param eventName 事件名称
   * @param listener  监听器函数
   * @param priority  优先级
   */
  private addPriorityListener(
    eventName: string,
    listener: Function,
    priority: Priority
  ): void {
    let listenerMap = this.priorityListeners.get(eventName);
    if (!listenerMap) {
      listenerMap = new Map();
      this.priorityListeners.set(eventName, listenerMap);
    }
    let set = listenerMap.get(priority);
    if (!set) {
      set = new Set();
      listenerMap.set(priority, set);
    }
    set.add(listener);
  }
}

export const globalEventBus = new EventBus();

export function createLoggingMiddleware(): EventMiddleware<keyof EventMap> {
  let startTime: number = 0;

  return {
    before(eventName, args) {
      startTime = performance.now();
      console.log(
        `[EventBus] emit: ${eventName} args: ${JSON.stringify(args)}`
      );
    },
    after(eventName, args) {
      const duration = (performance.now() - startTime).toFixed(3);
      console.log(
        `[EventBus] complete: ${eventName} time: ${duration}ms`
      );
    },
  };
}

/**
 * 创建验证中间件
 *
 * 中间件在事件派发前检查是否存在注册的验证器：
 * - 若无验证器，直接放行；
 * - 若有验证器且校验通过，放行；
 * - 若校验失败，输出警告信息，并根据 strictValidation 决定是否阻止事件。
 *
 * @param validators       验证器映射（通常来自 EventBus 内部 validators）
 * @param strictValidation 是否启用严格模式，默认 false
 */
export function createValidationMiddleware(
  validators: Map<string, EventValidator<keyof EventMap>>,
  strictValidation: boolean = false
): EventMiddleware<keyof EventMap> {
  return {
    before(eventName, args) {
      const validator = validators.get(eventName as string);
      if (!validator) return;

      const passed = validator(args);
      if (!passed) {
        console.warn(
          `[EventBus] Validation failed for event: ${eventName} args: ${JSON.stringify(args)}`
        );
        if (strictValidation) {
          return false;
        }
      }
    },
  };
}