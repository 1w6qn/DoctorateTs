/**
 * 任务管理器
 * 
 * 负责明日方舟中所有类型任务的管理，包括：
 * - 每日任务（DAILY）：每日刷新的常规任务
 * - 每周任务（WEEKLY）：每周一刷新的进阶任务
 * - 活动任务（ACTIVITY）：限时活动期间的特殊任务
 * - 开服任务（OPENSERVER）：服务器开启期间的限时任务
 * 
 * 任务系统核心机制：
 * 1. 任务按阶段解锁，完成前置任务后自动解锁下一任务
 * 2. 完成任务可获得任务点数，累计点数可兑换奖励
 * 3. 每日/每周任务到期自动重置进度
 */
import { MissionCalcState } from "../model/playerdata";
import excel from "@excel/excel";
import { ItemBundle } from "@excel/character_table";
import { PlayerCharacter } from "../model/character";
import { BattleData } from "../model/battle";
import { checkBetween, now, userTimestamp } from "@utils/time";
import { EventMap, TypedEventEmitter } from "@game/model/events";
import { MissionData } from "@excel/types_excel_gen";
import { PlayerDataManager } from "./PlayerDataManager";
import { logger } from "@utils/logger";

export class MissionManager {
  missions: { [key: string]: MissionProgress[] };
  /** init() 的 promise（构造期异步执行；AccountManager 加载后 await 它再播种活动任务） */
  initPromise?: Promise<void>;
  _trigger: TypedEventEmitter;
  _player: PlayerDataManager;

  /**
   * 构造函数
   * @param player 玩家数据管理器实例
   * @param _trigger 事件发射器实例
   */
  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this.missions = {};
    this._trigger.on("refresh:weekly", this.weeklyRefresh.bind(this));
    this._trigger.on("refresh:daily", this.dailyRefresh.bind(this));
  }

  /**
   * 获取当前每日任务周期ID
   * 根据当前时间和星期几，从配置表中获取对应的每日任务组ID
   */
  get dailyMissionPeriod(): string {
    const ts = now();
    // 修复：`getDay()+1` 把周日(0)→1、周五(5)→6，与配置表 1=周一..7=周日的
    // 周期编号错位（周日匹配到工作日组、周五匹配到周末组）；先映射周日→7
    const weekDay = new Date().getDay() === 0 ? 7 : new Date().getDay();
    const period = excel.MissionTable.dailyMissionPeriodInfo.find(
      (p) => p.startTime <= ts && p.endTime >= ts,
    )!;
    return period.periodList.find((p) =>
      p.period.includes(weekDay),
    )!.missionGroupId;
  }

  /**
   * 获取当前每日任务奖励周期ID
   * 根据当前时间和星期几，从配置表中获取对应的奖励组ID
   */
  get dailyMissionRewardPeriod(): string {
    const ts = now();
    // 修复：同 dailyMissionPeriod——getDay()+1 星期错位，先映射周日→7
    const weekDay = new Date().getDay() === 0 ? 7 : new Date().getDay();
    const period = excel.MissionTable.dailyMissionPeriodInfo.find(
      (p) => p.startTime <= ts && p.endTime >= ts,
    )!;
    return period.periodList.find((p) =>
      p.period.includes(weekDay),
    )!.rewardGroupId;
  }

  /**
   * 初始化任务系统
   * 遍历所有任务类型，为每个任务创建MissionProgress实例并初始化
   */
  async init() {
    // 先补 ACTIVITY 空分组（Immer draft 内不创建 MissionProgress，避免模板 push 到冻结 draft）
    await this._player.update(async (draft) => {
      draft.mission.missions["ACTIVITY"] = {};
    });
    for (const [type, v] of Object.entries(
      this._player._playerdata.mission.missions,
    )) {
      // 填充内存任务列表（confirmMission/getMissionById 依赖）
      this.missions[type] = [];
      for (const [id] of Object.entries(v)) {
        const mission = new MissionProgress(id, type, this._player);
        await mission.init();
        // 无效任务（数据表缺失）跳过——不进入内存列表
        if (mission.valid) {
          this.missions[type].push(mission);
        }
      }
    }
  }

  /**
   * 根据任务ID获取任务进度实例
   * @param missionId 任务ID
   * @returns MissionProgress实例（任务不在数据表/内存列表时返回 undefined，调用方自行判空）
   */
  async getMissionById(
    missionId: string,
  ): Promise<MissionProgress | undefined> {
    // 防御：数据表缺失（版本错位/下架任务）时 .type 解引用会 500
    const missionInfo = excel.MissionTable.missions[missionId];
    if (!missionInfo) return undefined;
    const type = missionInfo.type;
    return this.missions[type]?.filter((m) => m.missionId == missionId)[0];
  }

  /**
   * 每日任务刷新
   * 重置每日任务进度和奖励状态，加载新的每日任务列表
   */
  async dailyRefresh() {
    // 修复：退订旧实例监听器（防泄漏 + 旧进度写回新任务）
    for (const m of this.missions["DAILY"] ?? []) {
      m.unsubscribe();
    }
    await this._player.update(async (draft) => {
      draft.mission.missionRewards.dailyPoint = 0;
      draft.mission.missionRewards.rewards["DAILY"] = {};
      for (const reward of Object.values(
        excel.MissionTable.periodicalRewards,
      )) {
        // 防御：数据表末尾混入字段名伪键（值 null 的转换产物，如 "groupId"/"id"）
        // → reward.groupId 读 null 崩溃（2026-08-14 线上 daily refresh 500）
        if (!reward || typeof reward !== "object") continue;
        if (reward.groupId == this.dailyMissionRewardPeriod) {
          draft.mission.missionRewards.rewards["DAILY"][reward.id] = 0;
        }
      }
      // 修复：播种当前周期组任务到存档（原实现只重建内存列表——存档仍是创建时的旧组
      // 任务，当前组 id 在存档缺失 → init 全部 invalid → DAILY 列表空 → confirmMission
      // 拿不到实例返回空 → "任务无法确认"；且客户端仍显示旧组 state=3 任务，点确认无响应）。
      // 官方每日重置即替换当日任务组：删旧组条目、补新组条目（progress:[] 由模板 init 构建）。
      const currentIds =
        excel.MissionTable.missionGroups[this.dailyMissionPeriod].missionIds ??
        [];
      const daily = (draft.mission.missions["DAILY"] ??= {});
      for (const id of Object.keys(daily)) {
        if (!currentIds.includes(id)) delete daily[id];
      }
      for (const id of currentIds) {
        if (!daily[id]) {
          daily[id] = { state: 1, progress: [] };
        }
      }
    });
    const missionIds =
      excel.MissionTable.missionGroups[this.dailyMissionPeriod].missionIds;
    // 修复：原实现直接 new 不 init → progress 空/无监听器，刷新后任务系统失效；
    // 逐实例 init（与 Manager.init 一致，无效任务跳过）
    this.missions["DAILY"] = [];
    for (const missionId of missionIds) {
      const mission = new MissionProgress(missionId, "DAILY", this._player);
      await mission.init();
      if (mission.valid) {
        this.missions["DAILY"].push(mission);
      }
    }
  }

  /**
   * 每周任务刷新
   * 重置每周任务进度和奖励状态，加载新的每周任务列表
   */
  async weeklyRefresh() {
    // 修复：退订旧实例监听器（防泄漏 + 旧进度写回新任务）
    for (const m of this.missions["WEEKLY"] ?? []) {
      m.unsubscribe();
    }
    await this._player.update(async (draft) => {
      draft.mission.missionRewards.weeklyPoint = 0;
      draft.mission.missionRewards.rewards["WEEKLY"] = {};
    });
    // 修复：原实现 new 后不 init（progress 空/无监听器）；逐实例 init
    this.missions["WEEKLY"] = [];
    for (const mission of Object.values(excel.MissionTable.missions).filter(
      // 防御：数据表末尾字段名伪键（值 null）——m.type 读 null 崩溃，跳过
      (m): m is MissionData => !!m && typeof m === "object" && m.type == "WEEKLY",
    )) {
      const instance = new MissionProgress(
        mission.id,
        "WEEKLY",
        this._player,
      );
      await instance.init();
      if (instance.valid) {
        this.missions["WEEKLY"].push(instance);
      }
    }
  }

  /**
   * 重建 ACTIVITY 任务进度实例（活动播种后调用）
   *
   * MissionManager.init 在活动播种（unlockActivity）之前执行——init 时 ACTIVITY
   * 组为空（播种任务尚未写入），播种后的新任务没有 MissionProgress 实例/监听器，
   * 事件驱动进度（奇象巡展 8 类 Arkhub 模板）无法生效。此方法退订旧实例并按其
   * 当前存档重建（与 dailyRefresh 同款：无效任务跳过）。
   */
  async reloadActivity(): Promise<void> {
    for (const m of this.missions["ACTIVITY"] ?? []) {
      m.unsubscribe();
    }
    this.missions["ACTIVITY"] = [];
    const saveMissions = this._player._playerdata.mission.missions["ACTIVITY"] ?? {};
    for (const missionId of Object.keys(saveMissions)) {
      const mission = new MissionProgress(missionId, "ACTIVITY", this._player);
      await mission.init();
      if (mission.valid) {
        this.missions["ACTIVITY"].push(mission);
      }
    }
  }

  /**
   * 确认完成任务并领取奖励
   * @param missionId 任务ID
   * @returns 获得的物品奖励列表
   * 
   * 任务状态定义（参照明日方舟Torappu.MissionHoldingState）：
   * - 0: 未解锁（前置任务未完成）
   * - 1: 未接取（已解锁但未开始）
   * - 2: 进行中（已接取且未完成）
   * - 3: 已完成（可领取奖励）
   */
  async confirmMission(args: { missionId: string }): Promise<ItemBundle[]> {
    const { missionId } = args;
    const missionInfo = excel.MissionTable.missions[missionId];
    if (!missionInfo) {
      // 活动任务（ActivityTable.missionData，如 1arkhubActivity_*/53sideActivity_*）
      // 兜底领取——枢纽任务奖励同步 ARK_HUB.coin/tshop 币（官服形状）
      return this._confirmActivityTableMission(missionId);
    }
    const mission = await this.getMissionById(missionId);
    const items: ItemBundle[] = [];
    // 修复：确认判定以存档为准（内存列表可能因每日刷新重建/旧周期组为空——
    // 客户端仍显示存档中已完成可领取的任务，此前 getMissionById 拿不到实例直接返回空
    // → "无法领取奖励"）；持久化 confirmed 标记防重复（原仅内存实例标记，重启/列表
    // 重建后丢失 → 可重复刷周期点数）。
    // 再修复：按**进度**判定完成（对齐 opendoctoratepy-ex-public：所有 progress 项
    // value>=target 即可领取并置 state=3），而非要求 state==3——state 可能因事件链
    // 失败/旧存档未置 3（progress 已满但 state 仍为 2），仅查 state 会拒绝发放。
    if (mission?.confirmed) return items;
    await this._player.update(async (draft) => {
      const data = draft.mission.missions[missionInfo.type]?.[missionId];
      if (
        !data ||
        !Array.isArray(data.progress) ||
        data.progress.length === 0
      ) {
        return;
      }
      // confirmed 为服务端持久化的防重复标记（官方结构无此字段，按 any 访问）
      const full = data.progress.every((p) => p.value >= p.target);
      // 修复：state=3 是"已完成可领取"而非"已领取"——任务进度填满时 init 事件回调即置 3
      //（见 init），此刻奖励尚未发放。原 guard 把 data.state===3 一并视为已领 → 已完成待领取
      // 的任务 confirmMission 直接 return（items 空、dailyPoint 不累计）→ 客户端"显示待领取
      // 却无法领取"。改以新增的 confirmed 标记判重（发放时置 1），state 不再参与判重。
      if (!full || (data as any).confirmed) return;
      data.state = 3;
      (data as any).confirmed = 1;
      if (mission) mission.confirmed = true;
      const missionRewards = draft.mission.missionRewards;
      switch (missionInfo.type) {
        case "DAILY":
          missionRewards.dailyPoint += missionInfo.periodicalPoint;
          Object.entries(missionRewards.rewards["DAILY"]).forEach(([k, v]) => {
            const periodicalReward = excel.MissionTable.periodicalRewards[k];
            if (
              v == 0 &&
              missionRewards.dailyPoint >= periodicalReward.periodicalPointCost
            ) {
              missionRewards.dailyPoint -= periodicalReward.periodicalPointCost;
              items.push(...periodicalReward.rewards);
              missionRewards.rewards["DAILY"][k] = 1;
            }
          });
          break;
        case "WEEKLY":
          missionRewards.weeklyPoint += missionInfo.periodicalPoint;
          break;
        default:
          // 修复：MAIN/SUB/GUIDE/RETRO/SPECIAL 等非周期点任务——直接发放任务自身 rewards。
          // 原实现 default 分支空 out → 完成态任务 confirm 后 items 为空，客户端视为
          // "领取无奖励/无法领取"（2222 存档里大量 MAIN/SUB 任务即属此类）。
          for (const r of missionInfo.rewards ?? []) {
            items.push({ id: r.id, count: r.count, type: String(r.type) });
          }
          break;
      }
    });

    await this._trigger.emit("items:get", [items]);
    return items;
  }

  /**
   * 活动任务领取（ActivityTable.missionData，如 1arkhubActivity_* / 53sideActivity_*）
   *
   * 官服抓包对齐（R-1786877191677-0085 confirmMultiGroupMissionList）：领取后
   * 发 missionData.rewards、置 state=3，且枢纽任务（奖励含 act1arkhub_token_seal）
   * 同步累加 activity.ARK_HUB.act1arkhub.coin 与 tshop.shop_act1arkhub.coin。
   * @param missionId - 活动任务 ID
   * @returns 奖励物品列表（未知任务返回空）
   */
  private async _confirmActivityTableMission(
    missionId: string,
  ): Promise<ItemBundle[]> {
    const missionInfo = (excel.ActivityTable as any)?.missionData?.find(
      (m: any) => m.id === missionId,
    );
    if (!missionInfo) return [];
    const items: ItemBundle[] = (missionInfo.rewards ?? []).map((r: any) => ({
      id: r.id,
      count: r.count,
      type: String(r.type),
    }));
    let newlyCompleted = false;
    await this._player.update(async (draft) => {
      const activityMissions = (draft.mission as any)?.missions?.["ACTIVITY"];
      const data = activityMissions?.[missionId];
      if (data && data.state !== 3) {
        data.state = 3;
        newlyCompleted = true;
      }
      // 枢纽任务奖励 → ARK_HUB.coin / tshop.shop_act1arkhub.coin 同步累加
      const seal = (missionInfo.rewards ?? []).find(
        (r: any) => r.id === "act1arkhub_token_seal",
      );
      if (seal?.count) {
        const hub = (draft.activity as any)?.ARK_HUB?.act1arkhub;
        if (hub) hub.coin = (hub.coin ?? 0) + seal.count;
        const shop = (draft.tshop as any)?.["shop_act1arkhub"];
        if (shop) shop.coin = (shop.coin ?? 0) + seal.count;
      }
    });
    // 活动任务完成勋章（MissionCompleteSome，medal_activity_53side_04）：每新完成
    // 一个 53side 任务 +1，目标 = 任务列表长度
    if (newlyCompleted) {
      await this._trigger.emit("MissionCompleteSome", [{ count: 1 }]);
    }
    if (items.length > 0) {
      await this._trigger.emit("items:get", [items]);
    }
    return items;
  }

  /**
   * 确认完成任务组并领取奖励
   * @param missionGroupId 任务组ID
   * 
   * 任务组是多个相关任务的集合，完成所有任务后可领取组奖励
   */
  async confirmMissionGroup(args: { missionGroupId: string }) {
    const { missionGroupId } = args;
    const group = excel.MissionTable.missionGroups[missionGroupId];
    if (!group?.rewards) return;
    // 修复：已领取过的任务组不再发放（原实现每次调用都发放组奖励 → 重复刷）
    if (this._player._playerdata.mission.missionGroups[missionGroupId] === 1) {
      return;
    }
    await this._trigger.emit("items:get", [group.rewards]);
    await this._player.update(async (draft) => {
      draft.mission.missionGroups[missionGroupId] = 1;
    });
  }

  /**
   * 自动确认并领取所有已完成的任务奖励
   * @param type 任务类型（DAILY/WEEKLY等）
   * @returns 获得的物品奖励列表
   */
  async autoConfirmMissions(args: { type: string }): Promise<ItemBundle[]> {
    const { type } = args;
    const items: ItemBundle[] = [];
    // 对齐参考实现（opendoctoratepy-ex-public）：遍历存档该类型全部任务，由
    // confirmMission 按进度（value>=target）+ confirmed 标记判定发放——原实现只
    // 遍历内存列表（每日刷新/旧周期组导致为空）且过滤 state==2（恒不成立 →
    // 一键领取永远为空）
    const saveMissions =
      this._player._playerdata.mission.missions[type] ?? {};
    for (const missionId of Object.keys(saveMissions)) {
      items.push(...(await this.confirmMission({ missionId })));
    }
    return items;
  }

  /**
   * 使用任务点数兑换奖励
   * @param targetRewardsId 奖励ID
   * @returns 获得的物品奖励列表
   */
  async exchangeMissionRewards(args: { targetRewardsId: string }) {
    const { targetRewardsId } = args;
    const periodicalReward = excel.MissionTable.periodicalRewards[targetRewardsId];
    // 修复：原实现无已领校验、不扣点数 → 可无限刷奖励；
    // 现校验已领取状态与点数余额，发放时扣点并标记已领
    if (!periodicalReward?.rewards) return [];
    const type = periodicalReward.type === "WEEKLY" ? "WEEKLY" : "DAILY";
    const rewards: ItemBundle[] = [];
    await this._player.update(async (draft) => {
      const missionRewards = draft.mission.missionRewards;
      const claimed = missionRewards.rewards[type]?.[targetRewardsId] ?? 0;
      if (claimed !== 0) return;
      const points =
        type === "DAILY"
          ? missionRewards.dailyPoint
          : missionRewards.weeklyPoint;
      if (points < periodicalReward.periodicalPointCost) return;
      if (type === "DAILY") {
        missionRewards.dailyPoint -= periodicalReward.periodicalPointCost;
      } else {
        missionRewards.weeklyPoint -= periodicalReward.periodicalPointCost;
      }
      missionRewards.rewards[type][targetRewardsId] = 1;
      rewards.push(...periodicalReward.rewards);
    });
    await this._trigger.emit("items:get", [rewards]);
    return rewards;
  }
}

/**
 * 任务进度管理类
 * 
 * 负责单个任务的进度追踪、状态管理和事件监听。
 * 明日方舟任务系统的核心逻辑实现，包括：
 * - 根据任务模板注册相应的事件监听器
 * - 实时更新任务进度
 * - 任务完成后自动解锁下一任务
 */
export class MissionProgress {
  progress: MissionCalcState[];
  missionId: string;
  _trigger: TypedEventEmitter;
  _player: PlayerDataManager;
  param!: string[];
  type: string;
  value: number;
  state: number;
  confirmed: boolean;
  /** 任务是否有效（数据表缺失/版本错位时为 false——init 时跳过） */
  valid = true;
  /** 已注册的事件模板与监听器（供每日/每周刷新退订，防泄漏+旧进度写回） */
  private _registeredTemplate: keyof typeof MissionTemplates | null = null;
  private _registeredFunc: Function | null = null;

  /**
   * 构造函数
   * @param missionId 任务ID
   * @param type 任务类型（DAILY/WEEKLY/ACTIVITY/OPENSERVER）
   * @param player 玩家数据管理器实例
   */
  constructor(missionId: string, type: string, player: PlayerDataManager) {
    this.missionId = missionId;
    this.progress = [];
    this.value = 0;
    this.type = type;
    this._player = player;
    this._trigger = player._trigger;
    this.state = 0;
    this.confirmed = false;
  }

  /**
   * 获取当前任务状态
   * @returns 任务状态值（0-3）
   * 
   * 任务状态定义（参照明日方舟Torappu.MissionHoldingState）：
   * - 0: 未解锁（前置任务未完成）
   * - 1: 未接取（已解锁但未开始）
   * - 2: 进行中（已接取且未完成）
   * - 3: 已完成（可领取奖励）
   */
  async getState(): Promise<number> {
    // 防御：progress 未初始化（刷新后未 init 的实例）时不崩
    if (!this.progress?.[0] || !("value" in this.progress[0])) {
      return 0;
    }
    if (this.progress[0].value >= this.progress[0].target! && this.confirmed) {
      return 3;
    } else {
      const preMissionIds =
        excel.MissionTable.missions[this.missionId]?.preMissionIds;
      if (!preMissionIds) {
        return 2;
      }
      for (const i of preMissionIds) {
        // 防御：前置任务不在数据表/内存列表（下架/无效跳过）时按未完成处理，不 500
        const pre = await this._player.mission.getMissionById(i);
        if (!pre || pre.state != 3) {
          return 1;
        }
      }
      return 2;
    }
  }

  /**
   * 解锁下一个任务
   * 
   * 根据当前任务ID计算下一个任务ID，并将其状态设置为可接取（状态2）。
   * 某些任务是新阶段的起始任务，不需要解锁前置任务，这些任务被列入startList中。
   */
  async unlockNextMission() {
    const dailyStartList = [
      "daily_4801", "daily_4806", "daily_4808", "daily_4813", "daily_4814", "daily_4815",
      "daily_4816", "daily_4817", "daily_4819", "daily_4821", "daily_4822", "daily_4826",
      "daily_4829", "daily_4901", "daily_4906", "daily_4908", "daily_4913", "daily_4914",
      "daily_4915", "daily_4916", "daily_4917", "daily_4919", "daily_4921", "daily_4922",
      "daily_4926", "daily_4929", "daily_5001", "daily_5006", "daily_5008", "daily_5013",
      "daily_5014", "daily_5015", "daily_5016", "daily_5017", "daily_5019", "daily_5021",
      "daily_5022", "daily_5026", "daily_5029", "daily_5101", "daily_5106", "daily_5108",
      "daily_5113", "daily_5114", "daily_5115", "daily_5116", "daily_5117", "daily_5119",
      "daily_5121", "daily_5122", "daily_5126", "daily_5129", "daily_5201", "daily_5206",
      "daily_5208", "daily_5213", "daily_5214", "daily_5215", "daily_5216", "daily_5217",
      "daily_5219", "daily_5221", "daily_5222", "daily_5226", "daily_5229", "daily_5301",
      "daily_5306", "daily_5308", "daily_5313", "daily_5314", "daily_5315", "daily_5316",
      "daily_5317", "daily_5319", "daily_5321", "daily_5322", "daily_5326", "daily_5329",
      "daily_5401", "daily_5406", "daily_5408", "daily_5413", "daily_5414", "daily_5415",
      "daily_5416", "daily_5417", "daily_5419", "daily_5421", "daily_5422", "daily_5426",
      "daily_5429", "daily_5501", "daily_5506", "daily_5508", "daily_5513", "daily_5514",
      "daily_5515", "daily_5516", "daily_5517", "daily_5519", "daily_5521", "daily_5522",
      "daily_5526", "daily_5529", "daily_5601", "daily_5606", "daily_5608", "daily_5613",
      "daily_5614", "daily_5615", "daily_5616", "daily_5617", "daily_5619", "daily_5621",
      "daily_5622", "daily_5626", "daily_5629", "daily_5701", "daily_5706", "daily_5708",
      "daily_5713", "daily_5714", "daily_5715", "daily_5716", "daily_5717", "daily_5719",
      "daily_5721", "daily_5722", "daily_5726", "daily_5729", "daily_5801", "daily_5806",
      "daily_5808", "daily_5813", "daily_5814", "daily_5815", "daily_5816", "daily_5817",
      "daily_5819", "daily_5821", "daily_5822", "daily_5826", "daily_5829", "daily_5901",
      "daily_5906", "daily_5908", "daily_5913", "daily_5914", "daily_5915", "daily_5916",
      "daily_5917", "daily_5919", "daily_5921", "daily_5922", "daily_5926", "daily_5929",
      "daily_6001", "daily_6006", "daily_6008", "daily_6013", "daily_6014", "daily_6015",
      "daily_6016", "daily_6017", "daily_6019", "daily_6021", "daily_6022", "daily_6026",
      "daily_6029", "daily_6101", "daily_6106", "daily_6108", "daily_6113", "daily_6114",
      "daily_6115", "daily_6116", "daily_6117", "daily_6119", "daily_6121", "daily_6122",
      "daily_6126", "daily_6129", "daily_6201", "daily_6206", "daily_6208", "daily_6213",
      "daily_6214", "daily_6215", "daily_6216", "daily_6217", "daily_6219", "daily_6221",
      "daily_6222", "daily_6226", "daily_6229", "daily_6301", "daily_6306", "daily_6308",
      "daily_6313", "daily_6314", "daily_6315", "daily_6316", "daily_6317", "daily_6319",
      "daily_6321", "daily_6322", "daily_6326", "daily_6329",
    ];
    const weeklyStartList = [
      "weekly_701", "weekly_707", "weekly_708", "weekly_713", "weekly_714",
      "weekly_715", "weekly_716", "weekly_718", "weekly_720", "weekly_723",
      "weekly_725", "weekly_729", "weekly_732",
    ];

    let startList: string[];
    switch (this.type) {
      case "DAILY":
        startList = dailyStartList;
        break;
      case "WEEKLY":
        startList = weeklyStartList;
        break;
      default:
        return;
    }

    const parts = this.missionId.split("_");
    if (parts.length < 2) {
      return;
    }
    const prefix = parts[0] + "_";
    const num = parseInt(parts[1]);
    if (isNaN(num)) {
      return;
    }
    const nextNum = num + 1;
    const nextMissionId = prefix + nextNum;

    if (startList.includes(nextMissionId)) {
      return;
    }

    await this._player.update(async (draft) => {
      const missions = draft.mission.missions[this.type];
      if (nextMissionId in missions) {
        missions[nextMissionId].state = 2;
      }
    });
  }

  /**
   * 初始化任务进度
   * 
   * 从玩家数据中加载任务进度，根据任务模板注册事件监听器，
   * 监听相关游戏事件以更新任务进度。
   */
  async init() {
    const missionInfo =
      this._player._playerdata.mission.missions[this.type]?.[this.missionId];
    // 防御：数据缺失（每日刷新后新组任务未播种等）标记无效，不 500。
    // 修复：允许空 progress 的播种条目（dailyRefresh 新组任务 progress:[] 由模板 init 构建）——
    // 仅当整个条目缺失/非数组时无效
    if (!missionInfo || !Array.isArray(missionInfo.progress)) {
      this.valid = false;
      return;
    }
    this.value = missionInfo.progress[0]?.value ?? 0;
    this.progress = missionInfo.progress;
    this.state = missionInfo.state;
    let template: keyof typeof MissionTemplates;
    let mission: MissionData | undefined;
    if (this.type == "ACTIVITY") {
      // 活动任务（奇象巡展 1arkhubActivity_* / 53sideActivity_* 等）不在 MissionTable——
      // 定义在 ActivityTable.missionData（id/template/param/rewards）。原实现直接 return
      // （无监听器、进度全假）；现按模板注册监听器，事件驱动真实进度。
      // 注意：taskData 类型与 MissionData 同构（template/param），用 any 收窄。
      const actMission = (excel.ActivityTable as any)?.missionData?.find(
        (m: any) => m.id === this.missionId,
      ) as MissionData | undefined;
      if (!actMission) {
        this.valid = false;
        logger.debug("MissionManager", `Activity mission ${this.missionId} not found in ActivityTable.missionData`);
        return;
      }
      if (actMission.template in MissionTemplates) {
        template = actMission.template as keyof typeof MissionTemplates;
        this.param = actMission.param;
        // 后续 `if (mission)` 分支依赖 mission 非空——活动任务从 missionData 取
        mission = actMission as MissionData;
      } else {
        this.valid = false;
        logger.debug("MissionManager", `Invalid activity template: ${actMission.template} (${this.missionId})`);
        return;
      }
    } else if (this.type == "OPENSERVER") {
      // 开服任务数据缺失容错（excel 未初始化/版本错位）——标记无效并降级日志，避免 unhandled rejection
      const schedule = excel.OpenServerTable?.schedule;
      const group = schedule?.find((v) =>
        checkBetween(
          this._player._playerdata.status.registerTs,
          v.startTs,
          v.endTs,
        ),
      )?.id;
      if (!group) {
        this.valid = false;
        logger.debug("MissionManager", `OpenServer schedule not found (${this.missionId})`);
        return;
      }
      mission = excel.OpenServerTable!.dataMap[group].openServerMissionData.find(
        (m) => m.id == this.missionId,
      );
      if (!mission) {
        this.valid = false;
        logger.debug("MissionManager", `Mission ID ${this.missionId} not found in OpenServer data`);
        return;
      }
    } else {
      // excel 未初始化/表缺失时 mission 为 undefined → 走下方「任务不存在」降级分支（valid=false + debug）
      mission = excel.MissionTable?.missions?.[this.missionId];
    }
    if (mission) {
      if (mission.template in MissionTemplates) {
        template = mission.template as keyof typeof MissionTemplates;
        this.param = mission.param;
      } else {
        // 模板无效（数据版本错位）——标记无效并降级日志
        this.valid = false;
        logger.debug("MissionManager", `Invalid template: ${mission.template} (${this.missionId})`);
        return;
      }
    } else {
      // 任务不存在（旧版本存档任务在新数据中缺失——版本更新后常见）：
      // 标记无效并降级日志（debug），避免 ERROR 刷屏；init 循环跳过
      this.valid = false;
      logger.debug("MissionManager", `Mission ID ${this.missionId} not found in data`);
      return;
    }
    const func = async ([args]: unknown[]) => {
      MissionTemplates[template]![this.param[0]].update(this, args as never);
      if (this.progress[0].value >= this.progress[0].target!) {
        logger.info("MissionManager", `${this.missionId} complete`);
        this._trigger.off(template, func);
        await this._player.update(async (draft) => {
          draft.mission.missions[this.type][this.missionId].state = 3;
          // 修复：写回同一引用不产生 Immer patch → 进度值不进 delta，客户端进度条停滞；
          // 复制为新数组使 Immer 生成 replace patch，进度随 delta 下发
          draft.mission.missions[this.type][this.missionId].progress = [
            ...this.progress,
          ];
        });
        await this.unlockNextMission();
      } else {
        // 修复：getState 移出 recipe——Emittery.emit 并行执行所有监听器，多个同模板
        // 任务同时推进时，各 update() 的 recipe 内 await getState() 产生交错：
        // 一个 listener 的 finishDraft 撤销 draft 后，另一个 listener 的 recipe 继续
        // 写已撤销代理 → "Cannot perform 'set' on a proxy that has been revoked"，
        // 任务状态不落盘（无法完成/确认）。先算好 state，recipe 内不再 await。
        const nextState = await this.getState();
        await this._player.update(async (draft) => {
          draft.mission.missions[this.type][this.missionId].progress = [
            ...this.progress,
          ];
          draft.mission.missions[this.type][this.missionId].state = nextState;
        });
      }
    };
    // 修复：模板 init 仅在进度为空时构建进度（原实现每次 init 都 push →
    // 存档进度数组随每次刷新/加载重复累加，1.json 已出现 29 份重复条目、
    // 且 getState 读 progress[0] 恒为旧值）；已有 progress[0] 时直接沿用存档进度
    if (this.progress.length === 0) {
      MissionTemplates[template]![this.param[0]].init(this);
    }
    if (this.progress[0] && this.progress[0].value < this.progress[0].target!) {
      this._registeredTemplate = template;
      this._registeredFunc = func;
      this._trigger.on(template, func);
    }
  }

  /**
   * 退订本任务注册的事件监听器
   *
   * 每日/每周刷新重建任务列表时调用——原实现旧实例监听器永不移除：
   * 既泄漏（每次刷新叠加数百监听器），又会让旧实例把过期进度写回新任务。
   */
  unsubscribe(): void {
    if (this._registeredTemplate && this._registeredFunc) {
      this._trigger.off(
        this._registeredTemplate,
        this._registeredFunc as never,
      );
      this._registeredTemplate = null;
      this._registeredFunc = null;
    }
  }
}

/**
 * 任务模板接口
 * 定义了任务进度数据结构
 */
export interface MissionInfo {
  value: number;
  progress: MissionCalcState[];
  param: string[];
}

/**
 * 任务模板映射表
 * 
 * 参照明日方舟任务系统，定义了各种任务类型的进度追踪逻辑：
 * 
 * 任务模板分类：
 * - 关卡相关：CompleteStageAnyType, StageWithEnemyKill, EnemyKillInAnyStage, 
 *             CompleteStage, CompleteAnyStage, CompleteCampaign, CompleteMainStage,
 *             StageWithReplay, TakeOverReplay, PassStageWithSimpleCountMore等
 * - 干员相关：UpgradeChar, EvolveChar, HasChar, HasEquipment, BoostPotential,
 *             CharIntimacy, UpgradeSpecialization等
 * - 社交相关：ReceiveSocialPoint, VisitBuilding, SetAssistCharList, SendClue等
 * - 商店相关：BuyShopItem, NormalGacha等
 * - 基建相关：ManufactureItem, DeliveryOrder, DiyComfort, HasRoom, WorkshopSynthesis等
 * - 其他：GainIntimacy, UpgradeSkill, SquadFormation, EditBusinessCard等
 */
export const MissionTemplates: {
  [T in keyof Partial<EventMap>]: {
    [p: string]: {
      init: (mission: MissionInfo) => void;
      update: (mission: MissionInfo, ...args: EventMap[T]) => void;
    };
  };
} = {
  /**
   * 通关任意类型关卡累计次数
   *
   * 达成目标状态（param[2]，如 2=三星通关）即 +1，以累计通关场次为进度。
   * 典型用例：日常/周常「通关任意关卡 N 次」（如 daily_4801 param=[0,1,2]）。
   * @param param[0] 恒为 "0"（无实际作用，占位分支位）
   * @param param[1] 目标累计通关次数
   * @param param[2] 通关状态阈值（completeState >= 该值才计入）
   */
  CompleteStageAnyType: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: BattleData) => {
        const { completeState } = args;
        if (completeState >= parseInt(mission.param[2])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 指定关卡内击杀敌人（按分支细分击杀方式）
   *
   * param[0] 区分 6 种分支：
   *   0 / 3 —— 占位分支（同 param[0] 未启用），仅注册进度，update 为空
   *   1 —— 任意关卡三星通关后，按本场击杀数 killCnt 累计（日常/周常击杀任务）
   *   2 —— 指定敌人（param[2] 以 ^ 分隔 enemyId）击杀计数，标准 HP_ZERO 判定
   *   5 —— 指定关卡（param[1] ^ 分隔，可含 #f# 变体）三星后累计 killCnt
   *   6 —— 指定关卡（param[1]）内击杀达到 param[2] 即算完成 1 次
   * @param param[0] 分支标识
   * @param param[1] 目标值或关卡列表（依分支而定；目标场次/累计击杀用）
   * @param param[2] 敌人列表 / 关卡状态阈值 / 单场击杀下限（依分支而定）
   * @param param[3] 目标值或状态阈值（分支 6 用）
   */
  StageWithEnemyKill: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: () => {},
    },
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: BattleData) => {
        const { completeState } = args;
        if (completeState >= 2) {
          mission.progress[0].value += args.killCnt;
        }
      },
    },
    "2": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: BattleData) => {
        const enemies = mission.param[2].split("^");
        args.battleData.stats.enemyStats.forEach((stat) => {
          if (
            enemies.includes(stat.Key.enemyId) &&
            stat.Key.counterType == "HP_ZERO"
          ) {
            mission.progress[0].value += stat.Value;
          }
        });
      },
    },
    "3": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: () => {},
    },
    "5": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (stages.includes(args.stageId) && args.completeState >= 2) {
          mission.progress[0].value += args.killCnt;
        }
      },
    },
    "6": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[3]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId)) {
          return;
        }
        if (args.completeState < parseInt(mission.param[3])) {
          return;
        }
        if (args.killCnt >= parseInt(mission.param[2])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 任意关卡击杀敌人累计数
   *
   * 任意关卡通关状态达到 param[2] 后，累计本场击杀数 killCnt 为进度。
   * 典型用例：日常/周常「累计击杀敌人 N 个」（如 daily_4808 param=[0,100,2]）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标累计击杀数
   * @param param[2] 通关状态阈值（completeState >= 该值才累计本场击杀）
   */
  EnemyKillInAnyStage: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: BattleData) => {
        if (args.completeState < parseInt(mission.param[2])) {
          return;
        }
        mission.progress[0].value += args.killCnt;
      },
    },
  },

  /**
   * 携带助战干员通关
   *
   * 通关（completeState>=2）且本场使用助战（assistFriend 非空）即 +1，
   * 以累计携带助战通关场次为进度。
   * @param param[0] 恒为 "1"（分支标识）
   * @param param[1] 无实际作用（如 daily_4813 param=[1,1]）
   * @param param[2] 目标场次（常为 1 或 5，如 weekly_713）
   */
  StageWithAssistChar: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: BattleData & { assistFriend: any }) => {
        if (args.completeState >= 2 && args.assistFriend) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 干员养成升级（按分支细分养成口径）
   *
   * @param param[0] 分支标识：
   *   0 —— 任意干员养成事件 +1（周常「升级干员 N 次」）
   *   1 —— 干员精二达到 param[2]（evolvePhase）且等级达到 param[3] 各计 1
   *   2 —— 按累计获得的经验 exp 累加
   * @param param[1] 目标值
   * @param param[2] 精二阶段阈值（分支 1 用）
   * @param param[3] 等级阈值（分支 1 用）
   */
  UpgradeChar: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { char: PlayerCharacter }) => {
        if (args.char.evolvePhase < parseInt(mission.param[2])) {
          return;
        }
        if (args.char.level >= parseInt(mission.param[3])) {
          mission.progress[0].value += 1;
        }
      },
    },
    "2": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { exp: number }) => {
        mission.progress[0].value += args.exp;
      },
    },
  },

  /**
   * 获得社交点（助战信任点）
   *
   * @param param[0] 分支标识：
   *   0 —— 按累计收到的社交点 socialPoint 累加
   *   1 —— 事件触发一次 +1（如 daily_4815 param=[1,1]，周常=5次）
   * @param param[1] 目标值
   */
  ReceiveSocialPoint: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { socialPoint: number }) => {
        mission.progress[0].value += args.socialPoint;
      },
    },
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 购买商店物品（按分支细分商店来源）
   *
   * @param param[0] 分支标识：
   *   0 —— 购买任何商店（LS/HS/ES=物资/高层/标准商城）物品各计 1
   *   1 —— 购买信用交易所（SOCIAL）物品各计 1
   *   3 —— 购买信用交易所时按消费的社交点 socialPoint 累计
   * @param param[1] 目标值
   */
  BuyShopItem: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { type: string }) => {
        const shops = "LS^HS^ES".split("^");
        if (shops.includes(args.type)) {
          mission.progress[0].value += 1;
        }
      },
    },
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { type: string }) => {
        if (args.type == "SOCIAL") {
          mission.progress[0].value += 1;
        }
      },
    },
    "3": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { type: string; socialPoint: number }) => {
        if (args.type != "SOCIAL") {
          return;
        }
        mission.progress[0].value += args.socialPoint;
      },
    },
  },

  /**
   * 常规抽卡（公开招募）
   *
   * 每次抽取 +1。param[2] 为目标次数（如 daily_4818=[0,-1,3] 抽3次）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 无实际作用（常为 -1）
   * @param param[2] 目标抽取次数
   */
  NormalGacha: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 获得干员信赖值
   *
   * 每次获得信赖 count 累加，达 param[1] 完成（如 daily_4819=[0,5]）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标信赖值总量
   */
  GainIntimacy: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { count: number }) => {
        mission.progress[0].value += args.count;
      },
    },
  },

  /**
   * 制造站生产（按分支细分口径）
   *
   * @param param[0] 分支标识：
   *   0 —— 指定物品（param[2] itemId）累计生产数量
   *   1 —— 任意生产事件按产出 count 累加/计数（如 daily_4821=[1,1]）
   *   2 —— 指定物品集合（param[2] 以 # 分隔）任意命中 +1
   * @param param[1] 目标值
   * @param param[2] 指定物品 id 或 id 集合（分支 0/2 用）
   */
  ManufactureItem: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { item: ItemBundle }) => {
        if (args.item.id == mission.param[2]) {
          mission.progress[0].value += args.item.count;
        }
      },
    },
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { count: number }) => {
        mission.progress[0].value += args.count;
      },
    },
    "2": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { item: ItemBundle }) => {
        const items = mission.param[2].split("#");
        if (items.includes(args.item.id)) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 贸易站订单交付
   *
   * 每次交付订单 count 累加，达 param[1] 完成。分支 0 / 1 行为一致
   * （如 daily_4822=[1,1]、周常=15/30/50/80 单）。
   * @param param[0] 分支标识（0 或 1，行为相同）
   * @param param[1] 目标交付订单量
   */
  DeliveryOrder: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { count: number }) => {
        mission.progress[0].value += args.count;
      },
    },
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { count: number }) => {
        mission.progress[0].value += args.count;
      },
    },
  },

  /**
   * 恢复干员基础体力
   *
   * 每次恢复体力 count 累加，达 param[1] 完成（如 daily_4826=[0,1]）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标恢复体力值
   */
  RecoverCharBaseAp: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { count: number }) => {
        mission.progress[0].value += args.count;
      },
    },
  },

  /**
   * 访问好友基建
   *
   * 每次访问 +1，达 param[1] 完成（如 weekly_732=[0,5]）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标访问次数
   */
  VisitBuilding: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 升级技能（按分支细分口径）
   *
   * @param param[0] 分支标识：
   *   0 —— 每次技能升级事件 +1
   *   1 —— 按累计升级目标等级 targetLevel 累加
   * @param param[1] 目标值
   */
  UpgradeSkill: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { targetLevel: number }) => {
        mission.progress[0].value += args.targetLevel;
      },
    },
  },

  /**
   * 编队/阵容配置
   *
   * 每次编队事件 +1，达 param[2] 完成。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 无实际作用
   * @param param[2] 目标编队次数
   */
  SquadFormation: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },
  /**
   * 通关指定关卡（按分支细分通关类型）
   *
   * @param param[0] 分支标识：
   *   0 —— 指定关卡（param[1] 以 ^ 分隔 stageId）三星通关（completeState>=2）各计 1
   *   2 —— 任意关卡通关状态达到 param[2] 各计 1（文件主线外围任务）
   *   3 —— 演习（isPractice 非 0）三星通关各计 1
   *   4 —— 突袭关节（stageId 含 #f#）三星通关（completeState>=3）各计 1
   * @param param[1] 关卡列表（分支 0）或通关状态阈值（分支 2）或目标值（分支 3/4）
   * @param param[2] 目标通关次数（分支 0/2 用）
   */
  CompleteStage: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId)) {
          return;
        }
        if (args.completeState >= 2) {
          mission.progress[0].value += 1;
        }
      },
    },
    "2": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: BattleData) => {
        if (args.completeState >= parseInt(mission.param[1])) {
          mission.progress[0].value += 1;
        }
      },
    },
    "3": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: BattleData & { isPractice: number }) => {
        if (!args.isPractice) {
          return;
        }
        if (args.completeState >= 2) {
          mission.progress[0].value += 1;
        }
      },
    },
    "4": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (!args.stageId.includes("#f#")) {
          return;
        }
        if (args.completeState >= 3) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 升级玩家等级
   *
   * 进度直接取当前玩家等级 level（覆盖式）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标玩家等级
   */
  UpgradePlayer: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { level: number }) => {
        mission.progress[0].value = args.level;
      },
    },
  },

  /**
   * 通关任一指定关卡
   *
   * 指定关卡列表（param[1] 以 ^ 分隔）中命中一关、且通关状态达 param[2] 各计 1。
   * 文件主线章节任务（如 main_83=[0,main_15-04^main_15-04#s,2]）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 关卡列表（^ 分隔，可含 #s 变体）
   * @param param[2] 通关状态阈值
   */
  CompleteAnyStage: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId)) {
          return;
        }
        if (args.completeState >= parseInt(mission.param[2])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 拥有符合筛选条件的干员
   *
   * 每满足条件的干员 +1。分支 0 / 1 行为一致。用于「拥有某精二/等级/稀有度/职业干员」任务
   * （如 sub_10010 param=[0,30,-1,SNIPER]）。
   * @param param[0] 分支标识（0 或 1，行为相同）
   * @param param[1] 目标干员数量
   * @param param[2] 精二阶段下限（evolvePhase）
   * @param param[3] 等级下限
   * @param param[4] 稀有度（-1=不限）
   * @param param[5] 职业（ALL=不限，如 SNIPER/TANK/PIONEER）
   */
  HasChar: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { char: PlayerCharacter }) => {
        const data = excel.CharacterTable[args.char.charId];
        if (args.char.evolvePhase < parseInt(mission.param[2])) {
          return;
        }
        if (args.char.level < parseInt(mission.param[3])) {
          return;
        }
        if (
          data.rarity.toString() != mission.param[4] &&
          mission.param[4] != "-1"
        ) {
          return;
        }
        if (data.profession != mission.param[5] && mission.param[5] != "ALL") {
          return;
        }
        mission.progress[0].value += 1;
      },
    },
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { char: PlayerCharacter }) => {
        const data = excel.CharacterTable[args.char.charId];
        if (args.char.evolvePhase < parseInt(mission.param[2])) {
          return;
        }
        if (args.char.level < parseInt(mission.param[3])) {
          return;
        }
        if (
          data.rarity.toString() != mission.param[4] &&
          mission.param[4] != "-1"
        ) {
          return;
        }
        if (data.profession != mission.param[5] && mission.param[5] != "ALL") {
          return;
        }
        mission.progress[0].value += 1;
      },
    },
  },
  /**
   * 拥有符合条件（稀有度 + 模组等级）的已解锁模组
   *
   * 精二（evolvePhase>=2）干员，其稀有度命中 param[1]（^ 分隔），每有一个模组等级
   * 命中 param[2]（^ 分隔，模组等级列表）各计 1，达 param[3] 完成。
   * 用于「模组任务」（如 sub_20001 param=[0,4^5^6,1^2^3,1]）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 干员稀有度列表（^ 分隔）
   * @param param[2] 模组等级列表（^ 分隔）
   * @param param[3] 目标模组数量
   */
  HasEquipment: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[3]),
        });
      },
      update: (mission, args: { char: PlayerCharacter }) => {
        const data = excel.CharacterTable[args.char.charId];
        const rarities = mission.param[1].split("^");
        const levels = mission.param[2].split("^");
        if (args.char.evolvePhase < 2) {
          return;
        }
        if (!rarities.includes(data.rarity.toString())) {
          return;
        }
        Object.values(args.char.equip!).forEach((e) => {
          if (levels.includes(e.level.toString())) {
            mission.progress[0].value += 1;
          }
        });
      },
    },
  },

  /**
   * 干员精二
   *
   * 干员精二阶段达到 param[2] 各计 1，达 param[1] 完成。
   * 用于「精二 N 名干员」（如 sub_73 param=[1,3,1] 精二3名）。
   * @param param[0] 恒为 "1"（分支标识）
   * @param param[1] 目标精二干员数
   * @param param[2] 目标精二阶段（evolvePhase）
   */
  EvolveChar: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { char: PlayerCharacter }) => {
        if (args.char.evolvePhase >= parseInt(mission.param[2])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 基建舒适度提升（按分支细分）
   *
   * @param param[0] 分支标识：
   *   0 —— 按累计新增舒适度 comfort 累加（如 sub_85 param=[0,2000]）
   *   1 —— 直接以当前舒适度覆盖式进度（如 sub_113 param=[4000]）
   * @param param[1] 目标舒适度值
   */
  DiyComfort: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { comfort: number }) => {
        mission.progress[0].value += args.comfort || 0;
      },
    },
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { comfort: number }) => {
        mission.progress[0].value += args.comfort || 0;
      },
    },
  },

  /**
   * 基建房间建造（指定房间类型）
   *
   * 每次新增房间按 roomCount 累加，达 param[1] 完成。用于「建造 N 级某类型房间」
   * （如 sub_79 param=[0,1,2,POWER] 建造2级发电站）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标房间数
   * @param param[2] 房间等级（部分任务用）
   * @param param[3] 房间类型（如 POWER/MANUFACTURE/TRADING/WORKSHOP/CONTROL）
   */
  HasRoom: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { roomCount: number }) => {
        mission.progress[0].value += args.roomCount || 0;
      },
    },
  },

  /**
   * 车间合成物品
   *
   * 指定物品（param[2] itemId）合成时按产出数量累计，达 param[1] 完成。
   *   @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标合成数量
   * @param param[2] 指定产物 itemId
   */
  WorkshopSynthesis: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { item: ItemBundle }) => {
        if (args.item.id == mission.param[2]) {
          mission.progress[0].value += args.item.count;
        }
      },
    },
  },

  /**
   * 专精技能（升级专精等级）
   *
   * @param param[0] 分支标识：
   *   0 —— 每次专精事件 +1（如「专精任意技能 N 次」）
   *   1 —— 专精等级达到 param[1] 各计 1（如 sub_135 param=[1,1]、sub_137=[1,3]）
   * @param param[1] 目标值或目标专精等级
   */
  UpgradeSpecialization: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
    "1": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: { targetLevel: number }) => {
        if (args.targetLevel >= parseInt(mission.param[1])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 指定关卡内击杀敌人（单场阈值式）
   *
   * 指定关卡（param[1] ^ 分隔）单场击杀 killCnt 取较大值作为进度上限，达 param[2]
   * 完成。用于「在 XX 关卡单场击杀 N」（如 sub_69 param=[0,camp_01,350]）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 关卡列表（^ 分隔）
   * @param param[2] 单场目标击杀数
   */
  BattleWithEnemyKill: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId)) {
          return;
        }
        if (args.killCnt >= mission.progress[0].value) {
          mission.progress[0].value = args.killCnt;
        }
      },
    },
  },

  /**
   * 干员信赖（羁绊）达到指定百分比
   *
   * 按干员当前信赖百分比 percent（最大 200%=满信赖）判定，达到 param[2]% 各计 1，
   * 达 param[1] 完成。用于「信任 N 名干员达到 XX%」。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标干员数
   * @param param[2] 目标信赖百分比阈值（0-200）
   */
  CharIntimacy: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { favorPoint: number }) => {
        let percent: number;
        if (args.favorPoint == excel.FavorTable.maxFavor) {
          percent = 200;
        } else {
          percent = (
            excel.FavorTable.favorFrames.find((_f, idx, table) => {
              return (
                args.favorPoint >= table[idx].level &&
                args.favorPoint < table[idx + 1].level
              );
            })!.data as { percent: number }
          ).percent;
        }
        if (percent >= parseInt(mission.param[2])) {
          mission.progress[0].value += 1;        }
      },
    },
  },

  /**
   * 完成剧情/破镜奖励
   *
   * 每次完成奖励事件 +1，目标恒为 1。用于一次性剧情奖励任务。
   */
  CompleteBreakReward: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },
  /**
   * 信息分享（截图/分享）
   *
   * 每次分享事件 +1，达 param[1] 完成。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标分享次数
   */
  StartInfoShare: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 编辑名片
   *
   * 每次编辑名片 +1，目标恒为 1。
   */
  EditBusinessCard: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 设置助战干员列表
   *
   * 每次设置助战 +1，达 param[1] 完成。
   * @param param[0] 恒为 "1"（分支标识）
   * @param param[1] 目标设置次数
   */
  SetAssistCharList: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 修改编队/小队名称
   *
   * 每次改名 +1，达 param[1] 完成。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标改名次数
   */
  ChangeSquadName: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 通关时使用代理/再现（代理作战）
   *
   * 每次代理作战通关（isReplay 非空）+1，达 param[1] 完成。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标代理作战次数
   */
  StageWithReplay: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { isReplay: number }) => {
        if (args.isReplay) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 接管/中断代理作战（手动接管）
   *
   * 战斗中产生自动代理取消（autoReplayCancelled）各计 1，达 param[1] 完成。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标接管次数
   */
  TakeOverReplay: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: BattleData) => {
        if (args.battleData.stats.autoReplayCancelled) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 通关剿灭作战
   *
   * 三星通关（completeState>=2）且关卡类型为 CAMPAIGN（剿灭）：各计 1，达 param[1] 完成。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标剿灭通关次数
   */
  CompleteCampaign: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stageType = excel.StageTable.stages[args.stageId].stageType;
        if (args.completeState < 2) {
          return;
        }
        if (stageType == "CAMPAIGN") {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 设置基建助战（基建入驻助战位）
   *
   * 每次设置 +1，目标恒为 1。
   */
  SetBuildingAssist: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 提升潜能（潜能等级达阈值）
   *
   * 干员潜能提升后 targetLevel 达到 param[2] 各计 1，达 param[1] 完成。
   * @param param[0] 恒为 "1"（分支标识）
   * @param param[1] 目标干员数
   * @param param[2] 目标潜能等级
   */
  BoostPotential: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { targetLevel: number }) => {
        if (args.targetLevel >= parseInt(mission.param[2])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 车间额外产出
   *
   * 每次车间额外产出事件 +1，达 param[1] 完成。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标次数
   */
  WorkshopExBonus: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 提升常规抽卡（公开招募）数量
   *
   * 每次抽取 +1，达 param[1] 完成。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标抽取次数
   */
  BoostNormalGacha: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 通关指定主线关卡
   *
   * 指定主线关卡（param[1] stageId）三星通关（completeState>=2）各计 1，目标恒为 1。
   * 用于主线章节任务（如 main_28 param=[1,main_02-03,1]）。
   * @param param[0] 恒为 "1"（分支标识）
   * @param param[1] 指定主线关卡 id
   */
  CompleteMainStage: {
    "1": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId != mission.param[1]) {
          return;
        }
        if (args.completeState >= 2) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 发送线索
   *
   * 每次发送线索 +1，达 param[1] 完成（社会/基建线索交流）。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标发送次数
   */
  SendClue: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 获得团队干员（小程序/联动获得的干员）
   *
   * 每次获得 +1，目标恒为 1。
   */
  GainTeamChar: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 加速订单（基建加速制造/贸易）
   *
   * 每次加速订单 +1，目标恒为 1。
   */
  AccelerateOrder: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission) => {
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 消耗理智
   *
   * 每次战斗消耗理智按 ap 累加，达 param[1] 完成。
   * @param param[0] 恒为 "0"（占位分支位）
   * @param param[1] 目标消耗理智值
   */
  CostAp: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      // 修复：原 update 为空操作（事件即使 emit 也不累计）→ 消耗理智类任务永不推进；
      // 改为按实际消耗 AP 累计（emit 参数 {ap}）
      update: (mission, args: { ap: number }) => {
        mission.progress[0].value += args.ap;
      },
    },
  },

  Rlv2SettleGame: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: () => {},
    },
  },

  Rlv2SettleGameTimes: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: () => {},
    },
  },

  // ==================== 奇象巡展（ARK_HUB）任务模板 ====================
  // ActivityTable.missionData 的 template（1arkhubActivity_1..23，共 8 类）。
  // param 语义（对齐官服）：param[0]=参数类型位(恒"0")，param[1]=activityId("act1arkhub")，
  // 其余位随模板不同（见各模板注释）。事件名 = 模板名，由 arkhub 玩法/网关回调 emit。

  /** 引导任务：完成引导对话（param[2]=引导 flag，目标=1） */
  ArkhubMissionCompleted: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: { activityId: string; flag: string }) => {
        if (args.activityId !== mission.param[1]) return;
        if (args.flag !== mission.param[2]) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /** 每日物资：累计领取天数（param[2..3]=活动日期区间，param[4]=目标天数） */
  ArkhubDailyMissionCompleted: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[4]),
        });
      },
      update: (mission, args: { activityId: string; days: number }) => {
        if (args.activityId !== mission.param[1]) return;
        // 窗口门控（8/18 更新后任务：param[2] 起点 2026-08-18 16:00:00 前不推进）。
        // getTime() 为毫秒，需除以 1000 与 userTimestamp()（秒）对齐
        const start = Math.floor(
          new Date((mission.param[2] ?? "").replace(/\//g, "-")).getTime() / 1000,
        );
        const end = Math.floor(
          new Date((mission.param[3] ?? "").replace(/\//g, "-")).getTime() / 1000,
        );
        const ts = userTimestamp();
        if (Number.isNaN(start) || Number.isNaN(end) || !(ts >= start && ts <= end)) {
          return;
        }
        // 累计天数直接取当前值（服务端 ARK_HUB.dailySupplyDays 恒不小于历史值）
        mission.progress[0].value = Math.max(
          mission.progress[0].value,
          Math.min(args.days, mission.progress[0].target!),
        );
      },
    },
  },

  /** 收录生物种类：param[2]=目标 N，param[3]=collectionKey（arkhubMissionCollection1=全部 / 2=活动频繁） */
  ArkhubCreatureCollection: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (
        mission,
        args: { activityId: string; count: number; collectionKey: string },
      ) => {
        if (args.activityId !== mission.param[1]) return;
        if (args.collectionKey !== mission.param[3]) return;
        mission.progress[0].value = Math.max(
          mission.progress[0].value,
          Math.min(args.count, mission.progress[0].target!),
        );
      },
    },
  },

  /** 信息素诱引生物扫描（param[2]=目标次数，事件每次触发 +1） */
  ArkhubCreatureCaptured: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: { activityId: string }) => {
        if (args.activityId !== mission.param[1]) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /** 发起生物数据交换（param[2]=目标次数，事件每次触发 +1） */
  ArkhubCreatureExchange: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: { activityId: string }) => {
        if (args.activityId !== mission.param[1]) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /** 奇象拟合对战完成次数（param[2]=目标 N；count=ARK_HUB.duelCount 累计值） */
  ArkhubPassDexBattle: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: { activityId: string; count: number }) => {
        if (args.activityId !== mission.param[1]) return;
        mission.progress[0].value = Math.max(
          mission.progress[0].value,
          Math.min(args.count, mission.progress[0].target!),
        );
      },
    },
  },

  /** 发布画像数（param[2]=目标 N） */
  ArkhubPublishPixelArt: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: { activityId: string; count: number }) => {
        if (args.activityId !== mission.param[1]) return;
        mission.progress[0].value = Math.max(
          mission.progress[0].value,
          Math.min(args.count, mission.progress[0].target!),
        );
      },
    },
  },

  /** 收集画像数（param[2]=目标 N） */
  ArkhubCollectPixelArt: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: { activityId: string; count: number }) => {
        if (args.activityId !== mission.param[1]) return;
        mission.progress[0].value = Math.max(
          mission.progress[0].value,
          Math.min(args.count, mission.progress[0].target!),
        );
      },
    },
  },

  // ==================== act53side（arkodc）活动任务模板 ====================
  /**
   * 通关活动关卡累计（53sideActivity_37..39）
   *
   * param[1]=活动关卡列表（^ 分隔，含 #f# 突袭变体），param[2]=目标累计通关次数
   * （15/45/85）。事件 CompleteStageAct 由 battle 结算 emit，满足 completeState>=2
   * 且关卡命中列表时累计 +1。
   */
  CompleteStageAct: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId)) return;
        if (args.completeState < 2) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * arkodc 奖励组收集（53sideActivity_1..9）
   *
   * param[1]=arkodc topic 活动 id，param[2]=目标奖励组 id 列表（逗号分隔，
   * 如 reward_tre_a 等宝箱/任务奖励），param[3]=目标收集数量。事件
   * ArkodcRewardGroupAtLeast 在 triggerInteraction 收集奖励后 emit，模板统计
   * topic.rewards 中已命中 param[2] 列表的数量作为进度。
   */
  ArkodcRewardGroupAtLeast: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[3]),
        });
      },
      update: (
        mission,
        args: { activityId: string; rewards: Record<string, number> },
      ) => {
        if (args.activityId !== mission.param[1]) return;
        const targets = mission.param[2].split(",");
        let count = 0;
        for (const t of targets) {
          if (args.rewards?.[t]) count += 1;
        }
        mission.progress[0].value = Math.max(
          mission.progress[0].value,
          count,
        );
      },
    },
  },
};
