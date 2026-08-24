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
import { MissionData } from "@excel/excel-types";
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
    const period = (excel.MissionTable.dailyMissionPeriodInfo ?? []).find(
      (p) => p.startTime <= ts && p.endTime >= ts,
    );
    // 防御：periodicalRewards 缺失/单测未配置周期表时返回空串（兑换据此不过滤）
    if (!period) return "";
    const match = period.periodList?.find((p) => p.period.includes(weekDay));
    return match?.rewardGroupId ?? "";
  }

  /**
   * 获取当前每周任务奖励周期ID
   *
   * weeklyRewards 无 periodList 分组概念，每条凭 beginTime/endTime 时间窗标识生效期；
   * 取覆盖当前时间的所有奖励组（通常唯一），多组并存时按 id 排序取最小以保证确定。
   * @returns 当前生效的周奖励组 id（如 reward_weekly_g_4）；无覆盖时返回空串
   */
  get weeklyRewardPeriod(): string {
    const ts = now();
    const groupIds = new Set<string>(
      Object.values(excel.MissionTable.weeklyRewards ?? {})
        .filter(
          (r: any) => r && checkBetween(ts, r.beginTime, r.endTime),
        )
        .map((r: any) => r.groupId),
    );
    return [...groupIds].sort()[0] ?? "";
  }

  /**
   * 初始化任务系统
   * 遍历所有任务类型，为每个任务创建MissionProgress实例并初始化
   */
  async init() {
    // 先补 ACTIVITY 分组（Immer draft 内不创建 MissionProgress，避免模板 push 到冻结 draft）。
    // 修复：改为仅在分组不存在时补空——原无条件 `ACTIVITY = {}` 会清空已加载存档里的
    // ACTIVITY 任务（含奇象巡展 1arkhubActivity_* 的 progress 进度），后续 unlockActivity
    // 播种因组已空而全部重建为初始态 → 玩家既有任务进度无法从存档继承（丢失）。
    await this._player.update(async (draft) => {
      draft.mission.missions["ACTIVITY"] ??= {};
      // 播种特勤干员（SPECIAL_OPERATOR）任务（幂等：仅补缺失条目，见 seedSpecialOperatorMissions）
      this.seedSpecialOperatorMissions(draft);
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
   * 播种特勤干员（SPECIAL_OPERATOR）任务到玩家任务数据（幂等）。
   *
   * 数据源：SpecialOperatorTable.nodeUnlockMissionData（电弧/机械师解锁任务，type=SPECIAL_OPERATOR）。
   * 该表任务不在 MissionTable.missions，须在 init 阶段补种；播种条目 progress 为空数组，
   * 由 MissionProgress.init 按模板 init 构建（与 dailyRefresh 新组任务同款）。
   * 已有条目（旧存档/重复登录）保持不变，避免覆盖已完成进度。
   * @param draft update() 配方的可写草稿（playerData）
   */
  private seedSpecialOperatorMissions(draft: any): void {
    const missionData = (excel.SpecialOperatorTable as any)?.nodeUnlockMissionData;
    if (!missionData || typeof missionData !== "object") return;
    const group = (draft.mission.missions["SPECIAL_OPERATOR"] ??= {});
    for (const missionId of Object.keys(missionData)) {
      if (!group[missionId]) {
        group[missionId] = { state: 1, progress: [] };
      }
    }
  }

  /**
   * 生成任务的初始进度条目 [{value:0,target}]（非空数组）。
   *
   * dailyRefresh 播种日常任务时调用。原实现播种 `progress: []`（空数组），依赖
   * MissionProgress.init 里的模板 init 兜底填充；一旦该兜底未执行（数据缺失/边缘路径）
   * 便会向存档残留空数组，日常任务进度显示为空、无法推进。此处播种即调用模板 init
   * 推导真实 target，从根源保证 progress 结构完整。
   *
   * 纯计算，不触碰 playerdata（模板 init 只写入传入的临时 mission 对象），可在 update
   * 配方的 draft 内安全调用。
   * @param missionId 任务 ID（MissionTable.missions 中的键）
   * @returns 初始进度数组；模板缺失时兜底 [{value:0,target:1}]
   */
  private _seedInitialProgress(
    missionId: string,
  ): { value: number; target: number }[] {
    const info = excel.MissionTable.missions[missionId];
    const template = info?.template as keyof typeof MissionTemplates | undefined;
    const branch = info?.param?.[0];
    // 数据表缺失或模板/分支不存在 → 兜底单目标 1，仍保证非空数组
    if (!template || !branch || !(template in MissionTemplates)) {
      return [{ value: 0, target: 1 }];
    }
    const tpl = MissionTemplates[template]?.[branch ?? ""];
    if (!tpl?.init) {
      return [{ value: 0, target: 1 }];
    }
    const seed: { value: number; target: number }[] = [];
    try {
      // 复用模板 init 计算 target（与 MissionProgress.init 兜底一致）
      tpl.init({ progress: seed, value: 0, param: info.param } as never);
    } catch {
      return [{ value: 0, target: 1 }];
    }
    return seed.length > 0 ? seed : [{ value: 0, target: 1 }];
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
      // 官方每日重置即替换当日任务组：删旧组条目、补新组条目。
      const currentIds =
        excel.MissionTable.missionGroups[this.dailyMissionPeriod].missionIds ??
        [];
      const daily = (draft.mission.missions["DAILY"] ??= {});
      // 跨天周期组相同（如周内连续工作日同组）时，无论任务是否已存在都强制重置为
      // 初始可接取态（state=1），避免昨日完成态残留导致"每日更新不刷新进度"。
      // 修复（2026-08-23）：播种的 progress 直接写入结构完整、target 真实的
      // [{value:0,target}]——原实现播种 progress:[]（空数组中间态），一旦依赖的模板
      // init 兜底未执行便会残留空数组 → 日常任务进度被置空、存档坏数据。此处播种即
      // 用模板 init 推导初始 target，从根源保证 progress 永不为空数组。
      for (const id of currentIds) {
        daily[id] = { state: 1, progress: this._seedInitialProgress(id) };
      }
      // 删除当前组之外的历史任务条目
      for (const id of Object.keys(daily)) {
        if (!currentIds.includes(id)) delete daily[id];
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
      // 特勤干员任务（SpecialOperatorTable.nodeUnlockMissionData）：无 rewards，确认仅置
      // confirmed 防重复（节点解锁由客户端 SpecialOperatorUnlockNode 驱动），返回空奖励。
      const soMission = (excel.SpecialOperatorTable as any)?.nodeUnlockMissionData?.[
        missionId
      ];
      if (soMission) {
        await this._player.update(async (draft) => {
          const data = (draft.mission.missions as any)?.["SPECIAL_OPERATOR"]?.[
            missionId
          ];
          if (data) {
            data.state = 3;
            (data as any).confirmed = 1;
          }
        });
        return [];
      }
      // 活动任务（ActivityTable.missionData，如 1arkhubActivity_*/53sideActivity_*）
      // 兜底领取——枢纽任务奖励同步 ARK_HUB.coin/tshop 币（官服形状）
      return this.mergeItemBundles(
        await this._confirmActivityTableMission(missionId),
      );
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
        case "WEEKLY": {
          // 修复：WEEKLY 与 DAILY 对称——累加周期点后自动兑换所有达标周期奖励。
          // 原 WEEKLY 分支只累加 weeklyPoint 从不兑换 → 确认周任务后响应 items
          // 恒为空，客户端"获得物品"提示永不出现（官服 autoConfirm WEEKLY 抓包
          // R-1787047281356-0118 确认周任务会兑换 reward_weekly_* 并返回物品）。
          const isWeekly = missionInfo.type === "WEEKLY";
          const type = isWeekly ? "WEEKLY" : "DAILY";
          const pointField = isWeekly ? "weeklyPoint" : "dailyPoint";
          missionRewards[pointField] += missionInfo.periodicalPoint ?? 0;
          // 防御：新账号 missionRewards 可能为空对象（freshMission 只给
          // { missions, missionRewards: {}, missionGroups }），rewards 子树未初始化
          // → 原 Object.entries(undefined) 直接崩溃（接口 500 → 客户端无任何提示）。
          const rewardsTree = (missionRewards.rewards ??= {});
          const rewardMap = (rewardsTree[type] ??= {});
          // 奖励定义表：DAILY 走 periodicalRewards（仅 DAILY），WEEKLY 走 weeklyRewards——
          // 原实现统一查 periodicalRewards，而该表只有 DAILY → WEEKLY 周期奖励永不兑换。
          // 当前周期组：多组并存（历史组残留）时只兑换当前生效组，避免一次确认把多个
          // 奖励组的奖励全部发放（重复刷金币/材料/寻访凭证）。
          const rewardDefs = isWeekly
            ? (excel.MissionTable.weeklyRewards ?? {} as Record<string, any>)
            : (excel.MissionTable.periodicalRewards ?? {});
          const currentGroup = isWeekly
            ? this.weeklyRewardPeriod
            : this.dailyMissionRewardPeriod;
          for (const [k, v] of Object.entries(rewardMap)) {
            const reward = rewardDefs[k];
            // 防御：数据表缺该奖励（版本错位/伪键）时跳过，避免读 undefined.cost
            if (!reward || v != 0) continue;
            // 只兑当前周期组——rewards 若残留历史组条目，跳过以免多组同时发放
            if (currentGroup && reward.groupId !== currentGroup) continue;
            if (missionRewards[pointField] >= reward.periodicalPointCost) {
              missionRewards[pointField] -= reward.periodicalPointCost;
              items.push(...reward.rewards);
              rewardMap[k] = 1;
            }
          }
          break;
        }
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

    // 修复：合并相同物品（相同 type+id count 相加，保持首次出现顺序）——多任务
    // 兑换/发放产生的 items 常含重复 id 条目（如 autoConfirm 多个 reward 都含 GOLD
    // 4001），不合并则客户端"获得物品"提示按多条拆分、计数错乱/重复弹窗。
    const merged = this.mergeItemBundles(items);
    await this._trigger.emit("items:get", [merged]);
    return merged;
  }

  /**
   * 合并物品列表：相同 type+id 的条目 count 相加，保留首次出现顺序。
   *
   * 用于单任务确认与一键领取返回给客户端的"获得物品"列表——不同任务/周期奖励
   * 常产出重复 id 的物品（如多个奖励都含 GOLD 4001），未合并会拆成多条，客户端
   * 提示计数错误或重复弹出。合并后每类物品仅一条，count 为总和。
   * @param items 待合并的物品列表
   * @returns 合并后的物品列表
   */
  mergeItemBundles(items: ItemBundle[]): ItemBundle[] {
    const map = new Map<string, ItemBundle>();
    for (const item of items) {
      if (item == null) continue;
      const key = `${item.type}|${item.id}`;
      const prev = map.get(key);
      if (prev) {
        prev.count = (prev.count ?? 0) + (item.count ?? 0);
      } else {
        map.set(key, {
          id: item.id,
          count: item.count ?? 0,
          type: item.type,
        });
      }
    }
    return [...map.values()];
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
    let alreadyConfirmed = false;
    await this._player.update(async (draft) => {
      const activityMissions = (draft.mission as any)?.missions?.["ACTIVITY"];
      const data = activityMissions?.[missionId];
      // 修复：活动任务确认后还能重复确认刷奖励——原实现仅 state!=3 置 3，state 已为 3
      // 时仍无条件返回全部 rewards。现与普通任务一致：以持久化 confirmed 标记判重，
      // 已领取即返回空奖励并中止（不累加枢纽 ARK_HUB coin），避免重复发放。
      if (data && (data as any).confirmed) {
        alreadyConfirmed = true;
        return;
      }
      if (data && data.state !== 3) {
        data.state = 3;
        newlyCompleted = true;
      }
      if (data) (data as any).confirmed = 1;
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
    // 已领取：不发放奖励、不重复触发勋章/物品事件
    if (alreadyConfirmed) return [];
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
    // 聚合后统一合并相同物品（confirmMission 各自返回已合并，但跨任务重复 id
    // 仍需在此再聚合一次，保证一键领取响应去重）
    return this.mergeItemBundles(items);
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
    } else if (this.type == "SPECIAL_OPERATOR") {
      // 特勤干员任务（电弧/机械师解锁任务）不在 MissionTable——
      // 定义在 SpecialOperatorTable.nodeUnlockMissionData（type=SPECIAL_OPERATOR）。
      mission = (excel.SpecialOperatorTable as any)?.nodeUnlockMissionData?.[
        this.missionId
      ] as MissionData | undefined;
      if (!mission) {
        this.valid = false;
        logger.debug("MissionManager", `Special operator mission ${this.missionId} not found in SpecialOperatorTable.nodeUnlockMissionData`);
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
    // 防御：模板分支校验——模板 key 合法但 param[0] 分支在该模板中未定义时，
    // MissionTemplates[template][param[0]] 为 undefined，事件触发 func 会抛
    // "Cannot read properties of undefined (reading 'update')"。此类任务（rogue/
    // 活动里模板与 param 分支不匹配）标记无效并降级日志，不注册监听器。
    const tpl = MissionTemplates[template]?.[this.param[0]];
    if (!tpl?.update || !tpl?.init) {
      this.valid = false;
      logger.debug(
        "MissionManager",
        `Template branch not implemented: ${template}/${this.param[0]} (${this.missionId})`,
      );
      return;
    }
    const func = async ([args]: unknown[]) => {
      tpl.update(this, args as never);
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
      tpl.init(this);
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
 * 特勤干员（SPECIAL_OPERATOR）任务节点类型名 → 数值映射。
 * 用于 Rlv2PassNodeSpec 等模板把任务 param 中的节点类型名（如 "INCIDENT"、
 * "BATTLE_NORMAL,BATTLE_ELITE,BATTLE_BOSS"）解析为地图节点 type 数值。
 * 数值与 TorappuRoguelikeEventType / ROGUE6_NODE 对齐。
 * 岁兽残识"祸乱"节点（BATTLE / BATTLE_HARD）后端未实现专属机制，按作战/紧急作战近似。
 */
const RLV2_MISSION_NODE_VALUES: Record<string, number> = {
  BATTLE_NORMAL: 1,
  BATTLE_ELITE: 2,
  BATTLE_BOSS: 4,
  SHOP: 8,
  REST: 16,
  INCIDENT: 32,
  TREASURE: 64,
  ENTERTAINMENT: 128,
  UNKNOWN: 256,
  WISH: 512,
  SACRIFICE: 1024,
  EXPEDITION: 2048,
  BATTLE_SHOP: 4096,
  PORTAL: 8192,
  MISSION: 16384,
  STORY: 32768,
  STORY_HIDDEN: 65536,
  ALCHEMY: 131072,
  DUEL: 262144,
  EMPLOY: 33554432,
  BATTLE_SAVAGE: 134217728,
  SCRAP_SHOP: 2097152,
  BATTLE: 1,
  BATTLE_HARD: 2,
};

/**
 * 校验特勤干员任务事件上下文是否匹配任务 param 的 theme/mode/grade 门槛。
 * 各模板 param 布局不同（有的含 mode、有的不含），事件载荷缺失对应字段时跳过该校验。
 * @param mission 任务进度实例
 * @param ctx 事件载荷中的主题/模式/难度字段
 * @returns 匹配返回 true
 */
function matchesRlv2Context(
  mission: MissionInfo,
  ctx: { theme?: string; mode?: string; grade?: number },
): boolean {
  if (ctx.theme !== undefined && ctx.theme !== mission.param[1]) return false;
  if (ctx.mode !== undefined && ctx.mode !== mission.param[2]) return false;
  if (
    ctx.grade !== undefined &&
    ctx.grade < parseInt(mission.param[3] || "0", 10)
  ) {
    return false;
  }
  return true;
}

/** 在 grade 及以上通关过任意结局的分队数（按累计分队×难度记录统计） */
function countBandsAtGrade(
  bandGrade: Record<string, Record<string, number>>,
  minGrade: number,
): number {
  return Object.values(bandGrade).filter((grades) =>
    Object.entries(grades).some(
      ([g, cnt]) => parseInt(g, 10) >= minGrade && cnt > 0,
    ),
  ).length;
}

/** 在 grade 及以上达成过指定结局的分队数（按累计分队×结局、分队×难度记录统计） */
function countBandsWithEndingAtGrade(
  bandGrade: Record<string, Record<string, number>>,
  bandCnt: Record<string, Record<string, number>>,
  minGrade: number,
  ending: string,
): number {
  return Object.entries(bandCnt).filter(([bandId, endings]) => {
    if (!endings?.[ending]) return false;
    const grades = bandGrade?.[bandId] || {};
    return Object.entries(grades).some(
      ([g, cnt]) => parseInt(g, 10) >= minGrade && cnt > 0,
    );
  }).length;
}

/** 是否在 grade 及以上达成过指定结局（0/1） */
function achievedEndingAtGrade(
  bandGrade: Record<string, Record<string, number>>,
  bandCnt: Record<string, Record<string, number>>,
  minGrade: number,
  ending: string,
): number {
  return countBandsWithEndingAtGrade(bandGrade, bandCnt, minGrade, ending) > 0
    ? 1
    : 0;
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
    // 型1：线索分享类（target=param[1]，事件每次 +1）；对齐 DoctoratePy StartInfoShare type1
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

  // ==================== 特勤干员（SPECIAL_OPERATOR）任务模板 ====================
  // SpecialOperatorTable.nodeUnlockMissionData 中任务的 template（Rlv2* 系列，18 类）。
  // 事件名 = 模板名，由 rlv2 控制器在对应玩法动作处 emit（见 events.ts 特勤干员区块）。
  // param 布局因模板而异（见各模板注释）；param[0] 恒为分支位。

  /**
   * 到达指定区域（Rlv2PassZoneSpec）
   *
   * 在指定主题/模式/难度门槛下，到达 param[5] 指定区域（如 zone_2）各计 1，达 param[4] 完成。
   * 用例：「在XX的常规行动中，到达3层」（mcnist_t_evolve_1 param=["1","rogue_6","NORMAL","0","1","zone_2"]）。
   * @param param[1] 主题 id（rogue_5/rogue_6）
   * @param param[2] 模式（NORMAL）
   * @param param[3] 难度门槛（modeGrade >= 该值）
   * @param param[4] 目标到达次数
   * @param param[5] 区域 id（zone_N）
   */
  Rlv2PassZoneSpec: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[4]),
        });
      },
      update: (mission, args: { theme: string; mode: string; grade: number; zoneId: string }) => {
        if (!matchesRlv2Context(mission, args)) return;
        if (args.zoneId !== mission.param[5]) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 累计通过指定类型节点（Rlv2PassNodeSpec）
   *
   * 在主题/模式/难度门槛下，通过 param[4]（逗号分隔节点类型名）任一节点各计 1，达 param[5] 完成。
   * 用例：「累计通过5次不期而遇节点」（param[4]="INCIDENT"）、「累计通过12次任意界园战斗节点」
   * （param[4]="BATTLE_NORMAL,BATTLE_ELITE,BATTLE_BOSS"）。
   * @param param[1] 主题 id
   * @param param[2] 模式
   * @param param[3] 难度门槛
   * @param param[4] 节点类型名列表（逗号分隔，见 RLV2_MISSION_NODE_VALUES）
   * @param param[5] 目标通过次数
   */
  Rlv2PassNodeSpec: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[5]),
        });
      },
      update: (mission, args: { theme: string; mode: string; grade: number; nodeType: number }) => {
        if (!matchesRlv2Context(mission, args)) return;
        const names = mission.param[4].split(",");
        const ok = names.some((n) => RLV2_MISSION_NODE_VALUES[n] === args.nodeType);
        if (!ok) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 累计秉烛（Rlv2CandleTimes）
   *
   * 在主题/模式/难度门槛下，秉烛（岁兽残识中干员入队即视为秉烛）各计 1，达 param[4] 完成。
   * 用例：「累计秉烛5次」（param=["1","rogue_5","NORMAL","1","5"]）。
   * @param param[1] 主题 id
   * @param param[2] 模式
   * @param param[3] 难度门槛
   * @param param[4] 目标秉烛次数
   */
  Rlv2CandleTimes: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[4]),
        });
      },
      update: (mission, args: { theme: string; mode: string; grade: number }) => {
        if (!matchesRlv2Context(mission, args)) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 累计在岁兽残识消耗烛火（Rlv2SpZoneSteps）
   *
   * 在主题/模式/难度门槛下，移动消耗烛火按 cost 累计，达 param[4] 完成。
   * 用例：「累计在岁兽残识消耗8点烛火」（param=["1","rogue_5","NORMAL","1","8"]）。
   * @param param[1] 主题 id
   * @param param[2] 模式
   * @param param[3] 难度门槛
   * @param param[4] 目标烛火消耗
   */
  Rlv2SpZoneSteps: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[4]),
        });
      },
      update: (mission, args: { theme: string; mode: string; grade: number; cost: number }) => {
        if (!matchesRlv2Context(mission, args)) return;
        mission.progress[0].value += args.cost || 1;
      },
    },
  },

  /**
   * 使用 N 个分队在难度门槛以上通关任意结局（Rlv2BandGradeCnt）
   *
   * 结算时按累计「分队×难度」记录统计在 param[2] 及以上通关任意结局的分队数，取较大值作进度。
   * 用例：「请君入园·2及以上，通关任意结局」（param=["1","rogue_5","2","1"]）、
   * 「请君入园·4及以上，累计使用三个分队通关任意结局」（param=["1","rogue_5","4","3"]）。
   * @param param[1] 主题 id
   * @param param[2] 难度门槛
   * @param param[3] 目标分队数
   */
  Rlv2BandGradeCnt: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[3]),
        });
      },
      update: (mission, args: { theme: string; bandGrade: Record<string, Record<string, number>> }) => {
        if (args.theme !== mission.param[1]) return;
        const count = countBandsAtGrade(args.bandGrade, parseInt(mission.param[2]));
        mission.progress[0].value = Math.max(mission.progress[0].value, count);
      },
    },
  },

  /**
   * 使用 N 个分队在难度门槛以上达成指定结局（Rlv2EndingBandGradeCnt）
   *
   * 结算时按累计「分队×结局」「分队×难度」记录统计在 param[2] 及以上达成 param[4] 结局的分队数。
   * 用例：「请君入园·5及以上，累计使用三个分队达成结局'长卷留痕'」（param=["1","rogue_5","5","3","ro5_ending_2"]）。
   * @param param[1] 主题 id
   * @param param[2] 难度门槛
   * @param param[3] 目标分队数
   * @param param[4] 结局 id
   */
  Rlv2EndingBandGradeCnt: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[3]),
        });
      },
      update: (
        mission,
        args: {
          theme: string;
          bandGrade: Record<string, Record<string, number>>;
          bandCnt: Record<string, Record<string, number>>;
          ending: string;
        },
      ) => {
        if (args.theme !== mission.param[1]) return;
        if (args.ending !== mission.param[4]) return;
        const count = countBandsWithEndingAtGrade(
          args.bandGrade,
          args.bandCnt,
          parseInt(mission.param[2]),
          args.ending,
        );
        mission.progress[0].value = Math.max(mission.progress[0].value, count);
      },
    },
  },

  /**
   * 在难度门槛以上达成指定结局（Rlv2EndingModeGrade）
   *
   * 结算时按累计记录判定是否在 param[3] 及以上达成 param[4] 结局（目标恒 1）。
   * 用例：「请君入园·9及以上，达成结局'黑白入玄'」（param=["1","rogue_5","NORMAL","9","ro5_ending_3"]）。
   * @param param[1] 主题 id
   * @param param[2] 模式
   * @param param[3] 难度门槛
   * @param param[4] 结局 id
   */
  Rlv2EndingModeGrade: {
    "1": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (
        mission,
        args: {
          theme: string;
          bandGrade: Record<string, Record<string, number>>;
          bandCnt: Record<string, Record<string, number>>;
          ending: string;
        },
      ) => {
        if (args.theme !== mission.param[1]) return;
        if (args.ending !== mission.param[4]) return;
        const ok = achievedEndingAtGrade(
          args.bandGrade,
          args.bandCnt,
          parseInt(mission.param[3]),
          args.ending,
        );
        mission.progress[0].value = Math.max(mission.progress[0].value, ok);
      },
    },
  },

  /**
   * 使用指定分队招募指定干员并达成任意结局（Rlv2EndingWithBandChar）
   *
   * 本局判定：分队属于 param[4]（逗号分隔分队 id）、招募 param[5] 干员、通关任意结局。
   * 用例：「请君入园·7及以上，使用游客分队招募电弧并达成任意结局」
   * （param=["1","rogue_5","NORMAL","7","rogue_5_band_15,rogue_5_band_16,rogue_5_band_27","char_4195_radian"]）。
   * @param param[1] 主题 id
   * @param param[2] 模式
   * @param param[3] 难度门槛
   * @param param[4] 分队 id 列表（逗号分隔）
   * @param param[5] 指定干员 id
   */
  Rlv2EndingWithBandChar: {
    "1": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (
        mission,
        args: { theme: string; mode: string; grade: number; bandId: string; charIds: string[]; ending: string },
      ) => {
        if (!matchesRlv2Context(mission, args)) return;
        if (!args.ending) return;
        if (!mission.param[4].split(",").includes(args.bandId)) return;
        if (!args.charIds.includes(mission.param[5])) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 招募指定干员、通过 N 次祸乱节点并达成指定结局（Rlv2EndingWithCharPassSpBattle）
   *
   * 本局判定：招募 param[4] 干员、通过 >=param[5] 次祸乱节点、达成 param[6] 结局。
   * 用例：「请君入园·6及以上，招募干员电弧，通过至少2次'祸乱'节点并达成结局'依律镇抚'」
   * （param=["1","rogue_5","NORMAL","6","char_4195_radian","2","ro5_ending_1"]）。
   * @param param[1] 主题 id
   * @param param[2] 模式
   * @param param[3] 难度门槛
   * @param param[4] 指定干员 id
   * @param param[5] 祸乱节点通过次数门槛
   * @param param[6] 结局 id
   */
  Rlv2EndingWithCharPassSpBattle: {
    "1": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (
        mission,
        args: { theme: string; mode: string; grade: number; charIds: string[]; spBattleCount: number; ending: string },
      ) => {
        if (!matchesRlv2Context(mission, args)) return;
        if (args.ending !== mission.param[6]) return;
        if (!args.charIds.includes(mission.param[4])) return;
        if (args.spBattleCount < parseInt(mission.param[5])) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 招募指定干员、N 名干员成为伺烛客并达成指定结局（Rlv2EndingWithCandleChar）
   *
   * 本局判定：招募 param[4] 干员、伺烛客数 >=param[5]（param[5]="0" 表示任意）、达成 param[6] 结局。
   * 岁兽残识中所有入队干员即为伺烛客（秉烛）。
   * 用例：「请君入园·6及以上，招募干员电弧，令至少6名干员成为伺烛客并达成结局'长卷留痕'」
   * （param=["1","rogue_5","NORMAL","6","char_4195_radian","6","ro5_ending_2"]）。
   * @param param[1] 主题 id
   * @param param[2] 模式
   * @param param[3] 难度门槛
   * @param param[4] 指定干员 id
   * @param param[5] 伺烛客数门槛（0=任意）
   * @param param[6] 结局 id
   */
  Rlv2EndingWithCandleChar: {
    "1": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (
        mission,
        args: { theme: string; mode: string; grade: number; charIds: string[]; candleCharCount: number; ending: string },
      ) => {
        if (!matchesRlv2Context(mission, args)) return;
        if (args.ending !== mission.param[6]) return;
        if (!args.charIds.includes(mission.param[4])) return;
        const need = parseInt(mission.param[5]);
        if (need > 0 && args.candleCharCount < need) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 招募指定干员并通关任意紧急作战（Rlv2EliteBattleWithChar）
   *
   * 本局判定：招募 param[4] 干员、通关任意紧急作战（BATTLE_ELITE 节点）。
   * 用例：「请君入园·6及以上，招募干员电弧并通关任意紧急作战」
   * （param=["1","rogue_5","NORMAL","6","char_4195_radian"]）。
   * @param param[1] 主题 id
   * @param param[2] 模式
   * @param param[3] 难度门槛
   * @param param[4] 指定干员 id
   */
  Rlv2EliteBattleWithChar: {
    "1": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (
        mission,
        args: { theme: string; mode: string; grade: number; charIds: string[]; eliteCount: number; ending: string },
      ) => {
        if (!matchesRlv2Context(mission, args)) return;
        if (!args.ending) return;
        if ((args.eliteCount ?? 0) < 1) return;
        if (!args.charIds.includes(mission.param[4])) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 指定关卡内达成战斗简单事件计数（Rlv2StageSimpleEventMore）
   *
   * 在主题/模式/难度门槛下，指定关卡 param[4] 中战斗简单事件 param[5]（如击杀"易"）按计数累计。
   * 用例：「请君入园·6及以上，使用电弧及其召唤物击杀'易'」
   * （param=["1","rogue_5","NORMAL","6","ro5_b_4","radian_kill_enemy_dylbhm","1"]）。
   * @param param[1] 主题 id
   * @param param[2] 模式
   * @param param[3] 难度门槛
   * @param param[4] 关卡 id
   * @param param[5] 简单事件键（extraBattleInfo 键）
   * @param param[6] 目标计数
   */
  Rlv2StageSimpleEventMore: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[6]),
        });
      },
      update: (
        mission,
        args: { theme: string; mode: string; grade: number; stageId: string; events: Record<string, number> },
      ) => {
        if (!matchesRlv2Context(mission, args)) return;
        if (args.stageId !== mission.param[4]) return;
        const count = args.events?.[mission.param[5]] ?? 0;
        mission.progress[0].value = Math.max(
          mission.progress[0].value,
          Math.min(count, mission.progress[0].target!),
        );
      },
    },
  },

  /**
   * 招募指定干员（Rlv2RecruitSpecificChar）
   *
   * 在指定主题中招募 param[2] 干员各计 1，达 param[3] 完成（可跨局累计）。
   * 用例：「招募机械师」「累计招募机械师3次」（param=["1","rogue_6","char_4230_mcnist","3"]）。
   * @param param[1] 主题 id
   * @param param[2] 指定干员 id
   * @param param[3] 目标招募次数
   */
  Rlv2RecruitSpecificChar: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[3]),
        });
      },
      update: (mission, args: { theme: string; charId: string }) => {
        if (args.theme !== mission.param[1]) return;
        if (args.charId !== mission.param[2]) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 进阶指定干员（Rlv2UpgradeSpecificChar）
   *
   * 在指定主题中招募时直接进阶（upgradePhase>=1，如 limited_direct_upgrade 直接进阶）的
   * param[2] 干员各计 1，达 param[3] 完成。
   * 用例：「进阶机械师」（param=["1","rogue_6","char_4230_mcnist","1"]）。
   * @param param[1] 主题 id
   * @param param[2] 指定干员 id
   * @param param[3] 目标进阶次数
   */
  Rlv2UpgradeSpecificChar: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[3]),
        });
      },
      update: (mission, args: { theme: string; charId: string }) => {
        if (args.theme !== mission.param[1]) return;
        if (args.charId !== mission.param[2]) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 探索被"居民"的恶意占据的节点（Rlv2MeetBandit）
   *
   * 在主题/模式/难度门槛下，抵达"居民"据点（BATTLE_SAVAGE）节点各计 1，达 param[4] 完成。
   * 用例：「探索1次被'居民'的恶意占据的节点」（param=["1","rogue_6","NORMAL","4","1"]）。
   * @param param[1] 主题 id
   * @param param[2] 模式
   * @param param[3] 难度门槛
   * @param param[4] 目标探索次数
   */
  Rlv2MeetBandit: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[4]),
        });
      },
      update: (mission, args: { theme: string; mode: string; grade: number }) => {
        if (!matchesRlv2Context(mission, args)) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 累计获得零件（Rlv2GainItem）
   *
   * 获得 param[2] 类型物品按数量累计，达 param[1] 完成。
   * 用例：「累计获得10个零件」（param=["1","10","SCRAP"]）。
   * @param param[1] 目标数量
   * @param param[2] 物品类型（SCRAP）
   */
  Rlv2GainItem: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { itemType: string; count: number }) => {
        if (args.itemType !== mission.param[2]) return;
        mission.progress[0].value += args.count || 1;
      },
    },
  },

  /**
   * 累计消耗行动力（Rlv2MoveCostAp）
   *
   * 在主题/模式/难度门槛下，网格移动消耗行动力按 cost 累计，达 param[4] 完成。
   * 用例：「累计消耗40行动力」（param=["1","rogue_6","NORMAL","0","40"]）。
   * @param param[1] 主题 id
   * @param param[2] 模式
   * @param param[3] 难度门槛
   * @param param[4] 目标行动力消耗
   */
  Rlv2MoveCostAp: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[4]),
        });
      },
      update: (mission, args: { theme: string; mode: string; grade: number; cost: number }) => {
        if (!matchesRlv2Context(mission, args)) return;
        mission.progress[0].value += args.cost || 1;
      },
    },
  },

  /**
   * 累计卖出零件（Rlv2ShopRecycle）
   *
   * 卖出 param[1] 类型物品按数量累计，达 param[2] 完成。
   * 用例：「累计卖出10个零件」（param=["1","SCRAP","10"]）。
   * @param param[1] 物品类型（SCRAP）
   * @param param[2] 目标数量
   */
  Rlv2ShopRecycle: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: { itemType: string; count: number }) => {
        if (args.itemType !== mission.param[1]) return;
        mission.progress[0].value += args.count || 1;
      },
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
    // 型1：通关指定单关 n 次（param[1]=关卡，param[2]=目标次数，param[3]=星级门槛）。
    // 大量别传 EX/普通关单关任务（917 个 missionData 用此型）；对齐 DoctoratePy
    // CompleteStageAct type1：命中 param[1] 且 completeState>=param[3] 每次 +1
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2] ?? "1"),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[1]) return;
        const gate = parseInt(mission.param[3] ?? "2");
        if (args.completeState < gate) return;
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

  // ==================== 通用活动战斗模板（DoctoratePy MissionTemplate 移植）====================
  // 名称与 ActivityTable.missionData.template 一致；update 从 battle 结算携带的
  // battleData.stats（enemyStats/charStats/skillTrigStats/extraBattleInfo）读取真实统计。
  // param[0]=type 位，语义对齐 DoctoratePy mission.py。

  /**
   * 指定关卡内累计杀敌 / 用技能 / 部署（StageWithCondition）
   * type0：param[1]=关卡列表(^)，param[2]=enemyId，param[3]=目标击杀数
   * type1：param[1]=关卡列表，param[2]=目标技能施放次数
   * type2：param[1]=关卡列表，param[2]=目标干员部署次数
   */
  StageWithCondition: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[3]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId) || args.completeState < 2) return;
        const stats = args.battleData?.stats;
        let sum = 0;
        for (const n of stats?.enemyStats ?? []) {
          if (n.Key.enemyId === mission.param[2] && n.Key.counterType === "HP_ZERO") {
            sum += n.Value;
          }
        }
        mission.progress[0].value += sum;
      },
    },
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId) || args.completeState < 2) return;
        const stats = args.battleData?.stats;
        let sum = 0;
        for (const n of stats?.skillTrigStats ?? []) {
          sum += n.Value;
        }
        mission.progress[0].value += sum;
      },
    },
    "2": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId) || args.completeState < 2) return;
        const stats = args.battleData?.stats;
        let sum = 0;
        for (const n of stats?.charStats ?? []) {
          if (n.Key.counterType === "SPAWN") {
            sum += n.Value;
          }
        }
        mission.progress[0].value += sum;
      },
    },
    // 型3：关卡三星且 extraBattleInfo 同时命中 param[2]**param[3] 累计达 param[4]
    //（act50side 载具骑乘 trap_* , ride / enemy killed_no_eat）
    "3": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[4] ?? "1"),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId) || args.completeState < 2) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let cnt = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[2]) && k.includes(mission.param[3])) {
            cnt += v;
          }
        }
        mission.progress[0].value += cnt;
      },
    },
    // 型4：关卡三星且 extraBattleInfo 命中 param[2] 累计达 param[3]
    //（如 flashstun / criticaldamage）
    "4": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[3]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId) || args.completeState < 2) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let cnt = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[2])) {
            cnt += v;
          }
        }
        mission.progress[0].value += cnt;
      },
    },
  },

  /**
   * 活动关卡累计击杀敌人（EnemyKill，type0）
   * param[1]=关卡列表(^)，param[2]=目标累计击杀数；命中关卡三星后按 killCnt 累加
   */
  EnemyKill: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId) || args.completeState < 2) return;
        mission.progress[0].value += args.killCnt;
      },
    },
  },

  /**
   * 通关任意关卡（CompleteStageOrCampaign，type0）
   * param[1]=目标累计通关次数
   */
  CompleteStageOrCampaign: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (!args.stageId || args.completeState < 2) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 通关物资筹备关卡（CompleteDailyStage，type1）
   * param[1]=物资类型（如 MATERIAL），param[2]=目标累计通关次数；stageType==DAILY 才计入
   */
  CompleteDailyStage: {
    "1": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (!args.stageId || args.completeState < 2) return;
        const stageType = excel.StageTable.stages[args.stageId]?.stageType;
        if (stageType !== "DAILY") return;
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 通关多维合作（CompleteAnyMulStage，type0）
   * param[1]=关卡，param[2]=星级门槛（completeState）
   */
  CompleteAnyMulStage: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[1]) return;
        if (args.completeState < parseInt(mission.param[2])) return;
        mission.progress[0].value += 1;
      },
    },
  },

  /**
   * 自走车发射计数（CompleteStageSimpleAtLeastId，type0）
   * param[1]=星级门槛，param[2]=关卡，param[3]=enemyId，param[4]=counterType(born)，
   * param[5]=目标次数；extraBattleInfo 中 key 同时含 enemy+counterType 之和达标即 +1
   */
  CompleteStageSimpleAtLeastId: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[3]) && k.includes(mission.param[4])) {
            count += v;
          }
        }
        if (count >= parseInt(mission.param[5])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 阻止/避免指定事件（CompleteStageSimpleAtMostId，type0）
   * param[1]=星级门槛，param[2]=关卡，param[3]=enemyId，param[4]=counterType(take)，
   * param[5]=上限次数；extraBattleInfo 中命中项计数不超上限即通关计 1 次
   */
  CompleteStageSimpleAtMostId: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[3]) && k.includes(mission.param[4])) {
            count += v;
          }
        }
        if (count <= parseInt(mission.param[5])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 通关且满足战斗统计条件（CompleteStageCondition）
   * 覆盖 DoctoratePy 最常用的细分型（读 battleData.stats 统计，不依赖 ownSlots）：
   *  type0：param[1]=星级门槛，param[2]=关卡，param[3]=技能 id 列表(^)，param[4]=目标施放次数
   *  type3：param[1]=门槛，param[2]=关卡，param[3]=装置 key，param[4]=上限——命中装置不超上限
   *  type4：param[1]=门槛，param[2]=关卡，param[3]=装置 key，param[4]=上限——累计不超上限
   *  type8：param[1]=门槛，param[2]=关卡，param[3]=enemyId，param[4]=counterType(killed)，param[5]=目标击杀
   *  type10：param[1]=门槛，param[2]=关卡，param[3]=teamKey，param[4]=目标计数
   *  type11：param[1]=门槛，param[2]=关卡，param[3]=key，param[4]=上限（潮汐撤退/击倒）
   *  type12：param[1]=门槛，param[2]=关卡，param[3]=干员列表(^)——指定干员无 DEAD 即 +1
   *  type15：param[1]=门槛，param[2]=关卡，param[3]=上限，param[4]=key（受影响干员数上限）
   */
  CompleteStageCondition: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const skills = mission.param[3].split("^");
        const stats = args.battleData?.stats;
        let count = 0;
        for (const n of stats?.skillTrigStats ?? []) {
          if (skills.includes(n.Key.skillId)) {
            count += n.Value;
          }
        }
        if (count >= parseInt(mission.param[4])) {
          mission.progress[0].value += 1;
        }
      },
    },
    "3": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        for (const [k, v] of info) {
          if (k.includes(mission.param[3]) && v <= parseInt(mission.param[4])) {
            mission.progress[0].value += 1;
            return;
          }
        }
      },
    },
    "4": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[3])) {
            count += v;
          }
        }
        if (count <= parseInt(mission.param[4])) {
          mission.progress[0].value += 1;
        }
      },
    },
    "8": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        for (const [k, v] of info) {
          if (k.includes(mission.param[3]) && k.includes(mission.param[4]) && v >= parseInt(mission.param[5])) {
            mission.progress[0].value += 1;
            return;
          }
        }
      },
    },
    "10": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[3])) {
            count += v;
          }
        }
        if (count >= parseInt(mission.param[4])) {
          mission.progress[0].value += 1;
        }
      },
    },
    "11": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[3])) {
            count += v;
          }
        }
        if (count <= parseInt(mission.param[4])) {
          mission.progress[0].value += 1;
        }
      },
    },
    "12": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const chars = mission.param[3].split("^");
        const stats = args.battleData?.stats;
        for (const n of stats?.charStats ?? []) {
          if (n.Key.counterType === "DEAD" && chars.includes(n.Key.charId)) {
            return;
          }
        }
        mission.progress[0].value += 1;
      },
    },
    "15": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[4])) {
            count += v;
          }
        }
        if (count <= parseInt(mission.param[3])) {
          mission.progress[0].value += 1;
        }
      },
    },
    "2": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[3])) {
            count += v;
          }
        }
        if (count >= parseInt(mission.param[4])) {
          mission.progress[0].value += 1;
        }
      },
    },
    "9": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[3]) && k.includes(mission.param[4])) {
            count += v;
          }
        }
        if (count >= parseInt(mission.param[5])) {
          mission.progress[0].value += 1;
        }
      },
    },
    // 型13：N 星通关且部署非助战的指定干员（param[3]=charId，param[4]=推进数）。
    // 需 ownSlots（battleInfo），事件暂不带 → 占位防崩（对齐 DoctoratePy TODO）
    "13": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      // 近似实现：N 星通关该关且上场干员 charId==param[3] 且非助战（未在 stats.idList）即推进。
      // 较 DoctoratePy ownSlots 的「编入非助战」判定更宽松（按实际上场判定）
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const stats = args.battleData?.stats;
        const idList: string[] = (stats?.idList ?? []) as unknown as string[];
        for (const n of stats?.charStats ?? []) {
          if (
            n.Key.charId === mission.param[3] &&
            n.Key.counterType === "SPAWN" &&
            !idList.includes(n.Key.charId)
          ) {
            mission.progress[0].value += parseInt(mission.param[4] ?? "1");
            return;
          }
        }
      },
    },
    // 型14：N 星通关且额外进化 buff 达到 param[3]（param[4]=buff key；extraBattleInfo 命中 key 数）
    "14": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k] of info) {
          if (k.includes(mission.param[4])) {
            count += 1;
          }
        }
        if (count >= parseInt(mission.param[3])) {
          mission.progress[0].value += 1;
        }
      },
    },
    // 型5：N 星通关且场上干员数不超过 param[3]（charList 规模判定）
    "5": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const cl = (args.battleData?.stats?.charList ?? {}) as Record<string, unknown>;
        if (Object.keys(cl).length <= parseInt(mission.param[3] ?? "0")) {
          mission.progress[0].value += 1;
        }
      },
    },
    // 型6/7：N 星通关且 extraBattleInfo 命中 param[3] 累计不超 param[4]（如不使用的装置）
    "6": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[3])) {
            count += v;
          }
        }
        if (count <= parseInt(mission.param[4])) {
          mission.progress[0].value += 1;
        }
      },
    },
    "7": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const info = Object.entries(args.battleData?.stats?.extraBattleInfo ?? {});
        let count = 0;
        for (const [k, v] of info) {
          if (k.includes(mission.param[3])) {
            count += v;
          }
        }
        if (count <= parseInt(mission.param[4])) {
          mission.progress[0].value += 1;
        }
      },
    },
    // 型16：N 星通关且部署 param[3] 势力的干员累计 param[4]（charStats SPAWN + nationId）
    "16": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const stats = args.battleData?.stats;
        let count = 0;
        for (const n of stats?.charStats ?? []) {
          if (n.Key.counterType === "SPAWN") {
            const national = excel.CharacterTable[n.Key.charId]?.nationId;
            if (national === mission.param[3]) {
              count += n.Value;
            }
          }
        }
        if (count >= parseInt(mission.param[4])) {
          mission.progress[0].value += 1;
        }
      },
    },
    // 型17：N 星通关且上场干员中至少 param[3] 位含 tag=param[4]（近似 ownSlots 编队 tag 判定）
    "17": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const stats = args.battleData?.stats;
        const seen = new Set<string>();
        let count = 0;
        for (const n of stats?.charStats ?? []) {
          if (seen.has(n.Key.charId)) continue;
          seen.add(n.Key.charId);
          const tags = excel.CharacterTable[n.Key.charId]?.tagList;
          const hit = Array.isArray(tags)
            ? (tags as string[]).some((t) => String(t).includes(mission.param[4]))
            : String(tags ?? "").includes(mission.param[4]);
          if (hit) {
            count += 1;
            if (count >= parseInt(mission.param[3] ?? "1")) break;
          }
        }
        if (count >= parseInt(mission.param[3] ?? "1")) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 携带遗物通关（CompleteStageWithRelic，type0）
   * param[1]=关卡列表(^)，param[2]=遗物 id，param[3]=目标部署次数；
   * packedRuneDataList 命中遗物且部署达标即 +1
   */
  CompleteStageWithRelic: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        const stages = mission.param[1].split("^");
        if (!stages.includes(args.stageId) || args.completeState < 2) return;
        const stats = args.battleData?.stats as any;
        const runes: string[] = stats?.packedRuneDataList ?? [];
        if (!runes.some((r: string) => String(r).includes(mission.param[2]))) return;
        let deploy = 0;
        for (const n of stats?.charStats ?? []) {
          if (n.Key.counterType === "SPAWN") {
            deploy += n.Value;
          }
        }
        if (deploy >= parseInt(mission.param[3])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 携带小帮手组件通关（CompleteStageWithTechTree，type0）
   * param[1]=星级门槛，param[2]=关卡，param[3]=组件 id 列表(^)，param[4]=携带上限；
   * packedRuneDataList 中命中组件数不超上限即 +1
   */
  CompleteStageWithTechTree: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: (mission, args: BattleData & { stageId: string }) => {
        if (args.stageId !== mission.param[2]) return;
        if (args.completeState < parseInt(mission.param[1])) return;
        const techs = mission.param[3].split(";");
        const stats = args.battleData?.stats as any;
        const runes: string[] = stats?.packedRuneDataList ?? [];
        let count = 0;
        for (const r of runes) {
          if (techs.includes(String(r))) {
            count += 1;
          }
        }
        if (count <= parseInt(mission.param[4])) {
          mission.progress[0].value += 1;
        }
      },
    },
  },

  /**
   * 驻守关卡通关（CompleteInterlockStage，type0，参照 DoctoratePy 占位实现）
   * 锁活动（act1lock）专属；当前不推进进度（完整判定需链路关卡状态）
   */
  CompleteInterlockStage: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: () => {},
    },
  },

  /**
   * 携带标志物通关（CompleteStageWithCharm，type0，参照 DoctoratePy 占位）
   * act12side 专属（玄铁/旗舰标志物判定）；完整判定需玩法状态，暂不推进防崩
   */
  CompleteStageWithCharm: {
    "0": {
      init: (mission) => {
        mission.progress.push({ value: mission.value, target: 1 });
      },
      update: () => {},
    },
  },

  /**
   * 累计获得活动货币（ActivityCoinGain，type0）
   * param[1]=activityId，param[2]=目标累计数，param[3]=活动币 itemId（如 act17side_token_compass）；
   * 事件由 inventory 获得目标币物品时发射，按 itemId 过滤累计
   */
  ActivityCoinGain: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[2]),
        });
      },
      update: (mission, args: { itemId: string; count: number }) => {
        if (args.itemId !== mission.param[3]) return;
        mission.progress[0].value += args.count ?? 1;
      },
    },
  },

  /**
   * 累计消耗龙门币（CostGold，type0）
   * param[1]=目标累计消耗；升级/晋升/远征等耗币处 emit {goldCost}（此处由 char 升级/晋升触发）
   */
  CostGold: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { goldCost: number }) => {
        if (!Number.isFinite(args.goldCost)) return;
        mission.progress[0].value += args.goldCost;
      },
    },
  },

  /**
   * 干员升级与晋升中累计消耗龙门币（CostGoldPlus，type0）
   * param[1]=目标累计消耗；char 升级/晋升处 emit {goldCostPlus}
   */
  CostGoldPlus: {
    "0": {
      init: (mission) => {
        mission.progress.push({
          value: mission.value,
          target: parseInt(mission.param[1]),
        });
      },
      update: (mission, args: { goldCostPlus: number }) => {
        if (!Number.isFinite(args.goldCostPlus)) return;
        mission.progress[0].value += args.goldCostPlus;
      },
    },
  },
};
