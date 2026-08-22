import { PlayerCharacter } from "@game/model/character";
import { ItemBundle } from "@excel/character_table";
import excel from "@excel/excel";
import { now } from "@utils/time";
import { logger } from "@utils/logger";
import config from "../../config";
import { PlayerDataManager } from "./PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";
import { Draft } from "mutative";
import { PlayerDataModel } from "@game/model/playerdata";
import { PlayerBuildingMeetingClue } from "@game/model/playerdata";
import { BuildingData_OrderType, BuildingData_RoomType } from "@game/model/playerdata";
import { accountManager } from "./AccountManager";
import { getManufactFormula, getWorkshopFormula, getBuildingConstant, getRoomPhase, getGoldRate, getManufactPhase, getDormPhase, getFurnitureInfo, getRoomMaxLevel, getManufactFormulaType, getRoomElectricity, getMeetingPhase, getHirePhase } from "@excel/building_excel";
import {
  CharBuffSource,
  roomSpeedBonus,
  controlGlobalBonus,
  dormRecoveryBonus,
  charMoodCost,
  getActiveCharBuffs,
  parseVupValue,
} from "@game/building/buff";

/**
 * 基建管理器类
 *
 * 负责游戏基建系统的所有业务逻辑，包括房间管理、干员分配、订单生产、
 * 线索系统、预设队列以及其他基建相关功能。
 * 通过 Immer 进行状态管理，所有变更通过 PlayerDataManager.update 进行。
 */
export class BuildingManager {
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  /**
   * 构造函数
   * @param player - 玩家数据管理器实例
   * @param _trigger - 事件触发器
   */
  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    // 每日刷新：会客室每日免费线索重置（dailyReward=null——"今日未领"合法值）
    this._trigger.on("refresh:daily", this.dailyRefresh.bind(this));
    this._trigger.on(
      "building:char:init",
      async ([char]: [PlayerCharacter]) => {
        await this._player.update(async (draft) => {
          draft.building.chars[char.instId] = {
            charId: char.charId,
            lastApAddTime: now(),
            ap: 8640000,
            roomSlotId: "",
            index: -1,
            changeScale: 0,
            bubble: {
              normal: {
                add: -1,
                ts: 0,
              },
              assist: {
                add: -1,
                ts: 0,
              },
              private: {
                add: -1,
                ts: 0,
              },
            },
            workTime: 0,
            privateRooms: [],
          };
        });
      },
    );
  }

  /** 获取会客室留言板信息 */
  get boardInfo(): string[] {
    return Object.keys(
      Object.values(this._player._playerdata.building.rooms.MEETING)[0].board,
    );
  }

  /**
   * 每日刷新：重置会客室每日免费线索 + 留言板社交点周切 + 被动信用（好友访问）累积
   *
   * 修复：
   * 1. getDailyClue 置位 room.dailyReward 后全库无清除逻辑（无每日重置）→
   *    每日免费线索只能领取一次，会客室线索收集（7 阵营合成奖励）形同虚设；
   *    每日刷新将 dailyReward 复位为 null（模板存档的"今日未领"合法值）。
   * 2. messageLeave.sp 周切从未发生——lastWeek 恒 0，留言板"上周社交点"
   *    永远领不到；按周一 4:00 边界滚动：lastWeek ← thisWeek、累计入账。
   * 3. 被动信用（socialReward.daily）从不累积——模板初值领取一次后信用经济
   *    枯竭；每日刷新模拟好友访问：daily += 好友数 × friendSlotInc（封顶
   *    creditPassiveLimit），getMeetingroomReward 领取后清零重新累积。
   */
  async dailyRefresh() {
    let friendCount = 0;
    try {
      const social = await accountManager.getSocial(
        String(this._player._playerdata.status.uid),
      );
      friendCount = social.friends.length;
    } catch (e) {
      logger.warn(
        "building",
        `dailyRefresh 好友列表加载失败: ${(e as Error).message}`,
      );
    }
    await this._player.update(async (draft) => {
      const ts = now();
      for (const room of Object.values(draft.building.rooms.MEETING ?? {})) {
        (room as any).dailyReward = null;
        this._rolloverWeekSp(room as any, ts);
        // 修复：被动信用每日模拟好友访问（封顶 creditPassiveLimit）
        this._accumulateDailyCredit(draft, room, friendCount);
      }
    });
  }

  /**
   * 内部方法：留言板社交点周切（周一 4:00 边界）
   * sp = { lastWeek, lastWeekSum, thisWeek, thisWeekSum }：
   * - 当前周已进入 → lastWeek ← thisWeek（上周可领）、thisWeek 归零重新累计
   * - 跨多周（长时间未登录）→ 只滚动一次（避免累计失真）
   */
  private _rolloverWeekSp(room: any, ts: number): void {
    const leave = room?.messageLeave;
    if (!leave?.sp) return;
    const lastTs = leave.lastUpdateSpTs ?? 0;
    if (lastTs <= 0) {
      leave.lastUpdateSpTs = ts;
      return;
    }
    const weekStart = (t: number): number => {
      const d = new Date(t * 1000);
      // 周一为每周起点（getDay(): 0=周日）
      const day = (d.getDay() + 6) % 7;
      d.setDate(d.getDate() - day);
      d.setHours(4, 0, 0, 0);
      return Math.floor(d.getTime() / 1000);
    };
    if (weekStart(ts) <= weekStart(lastTs)) return; // 同一周
    const sp = leave.sp;
    // 上周累计入账 + 上周可领 ← 本周累计
    sp.lastWeekSum = (sp.lastWeekSum ?? 0) + (sp.lastWeek ?? 0);
    sp.lastWeek = sp.thisWeek ?? 0;
    sp.thisWeekSum = (sp.thisWeekSum ?? 0) + (sp.thisWeek ?? 0);
    sp.thisWeek = 0;
    leave.lastUpdateSpTs = ts;
  }

  /** 获取信息共享时间戳 */
  get infoShare(): number {
    return Object.values(this._player._playerdata.building.rooms.MEETING)[0]
      .infoShare.ts;
  }

  /** 获取家具数量 */
  get furnCnt(): number {
    return Object.keys(this._player._playerdata.building.furniture).length;
  }

  /**
   * 按 laborRecoverTime（秒/点）自动恢复劳动力（_advanceBuilding 统一 deltaTime 推进调用）
   * 例：laborRecoverTime=360 → 6 分钟恢复 1 点，封顶 maxValue
   * @param draft - mutative 可写草稿
   * @param ts - 当前时间基准（秒），elapsed = ts - lastUpdateTime
   */
  private _recoverLabor(draft: Draft<PlayerDataModel>, ts: number): void {
    const labor = draft.building.status.labor;
    const rate = getBuildingConstant<number>("laborRecoverTime") ?? 360;
    const elapsed = ts - (labor.lastUpdateTime || ts);
    if (elapsed <= 0 || rate <= 0) return;
    const gain = Math.floor(elapsed / rate);
    if (gain > 0) {
      labor.value = Math.min(labor.value + gain, labor.maxValue);
      labor.lastUpdateTime = ts;
    }
  }

  /** 会客室 infoShare 待领取奖励指示（官方 reward 为 0/1：socialReward 有未领取信用 → 1） */
  private _infoShareReward(
    sr: { daily?: number; search?: number } | undefined,
  ): number {
    return (sr?.daily ?? 0) + (sr?.search ?? 0) > 0 ? 1 : 0;
  }

  /**
   * 内部方法：单次好友访问/情报分享的信用量（会客室相位 friendSlotInc，
   * 保底 creditGuaranteed=10，兜底 35）——信用经济循环的每次入账量
   */
  private _meetingCreditPerVisit(draft: Draft<PlayerDataModel>): number {
    const guaranteed = getBuildingConstant<number>("creditGuaranteed") ?? 10;
    for (const slot of Object.values(draft.building.roomSlots)) {
      if (slot?.roomId !== "MEETING") continue;
      const phase = getMeetingPhase(slot.level ?? 1);
      if (typeof phase?.friendSlotInc === "number" && phase.friendSlotInc > 0) {
        return phase.friendSlotInc;
      }
      return guaranteed;
    }
    return guaranteed;
  }

  /**
   * 内部方法：被动信用（socialReward.daily）累积——好友访问会客室每次 +
   * friendSlotInc，封顶 creditPassiveLimit（领取后清零重新累积）
   */
  private _accumulateDailyCredit(
    draft: Draft<PlayerDataModel>,
    room: any,
    visitCount: number,
  ): void {
    if (!room || visitCount <= 0) return;
    const perVisit = this._meetingCreditPerVisit(draft);
    const limit = getBuildingConstant<number>("creditPassiveLimit") ?? 100;
    room.socialReward = room.socialReward ?? { daily: 0, search: 0 };
    room.socialReward.daily = Math.min(
      (room.socialReward.daily ?? 0) + visitCount * perVisit,
      limit,
    );
  }

  /**
   * 内部方法：主动信用（socialReward.search）累积——情报分享每个访客 +
   * friendSlotInc，封顶 creditInitiativeLimit
   */
  private _accumulateSearchCredit(
    draft: Draft<PlayerDataModel>,
    room: any,
    visitorCount: number,
  ): void {
    if (!room || visitorCount <= 0) return;
    const perVisit = this._meetingCreditPerVisit(draft);
    const limit = getBuildingConstant<number>("creditInitiativeLimit") ?? 100;
    room.socialReward = room.socialReward ?? { daily: 0, search: 0 };
    room.socialReward.search = Math.min(
      (room.socialReward.search ?? 0) + visitorCount * perVisit,
      limit,
    );
  }

  /**
   * 更新会客室 infoShare 字段（惰性初始化 + reward 待领取指示）
   * 官方 sync/基建请求响应 delta 含 infoShare（抓包 reward:1=有待领取，
   * getInfoShareReward 处理后归 0）；不更新则客户端红点/领取状态不刷新。
   */
  private _refreshInfoShare(draft: Draft<PlayerDataModel>): void {
    const room = Object.values(draft.building.rooms.MEETING)[0];
    if (!room) return;
    const is = (room.infoShare ??= { ts: 0, reward: 0 });
    is.reward = this._infoShareReward(room.socialReward);
  }

  /**
   * 同步基建数据
   * 时间驱动：劳动力恢复 → 干员心情档位重算（岗位/技能）→ 干员心情累积 →
   * 制造站生产累积 → 贸易站订单补充 → 训练室进度推进 → 会客室 infoShare 待领取指示。
   * @returns 当前时间戳
   */
  /**
   * 内部方法：推进各生产房间 completeWorkTime 到未来（修复高频无限 sync）
   *
   * 客户端基建界面依据每个房间的 completeWorkTime 设置倒计时，并在其到达时触发
   * /building/sync 刷新。若 completeWorkTime 为过去值（含 0/缺失），客户端判定该房间
   * "事件已到期待处理"→ 立即 sync → 服务端不推进 → 无限请求。官方存档中 completeWorkTime
   * 恒为未来（下一次生产/订单/招募完成时刻）。此处按当前生产进度重算：
   * - 制造站：now + (costPoint - processPoint) / capacity（下一方案完成）
   * - 贸易站：now + (maxPoint - next.processPoint) / next.speed（下一订单刷新）
   * - 会客室/招募：now + (phase 阶段点 - processPoint) / speed（下一线索/干员刷新）
   * @param draft - mutative 可写草稿
   * @param ts - 当前时间基准（秒）
   */
  private _refreshRoomCompletionTimes(
    draft: Draft<PlayerDataModel>,
    ts: number,
  ): void {
    const rooms = draft.building.rooms;
    // 制造站：下一方案完成时刻
    for (const [slotId, room] of Object.entries(rooms.MANUFACTURE ?? {})) {
      if (!room || room.state !== 1) continue;
      const formula = getManufactFormula(room.formulaId);
      if (!formula) continue;
      const costPoint = formula.costPoint ?? 0;
      const capacity = this._roomCapacity(draft, slotId, formula);
      if (costPoint <= 0 || capacity <= 0) continue;
      const remain = room.remainSolutionCnt ?? 0;
      if (remain > 0) {
        // 计划未耗尽：下一方案完成时刻（未来）
        const left = Math.max(0, costPoint - (room.processPoint ?? 0));
        room.completeWorkTime = ts + Math.max(1, Math.ceil(left / capacity));
      } else if (room.completeWorkTime == null || room.completeWorkTime < ts) {
        // 计划已停摆（remain=0）：对齐官方置 -1（无倒计时，客户端据此显示"待收取"而非过期）
        room.completeWorkTime = -1;
      }
    }
    // 贸易站：下一订单生成/刷新时刻（next.processPoint → maxPoint）
    for (const room of Object.values(rooms.TRADING ?? {})) {
      if (!room || room.state !== 1) continue;
      const next = (room as any).next;
      if (next && typeof next.maxPoint === "number" && typeof next.processPoint === "number") {
        const speed = next.speed && next.speed > 0 ? next.speed : 1;
        const left = Math.max(0, next.maxPoint - next.processPoint);
        const cwt = ts + Math.max(1, Math.ceil(left / speed));
        // 参考官方：贸易站 completeWorkTime = 下一订单完成时刻（含 stock 补货）
        if (room.completeWorkTime == null || room.completeWorkTime < ts) {
          room.completeWorkTime = cwt;
        }
      }
    }
    // 会客室/招募：推进到下一重置边界（避免过去值导致无限 sync）
    // 官方这些房间的 completeWorkTime 是"下一事件完成时刻"（分钟级）。私服存档
    // processPoint 无精确阈值，直接推进到下一个 4:00/16:00 基建重置边界——
    // 既保证恒为未来（客户端不会因过去值无限 sync），又避免秒级高频轮询。
    for (const rtype of ["MEETING", "HIRE"] as const) {
      for (const room of Object.values(rooms[rtype] ?? {})) {
        if (!room || room.state !== 1) continue;
        if (room.completeWorkTime == null || room.completeWorkTime < ts) {
          room.completeWorkTime = this._nextDailyBoundary(ts);
        }
      }
    }
  }

  /**
   * 内部方法：刷新 event.building = 下一个最近事件时刻
   *
   * 官方语义：客户端在 event.building 到达时触发下一次 /building/sync。
   * 取 min(下一 4:00/16:00 重置边界, 所有房间最小未来 completeWorkTime)——
   * 既有即将完成的房间事件（订单/生产完成）时用事件时刻，否则回到重置边界
   * （DoctoratePy 参考行为），保证 event.building 恒为未来、随 sync 动态推进。
   * @param draft - mutative 可写草稿
   * @param ts - 当前时间基准（秒）
   */
  private _refreshBuildingEventTs(
    draft: Draft<PlayerDataModel>,
    ts: number,
  ): void {
    const boundary = this._nextDailyBoundary(ts);
    let earliestCwt = Infinity;
    for (const roomsByType of Object.values(draft.building.rooms)) {
      for (const room of Object.values(roomsByType ?? {})) {
        const cwt = (room as any)?.completeWorkTime;
        if (typeof cwt === "number" && cwt > ts) {
          earliestCwt = Math.min(earliestCwt, cwt);
        }
      }
    }
    const target = Math.min(boundary, earliestCwt);
    draft.event.building = target;
  }

  /**
   * 内部方法：下一次 4:00/16:00 基建重置边界（秒）
   * @param ts - 当前时间戳（秒）
   * @returns 下一个 4:00/16:00 边界（若已过今日 16:00 则取明日 4:00）
   */
  private _nextDailyBoundary(ts: number): number {
    const d = new Date(ts * 1000);
    const at = (h: number): Date => {
      const x = new Date(d);
      x.setHours(h, 0, 0, 0);
      return x;
    };
    const t4 = at(4).getTime();
    const t16 = at(16).getTime();
    const t4Next = at(4);
    t4Next.setDate(t4Next.getDate() + 1);
    const ms = d.getTime();
    const target = ms <= t4 ? t4 : ms <= t16 ? t16 : t4Next.getTime();
    return Math.floor(target / 1000);
  }

  /**
   * 统一 deltaTime 基建状态推进入口
   *
   * 时间基准由调用方注入（ts=整数秒、tsFloat=浮点秒）——所有子系统以
   * elapsed = ts - lastUpdateTime 推进，同一轮推进内时间一致，且不依赖真实时钟
   * （测试可直接注入任意 ts 验证 deltaTime 语义，无需 mock now()）。
   *
   * 推进顺序（与官方 sync 语义一致）：
   * 劳动力恢复 → 心情档位重算 → 干员心情累积 → 制造站生产 → 贸易站订单推进 →
   * 贸易站补单兜底 → 训练室进度 → 会客室 infoShare 指示。
   *
   * @param draft - mutative 可写草稿
   * @param ts - 当前时间基准（整数秒）
   * @param tsFloat - 浮点秒时间基准（默认同 ts；干员心情用毫秒精度保证增量恒在）
   */
  private _advanceBuilding(
    draft: Draft<PlayerDataModel>,
    ts: number,
    tsFloat: number = ts,
  ): void {
    // 劳动力恢复（按 laborRecoverTime 自动回涨，封顶 maxValue）
    this._recoverLabor(draft, ts);
    // 干员心情档位（changeScale）按当前岗位 + 干员技能重算——换班后无需等客户端
    this._recomputeCharScales(draft);
    // 干员心情（building.chars[].ap）随时间累积——官方每次 sync 都下发 chars 增量
    this._accrueCharAp(draft, tsFloat);
    // 制造站生产随时间累积（进度/产出不再与时间脱钩）
    for (const roomSlotId of Object.keys(draft.building.rooms.MANUFACTURE)) {
      this._accrueManufacture(draft, roomSlotId, ts);
    }
    // 贸易站订单按 next.processPoint 随时间生成（deltaTime 驱动）+ 静态补单兜底
    this._accrueTrading(draft, ts);
    this._refreshTradingOrders(draft);
    // 训练室进度推进（trainee.processPoint 随时间累积，客户端进度显示一致）
    this._accrueTraining(draft, ts);
    // 会客室线索搜集进度推进（processPoint 随时间累积，speed 含 meet_* buff）
    this._accrueMeeting(draft, ts);
    // 人力办公室人脉搜集进度推进（processPoint 随时间累积，speed 含 hire_* buff）
    this._accrueHire(draft, ts);
    // 统一时间戳：所有工作时间房间（state=1）lastUpdateTime 推进到 ts——
    // 修复 CONTROL/无推进条件房间（如无 next 的旧存档贸易站）时间戳长期停留旧值
    // （2222 存档 CONTROL/MEETING/HIRE lastUpdateTime 停在 6 天前）
    this._touchActiveRooms(draft, ts);
    // 会客室 infoShare.reward 待领取指示（官方 sync 响应含该字段）
    this._refreshInfoShare(draft);
  }

  /**
   * 内部方法：会客室线索搜集进度推进
   *
   * 官方模型（PlayerBuildingMeeting）：processPoint 随时间按有效速度累积
   * （基础 gatheringSpeed × (1 + 进驻干员 meet_* buff)），达到阈值出线索。
   * 修复（2026-08-19）：此前无推进逻辑——2222 存档会客室 processPoint 停在
   * 540 万、lastUpdateTime 停在 8-13，客户端进度/倒计时失实。
   * 私服简化：进度真实累积供客户端显示；线索产出仍由 getDailyClue/访客/边界驱动。
   *
   * @param draft - mutative 可写草稿
   * @param ts - 当前时间基准（秒）
   */
  private _accrueMeeting(draft: Draft<PlayerDataModel>, ts: number): void {
    for (const [slotId, roomRaw] of Object.entries(draft.building.rooms.MEETING ?? {})) {
      const room = roomRaw as any;
      if (!room || room.state !== 1) continue;
      const slot = draft.building.roomSlots[slotId];
      const base = getMeetingPhase(slot?.level ?? 1)?.gatheringSpeed;
      if (typeof base !== "number" || base <= 0) continue;
      // 有效速度 = 基础搜集速度 × (1 + 干员 meet_* buff)，回写供客户端进度一致
      const bonus = roomSpeedBonus(
        this._roomCharSources(draft, slot),
        "MEETING",
        [],
        this._specialCtx(draft),
      );
      room.speed = Math.round(base * (1 + bonus));
      const elapsed = ts - (room.lastUpdateTime || ts);
      if (elapsed <= 0) continue;
      room.lastUpdateTime = ts;
      room.processPoint = (room.processPoint ?? 0) + elapsed * room.speed;
    }
  }

  /**
   * 内部方法：人力办公室人脉搜集进度推进
   *
   * 官方模型（PlayerBuildingHire）：processPoint 随时间按有效速度累积
   * （基础 resSpeed × (1 + 进驻干员 hire_* buff)），达到阈值刷新招募位。
   * 修复（2026-08-19）：同会客室——此前无推进逻辑（2222 人力 processPoint 停摆）。
   * 私服简化：进度真实累积供客户端显示；招募位刷新由边界/每日刷新驱动。
   *
   * @param draft - mutative 可写草稿
   * @param ts - 当前时间基准（秒）
   */
  private _accrueHire(draft: Draft<PlayerDataModel>, ts: number): void {
    for (const [slotId, roomRaw] of Object.entries(draft.building.rooms.HIRE ?? {})) {
      const room = roomRaw as any;
      if (!room || room.state !== 1) continue;
      const slot = draft.building.roomSlots[slotId];
      const base = getHirePhase(slot?.level ?? 1)?.resSpeed;
      if (typeof base !== "number" || base <= 0) continue;
      const bonus = roomSpeedBonus(
        this._roomCharSources(draft, slot),
        "HIRE",
        [],
        this._specialCtx(draft),
      );
      room.speed = Math.round(base * (1 + bonus));
      const elapsed = ts - (room.lastUpdateTime || ts);
      if (elapsed <= 0) continue;
      room.lastUpdateTime = ts;
      room.processPoint = (room.processPoint ?? 0) + elapsed * room.speed;
    }
  }

  /**
   * 内部方法：工作时间房间统一时间戳推进
   * 所有工作时间房间（state=1）及常驻房间（CONTROL 无 state 字段、恒运行）的
   * lastUpdateTime ← ts——保证 sync 后基建时间戳恒为当前时间（官方每次 sync 推进
   * 全部房间），不因"无生产逻辑"（CONTROL）或"无订单进度"（旧存档 TRADING）而停留旧值。
   * @param draft - mutative 可写草稿
   * @param ts - 当前时间基准（秒）
   */
  private _touchActiveRooms(draft: Draft<PlayerDataModel>, ts: number): void {
    for (const [rtype, roomsByType] of Object.entries(draft.building.rooms)) {
      for (const roomRaw of Object.values(roomsByType ?? {})) {
        const room = roomRaw as any;
        if (!room || typeof room.lastUpdateTime !== "number") continue;
        // 工作时间（state=1）或常驻房间（CONTROL 无 state 字段）
        const active = room.state === 1 || rtype === "CONTROL";
        if (active) room.lastUpdateTime = ts;
      }
    }
  }

  async sync() {
    return await this._player.update(async (draft) => {
      const ts = now();
      // 浮点秒（毫秒精度）：任意两次 sync（≥1ms 间隔）lastApAddTime 必变 →
      // chars 增量恒在（同秒紧邻调用也能正常推进，不会出现空 delta 回归）
      const tsFloat = Date.now() / 1000;
      // 统一 deltaTime 推进（时间基准一次取定，全子系统共用）
      this._advanceBuilding(draft, ts, tsFloat);
      // 修复（高频无限 sync 根因）：客户端基建界面据各房间 completeWorkTime 调度倒计时
      // 与下一次 sync——存档中 completeWorkTime 是过去值（2025）→ 客户端判定"事件已到期
      // 待处理"→ 立即 sync → 服务端不推进 → 无限循环。此处按生产进度把制造站/贸易站/
      // 会客室/招募的 completeWorkTime 推进到未来，客户端据此正常调度。
      this._refreshRoomCompletionTimes(draft, ts);
      // event.building = 下一个最近事件时刻（min：下一 4:00/16:00 重置边界 / 最小未来
      // completeWorkTime）——对齐官方：客户端在 event.building 时刻触发下一次 sync。
      this._refreshBuildingEventTs(draft, ts);
      // 强制 event.building 每次进 delta（对齐 DoctoratePy 响应恒含 event）：
      // Immer 对未变化的值不产生补丁，而客户端需用它调度下一次 sync——
      // 缺失时沿用缓存旧值（过期边界）→ 立即重同步 → 紧循环。
      // 经 PlayerDataManager.forcePatch 注入（不回写 _playerdata，仅进 delta）
      this._player.forcePatch(
        ["event", "building"],
        draft.event.building as number,
      );
      return ts;
    });
  }

  /**
   * 内部方法：训练室进度推进
   * trainee.processPoint += 流逝时间 × trainee.speed × (1 + 教官训练 buff 加成)（与官方模型一致）
   *
   * 修复（2026-08-19）：trainee.state 判定错误——官方 PlayerBuildingTraineeState 枚举
   * EMPTY=0/TRAINING=1/OUTOFDATE=2/WAITING=3，训练中为 **state=1**；原实现 `state !== 3`
   * 把 WAITING(3) 当训练态 → 真实存档（state=1）训练进度从不推进（2222 空弦 processPoint 停摆）。
   * 完成（state=2 OUTOFDATE）仍由客户端计时驱动 completeUpgradeSpecialization。
   *
   * @param draft - mutative 可写草稿
   * @param ts - 当前时间基准（秒），elapsed = ts - lastUpdateTime
   */
  private _accrueTraining(draft: Draft<PlayerDataModel>, ts: number): void {
    const trainingRoom = draft.building.rooms.TRAINING;
    for (const roomSlotId of Object.keys(trainingRoom)) {
      const room = trainingRoom[roomSlotId];
      const trainee = room?.trainee;
      if (!trainee || trainee.charInstId <= 0 || trainee.state !== 1) continue;
      // 教官（slot charInstIds[0] 或 room.trainer）的 train_* buff 加速训练
      const slot = draft.building.roomSlots[roomSlotId];
      const trainerId =
        room.trainer?.charInstId ?? slot?.charInstIds?.[0] ?? -1;
      const trainerSrc = trainerId > 0 ? this._charSource(draft, trainerId) : null;
      const trainBonus = roomSpeedBonus(
        trainerSrc ? [trainerSrc] : [],
        "TRAINING",
        [],
      );
      const elapsed = ts - (room.lastUpdateTime || ts);
      if (elapsed <= 0) continue;
      room.lastUpdateTime = ts;
      trainee.processPoint =
        (trainee.processPoint ?? 0) +
        elapsed * (trainee.speed ?? 1) * (1 + trainBonus);
    }
  }

  /**
   * 内部方法：生成一笔贸易站金币订单（结构对齐官服 O_GOLD：delivery 3003 → gain GOLD）
   * 1~4 张贸易凭证 × 汇率 = 金币收益；订单 instId 由调用方保证递增连续。
   *
   * 特殊技能适配（独占订单，数据源 gamedata_const cc.tra.* 术语）：
   * - trade_ord_pepe（佩佩）：固定获取「特别独占订单」——所需赤金交付数为 0、收益恒定
   * - trade_ord_closure（可露希尔）：固定获取「可露希尔特别订单」——赤金交付 2、收益恒定
   */
  private _genTradingOrder(draft: Draft<PlayerDataModel>, room: any, instId: number): void {
    const rate = getGoldRate();
    // 定位该房间槽位 → 进驻干员的 TRADING 技能
    const slotId = Object.entries(draft.building.rooms.TRADING).find(
      ([, r]) => r === room,
    )?.[0];
    const slot = slotId ? draft.building.roomSlots[slotId] : null;
    const chars = this._roomCharSources(draft, slot ?? null);
    const hasBuff = (re: RegExp) =>
      chars.some((c) =>
        getActiveCharBuffs(c, "TRADING").some((b) => re.test(b?.buffId ?? "")),
      );
    // 佩佩「特别独占订单」：赤金交付 0、收益恒定（rate×2）
    if (hasBuff(/^trade_ord_pepe/)) {
      room.stock.push({
        instId,
        delivery: [],
        type: "O_GOLD",
        gain: { id: "4001", type: "GOLD", count: rate * 2 },
        buff: [],
        special: "pepe",
      });
      return;
    }
    // 可露希尔「可露希尔特别订单」：赤金交付 2、收益恒定（rate×3）
    if (hasBuff(/^trade_ord_closure/)) {
      room.stock.push({
        instId,
        delivery: [{ id: "3003", type: "MATERIAL", count: 2 }],
        type: "O_GOLD",
        gain: { id: "4001", type: "GOLD", count: rate * 3 },
        buff: [],
        special: "closure",
      });
      return;
    }
    const count = 1 + Math.floor(Math.random() * 4);
    room.stock.push({
      instId,
      delivery: [{ id: "3003", type: "MATERIAL", count }],
      type: "O_GOLD",
      gain: { id: "4001", type: "GOLD", count: count * rate },
      buff: [],
    });
  }

  /**
   * 内部方法：贸易站订单时间推进（deltaTime 驱动）
   *
   * 官方模型（PlayerBuildingTradingNext）：next={order, processPoint, speed, maxPoint}，
   * processPoint 随时间按有效速度累积，达到 maxPoint 即生成一笔新订单并回退阈值。
   * 有效速度 = 存档 next.speed（基础订单效率）× (1 + 进驻干员 trade_* buff + 控制中枢
   * control_tra_* 全局)；回写 room.buff={speed, limit}（官方线格式，客户端倒计时显示）。
   *
   * 时间模型仅在存档已有订单进度（next.maxPoint > 0，官方迁移/时间累积过）时激活；
   * 旧存档无 next 数据 → 不惰性初始化（避免污染存档语义），交 _refreshTradingOrders
   * 静态补单兜底。
   *
   * @param draft - mutative 可写草稿
   * @param ts - 当前时间基准（秒）
   */
  private _accrueTrading(draft: Draft<PlayerDataModel>, ts: number): void {
    const controlBonus = this._controlGlobalFor(draft).TRADING ?? 0;
    for (const [slotId, room] of Object.entries(
      draft.building.rooms.TRADING ?? {},
    )) {
      if (!room || room.state !== 1) continue;
      // 回写官方线格式 buff：speed=订单效率加成、limit=库存上限（任何工作时间贸易站）
      const slot = draft.building.roomSlots[slotId];
      const chars = this._roomCharSources(draft, slot);
      const bonus =
        roomSpeedBonus(chars, "TRADING", [], this._specialCtx(draft)) +
        controlBonus;
      const roomBuff = (room.buff as any) ?? {};
      roomBuff.speed = bonus;
      roomBuff.limit = room.stockLimit ?? 0;
      room.buff = roomBuff;
      // 旧存档无订单进度 → 静态补单兜底（本方法不推进）
      const next = room.next;
      if (!next || (next.maxPoint ?? 0) <= 0) continue;
      const elapsed = ts - (room.lastUpdateTime || ts);
      if (elapsed <= 0) continue;
      room.lastUpdateTime = ts;
      // 有效速度 = 基础 × (1 + 加成)，回写 next.speed 供客户端倒计时一致
      const effSpeed = Math.max(0.01, (next.speed || 1) * (1 + bonus));
      next.speed = effSpeed;
      next.processPoint = (next.processPoint ?? 0) + elapsed * effSpeed;
      // 达到阈值 → 逐笔生成订单（修复：while 一次性结算全部达到的订单——
      // 原 if 只生成 1 笔，长时间离线累积多笔时进度滞留、订单节奏失真）
      const limit = Math.max(1, room.stockLimit ?? 2);
      while (
        next.processPoint >= next.maxPoint &&
        Array.isArray(room.stock) &&
        room.stock.length < limit
      ) {
        const orderId = (next.order ?? -1) + 1;
        this._genTradingOrder(draft, room, orderId);
        next.order = orderId;
        next.processPoint -= next.maxPoint;
      }
    }
  }

  /**
   * 内部方法：贸易站订单补充（静态兜底——旧存档无 next 时间累积的订单生成）
   *
   * 修复：服务端无订单生成逻辑——stock 由账号生成器静态填充，交付完即枯竭。
   * 简单机制：工作时间（state=1）且 stock 不足 stockLimit 时按 3003（贸易凭证）
   * × 汇率生成金币订单（结构与官服样本一致：delivery 3003 → gain GOLD）。
   *
   * 再修复：原实现恒补到 2 单（忽略 room.stockLimit）——贸易站升级/策略调整后
   * 库存上限形同虚设；现按 stockLimit 补单（缺省 2，防御 0/负数）。
   *
   * 时间模型已激活（next.maxPoint > 0）的房间跳过——订单由 _accrueTrading
   * 随时间逐笔生成，静态补单会破坏"订单获取效率"节奏。
   *
   * @param draft - mutative 可写草稿
   */
  private _refreshTradingOrders(
    draft: Draft<PlayerDataModel>,
  ): void {
    for (const slotId of Object.keys(draft.building.rooms.TRADING)) {
      const room = draft.building.rooms.TRADING[slotId];
      if (!room || room.state !== 1) continue;
      // 时间模型激活（next.maxPoint>0）→ 订单由 _accrueTrading 生成
      if (room.next?.maxPoint > 0) continue;
      if (!Array.isArray(room.stock)) room.stock = [];
      const target = Math.max(1, room.stockLimit ?? 2);
      if (room.stock.length >= target) continue;
      // instId 从现有库存最大值续增（保证递增连续）
      let maxInstId = room.stock.reduce((m, s) => Math.max(m, s?.instId ?? 0), 0);
      const missing = target - room.stock.length;
      for (let i = 0; i < missing; i++) {
        maxInstId += 1;
        this._genTradingOrder(draft, room, maxInstId);
      }
    }
  }

  /**
   * 切换基建背景音乐
   * @param args - 包含 musicId 的参数对象
   */
  async changeBGM(args: { musicId: string }) {
    const { musicId } = args;
    return await this._player.update(async (draft) => {
      const music = draft.building.music;
      music.selected = musicId;
      // 修复：inUse 未同步——客户端按 inUse 判定是否启用 BGM 播放
      music.inUse = !!musicId;
    });
  }

  /**
   * 设置私人宿舍归属
   *
   * 修复：
   * 1. CS 字段名为 charInsId（大 S），客户端发送 charInsId——
   *    原实现读 charInstId → undefined 写入 owners:[null] 破坏存档；
   * 2. 双端同步——原实现只写 room.owners：旧 owner 的 chars[].privateRooms
   *    残留旧宿舍、新 owner 若已在其他私人宿舍则两个宿舍同时挂 owner →
   *    客户端"干员已在其他私人宿舍"校验不一致。现同步清理旧 owner、迁移新 owner。
   *
   * @param args - 包含 slotId 和 charInstId 的参数对象
   */
  async setPrivateDormOwner(args: {
    slotId: string;
    charInstId?: number;
    charInsId?: number;
  }) {
    const { slotId } = args;
    // 修复：CS 字段名为 charInsId（大 S），客户端发送 charInsId——
    // 原实现读 charInstId → undefined 写入 owners:[null] 破坏存档
    const charInstId = args.charInstId ?? args.charInsId;
    if (charInstId == null) return;
    return await this._player.update(async (draft) => {
      const room = draft.building.rooms.PRIVATE[slotId];
      if (!room) return; // 防御：非法 slotId
      // 清理旧 owner：从该宿舍 owner 位置移除，并同步其 chars[].privateRooms
      for (const oldId of room.owners ?? []) {
        if (oldId > 0 && oldId !== charInstId) {
          const oldChar = draft.building.chars[String(oldId)];
          if (oldChar) {
            oldChar.privateRooms = (oldChar.privateRooms ?? []).filter(
              (r) => r !== slotId,
            );
          }
        }
      }
      // 若新 owner 此前在别的私人宿舍 → 移除旧归属（一干员一私人宿舍）
      const newChar = draft.building.chars[String(charInstId)];
      if (newChar) {
        for (const otherSlotId of newChar.privateRooms ?? []) {
          if (otherSlotId === slotId) continue;
          const otherRoom = draft.building.rooms.PRIVATE[otherSlotId];
          if (otherRoom) {
            otherRoom.owners = (otherRoom.owners ?? []).filter(
              (id) => id !== charInstId,
            );
          }
        }
        newChar.privateRooms = [
          ...(newChar.privateRooms ?? []).filter((r) => r !== slotId),
          slotId,
        ];
      }
      room.owners = [charInstId];
    });
  }

  /**
   * 设置基建助战干员
   * @param args - 包含 type（位置）和 charInstId 的参数对象
   */
  async setBuildingAssist(args: { type: number; charInstId: number }) {
    const { type, charInstId } = args;
    await this._player.update(async (draft) => {
      if (draft.building.assist.includes(charInstId)) {
        const index = draft.building.assist.indexOf(charInstId);
        draft.building.assist[index] = -1;
      }
      draft.building.assist[type] = charInstId;
    });
    // 修复：SetBuildingAssist 任务事件从未 emit → 设置基建助手类任务永不推进
    await this._trigger.emit("SetBuildingAssist", []);
  }

  // ==================== 内部工具方法 ====================

  /** 查找干员所在房间槽位 ID */
  _findRoomSlotIdByChar(charInstId: number): string | undefined {
    const slots = this._player._playerdata.building.roomSlots;
    for (const slotId of Object.keys(slots)) {
      if (slots[slotId].charInstIds.includes(charInstId)) {
        return slotId;
      }
    }
    return undefined;
  }

  /** 从所有房间槽位中移除指定干员（置为 -1） */
  _clearCharFromRooms(charInstIdList: number[]): void {
    const slots = this._player._playerdata.building.roomSlots;
    for (const slotId of Object.keys(slots)) {
      const ids = slots[slotId].charInstIds;
      for (let i = 0; i < ids.length; i++) {
        if (charInstIdList.includes(ids[i])) {
          ids[i] = -1;
        }
      }
    }
  }

  // ==================== 干员技能（buff）计算 ====================

  /** 干员 buff 激活所需信息（charId/level/evolvePhase），缺失返回 null */
  private _charSource(
    draft: Draft<PlayerDataModel>,
    instId: number,
  ): CharBuffSource | null {
    const char = draft.troop?.chars?.[String(instId)];
    if (!char?.charId) return null;
    return {
      charId: char.charId,
      level: char.level ?? 0,
      evolvePhase: char.evolvePhase ?? 0,
    };
  }

  /** 指定房间进驻干员的 buff 源列表（过滤无效干员） */
  private _roomCharSources(
    draft: Draft<PlayerDataModel>,
    slot: { charInstIds?: number[] } | null | undefined,
  ): CharBuffSource[] {
    return (slot?.charInstIds ?? [])
      .filter((i) => i > 0)
      .map((i) => this._charSource(draft, i))
      .filter((c): c is CharBuffSource => c != null);
  }

  /** 控制中枢进驻干员的全局 buff（按目标房间类型，乘法系数） */
  private _controlGlobalFor(
    draft: Draft<PlayerDataModel>,
  ): Record<string, number> {
    const ctlSlot = Object.values(draft.building.roomSlots).find(
      (s) => s.roomId === "CONTROL",
    );
    return controlGlobalBonus(
      this._roomCharSources(draft, ctlSlot ?? null),
      this._specialCtx(draft),
    );
  }

  /**
   * 特殊技能上下文：各房间进驻干员 charId（按房间类型分组）。
   * 供 fraction/token 条件技能判定（"每个进驻制造站的X干员"→ manufactureCharIds、
   * "≥N台作业平台进驻发电站"→ powerCharIds、"与X同驻控制中枢"→ controlCharIds）。
   */
  private _specialCtx(draft: Draft<PlayerDataModel>): any {
    const byRoom: Record<string, string[]> = {};
    for (const slot of Object.values(draft.building.roomSlots)) {
      if (!slot?.roomId) continue;
      const ids = (slot.charInstIds ?? [])
        .filter((i) => i > 0)
        .map((i) => this._charSource(draft, i)?.charId)
        .filter((c): c is string => c != null);
      (byRoom[slot.roomId] ??= []).push(...ids);
    }
    return {
      roomCharIds: byRoom.MANUFACTURE ?? [],
      manufactureCharIds: byRoom.MANUFACTURE ?? [],
      tradingCharIds: byRoom.TRADING ?? [],
      dormCharIds: byRoom.DORMITORY ?? [],
      powerCharIds: byRoom.POWER ?? [],
      controlCharIds: byRoom.CONTROL ?? [],
    };
  }

  /** 制造站基础容量（房间等级 phase.outputCapacity；缺数据回退房间存储值） */
  private _manufactBaseCapacity(
    draft: Draft<PlayerDataModel>,
    roomSlotId: string,
    room: any,
  ): number {
    const slot = draft.building.roomSlots[roomSlotId];
    const phase = getManufactPhase(slot?.level ?? 1);
    return phase?.outputCapacity ?? room?.capacity ?? 0;
  }

  /**
   * 制造站有效容量（基础容量 × (1 + 干员技能加成 + 控制中枢全局加成)）。
   * 官方线格式约定：room.capacity = 基础容量（相位 outputCapacity），buff.speed = 加成系数
   * ——服务端生产按有效容量随时间累积，并回写 buff.speed 供客户端计时显示一致。
   */
  private _roomCapacity(
    draft: Draft<PlayerDataModel>,
    roomSlotId: string,
    formula: any,
  ): number {
    const slot = draft.building.roomSlots[roomSlotId];
    const room = draft.building.rooms.MANUFACTURE[roomSlotId];
    const base = this._manufactBaseCapacity(draft, roomSlotId, room);
    const chars = this._roomCharSources(draft, slot);
    // targets 过滤：buff.targets 非空时仅对配方类型（F_GOLD/F_EXP/…）生效
    const targets = formula?.formulaType ? [formula.formulaType] : [];
    const bonus =
      roomSpeedBonus(chars, "MANUFACTURE", targets, this._specialCtx(draft)) +
      (this._controlGlobalFor(draft).MANUFACTURE ?? 0);
    if (room) {
      room.capacity = base;
      const roomBuff = (room.buff as any) ?? {};
      roomBuff.speed = bonus;
      room.buff = roomBuff;
    }
    return Math.max(1, Math.round(base * (1 + bonus)));
  }

  /**
   * 宿舍等级基础心情恢复（点/小时）：phase.manpowerRecover / 160（1 级 = 1.0 点/小时）。
   * 数据版本部分相位为占位字符串（YOSTAR_SDK_DELETE_ACCOUNT 等）→ 按等差回退（160 + (lv-1)×10）。
   */
  private _dormPhaseRecovery(level: number): number {
    const raw = getDormPhase(level)?.manpowerRecover;
    if (typeof raw === "number" && raw > 0) return raw;
    return 160 + (level - 1) * 10;
  }

  /**
   * 宿舍心情恢复档位（changeScale，AP/秒）：
   * (基础 + 舒适度 + 进驻干员 dorm_* buff + 控制中枢 control_dorm_* 全局) × 100
   * 单位校准：1 点/小时 = 100 AP/秒（真实存档：5 级 5000 舒适 → 405，与公式吻合）。
   */
  private _dormRecoveryPerSec(
    draft: Draft<PlayerDataModel>,
    slotId: string,
  ): number {
    const slot = draft.building.roomSlots[slotId];
    const room = draft.building.rooms.DORMITORY?.[slotId];
    const level = slot?.level ?? 1;
    const comfort = (room as any)?.comfort ?? 0;
    const basePerHour = this._dormPhaseRecovery(level) / 160;
    const comfortPerHour = (comfort / 1000) * 0.55; // 校准：5000 舒适 ≈ +2.75 点/小时
    const buffPerHour = dormRecoveryBonus(this._roomCharSources(draft, slot));
    const controlPerHour = this._controlGlobalFor(draft).DORMITORY ?? 0;
    return Math.round(
      (basePerHour + comfortPerHour + buffPerHour + controlPerHour) * 100,
    );
  }

  /** 输出类房间基础心情消耗（AP/秒，真实存档校准：制造/贸易 -55、会客/人力/发电 -65） */
  private _workBaseScale(roomType: string): number {
    switch (roomType) {
      case "MANUFACTURE":
      case "TRADING":
      case "WORKSHOP":
        return -55;
      case "MEETING":
      case "HIRE":
      case "POWER":
        return -65;
      default:
        return 0; // CONTROL/TRAINING/其他不消耗
    }
  }

  /**
   * 重算所有干员心情档位（changeScale）：
   * - 未进驻 → 0；宿舍 → 该宿舍恢复量；输出房间 → 基础消耗 - 技能附加消耗（charMoodCost）
   * 换班/休息后立即生效，随后 _accrueCharAp 按新档位随时间累积。
   */
  private _recomputeCharScales(draft: Draft<PlayerDataModel>): void {
    const roomTypeOf = new Map<number, string>();
    for (const slot of Object.values(draft.building.roomSlots)) {
      for (const instId of slot?.charInstIds ?? []) {
        if (instId > 0) roomTypeOf.set(instId, slot.roomId);
      }
    }
    // 宿舍恢复按宿舍房间分别计算（干员 → 所在宿舍恢复档位）
    const dormScale = new Map<number, number>();
    for (const [slotId, slot] of Object.entries(draft.building.roomSlots)) {
      if (slot.roomId !== "DORMITORY") continue;
      const scale = this._dormRecoveryPerSec(draft, slotId);
      for (const instId of slot.charInstIds ?? []) {
        if (instId > 0) dormScale.set(instId, scale);
      }
    }
    for (const [instIdStr, ch] of Object.entries(draft.building.chars ?? {})) {
      const instId = Number(instIdStr);
      const roomType = roomTypeOf.get(instId);
      let scale: number;
      if (roomType === "DORMITORY") {
        scale = dormScale.get(instId) ?? 0;
      } else if (!roomType) {
        scale = 0;
      } else {
        scale = this._workBaseScale(roomType);
        const src = this._charSource(draft, instId);
        if (src) {
          scale -= charMoodCost(src, roomType);
          // 特殊技能适配（控制中枢心情类，数据源 buffId 前缀 + <@cc.kw> 关键词干员）：
          // - control_mp_cost_double（魔王）：与阿米娅同驻控制中枢时，自身和阿米娅心情恢复
          // - control_mp_cost_reset（若叶睦）：与丰川祥子同驻控制中枢时，消除自身心情消耗
          if (roomType === "CONTROL") {
            const active = getActiveCharBuffs(src, "CONTROL");
            const ctlChars = this._roomCharSources(draft, this._controlSlot(draft));
            if (ctlChars.some((c) => c.charId === "char_002_amiya")) {
              const dbl = active.find((b) => /^control_mp_cost_double/.test(b?.buffId ?? ""));
              if (dbl) {
                // 恢复档位：描述 vup（点/小时）× 100 → AP/秒
                const rec = parseVupValue(dbl?.description);
                if (rec != null) scale = rec * 100;
              }
            }
            if (ctlChars.some((c) => c.charId === "char_4182_oblvns")) {
              const reset = active.find((b) => /^control_mp_cost_reset/.test(b?.buffId ?? ""));
              if (reset) scale = 0; // 消除自身心情消耗
            }
          }
        }
      }
      if (ch.changeScale !== scale) {
        ch.changeScale = scale;
      }
    }
  }

  /** 控制中枢槽位（特殊心情技能判定用） */
  private _controlSlot(draft: Draft<PlayerDataModel>): { charInstIds?: number[] } | null {
    return (
      Object.values(draft.building.roomSlots).find((s) => s.roomId === "CONTROL") ?? null
    );
  }

  // ==================== 房间管理 ====================

  /**
   * 建造房间（Excel 驱动——按 rooms[roomId].phases[1].buildCost 扣材料/劳动力）
   *
   * 修复：
   * 1. 建造前校验资源足额——原实现直接扣减，材料/金币不足时库存扣成负数；
   * 2. 建造后确保 rooms[roomId][slotId] 房间对象存在——原实现只改 slot，
   *    客户端按 roomId 查房间对象为空 → 房间"看不见"；
   * 3. 建造完成时间按 buildCost.time 推进（原实现恒 now()+1）。
   *
   * @param args - 包含 roomSlotId 和 roomId 的参数对象
   */
  async buildRoom(args: { roomSlotId: string; roomId: string }) {
    const { roomSlotId, roomId } = args;
    await this._player.update(async (draft) => {
      const slot = draft.building.roomSlots[roomSlotId];
      if (!slot) return;
      // 建造 = 1 级相位 buildCost（材料/金币/劳动力）
      const phase = getRoomPhase(roomId, 1);
      if (!phase) return; // 房间类型未知——容错跳过
      // 修复：资源足额校验——不足时拒绝建造（避免负库存/负金币）
      if (!this._canAfford(draft, phase.buildCost)) return;
      // 电力校验：新房间耗电（或换建时替换原房间耗电）后余额不得为负——
      // 官方行为：电力不足无法建造/升级，需先升级发电站
      const oldElec = slot.roomId ? getRoomElectricity(slot.roomId, slot.level ?? 1) : 0;
      const newElec = getRoomElectricity(roomId, 1);
      if (this._powerBalance(draft) - oldElec + newElec < 0) return;
      this._applyBuildCost(draft, phase.buildCost);
      slot.state = 1; // 建造中（completeUpgradeRoom 完成后置 2）
      slot.roomId = roomId as BuildingData_RoomType;
      slot.level = 1;
      const buildTime = phase.buildCost?.time ?? 0;
      slot.completeConstructTime = now() + Math.max(1, buildTime);
      // 修复：确保 rooms[roomId][slotId] 房间对象存在（客户端按类型查房间）
      const roomsByType = draft.building.rooms[roomId as keyof PlayerDataModel["building"]["rooms"]];
      if (roomsByType && !roomsByType[roomSlotId]) {
        (roomsByType as any)[roomSlotId] = { state: 1 };
      }
    });
    // 修复：HasRoom 任务事件从未 emit → 拥有房间类任务永不推进
    const roomCount = Object.values(
      this._player._playerdata.building.roomSlots,
    ).filter((s: any) => s.roomId).length;
    await this._trigger.emit("HasRoom", [{ roomCount }]);
  }

  /** 内部方法：建造/升级资源足额校验（items 含 GOLD 按 status.gold、MATERIAL 按 inventory；labor 按劳动力） */
  private _canAfford(
    draft: Draft<PlayerDataModel>,
    buildCost?: {
      items?: { id: string; count: number; type: string }[];
      time?: number;
      labor?: number;
    },
  ): boolean {
    for (const item of buildCost?.items ?? []) {
      const have =
        item.type === "GOLD"
          ? draft.status.gold
          : draft.inventory[item.id] || 0;
      if (have < (item.count ?? 0)) return false;
    }
    if (buildCost?.labor) {
      if (draft.building.status.labor.value < buildCost.labor) return false;
    }
    return true;
  }

  /**
   * 内部方法：当前电力余额（发电站供给 − 全部房间消耗，按相位 electricity 求和）。
   * POWER 房间相位为正向（+60/+130/+270 发电），其余房间为负向（-10/-30/… 消耗）。
   * 模板存档为满配布局，余额恰为 0——新建筑/升级需先升级发电站（官方行为）。
   */
  private _powerBalance(draft: Draft<PlayerDataModel>): number {
    let balance = 0;
    for (const slot of Object.values(draft.building.roomSlots)) {
      if (!slot?.roomId) continue;
      balance += getRoomElectricity(slot.roomId, slot.level ?? 1);
    }
    return balance;
  }

  /**
   * 升级房间等级（Excel 驱动——按目标等级相位 buildCost 扣资源）
   *
   * 修复：目标等级越界（超过 phases 上限）时按最高可用等级钳制——
   * 原实现相位不存在时静默跳过（客户端升级按钮无反馈）。
   *
   * @param args - 包含 roomSlotId 和 targetLevel 的参数对象
   */
  async upgradeRoom(args: { roomSlotId: string; targetLevel: number }) {
    const { roomSlotId, targetLevel } = args;
    return await this._player.update(async (draft) => {
      const slot = draft.building.roomSlots[roomSlotId];
      if (!slot) return;
      const maxLevel = getRoomMaxLevel(slot.roomId);
      const target = Math.max(1, Math.min(targetLevel || 1, maxLevel || 1));
      if (target <= (slot.level ?? 1)) return; // 无升级空间
      const phase = getRoomPhase(slot.roomId, target);
      if (!phase) return; // 相位不存在——容错跳过
      // 修复：升级前资源足额校验——不足时拒绝（避免负库存）
      if (!this._canAfford(draft, phase.buildCost)) return;
      // 电力校验：升级后耗电增量不得使余额为负（如发电站升级供给更多电力）
      const oldElec = getRoomElectricity(slot.roomId, slot.level ?? 1);
      const newElec = getRoomElectricity(slot.roomId, target);
      if (this._powerBalance(draft) - oldElec + newElec < 0) return;
      this._applyBuildCost(draft, phase.buildCost);
      slot.level = target;
      slot.state = 1; // 升级中（completeUpgradeRoom 完成后置 2，客户端进度一致）
    });
  }

  /**
   * 完成房间建造/升级
   *
   * 修复：原实现只刷新 event.building——buildRoom 置 state=1（建造中）后
   * 永远无法完成 → 客户端"建造中"房间卡死。现扫描全部槽位，将
   * state=1 且 completeConstructTime 已到的房间置为 state=2（已完成）。
   */
  async completeUpgradeRoom() {
    return await this._player.update(async (draft) => {
      const ts = now();
      for (const slot of Object.values(draft.building.roomSlots)) {
        if (slot.state === 1 && slot.completeConstructTime <= ts) {
          slot.state = 2;
        }
      }
      draft.event.building = this._nextDailyBoundary(now());
    });
  }

  /**
   * 降级房间
   *
   * 修复：等级下界钳制（原实现可降到 0 → 客户端房间等级非法）。
   * 简化实现：不返还建造材料。
   *
   * @param args - 包含 roomSlotId 的参数对象
   */
  async degradeRoom(args: { roomSlotId: string }) {
    const { roomSlotId } = args;
    return await this._player.update(async (draft) => {
      const slot = draft.building.roomSlots[roomSlotId];
      if (slot && slot.level > 1) {
        slot.level -= 1;
        slot.state = 2;
      }
    });
  }

  /** 内部方法：应用建造/升级消耗（items 扣 inventory/金币、labor 扣劳动力） */
  private _applyBuildCost(
    draft: Draft<PlayerDataModel>,
    buildCost?: { items?: { id: string; count: number; type: string }[]; time?: number; labor?: number },
  ): void {
    for (const item of buildCost?.items ?? []) {
      if (item.type === "GOLD") {
        draft.status.gold -= item.count;
      } else {
        draft.inventory[item.id] = (draft.inventory[item.id] || 0) - item.count;
      }
    }
    if (buildCost?.labor) {
      draft.building.status.labor.value = Math.max(
        draft.building.status.labor.value - buildCost.labor,
        0,
      );
    }
  }

  /**
   * 专精升级（开始训练）
   * 记录训练目标到训练室 trainee（官方 CS 枚举：TRAINING=1/OUTOFDATE=2/WAITING=3/EMPTY=0），
   * 将目标技能置为专精中（state=1），完成时由 completeUpgradeSpecialization 提升等级。
   *
   * 当 config.developer.specializationTimeZero=true 时，跳过训练等待——立即完成升级
   * （specializeLevel 直接 +1、技能复位、trainee 复位 WAITING），并照常发出
   * UpgradeSpecialization 任务事件。
   * @param args - 包含 charInstId 和 targetSkill（技能索引）的参数对象
   */
  async upgradeSpecialization(args: {
    charInstId: number;
    targetSkill: number;
    reduceTimeBd?: any;
  }) {
    const { charInstId, targetSkill } = args;
    // 专精时间强制为 0：调用即立即完成，任务事件照常发出（复用结算逻辑）
    if (config.developer?.specializationTimeZero) {
      let settledLevel = 0;
      await this._player.update(async (draft) => {
        const char = draft.troop.chars[String(charInstId)];
        if (char && char.skills && char.skills[targetSkill]) {
          char.skills[targetSkill].specializeLevel += 1;
          settledLevel = char.skills[targetSkill].specializeLevel;
          char.skills[targetSkill].state = 0;
          char.skills[targetSkill].completeUpgradeTime = -1;
        }
        // 复位训练室 trainee（官方线格式恒为对象：state=WAITING、targetSkill=-1）
        const rooms = Object.values(draft.building.rooms.TRAINING);
        const room =
          rooms.find((r) => r.trainee?.charInstId === charInstId) ?? rooms[0];
        if (room?.trainee) {
          room.trainee.state = 3; // WAITING
          room.trainee.targetSkill = -1;
          if (room.trainer) room.trainer.state = 3; // WAITING
          room.lastUpdateTime = now();
        }
      });
      if (settledLevel > 0) {
        await this._trigger.emit("UpgradeSpecialization", [
          { targetLevel: settledLevel },
        ]);
      }
      return;
    }
    return await this._player.update(async (draft) => {
      const char = draft.troop.chars[String(charInstId)];
      if (char && char.skills && char.skills[targetSkill]) {
        char.skills[targetSkill].state = 1; // 专精中
      }
      // 训练室状态同步：找到该干员的训练室（或首个空训练槽），记录训练目标。
      // 旧实现只改 skill.state，不写 trainee.targetSkill → 完成时（body 为空）读不到
      // 目标技能 → 专精永远无法结算。
      const rooms = Object.values(draft.building.rooms.TRAINING);
      const room =
        rooms.find((r) => r.trainee?.charInstId === charInstId) ??
        rooms.find((r) => !r.trainee || r.trainee.state === 0 || r.trainee.charInstId === -1) ??
        rooms[0];
      if (!room) return;
      if (room.trainee?.charInstId !== charInstId) {
        room.trainee = {
          charInstId,
          state: 1,
          targetSkill,
          processPoint: 0,
          speed: 1000,
        };
      } else {
        room.trainee.targetSkill = targetSkill;
        room.trainee.state = 1; // TRAINING
      }
      room.trainer = room.trainer ?? { charInstId: -1, state: 0 };
      room.trainer.state = 1; // TRAINING
      room.lastUpdateTime = now();
    });
  }

  /**
   * 完成专精升级（领取）
   * 提升目标技能 specializeLevel 并复位状态；trainee 复位为 WAITING（保留对象——官方
   * 线格式 trainee 恒为对象，置 null 会让客户端读 trainee.charInstId 崩溃 → 存档破坏）
   * @param args - 包含 charInstId 和 targetSkill（技能索引）的参数对象
   */
  async completeUpgradeSpecialization(args: {
    charInstId?: number;
    targetSkill?: number;
  }) {
    let settledLevel = 0;
    await this._player.update(async (draft) => {
      // 客户端请求体为空（抓包 body={}）——从训练室 trainee 读取待结算对象
      let charInstId = args.charInstId;
      let targetSkill = args.targetSkill;
      const rooms = Object.values(draft.building.rooms.TRAINING);
      const room =
        (charInstId != null
          ? rooms.find((r) => r.trainee?.charInstId === charInstId)
          : undefined) ??
        rooms.find(
          (r) => r.trainee && r.trainee.charInstId > 0 && r.trainee.targetSkill >= 0,
        );
      if (charInstId == null) charInstId = room?.trainee?.charInstId;
      if (targetSkill == null) targetSkill = room?.trainee?.targetSkill;
      if (charInstId == null || targetSkill == null || targetSkill < 0) return;
      const char = draft.troop.chars[String(charInstId)];
      let settled = false;
      if (char && char.skills && char.skills[targetSkill]) {
        char.skills[targetSkill].specializeLevel += 1;
        settledLevel = char.skills[targetSkill].specializeLevel;
        char.skills[targetSkill].state = 0;
        char.skills[targetSkill].completeUpgradeTime = -1;
        settled = true;
      }
      // 仅结算成功时复位 trainee——targetSkill 越界/干员 skills 为空时保留训练进度，
      // 避免"专精未发放但训练被清空"的存档破坏（训练成果丢失）
      if (settled && room?.trainee?.charInstId === charInstId) {
        // 官方线格式 trainee 恒为对象（LocalArknight 参考：完成后 state=WAITING、
        // targetSkill=-1，干员保留待下一次专精；置 null 会让客户端读 trainee.charInstId
        // 崩溃 → 存档破坏）
        room.trainee.state = 3; // WAITING
        room.trainee.targetSkill = -1;
        if (room.trainer) room.trainer.state = 3; // WAITING
        room.lastUpdateTime = now();
      }
    });
    // 修复：UpgradeSpecialization 任务事件从未 emit（建筑训练室路径）→ 专精任务永不推进；
    // char.ts 的"Duplicated"直改路径会发，本路径（真实训练室结算）补齐
    if (settledLevel > 0) {
      await this._trigger.emit("UpgradeSpecialization", [
        { targetLevel: settledLevel },
      ]);
    }
  }

  /**
   * 升级自定义等级
   * 简化实现：参考 Python 实现返回 202，预留接口
   */
  async upgradeDiyLevel() {
    return await this._player.update(async (draft) => {
      draft.event.building = this._nextDailyBoundary(now());
    });
  }

  // ==================== 干员分配 ====================

  /**
   * 分配干员到房间
   * 参考 Python AssignChar 实现：将干员从原房间移除并分配到目标房间
   * 对于训练室会特殊处理 trainer/trainee（修复：按房间类型定位训练室——
   * 原实现硬编码 slot_13，房间布局不同时训练室状态不同步）
   * @param args - 包含 roomSlotId 和 charInstIdList 的参数对象
   */
  async assignChar(args: { roomSlotId: string; charInstIdList: number[] }) {
    const { roomSlotId, charInstIdList } = args;
    return await this._player.update(async (draft) => {
      // 先将所有房间中已存在的相同干员移除（置为 -1）
      for (const slotKey in draft.building.roomSlots) {
        const slot = draft.building.roomSlots[slotKey];
        const ids = slot.charInstIds;
        for (let i = 0; i < ids.length; i++) {
          for (let n = 0; n < charInstIdList.length; n++) {
            if (charInstIdList[n] === ids[i]) {
              ids[i] = -1;
            }
          }
        }
      }
      // 将目标房间的干员列表替换为新列表
      draft.building.roomSlots[roomSlotId].charInstIds = charInstIdList;

      // 训练室特殊处理：按房间类型定位（不硬编码 slot_13）
      const slot = draft.building.roomSlots[roomSlotId];
      if (slot?.roomId === "TRAINING" && charInstIdList.length >= 2) {
        const trainer = charInstIdList[0];
        const trainee = charInstIdList[1];
        const trainingRoom = draft.building.rooms.TRAINING[roomSlotId];
        if (trainingRoom) {
          trainingRoom.trainee = trainingRoom.trainee ?? {
            charInstId: -1, processPoint: 0, speed: 1000, state: 0, targetSkill: -1,
          };
          trainingRoom.trainer = trainingRoom.trainer ?? { charInstId: -1, state: 0 };
          trainingRoom.trainee.charInstId = trainee;
          trainingRoom.trainee.targetSkill = -1;
          trainingRoom.trainee.speed = 1000;
          trainingRoom.trainer.charInstId = trainer;
          trainingRoom.trainee.state = trainee === -1 ? 0 : 3;
          trainingRoom.trainer.state = trainer === -1 ? 0 : 3;
        }
      }
      // 换班后立即按新岗位重算心情档位（下次 sync 按新档位随时间累积）
      this._recomputeCharScales(draft);
    });
  }

  /**
   * 批量更换工作干员
   * 将指定房间的干员列表替换为 charInstIdList，同时清空这些干员在其他房间的占用
   * @param args - 包含 roomSlotId 和 charInstIdList 的参数对象
   */
  /**
   * 批量更换工作干员（客户端换班管理入口）
   *
   * 官方协议：CS BuildingBatchChangeWorkCharRequest 无字段（实测 body={}）——
   * 客户端实际换班走 assignChar（每房间一条，含清人 assignChar [-1]）。
   * 服务端兼容请求体字段名变体（roomSlotId/slotId、charInstIdList/charInstIds/list），
   * 携带数据时立即生效；空请求体按官方行为返回当前状态（不 500、不改分配）。
   * @param args - 请求体（roomSlotId/slotId + charInstIdList/charInstIds/list）
   */
  /**
   * 内部方法：房间预设队列轮换——返回当前排班的下一组（循环）。
   * 客户端"换班"按钮调 batchChangeWorkChar（官方 CS 无字段）期望轮换排班；
   * 当前排班不在队列中 → 应用第一组；无队列 → null（不改分配）。
   */
  private _nextPresetQueue(
    draft: Draft<PlayerDataModel>,
    slotId: string,
  ): number[] | null {
    const queue = this._roomPresetQueue(draft, slotId);
    if (!queue || queue.length === 0) return null;
    const current = draft.building.roomSlots[slotId]?.charInstIds ?? [];
    const eq = (a: number[], b: number[]) =>
      Array.isArray(b) && a.length === b.length && a.every((v, i) => v === b[i]);
    const idx = queue.findIndex((q) => eq(current, q));
    if (idx === -1) return queue[0];
    return queue[(idx + 1) % queue.length];
  }

  async batchChangeWorkChar(args: {
    roomSlotId?: string;
    slotId?: string;
    charInstIdList?: number[];
    charInstIds?: number[];
    list?: number[];
  }) {
    const roomSlotId = args.roomSlotId ?? args.slotId;
    const charInstIdList = args.charInstIdList ?? args.charInstIds ?? args.list;
    return await this._player.update(async (draft) => {
      if (!roomSlotId) return;
      // 修复（2026-08-19）：官方 CS BuildingBatchChangeWorkCharRequest 无字段——
      // 客户端"换班"按钮发空体期望**预设队列轮换**（应用下一组排班）；
      // 原实现空体直接不改分配 → 客户端换班无效果。
      const target = Array.isArray(charInstIdList)
        ? charInstIdList
        : this._nextPresetQueue(draft, roomSlotId);
      if (!target) return;
      // 清空这些干员在其他房间的占用
      for (const slotKey in draft.building.roomSlots) {
        if (slotKey === roomSlotId) continue;
        const ids = draft.building.roomSlots[slotKey].charInstIds;
        for (let i = 0; i < ids.length; i++) {
          if (target.includes(ids[i])) {
            ids[i] = -1;
          }
        }
      }
      draft.building.roomSlots[roomSlotId].charInstIds = [...target];
      // 换班后立即按新岗位重算心情档位
      this._recomputeCharScales(draft);
    });
  }

  /**
   * 批量休息干员
   * 将指定干员从所有房间的工作位置移除（置为 -1）。
   * 官方 CS BuildingBatchChangeRestCharRequest 无字段（实际清人走 assignChar [-1]），
   * 服务端兼容 charInstIdList/charInstIds/list 字段名变体；空请求体不改分配。
   * @param args - 请求体（charInstIdList/charInstIds/list）
   */
  async batchRestChar(args: {
    charInstIdList?: number[];
    charInstIds?: number[];
    list?: number[];
  }) {
    const charInstIdList = args.charInstIdList ?? args.charInstIds ?? args.list;
    return await this._player.update(async (draft) => {
      if (!Array.isArray(charInstIdList)) return;
      for (const slotKey in draft.building.roomSlots) {
        const ids = draft.building.roomSlots[slotKey].charInstIds;
        for (let i = 0; i < ids.length; i++) {
          if (charInstIdList.includes(ids[i])) {
            ids[i] = -1;
          }
        }
      }
      // 休息后立即恢复空闲心情档位（0）
      this._recomputeCharScales(draft);
    });
  }

  /**
   * 清理房间槽位
   * 清空房间内全部干员（置为 -1）
   * @param args - 包含 roomSlotId 的参数对象
   */
  async cleanRoomSlot(args: { roomSlotId: string }) {
    const { roomSlotId } = args;
    return await this._player.update(async (draft) => {
      const slot = draft.building.roomSlots[roomSlotId];
      if (slot) {
        slot.charInstIds = slot.charInstIds.map(() => -1);
      }
    });
  }

  /**
   * 单次信赖增加量（Excel 驱动：basicFavorPerDay 每日信赖量 ÷ 60 ≈ 每小时量）
   * 例：basicFavorPerDay=720 → 12/次（官服按小时累积信赖，私服简化每次操作发放）
   */
  private get _intimacyGain(): number {
    const perDay = getBuildingConstant<number>("basicFavorPerDay") ?? 720;
    return Math.max(Math.round(perDay / 60), 1);
  }

  /** 给单个干员增加信赖（同步更新 troop.chars 与 charGroup） */
  private _addFavor(
    draft: Draft<PlayerDataModel>,
    charInstId: number,
    gain: number,
  ): void {
    const char = draft.troop.chars[String(charInstId)];
    if (!char) return;
    char.favorPoint += gain;
    if (draft.troop.charGroup[char.charId]) {
      draft.troop.charGroup[char.charId].favorPoint += gain;
    }
  }

  /**
   * 获得信赖（单个干员）
   * @param args - 包含 charInstId 的参数对象
   */
  async gainIntimacy(args: { charInstId: number }) {
    const { charInstId } = args;
    let gained = 0;
    await this._player.update(async (draft) => {
      this._addFavor(draft, charInstId, this._intimacyGain);
      gained = this._intimacyGain;
    });
    // 修复：GainIntimacy 任务事件从未 emit → 基建信赖类任务永不推进
    if (gained > 0) {
      await this._trigger.emit("GainIntimacy", [{ count: gained }]);
    }
  }

  /**
   * 获得全部信赖（所有在岗 + 助战干员）
   *
   * 修复：CS BuildingGainAllIntimacyResponse 含 normal/assist 计数——原实现
   * 只结算在岗干员且 assist 恒 0；现同步结算助战列表干员并返回真实计数。
   *
   * @param args - 请求体参数
   */
  async gainAllIntimacy(args: any): Promise<{ normal: number; assist: number }> {
    // 修复：响应需含 normal/assist 计数（CS BuildingGainAllIntimacyResponse）
    let normal = 0;
    let assist = 0;
    let total = 0;
    await this._player.update(async (draft) => {
      const seen = new Set<number>();
      for (const slotKey in draft.building.roomSlots) {
        for (const instId of draft.building.roomSlots[slotKey].charInstIds) {
          if (instId > 0 && !seen.has(instId)) {
            seen.add(instId);
            this._addFavor(draft, instId, this._intimacyGain);
            normal++;
          }
        }
      }
      // 修复：助战干员同步结算（与 gainAssistIntimacy 同源，客户端一键领取时计数正确）
      for (const instId of draft.building.assist ?? []) {
        if (instId > 0 && !seen.has(instId)) {
          seen.add(instId);
          this._addFavor(draft, instId, this._intimacyGain);
          assist++;
        }
      }
      total = normal + assist;
    });
    // 修复：GainIntimacy 任务事件从未 emit → 一键信赖不推进任务
    if (total > 0) {
      await this._trigger.emit("GainIntimacy", [{ count: total }]);
    }
    return { normal, assist };
  }

  /**
   * 获得助战信赖（assist 列表中的干员）
   * @param args - 请求体参数
   */
  async gainAssistIntimacy(args: any) {
    let gained = 0;
    await this._player.update(async (draft) => {
      for (const instId of draft.building.assist) {
        if (instId > 0) {
          this._addFavor(draft, instId, this._intimacyGain);
          gained += this._intimacyGain;
        }
      }
    });
    // 修复：GainIntimacy 任务事件从未 emit → 助战信赖不推进任务
    if (gained > 0) {
      await this._trigger.emit("GainIntimacy", [{ count: gained }]);
    }
  }

  /**
   * 确认私人宿舍信赖
   * 参考实现：将指定干员的信赖点数提升到 25570
   * @param args - 包含 charInstId 的参数对象
   */
  async confirmPrivateDormIntimacy(args: { charInstId: number }) {
    const charInstId = String(args.charInstId);
    let charId = "";
    const charInfo = this._player._playerdata.troop.chars[charInstId];
    if (charInfo) {
      charId = charInfo.charId;
    }
    return await this._player.update(async (draft) => {
      if (charId && draft.troop.charGroup[charId]) {
        draft.troop.charGroup[charId].favorPoint = 25570;
      }
      if (charId && draft.troop.chars[charInstId]) {
        draft.troop.chars[charInstId].favorPoint = 25570;
      }
    });
  }

  // ==================== 订单/生产 ====================

  /**
   * 内部方法：结算单条订单（真实订单结构——扣 delivery 物品、加 gain 物品）
   * 例：delivery=[{3003×3}]、gain={4001(金币)×1500} → 扣 3003×3、加金币 1500
   */
  private _settleOrderInternal(
    draft: Draft<PlayerDataModel>,
    stockItem: any,
  ): void {
    for (const d of stockItem?.delivery ?? []) {
      draft.inventory[d.id] = (draft.inventory[d.id] || 0) - (d.count ?? 1);
    }
    const gain = stockItem?.gain;
    if (gain) {
      if (gain.type === "GOLD") {
        draft.status.gold += gain.count ?? 0;
      } else {
        draft.inventory[gain.id] =
          (draft.inventory[gain.id] || 0) + (gain.count ?? 1);
      }
    }
  }

  /**
   * 加速订单（立即结算指定订单——按 instId 查找）
   * @param args - 包含 slotId 和 orderId（订单 instId）的参数对象
   */
  async accelerateOrder(args: { slotId: string; orderId: number }) {
    const { slotId, orderId } = args;
    return await this._player.update(async (draft) => {
      const room = draft.building.rooms.TRADING[slotId];
      if (room && Array.isArray(room.stock)) {
        const idx = room.stock.findIndex((s: any) => s.instId === orderId);
        if (idx !== -1) {
          this._settleOrderInternal(draft, room.stock[idx]);
          // 修复：splice 产生 DELETE patch（客户端删 stock 属性而非替换 → UI 残留）；
          // 用 filter 生成 replace patch（modified）
          room.stock = room.stock.filter((x: any) => x !== room.stock[idx]);
          // 修复：AccelerateOrder 任务事件从未 emit → 加速订单类任务永不推进
          await this._trigger.emit("AccelerateOrder", []);
        }
      }
    });
  }

  /**
   * 加速方案（制造站——立即完成当前生产方案 1 个）
   *
   * 修复（2026-08-14）：
   * 1. 原实现委托 settleSale 查 TRADING 房间，而客户端传的是制造站 slotId
   *    （抓包 {"slotId":"slot_15","cost":145}）→ 空 delta；改为按制造站槽位
   *    立即产出当前方案 1 个（受剩余目标限制）；
   * 2. 移除源石碎片（diamondShard）扣费——请求体 cost 为客户端本地消耗的
   *    「加速无人机」数量（客户端存档无服务端无人机计数字段），且设计文档明确
   *    「加速不消耗道具（私服友好）」；原实现把无人机数当源石碎片扣 → 玩家
   *    源石碎片被无故消耗（与 accelerateOrder 免费行为不一致，疑似 bug）。
   *
   * @param args - 包含 slotId（制造站槽位）和 cost（客户端无人机数，服务端不消耗）的参数对象
   */
  async accelerateSolution(args: { slotId: string; cost?: number }) {
    await this._player.update(async (draft) => {
      const room = draft.building.rooms.MANUFACTURE[args.slotId];
      // 无可加速方案（房间不存在/未开工/无配方）——不 500
      if (!room || !room.formulaId || room.state !== 1) return;
      const formula = getManufactFormula(String(room.formulaId));
      if (!formula) return;
      // 立即完成当前生产方案：产出 1 个方案
      if ((room.remainSolutionCnt ?? 0) > 0) room.remainSolutionCnt -= 1;
      room.outputSolutionCnt = (room.outputSolutionCnt ?? 0) + 1;
      room.processPoint = 0;
      room.lastUpdateTime = now();
      room.completeWorkTime = now();
    });
  }

  /**
   * 完成订单（贸易站交付——结算首条库存订单，扣 delivery 加 gain）
   * @param args - 包含 slotId 和 orderId 的参数对象
   */
  async deliveryOrder(args: { slotId: string; orderId: string }) {
    const { slotId, orderId } = args;
    let delivered = 0;
    await this._player.update(async (draft) => {
      const tradingRoom = draft.building.rooms.TRADING[slotId];
      if (tradingRoom && Array.isArray(tradingRoom.stock)) {
        // 修复：按客户端指定 orderId（instId）结算，缺省回退队首——与 deliveryBatchOrder 一致
        const idx =
          orderId != null
            ? tradingRoom.stock.findIndex(
                (s: any) => String(s.instId) === String(orderId),
              )
            : 0;
        if (idx !== -1 && tradingRoom.stock[idx]) {
          this._settleOrderInternal(draft, tradingRoom.stock[idx]);
          // 修复：splice → DELETE patch 客户端残留 → filter 替换
          tradingRoom.stock = tradingRoom.stock.filter(
            (x: any) => x !== tradingRoom.stock[idx],
          );
          delivered = 1;
        }
      }
    });
    // 修复：DeliveryOrder 任务事件从未 emit → 交付订单类任务永不推进
    if (delivered > 0) {
      await this._trigger.emit("DeliveryOrder", [{ count: delivered }]);
    }
  }

  /**
   * 批量完成订单（对 orderId 数组中的每个订单按 instId 结算）
   * 兼容字段变体（CS BuildingDeliveryBatchOrderRequest.slotList 为主）：
   * slotList / slotIdList / roomSlotIdList / 单值 slotId / roomSlotId——
   * 客户端改造版可能发不同字段名导致 200 但不交付（空循环）。
   * @param args - 包含 slotList（或变体）的参数对象
   */
  async deliveryBatchOrder(args: {
    slotList?: string[];
    slotIdList?: string[];
    roomSlotIdList?: string[];
    slotId?: string;
    roomSlotId?: string;
  }): Promise<{
    [slotId: string]: ItemBundle[];
  }> {
    // 修复：官方字段为 slotList（CS BuildingDeliveryBatchOrderRequest { slotList }，
    // 结算每个贸易站的全部库存订单）；原实现读 slotId/orderId → 客户端请求解构不到
    // → 空 delta。响应 delivered: { slotId: [收益物品] } 对齐 CS/抓包。
    const slotList =
      args.slotList ??
      args.slotIdList ??
      args.roomSlotIdList ??
      (args.slotId ? [args.slotId] : args.roomSlotId ? [args.roomSlotId] : []);
    const delivered: { [slotId: string]: ItemBundle[] } = {};
    let totalDelivered = 0;
    await this._player.update(async (draft) => {
      for (const slotId of slotList) {
        const room = draft.building.rooms.TRADING[slotId];
        if (!room || !Array.isArray(room.stock) || room.stock.length === 0) {
          delivered[slotId] = [];
          continue;
        }
        const gains: ItemBundle[] = [];
        // 倒序移除，避免索引错位
        for (let i = room.stock.length - 1; i >= 0; i--) {
          const stock = room.stock[i];
          const gain = stock?.gain;
          if (gain) {
            gains.push({ id: gain.id, type: gain.type, count: gain.count });
          }
          this._settleOrderInternal(draft, stock);
          // 修复：splice 产生 DELETE patch（客户端 UI 残留旧订单）→ filter 替换
          room.stock = room.stock.filter((x: any) => x !== stock);
          totalDelivered += 1;
        }
        delivered[slotId] = gains;
      }
    });
    // 修复：DeliveryOrder 任务事件从未 emit → 批量交付同样不推进任务
    if (totalDelivered > 0) {
      await this._trigger.emit("DeliveryOrder", [{ count: totalDelivered }]);
    }
    return delivered;
  }

  /**
   * 删除订单（按 instId）
   * @param args - 包含 slotId 和 orderId（订单 instId）的参数对象
   */
  async deleteOrder(args: { slotId: string; orderId: number }) {
    const { slotId, orderId } = args;
    return await this._player.update(async (draft) => {
      const room = draft.building.rooms.TRADING[slotId];
      if (room && Array.isArray(room.stock)) {
        room.stock = room.stock.filter((s: any) => s.instId !== orderId);
      }
    });
  }

  /**
   * 内部方法：制造站生产时间推进（deltaTime 驱动）
   * processPoint += 流逝时间 × 有效容量；达到 costPoint 产出 1 方案（计划剩余数钳制）。
   *
   * 修复：基建生产不随时间累积、生产速度 buff 无效的问题。
   * 官方模型：房间有效容量（基础容量 × (1 + 干员技能加成 + 控制中枢全局加成)）× 流逝时间
   * → processPoint，每满 formula.costPoint 产出 1 方案（remainSolutionCnt 递减、outputSolutionCnt 递增）。
   * 用房间自维护的 lastUpdateTime 计算流逝（生成器的 saveTime/tailTime 为相对值，不可用）。
   *
   * @param draft - mutative 可写草稿
   * @param roomSlotId - 制造站槽位 ID
   * @param ts - 当前时间基准（秒），elapsed = ts - lastUpdateTime
   */
  private _accrueManufacture(
    draft: Draft<PlayerDataModel>,
    roomSlotId: string,
    ts: number,
  ): void {
    const room = draft.building.rooms.MANUFACTURE[roomSlotId];
    if (!room || room.state !== 1) return;
    const formula = getManufactFormula(room.formulaId);
    if (!formula) return;
    const costPoint = formula.costPoint ?? 0;
    // 有效容量受进驻干员技能/控制中枢全局加成驱动（而非存档静态值）
    const capacity = this._roomCapacity(draft, roomSlotId, formula);
    if (costPoint <= 0 || capacity <= 0) return;
    // 修复：计划已耗尽（remain ≤ 0）即停止生产——官方计划完成后房间停摆待收取；
    // 原实现 remain=0 时跳过钳制 → 产出无上限累积（制造站赤金数量异常）
    const remain = room.remainSolutionCnt ?? 0;
    if (remain <= 0) return;
    const elapsed = ts - (room.lastUpdateTime || ts);
    if (elapsed <= 0) return;
    room.lastUpdateTime = ts;
    room.processPoint = (room.processPoint ?? 0) + elapsed * capacity;
    let produced = Math.floor(room.processPoint / costPoint);
    if (produced <= 0) return;
    // 修复：先按 remain 钳制再扣进度——原实现先扣全部 produced 再钳制，
    // 计划完成时超出部分的进度被整体销毁（如 produced=10、remain=3 → 7 方案进度蒸发）
    produced = Math.min(produced, remain);
    room.processPoint -= produced * costPoint;
    room.remainSolutionCnt = remain - produced;
    room.outputSolutionCnt = (room.outputSolutionCnt ?? 0) + produced;
  }

  /**
   * 制造站结算
   * 参考实现：根据配方将产出物品加入背包，并消耗对应材料，重置制造站状态
   * @param args - 包含 roomSlotId 的参数对象
   */
  async settleManufacture(args: { roomSlotIdList?: string[]; supplement?: number }) {
    // 修复：官方字段为 roomSlotIdList（数组），原实现读取单值 roomSlotId →
    // 客户端请求解构不到 → 空 delta → 客户端"无法更新制造站状态"
    const list = args.roomSlotIdList ?? [];
    let producedTotal = 0;
    await this._player.update(async (draft) => {
      for (const roomSlotId of list) {
        // 先推进时间累积的产出再结算
        this._accrueManufacture(draft, roomSlotId, now());
        const room = draft.building.rooms.MANUFACTURE[roomSlotId];
        producedTotal += room?.outputSolutionCnt ?? 0;
        await this._settleManufactureInternal(draft, roomSlotId);
        // 收获后状态（防御：非法 roomSlotId 直接跳过不 500）
        const roomAfter = draft.building.rooms.MANUFACTURE[roomSlotId];
        if (!roomAfter) continue;
        if ((roomAfter.remainSolutionCnt ?? 0) > 0) {
          // 修复：计划未耗尽时保留配方继续生产（原实现清空 state/formulaId →
          // 客户端"会清空当前计划"）；仅重置已收获的产出与进度
          roomAfter.outputSolutionCnt = 0;
          roomAfter.processPoint = 0;
          roomAfter.lastUpdateTime = now();
        } else {
          // 计划耗尽：停止生产并清空
          roomAfter.state = 0;
          roomAfter.formulaId = "";
          roomAfter.lastUpdateTime = now();
          roomAfter.completeWorkTime = -1;
          roomAfter.remainSolutionCnt = 0;
          roomAfter.outputSolutionCnt = 0;
          roomAfter.processPoint = 0;
        }
      }
    });
    // 修复：BuildingManufactureProductTimes 勋章事件从未 emit → 制造勋章永不推进
    if (producedTotal > 0) {
      await this._trigger.emit("BuildingManufactureProductTimes", [
        { count: producedTotal },
      ]);
    }
    // 返回结算的房间数（CS BuildingSettleManufactResponse.supplement）
    return list.length;
  }

  /**
   * 内部方法：执行制造站结算的材料/产出更新（Excel 驱动——查 manufactFormulas）
   * 产出：itemId × count × outputSolutionCnt；消耗：costs（MATERIAL 扣 inventory / GOLD 扣 status.gold）
   * @param draft - Immer 可写草稿
   * @param roomSlotId - 房间槽位 ID
   */
  private async _settleManufactureInternal(
    draft: Draft<PlayerDataModel>,
    roomSlotId: string,
  ) {
    const room = draft.building.rooms.MANUFACTURE[roomSlotId];
    if (!room) return;
    const outputSolutionCnt = room.outputSolutionCnt;
    const formulaIdStr = String(room.formulaId ?? "");
    if (outputSolutionCnt === 0 || !formulaIdStr) return;
    const formula = getManufactFormula(formulaIdStr);
    if (!formula) return; // 配方不存在（数据版本错位）——容错跳过

    // 产出：itemId × count × 已产出方案数
    const gainCount = (formula.count ?? 1) * outputSolutionCnt;
    draft.inventory[formula.itemId] =
      (draft.inventory[formula.itemId] || 0) + gainCount;
    // 修复：ManufactureItem 任务事件从未 emit → 制造物品类任务永不推进
    //（模板 0/2 读 item、模板 1 读 count，一并携带）
    await this._trigger.emit("ManufactureItem", [
      { item: { id: formula.itemId, count: gainCount }, count: gainCount },
    ]);

    // 消耗：costs（MATERIAL 扣 inventory / GOLD 扣 status.gold）
    // 修复：余额校验——材料/金币不足时按比例只结算可承担部分，避免负库存/负金币
    let affordable = outputSolutionCnt;
    for (const cost of formula.costs ?? []) {
      const per = cost.count ?? 0;
      if (per <= 0) continue;
      const need = per * outputSolutionCnt;
      const have =
        cost.type === "GOLD"
          ? draft.status.gold
          : draft.inventory[cost.id] || 0;
      if (need > 0 && have < need) {
        affordable = Math.min(affordable, Math.floor(have / per));
      }
    }
    if (affordable <= 0) {
      // 材料不足：回退产出（下轮 settle 再补扣），并恢复已产出方案到 remain——
      // 原实现只回退 inventory，outputSolutionCnt 残留被调用方清零 → 已产出货物丢失
      draft.inventory[formula.itemId] =
        (draft.inventory[formula.itemId] || 0) - gainCount;
      room.remainSolutionCnt =
        (room.remainSolutionCnt ?? 0) + room.outputSolutionCnt;
      room.outputSolutionCnt = 0;
      return;
    }
    const settleCount = Math.min(outputSolutionCnt, affordable);
    if (settleCount !== outputSolutionCnt) {
      // 部分结算：产出与消耗都按可承担数
      draft.inventory[formula.itemId] =
        (draft.inventory[formula.itemId] || 0) -
        (gainCount - (formula.count ?? 1) * settleCount);
      room.outputSolutionCnt = outputSolutionCnt - settleCount;
      room.remainSolutionCnt = (room.remainSolutionCnt ?? 0) + (outputSolutionCnt - settleCount);
    }
    for (const cost of formula.costs ?? []) {
      if (cost.type === "GOLD") {
        draft.status.gold -= cost.count * settleCount;
      } else {
        draft.inventory[cost.id] =
          (draft.inventory[cost.id] || 0) - cost.count * settleCount;
      }
    }
  }

  /**
   * 贸易站结算
   * 结算全部库存订单：扣贸易凭证 3003，按 count×500 兑换金币
   *
   * 修复：CS BuildingSettleSaleRequest 字段为 roomSlotIdList（数组）——
   * 原实现读单值 slotId → 客户端请求解构不到 → 空 delta；现兼容两种形态。
   *
   * @param args - 包含 slotId（或 roomSlotIdList）的参数对象
   */
  async settleSale(args: { slotId?: string; roomSlotIdList?: string[] }) {
    const list = args.roomSlotIdList?.length
      ? args.roomSlotIdList
      : args.slotId
        ? [args.slotId]
        : [];
    return await this._player.update(async (draft) => {
      for (const slotId of list) {
        const room = draft.building.rooms.TRADING[slotId];
        if (room && Array.isArray(room.stock)) {
          for (const item of room.stock) {
            this._settleOrderInternal(draft, item);
          }
          room.stock = [];
          room.lastUpdateTime = now();
        }
      }
    });
  }

  /**
   * 更换制造方案（客户端"收获后一键补货"入口）
   * 先推进并结算当前已产出的方案，再切换到新配方。
   * 返回 { change } 对齐官方 BuildingChangeManufactResponse（抓包 6 例均为 false——
   * 该字段为服务端确认标识，补货/换配方一律 false；方案本身按请求生效）。
   * @param args - 包含 roomSlotId、targetFormulaId、solutionCount 的参数对象
   */
  async changeManufactureSolution(args: {
    roomSlotId: string;
    targetFormulaId: string;
    solutionCount: number;
  }): Promise<{ change: boolean }> {
    const { roomSlotId, targetFormulaId, solutionCount } = args;
    await this._player.update(async (draft) => {
      // 先推进并结算当前已产出的方案
      this._accrueManufacture(draft, roomSlotId, now());
      this._settleManufactureInternal(draft, roomSlotId);
      // 切换到新配方（修复：产出随时间累积而非立即满产——
      // remainSolutionCnt 为目标批次数，outputSolutionCnt 从 0 开始由 _accrueManufacture 推进）
      const room = draft.building.rooms.MANUFACTURE[roomSlotId];
      if (!room) return;
      room.state = 1;
      room.formulaId = targetFormulaId;
      room.lastUpdateTime = now();
      room.completeWorkTime = -1;
      room.remainSolutionCnt = Math.max(0, solutionCount ?? 0);
      room.outputSolutionCnt = 0;
      room.processPoint = 0;
    });
    return { change: false };
  }

  /**
   * 更换贸易方案
   *
   * 修复：CS BuildingChangeShopRequest 字段为 roomSlotId/stockIndex/
   * targetFormulaId/solutionCount——原实现读 slotId/solution（客户端不发）
   * → 空 delta；现兼容两种形态：targetFormulaId→strategy（订单类型）、
   * solutionCount→stockLimit（库存上限）。
   *
   * @param args - 包含 slotId（或 roomSlotId）+ strategy/stockLimit（或 CS 字段）的参数对象
   */
  async changeSaleSolution(args: {
    slotId?: string;
    roomSlotId?: string;
    targetFormulaId?: string;
    solutionCount?: number;
    solution?: { strategy: string; stockLimit: number };
  }) {
    const slotId = args.slotId ?? args.roomSlotId;
    const strategy = args.solution?.strategy ?? args.targetFormulaId;
    const stockLimit = args.solution?.stockLimit ?? args.solutionCount;
    if (!slotId) return;
    return await this._player.update(async (draft) => {
      const room = draft.building.rooms.TRADING[slotId];
      if (room) {
        if (strategy) room.strategy = strategy as BuildingData_OrderType;
        if (stockLimit != null) room.stockLimit = stockLimit;
      }
    });
  }

  /**
   * 更换自定义方案
   *
   * 修复：舒适度由服务端按方案内家具 Excel 数据计算（BuildingData.customData
   * .furnitures[].comfort 求和）——原实现读 room.comfort 静态值，客户端摆放
   * 新家具后氛围不变（宿舍恢复/心情档位不受 DIY 影响）。
   *
   * @param args - 包含 roomSlotId 和 solution 的参数对象
   */
  async changeDiySolution(args: { roomSlotId: string; solution: any }) {
    const { roomSlotId, solution } = args;
    let comfort = 0;
    await this._player.update(async (draft) => {
      // 会客室（slot_36）单独处理
      if (roomSlotId === "slot_36") {
        (draft.building.rooms.MEETING[roomSlotId] as any).diySolution = solution;
        return;
      }
      // 其他房间：通过 roomSlots 找到房间类型
      const slot = draft.building.roomSlots[roomSlotId];
      if (slot) {
        const roomType = slot.roomId as keyof PlayerDataModel["building"]["rooms"];
        const room = draft.building.rooms[roomType];
        if (room && room[roomSlotId]) {
          (room[roomSlotId] as any).diySolution = solution;
          // 修复：舒适度服务端计算——墙纸/地板/地毯/其他家具 comfort 求和
          const sol = solution as {
            wallPaper?: string;
            floor?: string;
            carpet?: { id: string }[];
            other?: { id: string }[];
          };
          const ids = [
            sol?.wallPaper,
            sol?.floor,
            ...(sol?.carpet ?? []).map((f) => f?.id),
            ...(sol?.other ?? []).map((f) => f?.id),
          ].filter((id): id is string => !!id);
          comfort = ids.reduce((sum, id) => {
            const info = getFurnitureInfo(id);
            return sum + (info?.comfort ?? 0);
          }, 0);
          (room[roomSlotId] as any).comfort = comfort;
        }
      }
    });
    // 修复：DiyComfort 任务事件从未 emit → DIY 舒适度任务永不推进
    if (roomSlotId !== "slot_36" && comfort > 0) {
      await this._trigger.emit("DiyComfort", [{ comfort }]);
    }
  }

  /**
   * 加工站合成（Excel 驱动——查 workshopFormulas）
   * 消耗 costs（MATERIAL 扣 inventory / GOLD 扣金币）+ goldCost + 干员心情（apCost），
   * 产出 itemId×count×times；extraOutcomeRate 概率触发 extraOutcomeGroup 加权副产物。
   *
   * 修复（2026-08-14 经济系统补全）：
   * 1. 干员心情消耗——公式 apCost 为每次合成的心情成本（1 心情点 = manpowerDisplayFactor
   *    =360000 raw AP；模板公式 1 apCost=360000 = 1 点/次），从进驻加工站干员的
   *    building.chars[].ap 扣减，心情不足时按可承担次数合成；
   * 2. 工坊 bonus（ws_bonus）——进驻干员技能（如夜半「因果/业报」：累积 N 点必定产出
   *    一次副产品）：status.workshop.bonus[bonusId]=[curPoint,totalPoint] 逐次合成推进，
   *    满格后 bonusActive=1，下一次合成必定触发副产物并重置计数。
   *
   * @param args - 包含 roomSlotId、times、formulaId（客户端传，缺失时回退房间 formulaId）的参数对象
   * @returns 合成结果对象（包含 type/id/count）
   */
  async workshopSynthesis(args: {
    roomSlotId: string;
    times: number;
    formulaId?: string;
  }) {
    const { roomSlotId, times, formulaId } = args;
    // 修复：times 必须为正整数——小数（0.5 等）会产出小数物品/半价合成，损坏库存
    if (typeof times !== "number" || !Number.isInteger(times) || times <= 0) {
      return null;
    }
    let resultItem: { type: string; id: string; count: number } | null = null;
    let synGroup: string | undefined;
    await this._player.update(async (draft) => {
      const roomFormulaId =
        formulaId ?? (draft.building.rooms.MANUFACTURE as any)[roomSlotId]?.formulaId;
      const formula = getWorkshopFormula(roomFormulaId);
      if (!formula) return; // 配方不存在（数据版本错位/制造配方 ID）——容错跳过
      synGroup = formula.formulaType as string | undefined;

      // 修复：余额校验——材料/金币不足时按可承担次数合成，避免负库存/负金币
      const totalGoldCost = (formula.goldCost ?? 0) * times;
      let affordable = times;
      for (const cost of formula.costs ?? []) {
        const per = cost.count ?? 0;
        if (per <= 0) continue;
        const have =
          cost.type === "GOLD"
            ? draft.status.gold
            : draft.inventory[cost.id] || 0;
        if (have < per * times) {
          affordable = Math.min(affordable, Math.floor(have / per));
        }
      }
      if (totalGoldCost > 0 && draft.status.gold < totalGoldCost) {
        affordable = Math.min(affordable, Math.floor(draft.status.gold / (formula.goldCost ?? 1)));
      }
      // 干员心情（体力）余额：apCost 为每次合成的心情成本（raw AP），不足时按可承担次数
      const workshopChar = this._workshopChar(draft);
      const apCostPer = formula.apCost ?? 0;
      if (workshopChar && apCostPer > 0) {
        const charAp = workshopChar.ap ?? 0;
        affordable = Math.min(affordable, Math.floor(charAp / apCostPer));
      }
      if (affordable <= 0) return;
      const times2 = affordable;

      // 消耗：costs（MATERIAL 扣 inventory / GOLD 扣金币）
      for (const cost of formula.costs ?? []) {
        if (cost.type === "GOLD") {
          draft.status.gold -= cost.count * times2;
        } else {
          draft.inventory[cost.id] =
            (draft.inventory[cost.id] || 0) - cost.count * times2;
        }
      }
      // 消耗：goldCost（合成手续费）
      if (formula.goldCost) {
        draft.status.gold -= formula.goldCost * times2;
      }
      // 消耗：干员心情（按实际合成次数）
      if (workshopChar && apCostPer > 0) {
        workshopChar.ap = Math.max(0, (workshopChar.ap ?? 0) - apCostPer * times2);
      }
      // 产出（主产物）
      draft.inventory[formula.itemId] =
        (draft.inventory[formula.itemId] || 0) + (formula.count ?? 1) * times2;

      // 工坊 bonus（ws_bonus）：进驻干员技能累积"因果/业报"点数 → 必定副产物
      const ws = (draft.building.status.workshop ??= {
        bonusActive: 0,
        bonus: {},
      });
      const wsBonusIds = this._workshopBonusIds(draft, workshopChar);
      const formulaType = formula.formulaType as string | undefined;

      // 副产物：逐次合成处理 ws_bonus 累计/触发 + 概率副产物
      for (let i = 0; i < times2; i++) {
        const charged = ws.bonusActive === 1;
        let guaranteed = false;
        for (const bonusId of wsBonusIds) {
          if (formulaType && !this._wsBonusMatches(bonusId, formulaType)) continue;
          const entry = ws.bonus[bonusId] ?? (ws.bonus[bonusId] = [0, this._wsBonusThreshold(bonusId)]);
          const total = Math.max(1, entry[1] ?? 1);
          const cur = entry[0] ?? 0;
          if (charged) {
            // 蓄力状态：本次合成必定出副产物；首个满格 bonus 重置计数
            if (!guaranteed) {
              guaranteed = true;
              ws.bonus[bonusId] = [0, total];
            } else {
              ws.bonus[bonusId] = [cur + 1 >= total ? total : cur + 1, total];
            }
            ws.bonusActive = 0;
          } else {
            const next = cur + 1;
            if (next >= total) {
              // 满格蓄力：下一次合成必定副产物
              ws.bonus[bonusId] = [total, total];
              ws.bonusActive = 1;
            } else {
              ws.bonus[bonusId] = [next, total];
            }
          }
        }
        // 副产物（概率 or 蓄力必定）
        if (formula.extraOutcomeGroup?.length) {
          const shouldRoll =
            guaranteed ||
            (!!formula.extraOutcomeRate && Math.random() < formula.extraOutcomeRate);
          if (shouldRoll) {
            const pool = formula.extraOutcomeGroup as {
              weight?: number;
              itemId: string;
              itemCount: number;
            }[];
            const total = pool.reduce((s, g) => s + (g.weight ?? 1), 0);
            let roll = Math.random() * total;
            for (const g of pool) {
              roll -= g.weight ?? 1;
              if (roll <= 0) {
                draft.inventory[g.itemId] =
                  (draft.inventory[g.itemId] || 0) + (g.itemCount ?? 1);
                // 修复：WorkshopExBonus 任务事件从未 emit → 工坊副产物任务永不推进
                await this._trigger.emit("WorkshopExBonus", []);
                break;
              }
            }
          }
        }
      }

      resultItem = {
        type: "MATERIAL",
        id: formula.itemId,
        count: times2,
      };
      // 修复：WorkshopSynthesis 任务事件从未 emit → 工坊合成类任务永不推进
      await this._trigger.emit("WorkshopSynthesis", [
        {
          item: { id: formula.itemId, count: (formula.count ?? 1) * times2 },
        },
      ]);
    });
    // 修复：BuildingWorkshopSynthesisGroupByID 勋章事件从未 emit →
    // 工坊合成组勋章（F_EVOLVE 等）永不推进
    if (synGroup) {
      await this._trigger.emit("BuildingWorkshopSynthesisGroupByID", [
        { groupId: synGroup },
      ]);
    }
    return resultItem;
  }

  /** 内部方法：加工站进驻干员（首个有效干员；未进驻返回 null） */
  private _workshopChar(
    draft: Draft<PlayerDataModel>,
  ): { ap?: number; charId: string } | null {
    for (const slot of Object.values(draft.building.roomSlots)) {
      if (slot?.roomId !== "WORKSHOP") continue;
      for (const instId of slot.charInstIds ?? []) {
        if (instId > 0) {
          const ch = draft.building.chars?.[String(instId)];
          if (ch?.charId) return ch as { ap?: number; charId: string };
        }
      }
    }
    return null;
  }

  /** 内部方法：进驻干员的工坊 bonus 列表（BuildingData.workshopBonus[charId]） */
  private _workshopBonusIds(
    draft: Draft<PlayerDataModel>,
    workshopChar: { charId: string } | null,
  ): string[] {
    if (!workshopChar?.charId) return [];
    return (excel as any).BuildingData?.workshopBonus?.[workshopChar.charId] ?? [];
  }

  /** 内部方法：ws_bonus 阈值（存档条目缺失时按 id 解析：ws_bonus1_40 → 40） */
  private _wsBonusThreshold(bonusId: string): number {
    const m = /^ws_bonus\d+_(\d+)$/.exec(bonusId);
    return m ? parseInt(m[1], 10) : 16;
  }

  /** 内部方法：ws_bonus 是否匹配配方类型（对齐 buff targets，如 F_BUILDING/F_EVOLVE…） */
  private _wsBonusMatches(bonusId: string, formulaType: string): boolean {
    const tier = /^ws_bonus(\d+)_/.exec(bonusId)?.[1];
    if (!tier) return true;
    const buff = (excel as any).BuildingData?.buffs?.[`workshop_formula_bonus${tier}[000]`];
    const targets = buff?.targets;
    if (!Array.isArray(targets) || targets.length === 0) return true;
    return targets.includes(formulaType);
  }

  /**
   * 加工站分解
   * 分解家具为木材（30012），私服简化固定产出
   *
   * 修复：CS BuildingWorkshopDecompositionRequest 字段为 furniId/times——
   * 原实现读 furnitureId/count（客户端不发）→ 空 delta；现兼容两种形态。
   *
   * @param args - 包含 furnitureId（或 furniId）和 count（或 times）的参数对象
   */
  async workshopDecomposition(args: {
    furnitureId?: string;
    furniId?: string;
    count?: number;
    times?: number;
  }) {
    const furnitureId = args.furnitureId ?? args.furniId;
    const count = args.count ?? args.times;
    if (!furnitureId || typeof count !== "number" || count <= 0) return;
    return await this._player.update(async (draft) => {
      const furn = draft.building.furniture[furnitureId];
      if (!furn || furn.count < count) return;
      furn.count -= count;
      // 修复：分解产物按家具 Excel 配置（processedProductId/processedProductCount）——
      // 原实现恒产木材 30012×2，稀有家具分解产物错误
      const info = getFurnitureInfo(furnitureId);
      const productId = info?.processedProductId ?? "30012";
      const productCount = (info?.processedProductCount ?? 2) * count;
      draft.inventory[productId] = (draft.inventory[productId] || 0) + productCount;
    });
  }

  // ==================== 线索系统 ====================

  /** 获取首个会客室房间 */
  private _meetingRoom() {
    const rooms = this._player._playerdata.building.rooms.MEETING;
    return Object.values(rooms)[0];
  }

  /** 线索阵营（真实存档 type 取值，与 MEETING buff.weight keys 一致） */
  private static _CLUE_FACTIONS = [
    "RHINE",
    "PENGUIN",
    "BLACKSTEEL",
    "URSUS",
    "GLASGOW",
    "KJERAG",
    "RHODES",
  ];

  /**
   * 会客室线索阵营加权选择（特殊技能适配）
   *
   * meet_spd_notOwned（晓歌）：更容易获得线索板上尚未拥有的线索 → 未上板阵营权重 ×2；
   * meet_spd_Owned（U-Official）：更容易获得已拥有的线索 → 已上板阵营权重 ×2。
   * 私服无真实访客线索交换，getDailyClue 是唯一线索来源——按进驻会客室干员的
   * 技能修正各阵营抽取权重，使"未拥有线索"技能实际生效。
   * @param draft - mutative 可写草稿
   * @param room - 会客室房间对象
   * @returns 加权选出的阵营
   */
  private _clueFactionWeighted(
    draft: Draft<PlayerDataModel>,
    room: any,
  ): string {
    const factions = BuildingManager._CLUE_FACTIONS;
    const slot = Object.values(draft.building.roomSlots).find(
      (s) => s.roomId === "MEETING",
    );
    const chars = this._roomCharSources(draft, slot ?? null);
    const hasSkill = (re: RegExp) =>
      chars.some((c) =>
        getActiveCharBuffs(c, "MEETING").some((b) => re.test(b?.buffId ?? "")),
      );
    const preferNew = hasSkill(/^meet_spd_notOwned/);
    const preferOwned = hasSkill(/^meet_spd_Owned/);
    const onBoard = new Set(Object.keys(room?.board ?? {}));
    // 加权随机：未上板阵营在 preferNew 时 ×2；已上板阵营在 preferOwned 时 ×2
    const weights = factions.map((f) => {
      let w = 1;
      const isOnBoard = onBoard.has(f);
      if (preferNew && !isOnBoard) w *= 2;
      if (preferOwned && isOnBoard) w *= 2;
      return w;
    });
    const total = weights.reduce((s, w) => s + w, 0);
    let r = Math.random() * total;
    for (let i = 0; i < factions.length; i++) {
      r -= weights[i];
      if (r <= 0) return factions[i];
    }
    return factions[factions.length - 1];
  }

  /**
   * 获取每日线索
   * 每日一条免费线索（dailyReward 已领则不重复发放）
   * 真实格式：type=阵营、id={uid}#{随机}#{时间戳}
   * @param args - 请求体参数
   */
  async getDailyClue(args: any) {
    return await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room || room.dailyReward) return;
      const status = draft.status;
      // 特殊技能适配：进驻会客室干员的线索概率技能影响阵营抽取权重
      const clue: PlayerBuildingMeetingClue = {
        id: `${status.uid}#${Math.floor(Math.random() * 9000 + 1000)}#${now()}`,
        type: this._clueFactionWeighted(draft, room),
        number: 1 + Math.floor(Math.random() * 3),
        uid: String(status.uid),
        name: status.nickName,
        nickNum: String(status.nickNumber),
        chars: [],
        inUse: 0,
      };
      room.ownStock.push(clue);
      room.dailyReward = clue;
      // 推送：新线索可处理 → 客户端会客室红点
      draft.pushFlags.hasClues = 1;
    });
  }

  /**
   * 发送线索（ownStock → receiveStock，私服简化在同一玩家库存间流转）
   *
   * 修复：CS BuildingMeetingClueSendClueRequest 字段为 clueId/friendId——
   * 原实现读 id（客户端发 clueId）→ 空 delta；现兼容两种形态。
   *
   * @param args - 包含 id（或 clueId）和 friendId 的参数对象
   */
  async sendClue(args: { id?: string; clueId?: string; friendId: string }) {
    const id = args.id ?? args.clueId;
    const { friendId } = args;
    if (!id) return;
    let sent = false;
    await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room) return;
      const idx = room.ownStock.findIndex((c) => c.id === id);
      if (idx === -1) return;
      const clue = room.ownStock.splice(idx, 1)[0];
      clue.uid = String(friendId);
      room.receiveStock.push(clue);
      sent = true;
      // 推送：同步会客室红点（存在未上板线索 → 1）
      this._refreshClueFlag(draft, room);
    });
    // 修复：SendClue 任务事件从未 emit → 发送线索类任务永不推进
    if (sent) {
      await this._trigger.emit("SendClue", []);
    }
  }

  /**
   * 自动发送线索（发送第一条可发线索）
   * @param args - 请求体参数
   */
  async sendClueAuto(args: any) {
    return await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room || room.ownStock.length === 0) return;
      const clue = room.ownStock.shift()!;
      room.receiveStock.push(clue);
      // 修复：自动发送后同步红点（与 sendClue 一致）
      this._refreshClueFlag(draft, room);
    });
  }

  /**
   * 接收线索到库存（receiveStock → ownStock）
   *
   * 修复：CS BuildingMeetingClueReceiveClueToStockRequest 字段为 clues（列表）——
   * 原实现读 id（客户端发 clues）→ 空 delta；现兼容两种形态。
   *
   * @param args - 包含 id（或 clues 列表）的参数对象
   */
  async receiveClueToStock(args: { id?: string; clues?: string[] }) {
    const ids = args.clues?.length ? args.clues : args.id ? [args.id] : [];
    if (ids.length === 0) return;
    return await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room) return;
      for (const id of ids) {
        const idx = room.receiveStock.findIndex((c) => c.id === id);
        if (idx === -1) continue;
        const clue = room.receiveStock.splice(idx, 1)[0];
        room.ownStock.push(clue);
      }
      this._refreshClueFlag(draft, room);
    });
  }

  /**
   * 放置线索到留言板
   *
   * 修复（2026-08-14，官方存档格式校准）：
   * 1. CS BuildingMeetingCluePutClueToTheBoardRequest 字段为 clueId——
   *    原实现读 id（客户端发 clueId）→ 空 delta；现兼容两种形态；
   * 2. **官方 board 格式为 {[阵营type]: clueId}**（key=阵营、value=线索 id，
   *    见真实存档 2222：{"RHINE":"100566259#3490#...",...}）——原实现写成
   *    {[clueId]: clueId}，客户端按阵营槽位读板 → 上板线索不可见；
   * 3. **线索保留在 ownStock 中，以 inUse=1 标记上板**（官方存档中板线索
   *    仍在库存）——原实现 splice 移除，取下时线索数据丢失。
   *
   * @param args - 包含 id（或 clueId）的参数对象
   */
  async putClueToTheBoard(args: { id?: string; clueId?: string }) {
    const id = args.id ?? args.clueId;
    if (!id) return;
    return await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room) return;
      const idx = room.ownStock.findIndex((c) => c.id === id);
      if (idx === -1) return;
      const clue = room.ownStock[idx];
      // 官方模型：board = {[阵营type]: clueId}；线索保留库存，inUse=1 标记上板
      room.board[clue.type] = clue.id;
      clue.inUse = 1;
      this._refreshClueFlag(draft, room);
    });
  }

  /**
   * 自动放置线索到留言板（放置全部可放线索）
   *
   * 修复：同 putClueToTheBoard——board 按阵营索引、线索保留在 ownStock（inUse=1）。
   *
   * @param args - 请求体参数
   */
  async putClueToTheBoardAuto(args: any) {
    return await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room) return;
      for (const clue of room.ownStock) {
        room.board[clue.type] = clue.id;
        clue.inUse = 1;
      }
      this._refreshClueFlag(draft, room);
    });
  }

  /**
   * 从留言板取回线索（CS BuildingMeetingClueTakeClueFromBoardRequest { type }，
   * 客户端 UnequipClue 调用——按阵营取下该槽位线索回库存）
   *
   * 新增（2026-08-14 协议审计补齐）：此前无此端点，上板线索无法取下。
   * 官方模型：board[type] = clueId，线索在库存中以 inUse=1 标记——取回即
   * 删除 board 条目并复位 inUse=0。
   *
   * @param args - 包含 type（阵营，如 RHINE）的参数对象
   */
  async takeClueFromBoard(args: { type?: string }) {
    const type = args?.type;
    if (!type) return;
    return await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room?.board) return;
      const clueId = room.board[type];
      if (!clueId) return;
      delete room.board[type];
      // 线索在库存中（inUse=1）→ 复位为未上板
      const clue = [...(room.ownStock ?? []), ...(room.receiveStock ?? [])].find(
        (c) => c.id === clueId,
      );
      if (clue) clue.inUse = 0;
      this._refreshClueFlag(draft, room);
    });
  }

  /**
   * 删除自己持有的线索
   *
   * 修复：CS BuildingMeetingClueDeleteOwnClueRequest 字段为 clueId——
   * 原实现读 id（客户端发 clueId）→ 空 delta；现兼容两种形态；
   * 同时清理指向该线索的留言板条目（上板线索被删除时不留孤儿索引）。
   *
   * @param args - 包含 id（或 clueId）的参数对象
   */
  async deleteOwnClue(args: { id?: string; clueId?: string }) {
    const id = args.id ?? args.clueId;
    if (!id) return;
    return await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room) return;
      room.ownStock = room.ownStock.filter((c) => c.id !== id);
      this._clearBoardEntry(draft, room, id);
      this._refreshClueFlag(draft, room);
    });
  }

  /**
   * 删除接收到的线索
   *
   * 修复：CS BuildingMeetingClueDeleteReceiveClueRequest 字段为 clueId——
   * 原实现读 id（客户端发 clueId）→ 空 delta；现兼容两种形态；
   * 同时清理指向该线索的留言板条目。
   *
   * @param args - 包含 id（或 clueId）的参数对象
   */
  async deleteReceiveClue(args: { id?: string; clueId?: string }) {
    const id = args.id ?? args.clueId;
    if (!id) return;
    return await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room) return;
      room.receiveStock = room.receiveStock.filter((c) => c.id !== id);
      this._clearBoardEntry(draft, room, id);
      this._refreshClueFlag(draft, room);
    });
  }

  /**
   * 内部方法：清理留言板中指向指定线索 id 的条目（board = {[type]: clueId}）
   */
  private _clearBoardEntry(
    draft: Draft<PlayerDataModel>,
    room: any,
    clueId: string,
  ): void {
    if (!room?.board) return;
    for (const [type, id] of Object.entries(room.board)) {
      if (id === clueId) delete room.board[type];
    }
  }

  /**
   * 内部方法：刷新会客室红点（hasClues）——存在未上板（inUse=0）的线索 → 1
   * 官方模型：上板线索保留在库存（inUse=1），不计入"待处理"红点
   */
  private _refreshClueFlag(
    draft: Draft<PlayerDataModel>,
    room: any,
  ): void {
    const pending = [
      ...(room?.ownStock ?? []),
      ...(room?.receiveStock ?? []),
    ].some((c) => (c?.inUse ?? 0) === 0);
    (draft.pushFlags ??= {} as any).hasClues = pending ? 1 : 0;
  }

  /**
   * 获取线索盒（ownStock + receiveStock）
   * @returns 包含 box 字段的对象
   */
  async getClueBox() {
    const room = this._meetingRoom();
    return {
      box: [...(room?.ownStock ?? []), ...(room?.receiveStock ?? [])],
    };
  }

  /**
   * 获取线索好友列表（基于好友关系数据）
   * @returns 包含 result 字段的对象
   */
  async getClueFriendList() {
    const uid = String(this._player._playerdata.status.uid);
    const social = await accountManager.getSocial(uid);
    const result = await Promise.all(
      social.friends.map(async (f) => {
        // 修复：好友账号存档缺失/加载失败时跳过（原实现 Promise.all 整体 500）
        try {
          const info = await accountManager.getPlayerFriendInfo(f.uid);
          return {
            uid: f.uid,
            nickName: info.nickName,
            nickNumber: info.nickNumber,
            level: info.level,
          };
        } catch (e) {
          logger.warn(
            "building",
            `getClueFriendList 好友 ${f.uid} 数据加载失败: ${(e as Error).message}`,
          );
          return null;
        }
      }),
    );
    return {
      result: result.filter(
        (r): r is { uid: string; nickName: string; nickNumber: string; level: number } =>
          r !== null,
      ),
    };
  }

  /**
   * 获取会客室情报分享奖励（访客列表——友方访问 + 可领取的信用）
   *
   * CS: BuildingMeetingClueReceiveInfoShareRewardResponse { list: [VisitorInfo] }，
   * VisitorInfo = { uid, nickName, nickNumber, level, avatar, ts, alias, secretary, secretarySkinId }。
   * 私服：访客 = 好友列表（无真实访问记录，ts 用最近在线时间）。
   *
   * 修复：官方响应 delta 必含会客室干员体力累积（building.chars[].ap/lastApAddTime，
   * 见抓包 building_getInfoShareReward_res_1074）——客户端会客室会话按该增量推进
   * 情报分享状态；原实现不推进 → delta 为空 → 客户端死循环重拉。
   *
   * 再修复：同时推进 infoShare 字段（infoShare.ts = now）——官方该响应 delta 含
   * MEETING 房间完整状态（含 infoShare/socialPoint 信用发放）；不推进则同一批访客
   * 每次都被视为"新访客" → 重复计信用 → 无限重复获取。
   *
   * 信用经济（2026-08-14 补全）：主动信用（socialReward.search）按本次有效访客数 ×
   * friendSlotInc 累积（封顶 creditInitiativeLimit=100，领取后清零重新累积）——
   * 原实现只推进会话从不计信用，模板 search=40 领一次后信用经济枯竭。
   *
   * @returns 访客列表
   */
  async getInfoShareReward() {
    const uid = String(this._player._playerdata.status.uid);
    const social = await accountManager.getSocial(uid);
    const list = await Promise.all(
      social.friends.map(async (f) => {
        // 修复：好友账号存档缺失/加载失败时跳过（原实现整体 500）
        try {
          const info = await accountManager.getPlayerFriendInfo(f.uid);
          return {
            uid: f.uid,
            nickName: info.nickName,
            nickNumber: info.nickNumber,
            level: info.level,
            alias: null,
            ts: info.registerTs ?? 0,
            avatar: { type: "ASSISTANT", id: `${info.secretary ?? ""}#1` },
            secretary: info.secretary ?? "",
            secretarySkinId: info.secretarySkinId ?? "",
          };
        } catch (e) {
          logger.warn(
            "building",
            `getInfoShareReward 好友 ${f.uid} 数据加载失败: ${(e as Error).message}`,
          );
          return null;
        }
      }),
    );
    const validList = list.filter((x): x is NonNullable<typeof x> => x !== null);
    // 会客室干员体力（AP）随时间累积（changeScale>0 恢复；上限 8640000）+ 会话推进
    // + 主动信用累积（按有效访客数封顶）
    await this._player.update(async (draft) => {
      this._accrueCharAp(draft);
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (room) {
        // 惰性初始化 infoShare（旧存档缺失）；ts 推进（会话划分）+ reward 待领取指示
        const is = (room.infoShare ??= { ts: 0, reward: 0 });
        is.ts = now();
        // 修复：主动信用（search）按访客累积（封顶 creditInitiativeLimit）
        this._accumulateSearchCredit(draft, room, validList.length);
        is.reward = this._infoShareReward(room.socialReward);
      }
    });
    return { list: validList };
  }

  /**
   * 会客室干员体力（AP）随时间累积
   * 官方模型：building.chars[].ap += 流逝时间 × changeScale（会客室干员 changeScale>0
   * 恢复体力；工作干员 changeScale<0 消耗）；clamp 到 [0, 8640000]，更新 lastApAddTime。
   *
   * lastApAddTime 写**浮点秒（毫秒精度）**：官方每次基建请求都下发 chars 增量
   * （抓包 res_1074 含 308 chars）——秒级整型在客户端紧邻重拉（同一秒内多次调用）
   * 时无法变化 → 空 delta → 会客室会话不推进 → 无限重复获取；
   * 浮点秒保证任意两次调用（≥1ms 间隔）lastApAddTime 必变 → 增量恒在。
   * @param draft - mutative 可写草稿
   * @param nowSec - 当前时间基准（浮点秒，毫秒精度；缺省取 Date.now()/1000）
   */
  private _accrueCharAp(draft: Draft<PlayerDataModel>, nowSec?: number): void {
    const ts = nowSec ?? Date.now() / 1000; // 浮点秒（毫秒精度）
    let recovered = 0;
    for (const ch of Object.values(draft.building.chars ?? {})) {
      const last =
        typeof ch.lastApAddTime === "number" ? ch.lastApAddTime : ts;
      const elapsedSec = ts - last;
      if (elapsedSec <= 0) continue;
      ch.lastApAddTime = ts;
      const scale = ch.changeScale ?? 0;
      if (scale !== 0) {
        const before = ch.ap ?? 0;
        ch.ap = Math.min(Math.max((ch.ap ?? 0) + elapsedSec * scale, 0), 8640000);
        if (ch.ap > before) recovered += 1;
      }
    }
    // 修复：RecoverCharBaseAp 任务事件从未 emit → 恢复干员心情任务永不推进；
    // 本次有干员恢复心情时计 1 次
    if (recovered > 0) {
      void this._trigger.emit("RecoverCharBaseAp", [{ count: recovered }]);
    }
  }

  /**
   * 获取会议室奖励（信用点）
   *
   * 对齐官方（抓包 res_1044）：响应 rewards 为 ItemBundle 数组
   * `[{id:"SOCIAL_PT", type:"SOCIAL_PT", count:N}]`，且**服务端发放后清零**——
   * status.socialPoint += daily+search、socialReward 归零（一次性领取）。
   * 修复：原实现只透传 socialReward.daily（格式错误且不发放/不清零）→
   * 客户端每次领取同一份信用 → 无限信用点 + 会客室死循环。
   * @returns 领取的信用点（SOCIAL_PT ItemBundle；无可领返回空数组）
   */
  async getMeetingroomReward() {
    let granted = 0;
    await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room) return;
      const sr = room.socialReward;
      granted = (sr?.daily ?? 0) + (sr?.search ?? 0);
      if (granted <= 0) return;
      draft.status.socialPoint = (draft.status.socialPoint ?? 0) + granted;
      // 领取后清零（一次性，避免重复领取）+ infoShare.reward 归 0（待领取指示）
      room.socialReward = { daily: 0, search: 0 };
      this._refreshInfoShare(draft);
    });
    return {
      rewards:
        granted > 0
          ? [{ id: "SOCIAL_PT", type: "SOCIAL_PT", count: granted }]
          : [],
    };
  }

  // ==================== 预设队列 ====================

  /** 预设队列元数据（名称/锁定——官方线格式 room.presetQueue 仅为干员组数组，无名称） */
  private _presetQueues(draft: Draft<PlayerDataModel>): any {
    const building = draft.building as any;
    if (!building.presetQueues) building.presetQueues = {};
    return building.presetQueues;
  }

  /**
   * 获取房间的预设队列数组（官方线格式：room.presetQueue = number[][]，按索引）。
   * 含 presetQueue 字段的房间类型：MANUFACTURE/TRADING/POWER/CONTROL/MEETING/HIRE。
   * @returns 房间队列数组（不存在该字段的房间返回 null）
   */
  private _roomPresetQueue(
    draft: Draft<PlayerDataModel>,
    slotId: string,
  ): number[][] | null {
    const slot = draft.building.roomSlots[slotId];
    if (!slot) return null;
    const roomType = slot.roomId as keyof PlayerDataModel["building"]["rooms"];
    const room = draft.building.rooms[roomType]?.[slotId] as any;
    if (!room) return null;
    if (!Array.isArray(room.presetQueue)) room.presetQueue = [];
    return room.presetQueue;
  }

  /**
   * 添加预设队列
   * 对齐官方：CS BuildingAddPresetQueueRequest 仅 { slotId }——把房间当前排班
   * （charInstIds）追加为新队列；兼容请求体显式携带 charInstIdList。
   * @param args - { slotId }（或 roomSlotId）+ 可选 charInstIdList
   */
  async addPresetQueue(args: {
    slotId?: string;
    roomSlotId?: string;
    charInstIdList?: number[];
    presetName?: string;
  }) {
    const slotId = args.slotId ?? args.roomSlotId;
    if (!slotId) return;
    return await this._player.update(async (draft) => {
      const queue = this._roomPresetQueue(draft, slotId);
      if (!queue) return;
      const charInstIdList =
        args.charInstIdList ??
        draft.building.roomSlots[slotId]?.charInstIds ??
        [];
      queue.push([...charInstIdList]);
    });
  }

  /**
   * 删除预设队列（按索引）
   * 对齐官方：CS BuildingDeletePresetQueueRequest { slotId, index }。
   * @param args - { slotId, index }
   */
  async deletePresetQueue(args: {
    slotId?: string;
    roomSlotId?: string;
    index?: number;
  }) {
    const slotId = args.slotId ?? args.roomSlotId;
    if (!slotId) return;
    return await this._player.update(async (draft) => {
      const queue = this._roomPresetQueue(draft, slotId);
      if (!queue) return;
      const idx = args.index ?? 0;
      if (idx >= 0 && idx < queue.length) queue.splice(idx, 1);
    });
  }

  /**
   * 编辑预设队列（按索引）
   * 对齐官方：CS BuildingEditPresetQueueRequest { slotId, index, queue }。
   * @param args - { slotId, index, queue }
   */
  async editPresetQueue(args: {
    slotId?: string;
    roomSlotId?: string;
    index?: number;
    queue?: number[];
    charInstIdList?: number[];
  }) {
    const slotId = args.slotId ?? args.roomSlotId;
    if (!slotId) return;
    const queueList = args.queue ?? args.charInstIdList;
    if (!Array.isArray(queueList)) return;
    return await this._player.update(async (draft) => {
      const queue = this._roomPresetQueue(draft, slotId);
      if (!queue) return;
      const idx = args.index ?? 0;
      if (idx >= 0 && idx < queue.length) queue[idx] = [...queueList];
    });
  }

  /**
   * 使用预设队列（应用干员到房间，清空其他房间占用）
   * 对齐官方：CS BuildingUsePresetQueueRequest { slotId, index }——应用 room.presetQueue[index]。
   * @param args - { slotId, index }
   */
  async usePresetQueue(args: {
    slotId?: string;
    roomSlotId?: string;
    index?: number;
  }) {
    const slotId = args.slotId ?? args.roomSlotId;
    if (!slotId) return;
    return await this._player.update(async (draft) => {
      const queue = this._roomPresetQueue(draft, slotId);
      if (!queue || queue.length === 0) return;
      const idx = Math.min(args.index ?? 0, queue.length - 1);
      const charInstIdList = queue[idx];
      if (!Array.isArray(charInstIdList)) return;
      // 清空这些干员在其他房间的占用
      for (const slotKey in draft.building.roomSlots) {
        if (slotKey === slotId) continue;
        const ids = draft.building.roomSlots[slotKey].charInstIds;
        for (let i = 0; i < ids.length; i++) {
          if (charInstIdList.includes(ids[i])) ids[i] = -1;
        }
      }
      draft.building.roomSlots[slotId].charInstIds = [...charInstIdList];
      // 换班后立即按新岗位重算心情档位
      this._recomputeCharScales(draft);
    });
  }

  /**
   * 使用单个预设队列（单房间版，应用首个队列）
   * @param args - { slotId }（或 roomSlotId）
   */
  async useOnePresetQueue(args: {
    slotId?: string;
    roomSlotId?: string;
  }) {
    return this.usePresetQueue({ ...args, index: 0 });
  }

  /**
   * 修改预设名称（私服扩展：名称存 building.presetQueues 元数据，官方线格式无名称）
   * @param args - 包含 slotId/roomSlotId 和 presetName（或 name）的参数对象
   */
  async changePresetName(args: {
    slotId?: string;
    roomSlotId?: string;
    presetName?: string;
    name?: string;
  }) {
    const slotId = args.slotId ?? args.roomSlotId;
    const presetName = args.presetName ?? args.name;
    if (!slotId) return;
    return await this._player.update(async (draft) => {
      const queues = this._presetQueues(draft);
      const meta = (queues[slotId] ??= {});
      meta.name = presetName ?? "";
    });
  }

  /**
   * 保存自定义预设方案（diyPresetSolutions）
   * @param args - 包含 presetName 和 solution 的参数对象
   */
  async saveDiyPresetSolution(args: { presetName: string; solution: any }) {
    const { presetName, solution } = args;
    return await this._player.update(async (draft) => {
      (draft.building as any).diyPresetSolutions[presetName] = solution;
    });
  }

  /**
   * 编辑锁定队列（记录锁定状态到元数据）
   * @param args - 包含 slotId/roomSlotId 和 locked 的参数对象
   */
  async editLockQueue(args: { slotId?: string; roomSlotId?: string; locked: boolean }) {
    const slotId = args.slotId ?? args.roomSlotId;
    if (!slotId) return;
    return await this._player.update(async (draft) => {
      const queues = this._presetQueues(draft);
      const meta = (queues[slotId] ??= {});
      meta.locked = args.locked;
    });
  }

  // ==================== 其他功能 ====================

  /**
   * 更改贸易站策略
   * 参考实现：更新对应贸易站房间的 strategy 字段
   * @param args - 包含 slotId 和 strategy 的参数对象
   */
  async changeStrategy(args: { slotId: string; strategy: string }) {
    const { slotId, strategy } = args;
    return await this._player.update(async (draft) => {
      const tradingRoom = draft.building.rooms.TRADING[slotId];
      if (tradingRoom) {
        tradingRoom.strategy = strategy as BuildingData_OrderType;
      }
    });
  }

  /**
   * 购买劳动力
   * 消耗源石（1 源石/次），增加 labor.value（+10/次，上限 maxValue）
   * 注：apToLaborRatio=2 是 AP→劳动力 比例（apToLaborUnlockLevel=4 解锁），buyLabor 用源石走官方固定 10 点——YAGNI 未接入
   * @param args - 包含 buyCount 的参数对象
   */
  async buyLabor(args: { buyCount: number }) {
    const { buyCount } = args;
    // 修复：负数 buyCount 绕过余额守卫（androidDiamond -= 负数 → 免费源石）；非法入参直接拒绝
    if (
      typeof buyCount !== "number" ||
      !Number.isInteger(buyCount) ||
      buyCount <= 0
    ) {
      return;
    }
    return await this._player.update(async (draft) => {
      const labor = draft.building.status.labor;
      const cost = 1;
      if (draft.status.androidDiamond < cost * buyCount) return;
      draft.status.androidDiamond -= cost * buyCount;
      labor.value = Math.min(labor.value + 10 * buyCount, labor.maxValue);
    });
  }

  /**
   * 确认留言板奖励（会客室留言板）
   * 领取 messageLeave.sp.lastWeek 社交点（信用）→ status.socialPoint；累计 lastWeekSum。
   * 参考 CS BuildingPayloadConfirmMessageBoardRewardResponse { reward: List<ItemBundle> }
   * @param args - 请求体参数（无字段）
   * @returns 领取的社交点奖励（SOCIAL_PT 信用 ItemBundle 数组；无可领返回空）
   */
  async confirmMessageBoardReward(args: any): Promise<
    { id: string; count: number; type: string }[]
  > {
    let reward = 0;
    await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      const leave = room?.messageLeave;
      if (!leave) return;
      reward = leave.sp?.lastWeek ?? 0;
      if (reward <= 0) return;
      draft.status.socialPoint = (draft.status.socialPoint ?? 0) + reward;
      leave.sp.lastWeekSum = (leave.sp.lastWeekSum ?? 0) + reward;
      leave.sp.lastWeek = 0;
      leave.lastUpdateSpTs = now();
    });
    return reward > 0 ? [{ id: "SOCIAL_PT", count: reward, type: "SOCIAL_PT" }] : [];
  }

  /**
   * 获取留言板内容（会客室留言板）
   * 返回 CS BuildingPayloadGetMessageBoardContentResponse 形状：
   * 访客列表（无社交数据返回空）+ 访问统计 + lastWeekSpReward（上周可领取社交点）。
   * 修复：原实现透传请求体（202 空响应，客户端留言板空白）；现按 messageLeave 状态返回。
   * @param args - 请求体参数（无字段）
   * @returns 留言板内容
   */
  async getMessageBoardContent(args: any): Promise<{
    thisWeekVisitors: { uid: string; nickName: string; nickNumber: string }[];
    lastWeekVisitors: { uid: string; nickName: string; nickNumber: string }[];
    todayVisit: number;
    weeklyVisit: number;
    lastWeekVisit: number;
    lastWeekSpReward: number;
    lastShowTs: number;
  }> {
    let board = {
      thisWeekVisitors: [] as { uid: string; nickName: string; nickNumber: string }[],
      lastWeekVisitors: [] as { uid: string; nickName: string; nickNumber: string }[],
      todayVisit: 0,
      weeklyVisit: 0,
      lastWeekVisit: 0,
      lastWeekSpReward: 0,
      lastShowTs: now(),
    };
    await this._player.update(async (draft) => {
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room) return;
      // 懒初始化 messageLeave（旧存档缺失）
      room.messageLeave = room.messageLeave ?? {
        inUse: false,
        lastVisitTs: 0,
        lastShowTs: 0,
        lastUpdateSpTs: 0,
        sp: { lastWeek: 0, lastWeekSum: 0, thisWeek: 0, thisWeekSum: 0 },
      };
      const leave = room.messageLeave;
      leave.lastShowTs = now();
      board = {
        thisWeekVisitors: [],
        lastWeekVisitors: [],
        todayVisit: 0,
        weeklyVisit: leave.sp?.thisWeek ?? 0,
        lastWeekVisit: leave.sp?.lastWeekSum ?? 0,
        lastWeekSpReward: leave.sp?.lastWeek ?? 0,
        lastShowTs: leave.lastShowTs,
      };
    });
    return board;
  }

  /**
   * 获取协助报告
   * 参考实现：返回近 4 天的制造/贸易/信赖报告数据
   * @returns 包含 reports 数组的对象
   */
  async getAssistReport() {
    const ts = now();
    return {
      reports: [
        { ts, manufacture: {}, trading: {}, favor: [] },
        { ts: ts - 86400, manufacture: {}, trading: {}, favor: [] },
        { ts: ts - 172800, manufacture: {}, trading: {}, favor: [] },
        { ts: ts - 345600, manufacture: {}, trading: {}, favor: [] },
      ],
    };
  }

  /**
   * 获取信息共享访客数
   *
   * 修复：原实现恒返回 0——客户端会客室"可访问人数"徽标恒空；
   * 现按好友数返回（私服访客 = 好友列表，与 getInfoShareReward 同源）。
   *
   * @returns 包含 num 字段的对象
   */
  async getInfoShareVisitorsNum() {
    const uid = String(this._player._playerdata.status.uid);
    let num = 0;
    try {
      const social = await accountManager.getSocial(uid);
      num = social.friends.length;
    } catch (e) {
      logger.warn(
        "building",
        `getInfoShareVisitorsNum 好友数据加载失败: ${(e as Error).message}`,
      );
    }
    return { num };
  }

  /**
   * 获取最近访客
   *
   * 修复：原实现恒空——客户端"最近来访"列表空白；私服访客 = 好友列表
   * （无真实访问记录，ts 用注册时间），结构对齐 CS RecentVisitor。
   *
   * @returns 包含 visitors 字段的对象
   */
  async getRecentVisitors(): Promise<{
    visitors: {
      uid: string;
      nickName: string;
      nickNumber: string;
      secretary: string;
      secretarySkinId: string;
      level: number;
      ts: number;
    }[];
  }> {
    const uid = String(this._player._playerdata.status.uid);
    let visitors: {
      uid: string;
      nickName: string;
      nickNumber: string;
      secretary: string;
      secretarySkinId: string;
      level: number;
      ts: number;
    }[] = [];
    try {
      const social = await accountManager.getSocial(uid);
      visitors = (
        await Promise.all(
          social.friends.map(async (f) => {
            try {
              const info = await accountManager.getPlayerFriendInfo(f.uid);
              return {
                uid: f.uid,
                nickName: info.nickName,
                nickNumber: info.nickNumber,
                secretary: info.secretary ?? "",
                secretarySkinId: info.secretarySkinId ?? "",
                level: info.level,
                ts: info.registerTs ?? 0,
              };
            } catch (err) {
              logger.warn(
                "building",
                `getRecentVisitors 好友 ${f.uid} 数据加载失败: ${(err as Error).message}`,
              );
              return null;
            }
          }),
        )
      ).filter((v): v is NonNullable<typeof v> => v !== null);
    } catch (e) {
      logger.warn(
        "building",
        `getRecentVisitors 好友列表加载失败: ${(e as Error).message}`,
      );
    }
    return { visitors };
  }

  /**
   * 获取他人留言板内容
   *
   * 修复：原实现纯透传（客户端拿到空响应，访问好友基建留言板空白）；
   * 现读取好友存档的会客室 messageLeave 状态返回（只读，不修改对方数据）。
   *
   * @param args - 请求体参数（uid）
   * @returns 对方留言板内容（结构同 getMessageBoardContent）
   */
  async getOthersMessageBoardContent(args: {
    uid?: string;
    friendId?: string;
  }): Promise<{
    thisWeekVisitors: { uid: string; nickName: string; nickNumber: string }[];
    lastWeekVisitors: { uid: string; nickName: string; nickNumber: string }[];
    todayVisit: number;
    weeklyVisit: number;
    lastWeekVisit: number;
    lastWeekSpReward: number;
    lastShowTs: number;
  }> {
    const emptyBoard = () => ({
      thisWeekVisitors: [] as { uid: string; nickName: string; nickNumber: string }[],
      lastWeekVisitors: [] as { uid: string; nickName: string; nickNumber: string }[],
      todayVisit: 0,
      weeklyVisit: 0,
      lastWeekVisit: 0,
      lastWeekSpReward: 0,
      lastShowTs: now(),
    });
    const uid = String(args.uid ?? args.friendId ?? "");
    if (!uid || uid === String(this._player._playerdata.status.uid)) {
      return emptyBoard();
    }
    try {
      const friend = await accountManager.getPlayerData(uid);
      const room = Object.values(
        friend._playerdata.building?.rooms?.MEETING ?? {},
      )[0] as any;
      const leave = room?.messageLeave;
      return {
        thisWeekVisitors: [],
        lastWeekVisitors: [],
        todayVisit: 0,
        weeklyVisit: leave?.sp?.thisWeek ?? 0,
        lastWeekVisit: leave?.sp?.lastWeekSum ?? 0,
        lastWeekSpReward: leave?.sp?.lastWeek ?? 0,
        lastShowTs: leave?.lastShowTs ?? 0,
      };
    } catch (e) {
      logger.warn(
        "building",
        `getOthersMessageBoardContent 好友 ${uid} 数据加载失败: ${(e as Error).message}`,
      );
      return emptyBoard();
    }
  }

  /**
   * 获取缩略图 URL
   * 简化实现：预留接口（私服无云端缩略图），返回空列表
   * @param args - 请求体参数
   */
  async getThumbnailUrl(args: any) {
    return { list: [] };
  }

  /**
   * 发送表情
   * 简化实现：参考 Python 实现返回 202，预留接口
   * @param args - 请求体参数
   */
  async sendEmoji(args: any) {
    return args;
  }

  /**
   * 开始信息共享（会客室情报分享会话）
   * 对齐官方：记录会话开始时间 infoShare.ts = now——访客列表按会话划分，
   * 早于该时间的访客视为"已分享过"（客户端不再重复计信用）。
   * 官方响应 delta 含会客室干员体力累积（抓包 res_1071）→ 同步推进 _accrueCharAp。
   * 修复：原实现透传请求体（202 不落状态）→ 会话永不推进 → 同一批访客
   * 每次都被视为新访客 → 无限信用点。
   * @param args - 请求体参数
   */
  async startInfoShare(args: any) {
    await this._player.update(async (draft) => {
      this._accrueCharAp(draft);
      const room = Object.values(draft.building.rooms.MEETING)[0];
      if (!room) return;
      room.infoShare.ts = now();
      room.infoShare.reward = this._infoShareReward(room.socialReward);
    });
    // 修复：StartInfoShare 任务事件从未 emit → 开启信息分享类任务永不推进
    await this._trigger.emit("StartInfoShare", []);
  }

  /**
   * 访问好友基建
   * 修复：原为纯透传 stub——VisitBuilding 是每日任务（26 个），事件从不 emit 任务
   * 永不推进；补事件 + 被访方发放社交点（align S5 社交点来源）
   *
   * 再修复（2026-08-14 信用经济）：被访方社交点改为**被动信用**入账——
   * socialReward.daily += friendSlotInc（封顶 creditPassiveLimit），经
   * getMeetingroomReward 领取；原实现直接 +20 socialPoint（绕过信用循环）。
   *
   * @param args - 请求体参数（friendId）
   */
  async visitBuilding(args: any) {
    const friendId = args?.friendId;
    // 修复：VisitBuilding 任务事件从未 emit → 访问基建任务永不推进
    await this._trigger.emit("VisitBuilding", []);
    // 被访方被动信用（访问基建给主人 friendSlotInc 信用 → 会客室待领）
    if (friendId && String(friendId) !== String(this._player.uid)) {
      try {
        const owner = await accountManager.getPlayerData(String(friendId));
        await owner.update(async (draft) => {
          const room = Object.values(draft.building?.rooms?.MEETING ?? {})[0];
          if (!room) return;
          this._accumulateDailyCredit(draft, room, 1);
        });
      } catch (e) {
        logger.warn(
          "building",
          `访问基建 ${friendId} 信用发放失败: ${(e as Error).message}`,
        );
      }
    }
    return args;
  }
}
