/**
 * 集成战略（rlv2）分区逻辑：结算（结局结算/评分/黑流效率/乐队段位等）
 *
 * 由 RoguelikeV2Manager 拆分而来：函数首参 mgr 为管理器实例，
 * 类侧保留同名薄委派（见 logic.ts）。
 */
import type { RoguelikeV2Manager } from "./logic";
import type { PlayerRoguelikeV2 } from "./rlv2-model";
import excel from "@excel/excel";
import { isJsonArray, isJsonObject, type JsonObject } from "@excel/json-value";
import { now } from "@utils/time";
import {
  ROGUE6_BATTLE_NODES,
  ROGUE6_SHOP_NODES,
  ROGUE6_NODE_SCENE_PREFIX,
  ROGUE6_END2_BOSS_STAGE,
  ROGUE6_END2_RELICS,
  ROGUE6_END3_RELIC,
  ROGUE6_BEAK_OUTBUFF,
  ROGUE6_NON_PORTABLE_SCRAPS,
  ROLL_NODE_TYPE_VALUES,
  isBlackstream,
} from "./theme-rules";

/**
 * 分队升级引用条目（`details[theme].bandRef` 的值）。
 *
 * 线格式键为 `itemID`（CS 字段名，data/excel 实测），生成模型
 * `RoguelikeBandRefData` 写作 `itemId`，故此处按实际数据显式声明；
 * `normalBandId` 缺省回落 itemID 的判定保持原样。
 */
interface RoguelikeBandRefEntry {
  bandLevel?: number;
  normalBandId?: string;
  itemID?: string;
}

/** 废品库存条目（黑流树海 `scrap.inventory` 的值，仅声明结算消费的 id） */
interface ScrapInventoryEntry {
  id?: string;
}

/** 局外主题数据字典（配方外传 mgr.outer，配方内传 draft.outer） */
type OuterThemeMap = { [theme: string]: PlayerRoguelikeV2.OuterData };

/**
 * `customizeData[theme]` 的科技树节点字典。
 *
 * customizeData 为未建模线格式 JSON（生成类型 `RoguelikeTopicCustomizeData` = JsonValue），
 * 按原逻辑取值：`developments`（非数组）优先，否则回落 `commonDevelopment.developments`。
 * @param theme - 肉鸽主题 id
 * @returns 节点 id → 节点数据的字典（无该主题/无节点时 undefined）
 */
function developmentNodes(theme: string): JsonObject | undefined {
  const customize = excel.RoguelikeTopicTable.customizeData?.[theme];
  if (customize === undefined || !isJsonObject(customize)) return undefined;
  const own = customize.developments;
  const common = customize.commonDevelopment;
  const devs =
    own && !isJsonArray(own)
      ? own
      : isJsonObject(common)
        ? common.developments
        : undefined;
  return devs !== undefined && isJsonObject(devs) ? devs : undefined;
}

  /**
   * 分队升级可见性同步（科技树解锁 → collect.band state）。
   * 规则：bandRef 中 bandLevel>0 的升级变体（unlockCondDesc 提到科技树节点名，
   * 如"激活分裂/卵生/胎生/顶冠/角/鳍"）解锁时，升级变体 state 1、其 normalBandId 旧分队 state 0。
   * @param theme 主题
   * @param buffId 刚解锁的科技树节点（buffId 或 buffName 匹配）
   * @param collectBand collect.band 引用（原地修改）
   */
export function applyBandUpgradeVisibility(mgr: RoguelikeV2Manager, theme: string,
    buffId: string,
    collectBand: { [key: string]: { state: number } },) : void {
    const detail = excel.RoguelikeTopicTable.details[theme];
    const bandRef = (detail?.bandRef || {}) as Record<string, RoguelikeBandRefEntry>;
    // 刚解锁节点名（buffName，用于匹配 unlockCondDesc 中的"激活XXX"）
    const devs = developmentNodes(theme);
    const devNode = devs?.[buffId];
    const devName =
      devNode !== undefined &&
      isJsonObject(devNode) &&
      typeof devNode.buffName === "string"
        ? devNode.buffName
        : "";
    const upgradeVariants = Object.entries(bandRef).filter(
      ([, r]) => (r.bandLevel ?? 0) > 0,
    );
    for (const [upgradeId, ref] of upgradeVariants) {
      const cond = detail?.items?.[upgradeId]?.unlockCondDesc || "";
      // 升级条件提到该节点名（分裂/卵生/胎生/顶冠/角/鳍）→ 该升级已解锁
      const matched = devName !== "" && cond.includes(`“${devName}”`);
      if (!matched) continue;
      const info: { state: number; progress: number[] | null } = {
        state: 1,
        progress: null,
      };
      collectBand[upgradeId] = info;
      const baseId = ref.normalBandId || ref.itemID;
      if (baseId && baseId !== upgradeId && collectBand[baseId]) {
        collectBand[baseId].state = 0;
      }
    }
}

  /**
   * 难度解锁状态（collect.modeGrade）：进阶式扩展难度——通关 grade N 解锁 grade N+1。
   * grade 0 默认解锁（state 2）；grade N（>=1）仅当上一级已通关（record.modeGrade 含 N-1 通关记录）才 state 2，
   * 否则 state 1（可见未解锁）。客户端按 state 决定难度可选性。
   */
export function initModeGradeStates(mgr: RoguelikeV2Manager, theme: string,
    map?: OuterThemeMap,
    game?: PlayerRoguelikeV2.CurrentData.Game | null,) : {
    [mode: string]: { [grade: string]: { state: number; progress: number[] | null } };
  } {
    const detail = excel.RoguelikeTopicTable.details[theme];
    const difficulties = (detail?.difficulties || []).filter(
      (x) => (x.modeDifficulty ?? "NORMAL") === "NORMAL",
    );
    const states: {
      [grade: string]: { state: number; progress: number[] | null };
    } = {};
    // 已通关难度（record.modeGrade[mode] 各难度通关计数 > 0）
    const rec: PlayerRoguelikeV2.OuterData.Record =
      (map ?? mgr.outer)?.[theme]?.record ||
      ({} as PlayerRoguelikeV2.OuterData.Record);
    const cleared = new Set<number>();
    const mode = (game ?? mgr.current.game)?.mode || "NORMAL";
    const clearedGrades: { [g: string]: number } = rec.modeGrade?.[mode] || {};
    for (const [g, cnt] of Object.entries(clearedGrades)) {
      if (cnt > 0) cleared.add(parseInt(g, 10));
    }
    for (const diff of difficulties) {
      const g = diff.grade ?? 0;
      const isCleared = g === 0 || cleared.has(g) || cleared.has(g - 1) || g <= mgr.maxClearedGrade(cleared);
      states[String(g)] = {
        state: isCleared ? 2 : 1,
        progress: null,
      };
    }
    return { [mode]: states };
}

  /** 已通关的最高连续难度（进阶式：通关 N-1 才解锁 N） */
export function maxClearedGrade(mgr: RoguelikeV2Manager, cleared: Set<number>) : number {
    let max = 0;
    for (let g = 1; ; g++) {
      if (cleared.has(g)) max = g;
      else break;
    }
    return max;
}

export function buildSettlement(mgr: RoguelikeV2Manager, over: boolean,
    success: number,
    ending: string,) {
    const game = mgr.current.game!;
    const theme = game.theme;
    // endTs 用秒（now() 秒级），与 game.start（now() 秒级）保持一致
    //（原实现 Date.now() 为毫秒 → 响应里 endTs 13 位而 startTs 10 位，长度/t 值域不一致）
    const endTs = now();
    const startTs = game.start || endTs;
    const property = mgr._status.property;

    // 战斗/招募计数（trace 节点类型统计）
    let cntBattleNormal = 0;
    let cntBattleElite = 0;
    let cntBattleBoss = 0;
    let cntArrivedNode = mgr._status.trace.length;
    const cntArrivedNodeType: { [key: number]: number } = {};
    for (const t of mgr._status.trace) {
      const node = mgr._map.zones[mgr.zoneKey(t.zone)]?.nodes[
        `${(t.position?.x ?? 0) * 100 + (t.position?.y ?? 0)}`
      ];
      const type = node?.type ?? 0;
      cntArrivedNodeType[type] = (cntArrivedNodeType[type] ?? 0) + 1;
      if (type === 1) cntBattleNormal++;
      else if (type === 2) cntBattleElite++;
      else if (type === 4) cntBattleBoss++;
    }
    const recruitChars = Object.values(mgr.inventory!.recruit || {}).filter(
      (t) => t.result,
    );
    const cntRecruitChar = recruitChars.length;
    const troopChars = Object.values(mgr.troop.chars).map((c) => {
      const char = { ...c };
      return {
        instId: String(char.instId),
        charId: char.charId,
        type: char.type || "NORMAL",
        upgradePhase: char.upgradePhase ?? 0,
        evolvePhase: char.evolvePhase ?? 0,
        level: char.level ?? 1,
        potentialRank: char.potentialRank ?? 0,
        mainSkillLvl: char.mainSkillLvl ?? 1,
      };
    });

    const brief = {
      level: property.level,
      over,
      success,
      ending,
      theme,
      mode: game.mode,
      // 预置剧本 id：无预置剧本（NORMAL 等）时为 null 而非 ""——official brief.predefined 为 null
      //（原实现 `|| ""` 会把 null 强转成空串，客户端按"有预置剧本"解析）
      predefined: game.predefined ?? null,
      band: mgr._bandId || "",
      startTs,
      endTs,
      endZoneId: `zone_${mgr._status.cursor.zone}`,
      endProperty: {
        hp: property.hp?.current ?? 0,
        gold: property.gold ?? 0,
        populationCost: property.population?.cost ?? 0,
        populationMax: property.population?.max ?? 0,
        san: 0,
      },
      innerMission: false,
      innerMissionProcess: null,
      // 官服 brief 恒定携带这两个键（innerMissionProcessAddition 恒 null；
      // seed 为 "{随机},{theme},{modeGrade}" 战报种子，客户端据此分享/复现）
      innerMissionProcessAddition: null,
      modeGrade: game.modeGrade,
      seed: mgr.gameSeed(),
    };

    // 招募干员职业分布（record.cntRecruitProfession）：按当前队伍干员职业统计。
    // 官方键为职业名（TANK/CASTER/SNIPER…），值 = 该职业干员数。
    const cntRecruitProfession: { [key: string]: number } = {};
    for (const t of troopChars) {
      const prof = excel.CharacterTable?.[t.charId]?.profession;
      if (prof) cntRecruitProfession[prof] = (cntRecruitProfession[prof] ?? 0) + 1;
    }
    // 废品/零件箱各 id 持有数（黑流树海 record.scrapCounter）
    const scrapCounter: { [key: string]: number } = {};
    const scrapInv = (
      mgr._module.scrap as
        | { inventory?: Record<string, ScrapInventoryEntry> }
        | undefined
    )?.inventory;
    if (scrapInv) {
      for (const it of Object.values(scrapInv)) {
        const id = it?.id;
        if (id) scrapCounter[id] = (scrapCounter[id] ?? 0) + 1;
      }
    }

    const record = {
      cntZone: Object.keys(mgr._map.zones).length,
      cntBattleNormal,
      cntBattleElite,
      cntBattleBoss,
      cntArrivedNode,
      cntRecruitChar,
      cntUpgradeChar: 0,
      cntKillEnemy: 0,
      cntShopBuy: 0,
      cntPerfectBattle: property.conPerfectBattle ?? 0,
      cntProtectBox: 0,
      cntRecruitFree: 0,
      cntRecruitAssist: 0,
      cntRecruitNpc: 0,
      cntRecruitProfession,
      troopChars,
      cntArrivedNodeType,
      relicList: Object.values(mgr.inventory!.relic || {}).map(
        (r) => r.id,
      ),
      capsuleList: [],
      activeToolList: Object.values(mgr.inventory?.exploreTools() || {}).map(
        (t) => t.id,
      ),
      exploreToolList: Object.values(mgr.inventory?.exploreTools() || {}).map(
        (t) => t.id,
      ),
      // 官服 record.zones 为区域数组 [{index, zoneId, variation}]（黑流树海无相地图，
      // 由 grid_zone 模块生成）；原实现误写为层数数字 → 客户端合并结构错误。改从
      // _map.zones 值构造（每个值即含 id/index/variation）。
      zones: Object.values(mgr._map.zones).map((z) => ({
        index: z.index,
        zoneId: z.id, // 形如 "zone_1"
        variation: Array.isArray(z.variation) ? z.variation : [],
      })),
      legacyList: [],
      scrapCounter,
      cntExpedition: {},
      cntWeatherMainGain: {},
      cntWeatherSubGain: {},
      cntWeatherMainClear: {},
      cntScrapIdentify: 0,
      cntShopRecycleCount: {},
      cntShopRecycleProfit: {},
      cntEndZoneBattle: {},
      cntSettleSavage: 0,
      cntSettleBandit: 0,
      cntNodePassBattle: 0,
      nodeMission: [],
      squadBuff: mgr.current.buff?.squadBuff || [],
      charBuff: [],
    };

    // 本局银行余额（GAME_SETTLE.result.buffBankPut，官服 giveUpGame/gameSettle 结算携带）
    const buffBankPut = mgr.outer[theme]?.bank?.current ?? 0;
    return { brief, record, buffBankPut };
}

  /**
   * 探索分数逐项明细（dorothinights gameSettle 参考：官方结算页逐行列出贡献项）。
   * 每行固定为 [count, score] 二元组，顺序 = 层数档位 / 步数×1 / 普通战×10 / 精英战×20 /
   * 领袖战×30 / 物品×5（收藏品+战术道具，不含思绪）/ 招募×2（难度倍率前 raw 贡献）。
   * @returns detail 明细对 + raw 未乘难度倍率的原始分数
   */
export function exploreBreakdown(mgr: RoguelikeV2Manager) : { detail: number[][]; raw: number } {
    // 层数档位 0/30/80/150/270/400/550/650（>7 按 7）
    const ZONE_SCORES = [0, 30, 80, 150, 270, 400, 550, 650];
    const zoneCount = Math.min(mgr._status.cursor.zone, 7);
    const zoneScore = ZONE_SCORES[zoneCount] ?? 0;
    const stepCount = mgr._status.trace.length;
    let normalCount = 0;
    let eliteCount = 0;
    let bossCount = 0;
    for (const t of mgr._status.trace) {
      const node = mgr._map.zones[mgr.zoneKey(t.zone)]?.nodes[
        `${(t.position?.x ?? 0) * 100 + (t.position?.y ?? 0)}`
      ];
      const type = node?.type ?? 0;
      if (type === 1) normalCount++;
      else if (type === 2) eliteCount++;
      else if (type === 4) bossCount++;
    }
    const recruitCount = Object.values(mgr.inventory!.recruit || {}).filter(
      (t) => t.result,
    ).length;
    const itemCount =
      Object.keys(mgr.inventory!.relic || {}).length +
      Object.keys(mgr.inventory?.exploreTool || {}).length;
    const detail: number[][] = [
      [zoneCount, zoneScore], // 通过层数（档位）
      [stepCount, stepCount * 1], // 通过步数 ×1
      [normalCount, normalCount * 10], // 普通战斗 ×10
      [eliteCount, eliteCount * 20], // 精英战斗 ×20
      [bossCount, bossCount * 30], // 领袖战斗 ×30
      [itemCount, itemCount * 5], // 获得物品 ×5
      [recruitCount, recruitCount * 2], // 招募干员 ×2
    ];
    const raw = detail.reduce((sum, [, score]) => sum + score, 0);
    return { detail, raw };
}

  /** 当前难度对应的探索分数倍率（difficulty.scoreFactor，无则默认 1） */
export function exploreScoreFactor(mgr: RoguelikeV2Manager) : number {
    const theme = mgr.current.game!.theme;
    const detail = excel.RoguelikeTopicTable.details[theme];
    const difficulty = detail?.difficulties?.find(
      (d) => d.modeDifficulty === mgr.current.game!.mode && d.grade === mgr.current.game!.modeGrade,
    );
    return difficulty?.scoreFactor ?? 1;
}

  /**
   * 探索分数 = 明细求和 × 难度倍率（dorothinights 对齐：仅按难度单次放大，
   * 生命游戏/难度 bump 的「源流样本」效率走 buff/bp，不放大 score 本体）。
   */
export function exploreScore(mgr: RoguelikeV2Manager) : number {
    return Math.floor(mgr.exploreBreakdown().raw * mgr.exploreScoreFactor());
}

  /**
   * 黑流树海（rogue_6）「生命游戏」增益树节点集合。
   * 来源：customizeData[theme].developments / commonDevelopment.developments（upgradeBuff 同源）。
   * 仅统计 outbuff 型生长节点（`rogue_6_outbuff_*`），难度解锁节点（`rogue_6_difficulty_*`）不计入——
   * 演化算子只用于升级【生命游戏】（生长树）节点。
   * @returns 节点 id 数组
   */
export function lifeGameNodes(mgr: RoguelikeV2Manager, theme: string) : string[] {
    const devs = developmentNodes(theme);
    const all = devs ? Object.keys(devs) : [];
    return all.filter(
      (id) =>
        isBlackstream(theme) ? id.includes("rogue_6_outbuff_") : true,
    );
}

  /**
   * 黑流树海分数→源流样本转换效率。
   * 默认 1:1；【生命游戏】科技树按已解锁生长节点占比 ×10% 累加（封顶 +10%）；
   * 难度等级 ≥3/≥6/≥9 时各额外 +2% → 1:1.1 / 1.12 / 1.14 / 1.16（生命游戏满级基准）。
   * 非黑流树海主题恒为 1（保持 1:1，不启用效率加成）。
   * @param theme 主题
   * @param grade 难度等级（modeGrade）
   */
export function blackstreamEfficiency(mgr: RoguelikeV2Manager, theme: string, grade: number) : number {
    if (!isBlackstream(theme)) return 1;
    const nodes = mgr.lifeGameNodes(theme);
    const unlocked = Object.keys(mgr.outer?.[theme]?.buff?.unlocked || {}).filter(
      (id) => id.includes("rogue_6_outbuff_"),
    ).length;
    let efficiency = 1;
    // 生命游戏：按已解锁生长节点占比累加，封顶 +10%
    if (nodes.length > 0) {
      efficiency += 0.1 * Math.min(1, unlocked / nodes.length);
    }
    // 难度等级 3+/6+/9+ 各额外提升 2%
    if (grade >= 3) efficiency += 0.02;
    if (grade >= 6) efficiency += 0.02;
    if (grade >= 9) efficiency += 0.02;
    return efficiency;
}

  /**
   * 是否仍可获得演化算子（黑流树海）。
   * 官方说明：当获得的演化算子能够升级所有【生命游戏】节点时停止获得。
   * 这里以「还有未解锁的生长节点」近似判定——全部解锁即不再发放，
   * 否则跨局累计的源流堆栈满 200 点得分的演化算子继续发放。
   * @param theme 主题
   */
export function canEvolveOperators(mgr: RoguelikeV2Manager, theme: string) : boolean {
    if (!isBlackstream(theme)) return false;
    const nodes = mgr.lifeGameNodes(theme);
    if (nodes.length === 0) return true;
    const unlocked = Object.keys(mgr.outer?.[theme]?.buff?.unlocked || {}).filter(
      (id) => id.includes("rogue_6_outbuff_"),
    ).length;
    return unlocked < nodes.length;
}

  /**
   * 黑流树海结算奖励统计算法（源流样本 + 演化算子）。
   * 源流样本得分 = floor(探索分数 × 转换效率)；
   * 跨局源流堆栈（buff.sourceStack）累计该得分，每满 200 点 → 1 点演化算子（pointOwned），
   * 不满 200 的余数保留到后续探索继续累加。非黑流树海满 1:1（源流得分=探索分数、无算子）。
   * @returns 当局源流样本得分与转换效率
   */
export function blackstreamAwards(mgr: RoguelikeV2Manager) : { sourceScore: number; efficiency: number } {
    const theme = mgr.current.game!.theme;
    const exploreScore = mgr.exploreScore();
    const efficiency = mgr.blackstreamEfficiency(
      theme,
      mgr.current.game?.modeGrade ?? 0,
    );
    const sourceScore = Math.floor(exploreScore * efficiency);
    return { sourceScore, efficiency };
}

export async function gameSettle(mgr: RoguelikeV2Manager) : Promise<void> {
    // 幂等：清空 pending，保证结算事件唯一（重登恢复的"放弃结算中间态"存档可能已带 GAME_SETTLE）
    mgr.clearPending();
    const theme = mgr.current.game!.theme;
    const ending = mgr._status.toEnding || "";
    // 本局运行态快照（2026-09-09 修复）：结算 update 会清空本局运行态（trace / map /
    // 入队干员），而勋章与特勤干员任务的事件载荷需要「本局」数据 —— 原实现把 emit 放在
    // update 之后，读到的 nodeTypeCounts() 与 troop.chars 全为空（胜利/作战/干员数恒 0）。
    // 故在结算前取快照并显式下传给各 emitter。
    const runSnapshot = {
      charIds: Object.keys(mgr.troop.chars ?? {}),
      nodeCounts: mgr.nodeTypeCounts(),
      bandId: mgr._bandId || "",
      mode: mgr.current.game?.mode || "NORMAL",
    };
    // 修复：原实现 toEnding 恒为 "roX_ending_1/2"（非 "normal"）且 chgEnding 仅持有
    // 结局变更藏品时为 true → 通关结算恒显示失败；改按本局结果标记判定
    const success =
      mgr._status.runResult === "success" || mgr._status.chgEnding ? 1 : 0;
    const { brief, record, buffBankPut } = mgr.buildSettlement(true, success, ending);
    // current.record 为 _playerdata.rlv2 引用（update() 后冻结），写入放入下方 update() 配方
    const exploreScore = mgr.exploreScore();
    // 黑流树海（rogue_6）启用「源流样本 + 演化算子」多币种结算；其余主题保持分数→科技树点数 1:1。
    const themeBlackstream = isBlackstream(theme);
    const { sourceScore } = mgr.blackstreamAwards();
    await mgr.update(async (draft) => {
      draft.current.record = { brief, record };
      const outerTheme =
        draft.outer[theme] ?? (draft.outer[theme] = {} as PlayerRoguelikeV2.OuterData);
      const buff =
        outerTheme.buff ??
        (outerTheme.buff = {
          pointOwned: 0,
          pointCost: 0,
          unlocked: {},
          score: 0,
          sourceStack: 0,
        });
      // 累计探索分数 = 探索分数（dorothinights 对齐：不放大；生命游戏加成走演化算子）
      buff.score = (buff.score || 0) + exploreScore;
      if (themeBlackstream && mgr.canEvolveOperators(theme)) {
        // 演化算子：跨局累计源流堆栈（每满 200 点源流得分 → 1 点演化算子），
        // 不足 200 的余数保留到后续探索继续累加；演化算子即科技树货币 pointOwned。
        const stack = (buff.sourceStack || 0) + sourceScore;
        const operators = Math.floor(stack / 200);
        buff.sourceStack = stack - operators * 200;
        buff.pointOwned = (buff.pointOwned || 0) + operators;
      } else {
        // 非黑流树海 / 生命游戏节点已全部解锁：分数直接 1:1 计入科技树点数
        buff.pointOwned = (buff.pointOwned || 0) + exploreScore;
      }

      // 记录本把到达的最深层——官服 record 无 lastZone 键（8-11/8-18 抓包对照），
      // 支援选项判定改由 stageCnt 3 层关卡存在性承载；lastZone 仅为旧存档兼容读取。
      const rec =
        outerTheme.record ??
        (outerTheme.record = {} as PlayerRoguelikeV2.OuterData.Record);
      // 上次结束时间用秒（now()）——原实现 Date.now() 为毫秒（13 位），与本局
      // startTs/endTs（秒、10 位）与 record 其余时间字段值域不一致。
      rec.last = now();
      // 难度通关记录（进阶式解锁：通关 grade N 解锁 N+1）——record.modeGrade[mode][grade]++
      const mode = mgr.current.game?.mode || "NORMAL";
      const grade = mgr.current.game?.modeGrade ?? 0;
      const recMode = rec.modeGrade ?? (rec.modeGrade = {});
      const recGrades = recMode[mode] ?? (recMode[mode] = {});
      recGrades[grade] = (recGrades[grade] || 0) + 1;
      // 特勤干员任务数据源：成功结算记录「分队×结局」「分队×难度」（Rlv2BandGradeCnt /
      // Rlv2EndingBandGradeCnt / Rlv2EndingModeGrade 模板按此统计累计分队数）。
      // bandCnt[bandId][endingId]++、bandGrade[bandId][gradeId]++。
      // 仅常规行动（NORMAL 模式）计入——MONTH_TEAM 等特殊模式不参与特勤干员任务。
      if (success === 1 && ending && mgr._bandId && mode === "NORMAL") {
        const soBandCnt = rec.bandCnt ?? (rec.bandCnt = {});
        const perEnding =
          soBandCnt[mgr._bandId] ?? (soBandCnt[mgr._bandId] = {});
        perEnding[ending] = (perEnding[ending] || 0) + 1;
        const soBandGrade = rec.bandGrade ?? (rec.bandGrade = {});
        const perGrade =
          soBandGrade[mgr._bandId] ?? (soBandGrade[mgr._bandId] = {});
        perGrade[String(grade)] = (perGrade[String(grade)] || 0) + 1;
      }
      // 同步 collect.modeGrade 解锁状态（当前难度 + 下一级可解锁）
      const collect = outerTheme.collect;
      if (collect?.modeGrade?.[mode]) {
        collect.modeGrade[mode][String(grade)] = { state: 2, progress: null };
        const next = String(grade + 1);
        if (collect.modeGrade[mode][next]) {
          collect.modeGrade[mode][next] = { state: 2, progress: null };
        }
      }
      // 结局图鉴 + 对局历史（2026-09-09 修复）：官方 outer[theme].record.history[] 与
      // collect.endBook 此前**从不写入**——结局类勋章（Rlv2EndingCollect「达成 N 种结局」）
      // 因此无数据可依。history 形状对齐 types-playerdata
      // PlayerRoguelikeV2_OuterData_Record_History；仅保留最近 100 局避免无限增长。
      const history = Array.isArray(rec.history) ? rec.history : (rec.history = []);
      history.push({
        seed: mgr.gameSeed(),
        bandId: mgr._bandId ?? "",
        mode,
        modeGrade: grade,
        ending: success === 1 ? ending || "" : "",
        failEnding: success === 1 ? "" : ending || "",
        result: success,
        endTs: now(),
      });
      if (history.length > 100) {
        history.splice(0, history.length - 100);
      }
      // 结局图鉴（collect.endBook）：达成过的结局去重记录 —— Rlv2EndingCollect 计数来源
      // （collect 可能尚未初始化——旧存档/测试现场只有 buff 时先补建）
      if (success === 1 && ending) {
        if (!outerTheme.collect) {
          outerTheme.collect = {} as PlayerRoguelikeV2.OuterData.Collection;
        }
        const collectRef = outerTheme.collect;
        const endBook = collectRef.endBook ?? (collectRef.endBook = {});
        endBook[ending] = { state: 2, progress: null };
      }
      // 黑流树海襁褓类藏品（LEGACY 型：局内获得 → 下一局增益）持久化到 record.legacy
      const legacy = Object.values(mgr.inventory?.relic || {})
        .map((r) => r.id)
        .filter((id) => {
          const def = excel.RoguelikeTopicTable.details[theme]?.items?.[id];
          return def?.type === "LEGACY" || id.includes("legacy");
        });
      if (legacy.length > 0) {
        rec.legacy = [...new Set([...(rec.legacy || []), ...legacy])];
      }
      // 难度 0 失败补偿：本次探索失败 → 下次开局获得收藏品【特勤任务影像】
      // （官方保密等级·0"失败时下次探索获得特勤任务影像"；难度 4+ 起"失败后不再获得"）
      if (success === 0 && (mgr.current.game?.modeGrade ?? 0) <= 3) {
        rec.legacy = [
          ...new Set([
            ...(rec.legacy || []),
            "rogue_6_relic_fight_29",
          ]),
        ];
      }
      // 分队升级隐藏（使用分队通关解锁其升级变体）：本把所选分队（_bandId）若有升级变体
      // （bandRef bandLevel>0 且 normalBandId == _bandId）→ 升级变体 state 1、旧分队隐藏。
      const usedBand = mgr._bandId;
      const bandRef = (excel.RoguelikeTopicTable.details[theme]?.bandRef || {}) as Record<
        string,
        RoguelikeBandRefEntry
      >;
      const collectBand = outerTheme.collect?.band;
      if (usedBand && collectBand && typeof collectBand === "object") {
        const upgradeVariant = Object.entries(bandRef).find(
          ([, r]) =>
            (r.bandLevel ?? 0) > 0 && (r.normalBandId ?? r.itemID) === usedBand,
        );
        if (upgradeVariant) {
          const [upgradeId, ref] = upgradeVariant;
          collectBand[upgradeId] = { state: 1, progress: null };
          const baseId = ref.normalBandId || ref.itemID;
          if (baseId && collectBand[baseId]) collectBand[baseId].state = 0;
        }
      }
    });

    // 勋章（2026-09-09）：结算后局外收藏/分队统计变化 → Rlv2CollectRelic / Rlv2UnlockBand
    // （载荷为当前累计值而非增量，模板取 max —— 幂等）
    await mgr.emitOuterProgressionMedals(theme);

    // 勋章（2026-09-09）：Rlv2FinishBattleWithSpecChar「携带指定干员战斗胜利 N 次」。
    // 官服 getMethod 为「常规行动**或**讲述者列表下」——两种模式都计入，故不放在仅
    // NORMAL 生效的 emitSpecialOperatorSettle 内。载荷：本局参战干员 + 本局作战胜利数
    // （nodeTypeCounts 的普通作战(1)与紧急作战(2)之和，与特勤干员任务同口径）。
    {
      const winCount =
        (runSnapshot.nodeCounts.get(1) ?? 0) + (runSnapshot.nodeCounts.get(2) ?? 0);
      await mgr._trigger.emit("Rlv2FinishBattleWithSpecChar", [
        {
          theme,
          mode: runSnapshot.mode,
          charIds: runSnapshot.charIds,
          battleWinCount: winCount,
        },
      ]);
    }

    // 特勤干员任务：结算事件（仅成功达成结局时推进——giveup/失败不产生分队×结局记录）
    if (success === 1) {
      // 分支修复（2026-09-09）：下传结算前快照 —— 原实现让 emitter 自己读
      // mgr.nodeTypeCounts()/mgr.troop.chars，而结算 update 已清空本局运行态，
      // 导致 charIds/spBattleCount/eliteCount 恒为空/0（特勤干员任务与相关勋章永不推进）。
      await mgr.emitSpecialOperatorSettle(theme, ending, runSnapshot);
      // 修复（2026-09-09，S2）：补发「完成并结算集成战略」任务事件——原实现全仓无
      // emit 站点，soWeekTask_3（Rlv2SettleGame，指定主题）与 soWeekTask_3_rogue6
      // （Rlv2SettleGameTimes，任意主题）永久无法完成。
      // 载荷为 rlv2 存档三键（mgr 的 live getter：current/outer 即存档引用，模板只读 game.theme）。
      const rlv2State: PlayerRoguelikeV2 = {
        current: mgr.current,
        outer: mgr.outer,
        pinned: mgr.pinned,
      };
      await mgr._trigger.emit("Rlv2SettleGame", [{ data: rlv2State }]);
      await mgr._trigger.emit("Rlv2SettleGameTimes", []);
    }

    await mgr._trigger.emit("rlv2:event:create", [
      "GAME_SETTLE",
      {
        success,
        result: { brief, record, buffBankPut },
        detailStr: mgr.buildDetailStr(brief),
        popReport: false,
      },
    ]);

    mgr._status.state = "END";
    // 结算完成：令 toJSON/persistCurrent 输出 current 全空（本局结束，不再保留续局运行态）
    mgr._settled = true;
}

  /**
   * 结算响应顶层数据（gameSettle_res 官方抓包：{ game, outer }）：
   * game = { brief, record, score }；outer = 局外结算快照（mission before/after、BP、解锁、spOperatorInfo）。
   * 客户端在 gameSettle 响应里读取该结构渲染结算页；缺失即"点了放弃没反应"。
   */
export function buildSettleResponse(mgr: RoguelikeV2Manager) {
    const theme = mgr.current.game!.theme;
    const { brief, record } = mgr.current.record!;
    // dorothinights gameSettle 对齐：score 仅按难度单次放大；生命游戏/难度 bump 的效率
    // （extra_grow_point → buff=1+extra、bp.cnt=floor(score×buff)）不放大 score 本体。
    const efficiency = mgr.blackstreamEfficiency(theme, mgr.current.game?.modeGrade ?? 0);
    const scoreFactor = mgr.exploreScoreFactor();
    const { detail, raw } = mgr.exploreBreakdown();
    const score = Math.floor(raw * scoreFactor); // 探索分数
    const boosted = Math.floor(score * efficiency); // bp.cnt（源流样本，含生命游戏加成）
    const outerTheme =
      mgr.outer[theme] ?? ({} as PlayerRoguelikeV2.OuterData);
    const bp = (from: number) => ({ cnt: 0, from, to: from });
    const missionList = Array.isArray(outerTheme.mission?.list)
      ? outerTheme.mission.list
      : [];
    const mission = { before: missionList, after: missionList };
    return {
      game: {
        brief: brief ?? {},
        record: record ?? {},
        score: {
          detail,
          scoreFactor,
          score,
          buff: efficiency,
          bp: { cnt: boosted, from: 55000, to: 55000 },
          gp: 0,
          gpChange: [100, 100],
          accumulation: [20000, 20000],
        },
      },
      outer: {
        mission,
        missionBp: bp(55000),
        relicBp: bp(55000),
        totemBp: bp(55000),
        fragmentBp: bp(55000),
        copperBp: bp(55000),
        scrapBp: bp(55000),
        relicUnlock: [],
        totemUnlock: [],
        fragmentUnlock: [],
        copperUnlock: [],
        scrapUnlock: [],
        gp: 0,
        spOperatorInfo: [],
      },
    };
}
