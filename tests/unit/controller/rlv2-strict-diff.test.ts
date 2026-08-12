import { describe, it, expect, vi, beforeAll } from "vitest";
import { enablePatches } from "immer";
import * as fs from "node:fs";
import * as path from "node:path";

enablePatches();

// ===== 官服抓包严格结构 diff（2026-08-11 rogue_6 对局）=====
// 用真实 excel + 官服请求序列驱动当前逻辑，对响应的每一节做递归结构比对
// （缺失/多余字段、类型差异、数组长度），输出全部差异。

vi.mock("@utils/crypt", () => ({
  decryptBattleData: vi.fn().mockResolvedValue({ completeState: 1, finalHp: 8, isPerfect: 1 }),
}));

import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { mockPlayerData } from "../../helpers";
import excel from "@excel/excel";

// 加载真实 excel 数据（严格比对需要真实表结构）
beforeAll(async () => {
  await excel.init();
}, 120000);

const CAPTURE_ROOT = path.resolve(__dirname, "../../../tmp");

function readRes(route: string, ts: string) {
  const f = path.join(CAPTURE_ROOT, "rlv2", route, `${ts}.json`);
  return JSON.parse(fs.readFileSync(f, "utf8"));
}

function diff(a: any, b: any, p: string, out: string[]) {
  const typeA = a === null ? "null" : Array.isArray(a) ? "array" : typeof a;
  const typeB = b === null ? "null" : Array.isArray(b) ? "array" : typeof b;
  if (typeA !== typeB) {
    out.push(`${p}: 类型差异 官服=${typeA} 当前=${typeB} (官服=${JSON.stringify(a)?.slice(0, 60)} 当前=${JSON.stringify(b)?.slice(0, 60)})`);
    return;
  }
  if (typeA === "object") {
    const missing = Object.keys(a).filter((k) => !(k in b));
    const extra = Object.keys(b).filter((k) => !(k in a));
    if (missing.length) out.push(`${p}: 缺失 [${missing.join(",")}]`);
    if (extra.length) out.push(`${p}: 多余 [${extra.join(",")}]`);
    for (const k of Object.keys(a)) {
      if (k in b) diff(a[k], b[k], `${p}.${k}`, out);
    }
    return;
  }
  if (typeA === "array") {
    if (a.length !== b.length) out.push(`${p}: 长度 官服=${a.length} 当前=${b.length}`);
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i++) diff(a[i], b[i], `${p}[${i}]`, out);
  }
}

function makePlayer() {
  const pd: any = mockPlayerData({
    pushFlags: { status: 123456 } as any,
    rlv2: {
      outer: {
        rogue_6: {
          record: { last: 0, lastZone: 3, legacy: [], stageCnt: {}, bandCnt: {}, bandGrade: {} },
          collect: { band: {} },
          buff: { pointOwned: 0, pointCost: 0, unlocked: {}, score: 0 },
        },
      },
      current: {},
      pinned: {},
    } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
    troop: { chars: { 1: { charId: "char_502_nblade" }, 2: { charId: "char_503_rang" }, 3: { charId: "char_237_gravel" }, 4: { charId: "char_501_durin" }, 5: { charId: "char_208_melan" }, 6: { charId: "char_500_noirc" }, 7: { charId: "char_120_hibisc" }, 8: { charId: "char_278_orchid" } } } as any,
  });
  const player = new PlayerDataManager(pd._playerdata);
  (player.rlv2 as any).current.game = { theme: "rogue_6", mode: "NORMAL", modeGrade: 15, predefined: null } as any;
  return player;
}

const SECTIONS = ["current.player", "current.module", "current.map", "current.inventory", "current.buff", "current.record", "current.troop", "current.game", "pinned"];

function extractOur(json: any, sec: string): any {
  let v: any = json;
  for (const p of sec.split(".")) v = v?.[p];
  return v;
}
function ourKeyOf(rlv2: any) {
  const json = JSON.parse(JSON.stringify(rlv2.toJSON()));
  return {
    state: json.current.player.state,
    pendingTypes: (json.current.player.pending || []).map((e: any) => e.type),
  };
}

function extractOfficial(official: any, sec: string): any {
  let v: any = official.playerDataDelta?.modified?.rlv2;
  for (const p of sec.split(".")) v = v?.[p];
  return v;
}

/** 对某一步：全段严格 diff，返回差异列表（忽略标量值、只报结构） */
function strictCompare(official: any, ourJson: any): string[] {
  const out: string[] = [];
  for (const sec of SECTIONS) {
    const o = extractOfficial(official, sec);
    const n = extractOur(ourJson, sec);
    // 官服某节存在才比对（避免动态缺失）
    if (o === undefined) continue;
    diff(o, n ?? {}, sec, out);
  }
  return out;
}

describe("官服抓包严格结构 diff（2026-08-11 rogue_6）", () => {
  function allowedDiff(d: string): boolean {
    // 已知允许的动态差异：真实玩家数据/随机值/进度类
    return (
      d.startsWith("current.inventory.relic") ||
      d.startsWith("current.inventory.recruit") ||
      d.startsWith("current.inventory.stashRecruit") ||
      d.startsWith("current.game.") ||
      d.startsWith("current.player.property.") ||
      d.startsWith("current.player.trace") ||
      d.startsWith("current.player.cursor") ||
      d.startsWith("current.player.pending") ||
      d.startsWith("outer.rogue_6.") ||
      d.startsWith("current.record.") ||
      d.startsWith("current.buff.") ||
      d.startsWith("current.module.weather.") ||
      d.includes("stepRemain") ||
      d.includes("initSupport.scene.choices") || // 3 选 1 随机值差异
      d.includes("initRelic.items") || // 分队可选列表按解锁态过滤（首玩全给 vs 官服已解锁集合）
      d.includes("stashRecruit") ||
      d.includes("current.troop.")
    );
  }

  async function replayStep(rlv2: any, step: () => Promise<void>, route: string, ts: string, label: string) {
    await step();
    const off = readRes(route, ts);
    const diffs = strictCompare(off, JSON.parse(JSON.stringify(rlv2.toJSON())));
    const real = diffs.filter((d) => !allowedDiff(d));
    console.log(`===== ${label} =====`);
    if (real.length === 0) console.log("  ✅ 无结构差异（除动态数据）");
    else for (const d of real) console.log("  ❌", d);
    return real;
  }

  it("createGame → 开局全流程 严格结构比对", async () => {
    const player = makePlayer();
    const rlv2 = player.rlv2 as any;
    const all: string[][] = [];

    all.push(await replayStep(rlv2, () => rlv2.createGame({ theme: "rogue_6", mode: "NORMAL", modeGrade: 15, predefinedId: null }), "createGame", "2026-08-11T07-45-24-344Z", "createGame"));
    all.push(await replayStep(rlv2, () => rlv2.chooseInitialRelic({ select: "0" }), "chooseInitialRelic", "2026-08-11T07-45-29-912Z", "chooseInitialRelic"));
    all.push(await replayStep(rlv2, () => rlv2.finishEvent(), "finishEvent", "2026-08-11T07-45-32-446Z", "finishEvent(GIFT)"));
    all.push(await replayStep(rlv2, () => rlv2.selectChoice({ choice: "choice_ro6_startbuff_1" }), "selectChoice", "2026-08-11T07-45-47-290Z", "selectChoice(SUPPORT)"));
    all.push(await replayStep(rlv2, () => rlv2.chooseInitialRecruitSet({ select: "recruit_group_1" }), "chooseInitialRecruitSet", "2026-08-11T07-46-12-074Z", "chooseInitialRecruitSet"));

    // 断言：无"非动态"结构差异（缺失/多余字段/类型差异）
    for (const stepDiffs of all) {
      for (const d of stepDiffs) {
        expect(d, `结构差异: ${d}`).toBeUndefined();
      }
    }
  });

  it("battleFinish 胜利 → BATTLE_REWARD 结构比对（含 scrap 零件组）", async () => {
    // 固定 random：废品/收藏品掉落概率稳定
    const rand = vi.spyOn(Math, "random").mockReturnValue(0.1);
    try {
    const player = makePlayer();
    const rlv2 = player.rlv2 as any;
    await rlv2.createGame({ theme: "rogue_6", mode: "NORMAL", modeGrade: 15, predefinedId: null });
    await rlv2.chooseInitialRelic({ select: "0" });
    await rlv2.finishEvent();
    const gz = ourKeyOf(rlv2);
    if (gz.pendingTypes[0]?.startsWith("GAME_INIT_SUPPORT")) {
      await rlv2.selectChoice({ choice: "choice_ro6_startbuff_1" });
    }
    await rlv2.chooseInitialRecruitSet({ select: "recruit_group_1" });
    const recruitEvt = rlv2._status.pending.find((e: any) => e.type === "GAME_INIT_RECRUIT");
    const tickets = [...recruitEvt.content.initRecruit.tickets];
    for (const t of tickets) {
      await rlv2.activeRecruitTicket({ id: t });
      const ticket = rlv2.inventory.recruit[t];
      if (ticket?.list?.length) await rlv2.recruitChar({ ticketIndex: t, optionId: String(ticket.list[0].instId) });
    }
    await rlv2.finishEvent(); // WAIT_MOVE + 地图
    // 战斗
    await rlv2._trigger.emit("rlv2:event:create", ["BATTLE", { state: 1, chestCnt: 2, goldTrapCnt: 1, boxInfo: {}, tmpChar: [] }]);
    rlv2._status.property.hp = { current: 10, max: 10 };
    await rlv2._battle.finish([{ battleLog: "", data: "encrypted", battleData: { completeState: 1, finalHp: 8, isPerfect: 1 } }]);
    const off = readRes("battleFinish", "2026-08-11T07-48-18-678Z");
    const diffs = strictCompare(off, JSON.parse(JSON.stringify(rlv2.toJSON())));
    const real = diffs.filter((d) => !allowedDiff(d));
    console.log("===== battleFinish =====");
    if (real.length === 0) console.log("  ✅ 无结构差异");
    else for (const d of real) console.log("  ❌", d);
    for (const d of real) expect(d).toBeUndefined();
    // BATTLE_REWARD 含零件组
    const rewardEvent = rlv2._status.pending.find((e: any) => e.type === "BATTLE_REWARD");
    const hasScrap = (rewardEvent.content.battleReward.rewards || []).some((g: any) =>
      g.items.some((it: any) => String(it.id).includes("scrap")),
    );
    expect(hasScrap).toBe(true);
    } finally {
      rand.mockRestore();
    }
  });

  it("stashRecruitTicket / useStashedTicket 结构比对", async () => {
    const player = makePlayer();
    const rlv2 = player.rlv2 as any;
    await rlv2.createGame({ theme: "rogue_6", mode: "NORMAL", modeGrade: 15, predefinedId: null });
    rlv2.inventory._recruit.gain("rogue_6_recruit_ticket_pioneer", "battle", 0);
    const idx = Object.keys(rlv2.inventory.recruit)[0];
    await rlv2.stashRecruitTicket({ index: idx });
    const off = readRes("stashRecruitTicket", "2026-08-11T07-50-50-630Z");
    const diffs = strictCompare(off, JSON.parse(JSON.stringify(rlv2.toJSON())));
    const real = diffs.filter((d) => !allowedDiff(d));
    console.log("===== stashRecruitTicket =====");
    if (real.length === 0) console.log("  ✅ 无结构差异");
    else for (const d of real) console.log("  ❌", d);
    for (const d of real) expect(d).toBeUndefined();
    const inv = JSON.parse(JSON.stringify(rlv2.inventory.toJSON()));
    expect(Array.isArray(inv.stashRecruit)).toBe(true);
    expect(inv.stashRecruitLimit).toBe(3);
  });
});
