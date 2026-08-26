import { describe, it, expect, beforeEach, vi } from "vitest";
import zlib from "node:zlib";

vi.mock("@excel/excel", () => ({
  default: {
    RoguelikeTopicTable: {
      details: {
        rogue_6: {
          init: [{ modeGrade: 15, predefinedId: null, modeId: "NORMAL", initRelic: {}, initRecruit: {} }],
          recruitTickets: {},
          relics: {},
          items: {},
          bandRef: {},
        },
      },
      modules: {
        rogue_6: { moduleTypes: ["GRID_ZONE", "WEATHER", "SCRAP"] },
      },
      consts: {},
    },
    CharacterTable: {},
  },
}));

import { PlayerDataManager } from "@game/service/manager/PlayerDataManager";
import { mockPlayerData } from "../../../helpers";

/**
 * 2222 存档"无法放弃/无法继续"回归测试（2026-08-19）：
 * 1. giveUpGame 幂等：重登恢复的"放弃结算中间态"存档（pending 已带 GAME_SETTLE）
 *    再次 giveUpGame 不得产生重复事件（官服 giveUpGame 后 pending 只有 1 个）
 * 2. module.continue() 恢复：重登"继续探索"按主题创建模块管理器
 *    （原空实现导致 gridZone/scrap 等 getter 为 undefined，续局请求崩溃）
 */
describe("rlv2 结算残留续局恢复", () => {
  /** 模拟"giveUpGame 后 gameSettle 前中断"的存档（state=PENDING + GAME_SETTLE 残留） */
  function makeSettleStuckPlayer() {
    const pd: any = mockPlayerData({
      pushFlags: { status: 123456 } as any,
      rlv2: {
        outer: {},
        current: {
          player: {
            state: "PENDING",
            property: { hp: { current: 4, max: 4 }, gold: 8 },
            cursor: { zone: 1, position: { x: 0, y: 1 } },
            trace: [],
            pending: [
              {
                index: "e_0",
                type: "GAME_SETTLE",
                content: { success: 0, result: { brief: {}, record: {} }, popReport: false },
              },
            ],
            status: { bankPut: 0 },
            toEnding: "",
            chgEnding: false,
          },
          map: {},
          troop: { chars: {} },
          inventory: {},
          game: {
            theme: "rogue_6",
            mode: "NORMAL",
            modeGrade: 15,
            predefined: null,
            outer: { support: false },
            start: 1,
            equivalentGrade: 15,
          },
          buff: { tmpHP: 0, capsule: null, squadBuff: [] },
          record: { brief: null },
          module: {},
        },
        pinned: {},
      } as any,
      medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
      mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
    });
    return new PlayerDataManager(pd._playerdata);
  }

  it("giveUpGame 幂等：残留 GAME_SETTLE 清掉后再生成，pending 恒 1 个", async () => {
    const player = makeSettleStuckPlayer();
    const rlv2 = player.rlv2 as any;
    // 构造期 emit("rlv2:continue") 为异步微任务（Emittery）——等落定后再断言
    await Promise.resolve();
    await Promise.resolve();
    // 恢复后 pending 带残留 GAME_SETTLE；且"结算终态对齐"：PENDING 僵尸态被归一为 END
    // （否则客户端把该对局当进行中继续探索而冻结——存档2222 卡死根因）
    expect(rlv2._status.state).toBe("END");
    expect(rlv2._status.pending.map((e: any) => e.type)).toEqual(["GAME_SETTLE"]);

    await rlv2.giveUpGame();
    // 清残留后仅 1 个新 GAME_SETTLE（不重复）
    expect(rlv2._status.pending.map((e: any) => e.type)).toEqual(["GAME_SETTLE"]);

    // 连续调用依然幂等
    await rlv2.giveUpGame();
    expect(rlv2._status.pending.map((e: any) => e.type)).toEqual(["GAME_SETTLE"]);

    // gameSettle 后结算完成（同样清残留）
    await rlv2.gameSettle();
    expect(rlv2._status.state).toBe("END");
  });

  it("giveUpGame 应丢弃进行中遗留事件，pending 只留 1 个 GAME_SETTLE（防客户端状态机卡死）", async () => {
    const player = makeSettleStuckPlayer();
    const rlv2 = player.rlv2 as any;
    // 等构造期 emit("rlv2:continue") 微任务落定后再修改状态
    await Promise.resolve();
    await Promise.resolve();
    // 模拟"在地图中途放弃"：WAIT_MOVE 态 + pending 残留进行中事件（如 RECRUIT）
    rlv2._status.state = "WAIT_MOVE";
    (rlv2._status._pending._pending as any[]) = [
      { index: "e_0", type: "RECRUIT", content: { recruit: { ticket: "t1" } } },
    ];
    await rlv2.giveUpGame();
    // 官服 giveUpGame 后 pending 只有 1 个 GAME_SETTLE（清除进行中残留，避免与结算页冲突）
    expect(rlv2._status.pending.map((e: any) => e.type)).toEqual(["GAME_SETTLE"]);
  });

  it("module.continue() 按主题恢复模块管理器（重登继续探索不崩）", async () => {
    const player = makeSettleStuckPlayer();
    const rlv2 = player.rlv2 as any;
    // 构造期 emit("rlv2:continue") 为异步微任务（Emittery）——等落定后再断言
    await Promise.resolve();
    await Promise.resolve();
    // 构造期 hasRunning=true 走 continue：module 管理器应恢复 GRID_ZONE/WEATHER/SCRAP
    const modules = Object.keys(rlv2._module._modules);
    expect(modules.sort()).toEqual(["GRID_ZONE", "SCRAP", "WEATHER"]);
    // 存档无模块数据 → 空值兜底（不崩溃）
    expect(rlv2._module.gridZone).toBeTruthy();
    expect(rlv2._module.scrap).toBeTruthy();
    expect(rlv2._module.weather).toBeTruthy();
    expect(Object.keys(rlv2._module.gridZone.zones || {})).toHaveLength(0);
    expect(rlv2._module.scrap.limit).toBe(10);
  });

  it("giveUpGame 结算产物对齐官服：brief 带 seed/innerMissionProcessAddition、record.zones 为数组", async () => {
    const player = makeSettleStuckPlayer();
    const rlv2 = player.rlv2 as any;
    // 等构造期 emit("rlv2:continue") 微任务落定
    await Promise.resolve();
    await Promise.resolve();
    await rlv2.giveUpGame();
    const rec = (rlv2.current as any).record;
    expect(rec).toBeTruthy();
    // brief：官服恒定带 innerMissionProcessAddition(null) 与战报种子 seed
    expect(rec.brief.innerMissionProcessAddition).toBeNull();
    // seed 格式 "{随机18位base62},{theme},{modeGrade}"；同实例与 gameSettle 的 brief 一致
    expect(rec.brief.seed).toMatch(/^[A-Za-z0-9]{18},rogue_6,15$/);
    // record.zones：官服为区域数组 [{index,zoneId,variation}]，原实现误写成数字
    expect(Array.isArray(rec.record.zones)).toBe(true);
    // player.pending 中的 GAME_SETTLE.result.record 同步为数组
    const settle = rlv2._status.pending.find((e: any) => e.type === "GAME_SETTLE");
    expect(Array.isArray(settle.content.result.record.zones)).toBe(true);
    // detailStr：官服 giveUpGame/gameSettle 携带，格式 base64(zlib-deflate(JSON))
    expect(typeof settle.content.detailStr).toBe("string");
    const detail = JSON.parse(zlib.inflateSync(Buffer.from(settle.content.detailStr, "base64")).toString("utf8"));
    // 键结构与官服解压一致（brief/troopChars/initial/zones），brief 内联 valid seed
    expect(Object.keys(detail).sort()).toEqual(["brief", "initial", "troopChars", "zones"]);
    expect(detail.brief.seed).toMatch(/^[A-Za-z0-9]{18},rogue_6,15$/);
    expect(Array.isArray(detail.troopChars)).toBe(true);
    expect(Array.isArray(detail.zones)).toBe(true);
    expect(typeof detail.initial).toBe("object");
  });
});
