import { describe, it, expect, beforeEach, vi } from "vitest";
import { enablePatches } from "immer";

enablePatches();

vi.mock("@excel/excel", () => ({
  default: {
    RoguelikeTopicTable: {
      details: {
        rogue_3: {
          init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL", initRelic: {}, initRecruit: {} }],
          recruitTickets: {},
        },
      },
      modules: {
        rogue_3: { totemBuff: { totemBuffDatas: {} } },
      },
      consts: {},
    },
    CharacterTable: {},
  },
}));

import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { mockPlayerData } from "../../helpers";

function makePlayer() {
  const pd: any = mockPlayerData({
    rlv2: { outer: {}, current: {}, pinned: {} } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
  });
  return new PlayerDataManager(pd._playerdata);
}

/**
 * rlv2 引用同步回归测试
 *
 * RoguelikeV2Controller.update() 在 recipe 结束后统一刷新 outer/current/pinned 引用。
 * 若刷新缺失，recipe 克隆过的子树会让 this.current/this.outer 指向旧对象，
 * createGame/gameSettle 的直接写会落到孤儿对象（不持久化，重启丢失）。
 */
describe("rlv2 引用同步（wrapper 统一刷新）", () => {
  let player: PlayerDataManager;

  beforeEach(() => {
    player = makePlayer();
  });

  it("update() 克隆子树后 outer/current/pinned 与持久态同步", async () => {
    const rlv2 = player.rlv2 as any;
    const oldCurrent = rlv2.current;
    await rlv2.update(async (draft) => {
      draft.current.game = {
        mode: "NONE",
        predefined: "",
        theme: "",
        outer: { support: false },
        start: -1,
        modeGrade: 0,
        equivalentGrade: 0,
      };
    });
    expect(rlv2.current).toBe(player._playerdata.rlv2.current);
    expect(rlv2.current).not.toBe(oldCurrent);
    expect(rlv2.outer).toBe(player._playerdata.rlv2.outer);
    expect(rlv2.pinned).toBe(player._playerdata.rlv2.pinned);
  });

  it("setPinned 后 pinned 引用同步到持久态", async () => {
    const rlv2 = player.rlv2 as any;
    await rlv2.setPinned({ id: "relic_1" });
    expect(player._playerdata.rlv2.pinned).toBe("relic_1");
    expect(rlv2.pinned).toBe("relic_1");
  });

  it("giveUpGame 后再 createGame：直接写落在持久态（重启不丢失）", async () => {
    const rlv2 = player.rlv2 as any;
    // rlv2:create 的子管理器 create() 处理器需要完整 excel 配置（与本用例断言无关），stub 掉
    const originalEmit = player._trigger.emit.bind(player._trigger);
    vi.spyOn(player._trigger as any, "emit").mockImplementation(
      (event: any, ...args: any[]) => {
        if (event === "rlv2:create") return Promise.resolve();
        return originalEmit(event, ...args);
      },
    );

    await rlv2.giveUpGame();
    expect(rlv2.current).toBe(player._playerdata.rlv2.current);

    await rlv2.createGame({
      theme: "rogue_3",
      mode: "NORMAL",
      modeGrade: 0,
      predefinedId: null,
    });
    expect(rlv2.current.game!.theme).toBe("rogue_3");
    expect(player._playerdata.rlv2.current.game!.theme).toBe("rogue_3");
  });
});
