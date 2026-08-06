import { describe, it, expect, vi, beforeEach } from "vitest";
import { enablePatches } from "immer";

enablePatches();

// 官方 excel mock：rogue_1/2/4/6 的 choices 含 startbuff 选项
vi.mock("@excel/excel", () => {
  const startbuffChoices = (prefix: string, n: number) => {
    const c: any = {};
    for (let i = 1; i <= n; i++) c[`${prefix}${i}`] = { id: `${prefix}${i}`, type: "TRADE" };
    return c;
  };
  return {
    default: {
      RoguelikeTopicTable: {
        details: {
          rogue_1: {
            init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
            choices: { ...startbuffChoices("choice_startbuff_", 6) },
          },
          rogue_2: {
            init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
            choices: { ...startbuffChoices("choice_ro2_startbuff_", 8) },
          },
          rogue_4: {
            init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
            choices: { ...startbuffChoices("choice_ro4_startbuff_", 7) },
          },
          rogue_6: {
            init: [{ modeGrade: 0, predefinedId: null, modeId: "NORMAL" }],
            choices: { ...startbuffChoices("choice_ro6_startbuff_", 12) },
          },
        },
        modules: {},
        consts: {},
      },
      CharacterTable: {},
      RoguelikeConsts: {},
    },
  };
});

import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { mockPlayerData } from "../../helpers";
import { RoguelikePendingEvent } from "@game/controller/rlv2/events";

function makePlayer(theme: string) {
  const pd: any = mockPlayerData({
    rlv2: { outer: {}, current: {}, pinned: {} } as any,
    medal: { medals: {}, custom: { currentIndex: "0", customs: {} } } as any,
    mission: { missions: { DAILY: {}, ACTIVITY: {} }, missionRewards: { dailyPoint: 0, weeklyPoint: 0, rewards: {} } } as any,
  });
  const player = new PlayerDataManager(pd._playerdata);
  player.rlv2.current.game = { theme, mode: "NORMAL", modeGrade: 0, predefined: null } as any;
  return player;
}

describe("rlv2 开局 buff 选择数据", () => {
  describe("choices.json 数据文件", () => {
    it("应覆盖 6 主题 startbuff 场景", () => {
      const data = require("../../../data/rlv2/choices.json");
      const scenes = data.choiceScenes;
      expect(scenes["scene_startbuff_enter"]).toBeDefined();
      expect(scenes["scene_ro2_startbuff_enter"]).toBeDefined();
      expect(scenes["scene_ro3_startbuff_enter"]).toBeDefined();
      expect(scenes["scene_ro4_startbuff_enter"]).toBeDefined();
      expect(scenes["scene_ro5_startbuff_enter"]).toBeDefined();
      expect(scenes["scene_ro6_startbuff_enter"]).toBeDefined();
    });

    it("各主题选项数量正确", () => {
      const data = require("../../../data/rlv2/choices.json");
      expect(data.choiceScenes["scene_startbuff_enter"].choices).toHaveLength(6);
      expect(data.choiceScenes["scene_ro2_startbuff_enter"].choices).toHaveLength(8);
      expect(data.choiceScenes["scene_ro6_startbuff_enter"].choices).toHaveLength(12);
    });
  });

  describe("GAME_INIT_SUPPORT 按主题动态化", () => {
    it("rogue_1 应生成无 ro 前缀场景与选项", () => {
      const player = makePlayer("rogue_1");
      const ev = new RoguelikePendingEvent(
        player.rlv2 as any,
        (player.rlv2 as any)._trigger,
        "GAME_INIT_SUPPORT",
        0,
        { step: [2, 3], id: "" },
      );
      const scene = ev.content.initSupport!.scene;
      expect(scene.id).toBe("scene_startbuff_enter");
      expect(Object.keys(scene.choices).sort()).toEqual([
        "choice_startbuff_1", "choice_startbuff_2", "choice_startbuff_3",
        "choice_startbuff_4", "choice_startbuff_5", "choice_startbuff_6",
      ]);
    });

    it("rogue_4 应生成 choice_ro4_startbuff_1..7", () => {
      const player = makePlayer("rogue_4");
      const ev = new RoguelikePendingEvent(
        player.rlv2 as any,
        (player.rlv2 as any)._trigger,
        "GAME_INIT_SUPPORT",
        0,
        { step: [2, 3], id: "" },
      );
      const scene = ev.content.initSupport!.scene;
      expect(scene.id).toBe("scene_ro4_startbuff_enter");
      expect(Object.keys(scene.choices)).toHaveLength(7);
      expect(scene.choices["choice_ro4_startbuff_1"]).toBe(1);
      expect(scene.choices["choice_ro4_startbuff_7"]).toBe(1);
    });

    it("rogue_6 应生成 12 个选项", () => {
      const player = makePlayer("rogue_6");
      const ev = new RoguelikePendingEvent(
        player.rlv2 as any,
        (player.rlv2 as any)._trigger,
        "GAME_INIT_SUPPORT",
        0,
        { step: [2, 3], id: "" },
      );
      const scene = ev.content.initSupport!.scene;
      expect(scene.id).toBe("scene_ro6_startbuff_enter");
      expect(Object.keys(scene.choices)).toHaveLength(12);
    });
  });
});
