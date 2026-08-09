import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@excel/excel", () => {
  return {
    default: {},
  };
});

vi.mock("@game/manager/PlayerDataManager", () => ({
  PlayerDataManager: vi.fn(),
}));

vi.mock("@utils/time", () => ({
  now: () => 1234567890,
}));

vi.mock("@excel/character_table", () => ({ ItemBundle: {} }));
vi.mock("@excel/types_auto_gen", () => ({}));

// Mock lodash:maxBy 返回固定值,便于断言 createPreset 的 instId 取值
vi.mock("lodash", () => ({
  maxBy: () => "3",
}));

// Mock immer:original 在源码中导入但未实际使用,提供空实现避免运行时错误
vi.mock("immer", () => ({
  original: (x: any) => x,
}));

import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import {
  CharRotationManager,
  CharRotationUpdatePresetRequest,
} from "@game/manager/charRotation";

/**
 * CharRotationManager 单元测试
 * 覆盖预设的增删改查与当前界面配置切换
 */
describe("CharRotationManager", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;

  beforeEach(() => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();

    mockPlayer = mockPlayerData({
      charRotation: {
        current: "1",
        preset: {
          "1": {
            name: "预设1",
            background: "bg_rhodes_day",
            homeTheme: "tm_rhodes_day",
            profile: "char_002_amiya#1",
            profileInst: 1001,
            slots: [
              { charId: "char_002_amiya", skinId: "char_002_amiya#1", skinSp: false },
            ],
          },
        },
      },
      background: {
        selected: "bg_default",
        bgs: {},
      },
      homeTheme: {
        selected: "tm_default",
        themes: {},
      },
      status: {
        nickName: "TestUser",
        nickNumber: "0",
        level: 1,
        exp: 0,
        socialPoint: 0,
        gachaTicket: 0,
        tenGachaTicket: 0,
        instantFinishTicket: 0,
        hggShard: 0,
        lggShard: 0,
        recruitLicense: 0,
        progress: 0,
        buyApRemainTimes: 0,
        apLimitUpFlag: 0,
        uid: "10000",
        flags: {},
        ap: 100,
        maxAp: 100,
        androidDiamond: 0,
        iosDiamond: 0,
        diamondShard: 0,
        gold: 9999,
        practiceTicket: 0,
        lastRefreshTs: 0,
        lastApAddTime: 0,
        mainStageProgress: null,
        registerTs: 0,
        lastOnlineTs: 0,
        serverName: "TestServer",
        avatarId: "",
        resume: "",
        birthday: { month: 1, day: 1 },
        friendNumLimit: 50,
        monthlySubscriptionStartTime: 0,
        monthlySubscriptionEndTime: 0,
        secretary: "",
        secretarySkinId: "",
        tipMonthlyCardExpireTs: 0,
        avatar: { type: "ICON", id: "avatar_001" },
        globalVoiceLan: "CN_MANDARIN",
        classicShard: 0,
        classicGachaTicket: 0,
        classicTenGachaTicket: 0,
      } as any,
      troop: {
        curCharInstId: 1001,
        curSquadCount: 1,
        squads: {},
        chars: {
          1001: {
            instId: 1001,
            charId: "char_002_amiya",
            favorPoint: 0,
            potentialRank: 0,
            mainSkillLvl: 1,
            skin: "char_002_amiya#1",
            level: 1,
            exp: 0,
            evolvePhase: 0,
            defaultSkillIndex: -1,
            gainTime: 1234567890,
            skills: [],
            currentEquip: null,
            equip: {},
            voiceLan: "CN_MANDARIN",
          },
        },
        addon: {},
        charGroup: {},
        charMission: {},
      },
    });

    mockPlayer._trigger = mockTrigger;
    mockPlayer.update = vi
      .fn()
      .mockImplementation(
        async (recipe: (draft: any) => Promise<any> | any) => {
          const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
          const result = await recipe(draft);
          Object.assign(mockPlayer._playerdata, draft);
          return result;
        }
      );
  });

  describe("constructor", () => {
    it("应该正确初始化 CharRotationManager 实例", () => {
      const manager = new CharRotationManager(
        mockPlayer as any,
        mockTrigger as any
      );
      expect(manager).toBeDefined();
      expect(manager._player).toBe(mockPlayer);
      expect(manager._trigger).toBe(mockTrigger);
    });
  });

  describe("setCurrent", () => {
    it("应该切换当前预设并同步背景、主题与秘书配置", async () => {
      const manager = new CharRotationManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.setCurrent({ instId: "1" });

      expect(mockPlayer._playerdata.charRotation!.current).toBe("1");
      expect(mockPlayer._playerdata.background!.selected).toBe("bg_rhodes_day");
      expect(mockPlayer._playerdata.homeTheme!.selected).toBe("tm_rhodes_day");
      expect(mockPlayer._playerdata.status!.secretarySkinId).toBe(
        "char_002_amiya#1"
      );
      expect(mockPlayer._playerdata.status!.secretary).toBe("char_002_amiya");
    });
  });

    it("profileInst 指向不存在干员时应回退 profile 字符串而非 500", async () => {
      const manager = new CharRotationManager(
        mockPlayer as any,
        mockTrigger as any
      );
      // preset 1 的 profileInst=1 在 mock 中不存在（mock chars 键为 1001）→ 回退 profile
      mockPlayer._playerdata.charRotation!.preset["1"] = {
        name: "test",
        background: "bg_rhodes_day",
        homeTheme: "tm_rhodes_day",
        profile: "char_1012_skadi2#1",
        profileInst: 1,
        slots: [],
      };
      await expect(
        manager.setCurrent({ instId: "1" }),
      ).resolves.not.toThrow();
      expect(mockPlayer._playerdata.status!.secretary).toBe("char_1012_skadi2");
    });

    it("未知预设 instId 不应抛错（不再 500）", async () => {
      const manager = new CharRotationManager(
        mockPlayer as any,
        mockTrigger as any
      );
      await expect(
        manager.setCurrent({ instId: "999" }),
      ).resolves.not.toThrow();
    });

  describe("createPreset", () => {
    it("应该创建新预设并返回 instId", async () => {
      const manager = new CharRotationManager(
        mockPlayer as any,
        mockTrigger as any
      );

      // mock maxBy 返回 "3",新预设将以 "3" 为 key
      const result = await manager.createPreset();

      expect(result).toBe("3");
      const preset = mockPlayer._playerdata.charRotation!.preset["3"];
      expect(preset).toBeDefined();
      expect(preset.name).toBe("未命名界面配置");
      expect(preset.background).toBe("bg_rhodes_day");
      expect(preset.homeTheme).toBe("tm_rhodes_day");
      expect(preset.profile).toBe("char_002_amiya#1");
      expect(preset.profileInst).toBe(1);
      expect(preset.slots).toEqual([
        { charId: "char_002_amiya", skinId: "char_002_amiya#1", skinSp: false },
      ]);
    });
  });

  describe("updatePreset", () => {
    it("应该根据传入 data 更新预设字段并同步当前选中状态", async () => {
      const manager = new CharRotationManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const req: CharRotationUpdatePresetRequest = {
        instId: "1",
        flag: 0,
        data: {
          name: "更新后的预设",
          background: "bg_new",
          homeTheme: "tm_new",
          secretarySkinId: "char_002_amiya#2",
          secretaryCharInstId: "1001",
          slots: [
            { charId: "char_002_amiya", skinId: "char_002_amiya#2" },
          ],
        },
      };
      await manager.updatePreset(req);

      const preset = mockPlayer._playerdata.charRotation!.preset["1"];
      expect(preset.name).toBe("更新后的预设");
      expect(preset.background).toBe("bg_new");
      expect(preset.homeTheme).toBe("tm_new");
      expect(preset.profile).toBe("char_002_amiya#2");
      expect(preset.profileInst).toBe(1001);
      expect(preset.slots).toEqual([
        { charId: "char_002_amiya", skinId: "char_002_amiya#2" },
      ]);
      // 同步当前选中状态
      expect(mockPlayer._playerdata.background!.selected).toBe("bg_new");
      expect(mockPlayer._playerdata.homeTheme!.selected).toBe("tm_new");
      expect(mockPlayer._playerdata.status!.secretarySkinId).toBe(
        "char_002_amiya#2"
      );
      expect(mockPlayer._playerdata.status!.secretary).toBe("char_002_amiya");
    });

    it("当 data 仅含部分字段时应该只更新对应字段", async () => {
      const manager = new CharRotationManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const originalPreset = JSON.parse(
        JSON.stringify(mockPlayer._playerdata.charRotation!.preset["1"])
      );

      await manager.updatePreset({
        instId: "1",
        flag: 0,
        data: {
          name: "仅改名",
        },
      });

      const preset = mockPlayer._playerdata.charRotation!.preset["1"];
      expect(preset.name).toBe("仅改名");
      // 其他字段保持不变
      expect(preset.background).toBe(originalPreset.background);
      expect(preset.homeTheme).toBe(originalPreset.homeTheme);
      expect(preset.profile).toBe(originalPreset.profile);
    });
  });

  describe("deletePreset", () => {
    it("应该删除指定 instId 的预设", async () => {
      const manager = new CharRotationManager(
        mockPlayer as any,
        mockTrigger as any
      );

      // 先添加第二个预设,确保删除后仍有预设存在
      mockPlayer._playerdata.charRotation!.preset["2"] = {
        name: "预设2",
        background: "bg_2",
        homeTheme: "tm_2",
        profile: "p2",
        profileInst: 2,
        slots: [],
      };

      await manager.deletePreset({ instId: "1" });

      expect(
        mockPlayer._playerdata.charRotation!.preset["1"]
      ).toBeUndefined();
      expect(
        mockPlayer._playerdata.charRotation!.preset["2"]
      ).toBeDefined();
    });
  });
});
