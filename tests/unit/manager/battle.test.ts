import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@excel/excel", () => {
  return {
    default: {
      MissionTable: {
        missions: {},
        missionGroups: {},
        periodicalRewards: {},
        weeklyRewards: {},
        soCharMissionGroupInfo: {},
        dailyMissionGroupInfo: {},
        dailyMissionPeriodInfo: [],
        mainlineMissionEndImageDataList: [],
        crossAppShareMissions: {},
        crossAppShareMissionConst: {},
        guideMissionGroupInfo: {},
      },
      MedalTable: { medalList: [], medalTypeData: {} },
      StageTable: {
        stages: {
          "main_01-07": {
            stageId: "main_01-07",
            zoneId: "zone_01",
            apCost: 10,
            dangerLevel: "精英1",
            apFailReturn: 10,
            expGain: 200,
            goldGain: 300,
            stageType: "MAIN",
            stageDropInfo: { displayDetailRewards: [] },
            unlockCondition: [],
          },
        },
        runeStageGroups: {},
        mapThemes: {},
        tileInfo: {},
        forceOpenTable: {},
        timelyStageDropInfo: {},
        overrideDropInfo: {},
        overrideUnlockInfo: {},
        timelyTable: {},
        stageValidInfo: {},
        stageFogInfo: {},
        stageStartConds: {},
        diffGroupTable: {},
        storyStageShowGroup: {},
        specialBattleFinishStageData: {},
        recordRewardData: {},
        apProtectZoneInfo: {},
        antiSpoilerDict: {},
        actCustomStageDatas: {},
        spNormalStageIdFor4StarList: [],
        storylines: {},
        storylineStorySets: {},
        storylineTags: {},
        storylineConst: {},
        cgGalleryDisplays: {},
        cgGalleryGroups: {},
        cgGalleryCgs: {},
        sixStarRuneData: {},
        sixStarMilestoneInfo: {},
      },
      GachaTable: {},
      GameDataConst: {},
      CharacterTable: {},
      ItemTable: { 
        items: {
          "mat_001": { itemType: "MATERIAL", rarity: 1 },
        }, 
        expItems: {} 
      },
      ShopClientTable: {},
      SkillDataBundle: {},
    },
  };
});

vi.mock("@game/manager/PlayerDataManager", () => ({
  PlayerDataManager: vi.fn(),
}));

vi.mock("@utils/time", () => ({
  now: () => Math.floor(Date.now() / 1000),
  checkBetween: (ts: number, start: number, end: number) =>
    ts >= start && ts <= end,
}));

vi.mock("@excel/character_table", () => ({ ItemBundle: {} }));
vi.mock("@excel/stage_table", () => ({
  DisplayDetailRewards: {},
  ConditionDesc: {},
}));

vi.mock("@utils/crypt", () => ({
  decryptBattleData: vi.fn().mockResolvedValue({
    battleId: "1",
    battleData: {
      stats: { enemyList: {}, autoReplayCancelled: false },
    },
    completeState: 3,
  }),
}));

vi.mock("@game/manager/AccountManager", () => {
  const mockAccountConfigs: any = {
    "10000": {
      battle: {
        infos: {
          "1": {
            stageId: "main_01-07",
            isPractice: false,
          },
        },
        replays: {
          "main_01-07": "replay_data",
        },
      },
    },
  };

  return {
    accountManager: {
      configs: mockAccountConfigs,
      saveBattleInfo: vi.fn().mockImplementation(async (uid: string, battleId: string, info: any) => {
        if (!mockAccountConfigs[uid]) {
          mockAccountConfigs[uid] = { battle: { infos: {}, replays: {} } };
        }
        mockAccountConfigs[uid].battle.infos[battleId] = info;
      }),
      getBattleInfo: vi.fn().mockImplementation(async (uid: string, battleId: string) => {
        return mockAccountConfigs[uid]?.battle?.infos?.[battleId];
      }),
      getBattleReplay: vi.fn().mockImplementation(async (uid: string, stageId: string) => {
        return mockAccountConfigs[uid]?.battle?.replays?.[stageId] || "";
      }),
      saveBattleReplay: vi.fn().mockImplementation(async (uid: string, stageId: string, replay: string) => {
        if (!mockAccountConfigs[uid]) {
          mockAccountConfigs[uid] = { battle: { infos: {}, replays: {} } };
        }
        mockAccountConfigs[uid].battle.replays[stageId] = replay;
      }),
    },
  };
});

import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import { BattleManager } from "@game/manager/battle";

describe("BattleManager", () => {
  let mockPlayer: ReturnType<typeof mockPlayerData>;
  let mockTrigger: ReturnType<typeof mockTypedEventEmitter>;
  let mockExcelRef: any;

  beforeEach(async () => {
    vi.restoreAllMocks();
    mockTrigger = mockTypedEventEmitter();
    mockExcelRef = (vi.mocked(await import("@excel/excel")).default as any);

    mockPlayer = mockPlayerData({
      dungeon: {
        stages: {
          "main_01-07": {
            stageId: "main_01-07",
            state: 0,
            completeTimes: 0,
            startTimes: 0,
            practiceTimes: 0,
            hasBattleReplay: 0,
            noCostCnt: 0,
          },
        },
      },
      troop: {
        chars: {
          1001: {
            level: 50,
            evolvePhase: 1,
          },
        },
      },
      dexNav: { enemy: { stage: {} }, character: {} },
      recruit: { normal: { slots: [{ state: 0 }, { state: 0 }] } },
      status: { 
        mainStageProgress: "",
        uid: "10000",
        gold: 9999,
        ap: 100,
        maxAp: 100,
      },
      pushFlags: {
        status: {},
      },
      skin: {
        characterSkins: {},
        skinTs: {},
      },
      building: {
        furniture: {},
        solution: { furnitureTs: {} },
      },
      avatar: { avatar_icon: {} },
      nameCardStyle: {
        skin: {
          state: {},
        },
      },
      inventory: {},
      consumable: {},
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
    it("应该正确初始化 BattleManager 实例", () => {
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );
      expect(manager).toBeDefined();
      expect(manager._player).toBe(mockPlayer);
      expect(manager._trigger).toBe(mockTrigger);
    });

    it("应该注册 battle:start 和 battle:finish 事件监听", () => {
      const onSpy = vi.spyOn(mockTrigger, "on");
      new BattleManager(mockPlayer as any, mockTrigger as any);
      expect(onSpy).toHaveBeenCalledWith(
        "battle:start",
        expect.any(Function)
      );
      expect(onSpy).toHaveBeenCalledWith(
        "battle:finish",
        expect.any(Function)
      );
    });
  });

  describe("start", () => {
    it("应该成功开始战斗并返回正确结构", async () => {
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const squad = {
        slots: [
          { charInstId: 1001 },
          null,
        ],
      };

      const result = await manager.start({
        stageId: "main_01-07",
        usePracticeTicket: false,
        squad,
      } as any);

      expect(result).toBeDefined();
      expect(result.battleId).toBeDefined();
      expect(result.result).toBe(0);
      expect(result.apFailReturn).toBeDefined();
    });

    it("当使用练习券时应该设置 isApProtect 为 0", async () => {
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const squad = { slots: [null, null] };

      const result = await manager.start({
        stageId: "main_01-07",
        usePracticeTicket: true,
        squad,
      } as any);

      expect(result.isApProtect).toBe(0);
    });

    it("当关卡首次进入时应该初始化关卡数据", async () => {
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );

      mockPlayer._playerdata.dungeon!.stages = {
        "main_01-07": {
          stageId: "main_01-07",
          state: 0,
          completeTimes: 0,
          startTimes: 0,
          practiceTimes: 0,
          hasBattleReplay: 0,
          noCostCnt: 0,
        },
      };

      const squad = { slots: [null, null] };

      await manager.start({
        stageId: "main_01-07",
        usePracticeTicket: false,
        squad,
      } as any);

      expect(
        mockPlayer._playerdata.dungeon!.stages["main_01-07"]
      ).toBeDefined();
    });

    it("两次 start 应生成不同的 battleId", async () => {
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const squad = { slots: [null, null] };
      const r1 = await manager.start({
        stageId: "main_01-07",
        usePracticeTicket: false,
        squad,
      } as any);
      const r2 = await manager.start({
        stageId: "main_01-07",
        usePracticeTicket: false,
        squad,
      } as any);

      expect(r1.battleId).toBeDefined();
      expect(r1.battleId).not.toBe(r2.battleId);
    });
  });

  describe("finish", () => {
    it("应该完成战斗并触发 items:get 事件", async () => {
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      const result = await manager.finish({
        data: "encrypted_battle_data",
        battleData: { isCheat: "0", completeTime: 100 },
      } as any);

      expect(result).toBeDefined();
      expect(emitSpy).toHaveBeenCalledWith(
        "items:get",
        expect.any(Array)
      );
    });

    it("completeState 为 3 时应该设置 goldScale 和 expScale 为 1.2", async () => {
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const result = await manager.finish({
        data: "encrypted_battle_data",
        battleData: { isCheat: "0", completeTime: 100 },
      } as any);

      expect(result.goldScale).toBe(1.2);
      expect(result.expScale).toBe(1.2);
    });

    it("应该触发 CompleteStageAnyType 和 CompleteStage 事件", async () => {
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      await manager.finish({
        data: "encrypted_battle_data",
        battleData: { isCheat: "0", completeTime: 100 },
      } as any);

      expect(emitSpy).toHaveBeenCalledWith(
        "CompleteStageAnyType",
        expect.any(Object)
      );
      expect(emitSpy).toHaveBeenCalledWith(
        "CompleteStage",
        expect.any(Object)
      );
    });

    it("finish 用 battleStart 快照的 loginTime 解密（而非当前 pushFlags.status）", async () => {
      // 模拟：battleStart 时 pushFlags.status=锚点A；随后 syncData 把它推进为锚点B。
      // finish 必须用锚点A（客户端实际加密用值）解密，避免 key 漂移 bad decrypt。
      (mockPlayer._playerdata.pushFlags as any).status = "anchorA";
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );
      const squad = { slots: [{ charInstId: 1001 }, null] };

      const started = await manager.start({
        stageId: "main_01-07",
        usePracticeTicket: false,
        squad,
      } as any);

      // battleStart 后 syncData 推进锚点
      (mockPlayer._playerdata.pushFlags as any).status = "anchorB";

      const crypt = await import("@utils/crypt");
      vi.mocked(crypt.decryptBattleData).mockResolvedValue({
        battleId: started.battleId,
        battleData: { stats: { enemyList: {}, autoReplayCancelled: false } },
        completeState: 3,
      } as any);

      await manager.finish({
        data: "encrypted_battle_data",
        battleData: { isCheat: "0", completeTime: 100 },
      } as any);

      // 解密必须用 battleStart 快照的锚点A，而非推进后的 anchorB
      expect(crypt.decryptBattleData).toHaveBeenCalledWith(
        "encrypted_battle_data",
        "anchorA",
      );
    });
  });

  describe("loadReplay", () => {
    it("应该加载战斗回放数据", async () => {
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const result = await manager.loadReplay({
        stageId: "main_01-07",
      });

      expect(result).toBe("replay_data");
    });
  });

  describe("saveReplay", () => {
    it("应该保存战斗回放数据", async () => {
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const result = await manager.saveReplay({
        battleId: "1",
        battleReplay: "new_replay_data",
      });

      expect(result).toBeUndefined();
    });
  });

  describe("dropReward", () => {
    it("应该返回正确结构的奖励数组", async () => {
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const rewards = [
        {
          occPercent: 0,
          dropType: 0,
          id: "mat_001",
          type: "MATERIAL",
        },
      ];

      const result = await manager.dropReward(
        rewards as any,
        3,
        "main_01-07"
      );

      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(4);
    });

    it("持续零产出时不应无限递归（防栈溢出）", async () => {
      const randomUtils = await import("@utils/random");
      // 所有概率掉落都不命中 → 每轮零产出 → 触发重试路径
      vi.spyOn(randomUtils, "randomChoices").mockReturnValue([0] as any);
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const result = await manager.dropReward(
        [
          { occPercent: 4, dropType: 2, id: "mat_001", type: "MATERIAL" },
        ] as any,
        3,
        "main_01-07"
      );

      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(4);
    });

    it("ALWAYS+NORMAL 必掉材料应产出到 rewards", async () => {
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const result = await manager.dropReward(
        [
          { occPercent: 0, dropType: 2, id: "mat_001", type: "MATERIAL" },
        ] as any,
        3,
        "main_01-07"
      );

      // result[3] = rewards
      expect(result[3].some((r: any) => r.id === "mat_001")).toBe(true);
    });
  });

  describe("finishStoryStage", () => {
    it("应该完成关卡并解锁后续关卡", async () => {
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );

      mockExcelRef.StageTable.stages["main_01-08"] = {
        stageId: "main_01-08",
        // 真实数据 unlockCondition[].completeState 为字符串枚举（"PASS"/"COMPLETE"）
        unlockCondition: [{ stageId: "main_01-07", completeState: "COMPLETE" }],
      };

      const emitSpy = vi.spyOn(mockTrigger, "emit");
      const result = await manager.finishStoryStage({
        stageId: "main_01-07",
      });

      expect(result).toBeDefined();
      expect(result.unlockStages).toBeDefined();
      expect(emitSpy).toHaveBeenCalledWith(
        "items:get",
        expect.any(Array)
      );
    });

    it("stages 含 null 伪键时 finishStoryStage / finish 不应 500", async () => {
      // 数据表末尾字段名伪键（值 null）——修复前 unlock 循环遍历到 null →
      // stage.unlockCondition 崩溃（2026-08-14 数据更新后所有生成表均带该伪键）
      mockExcelRef.StageTable.stages["stageType"] = null;
      mockExcelRef.StageTable.stages["unlockCondition"] = null;
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await expect(
        manager.finishStoryStage({ stageId: "main_01-07" }),
      ).resolves.not.toThrow();

      // finish 胜利路径（state=1 触发解锁扫描）
      mockPlayer._playerdata.dungeon!.stages["main_01-07"].state = 1;
      await expect(
        manager.finish({
          data: "encrypted_battle_data",
          battleData: { isCheat: "0", completeTime: 100 },
        } as any),
      ).resolves.not.toThrow();
    });
  });

  describe("finish 后处理", () => {
    beforeEach(() => {
      mockExcelRef.StageTable.stages["main_01-07"].stageDropInfo.displayDetailRewards =
        [];
      delete mockExcelRef.StageTable.stages["main_01-08"];
    });

    it("胜利时应返回真实结算清单并累加 completeTimes", async () => {
      mockExcelRef.StageTable.stages[
        "main_01-07"
      ].stageDropInfo.displayDetailRewards = [
        { occPercent: 0, dropType: 3, id: "mat_001", type: "MATERIAL" },
      ];
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const result = await manager.finish({
        data: "encrypted_battle_data",
        battleData: { isCheat: "0", completeTime: 100 },
      } as any);

      expect(result.rewards).toBeDefined();
      expect(result.unusualRewards).toBeDefined();
      expect(result.additionalRewards).toBeDefined();
      expect(result.furnitureRewards).toBeDefined();
      expect(result.firstRewards).toBeDefined();
      expect(result.unlockStages).toBeDefined();
      expect(
        mockPlayer._playerdata.dungeon!.stages["main_01-07"].completeTimes
      ).toBe(1);
    });

    it("首次通关（state=0 → completeState=3）应返回 firstRewards", async () => {
      mockExcelRef.StageTable.stages[
        "main_01-07"
      ].stageDropInfo.displayDetailRewards = [
        { occPercent: 0, dropType: 1, id: "mat_001", type: "MATERIAL" },
      ];
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const result = await manager.finish({
        data: "encrypted_battle_data",
        battleData: { isCheat: "0", completeTime: 100 },
      } as any);

      expect(result.firstRewards.length).toBeGreaterThan(0);
    });

    it("胜利时应返回解锁关卡列表", async () => {
      mockPlayer._playerdata.dungeon!.stages["main_01-07"].state = 1;
      mockExcelRef.StageTable.stages["main_01-08"] = {
        stageId: "main_01-08",
        stageType: "MAIN",
        // 真实数据 unlockCondition[].completeState 为字符串枚举（"PASS"/"COMPLETE"）
        unlockCondition: [{ stageId: "main_01-07", completeState: "COMPLETE" }],
      };
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );

      const result = await manager.finish({
        data: "encrypted_battle_data",
        battleData: { isCheat: "0", completeTime: 100 },
      } as any);

      expect(result.unlockStages).toContain("main_01-08");
    });

    it("胜利时不应覆盖已解锁/已通关的后续关卡（in Object.keys 数组 bug 修复）", async () => {
      // 场景：main_01-08 已解锁且已通关（state=3, completeTimes=5），再通关
      // main_01-07（state=1）触发全表解锁扫描——修复前
      // `item in Object.keys(draft.dungeon.stages)` 对数组用 in 恒 false →
      // main_01-08 被整体覆盖为 state:0/completeTimes:0（重新变锁定、通关次数清零）
      mockPlayer._playerdata.dungeon!.stages["main_01-07"].state = 1;
      mockPlayer._playerdata.dungeon!.stages["main_01-08"] = {
        stageId: "main_01-08",
        state: 3,
        completeTimes: 5,
        startTimes: 2,
        practiceTimes: 0,
        hasBattleReplay: 0,
        noCostCnt: 0,
      };
      mockExcelRef.StageTable.stages["main_01-08"] = {
        stageId: "main_01-08",
        stageType: "MAIN",
        unlockCondition: [{ stageId: "main_01-07", completeState: "COMPLETE" }],
      };
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );

      await manager.finish({
        data: "encrypted_battle_data",
        battleData: { isCheat: "0", completeTime: 100 },
      } as any);

      const kept = mockPlayer._playerdata.dungeon!.stages["main_01-08"];
      expect(kept.state).toBe(3);
      expect(kept.completeTimes).toBe(5);
      expect(kept.startTimes).toBe(2);
    });

    it("胜利时应给出战干员增加信赖", async () => {
      (mockPlayer._playerdata.troop!.chars as any)["1001"].favorPoint = 0;
      const manager = new BattleManager(
        mockPlayer as any,
        mockTrigger as any
      );
      const squad = { slots: [{ charInstId: 1001 }, null] };

      const started = await manager.start({
        stageId: "main_01-07",
        usePracticeTicket: false,
        squad,
      } as any);
      // 让 finish 使用 start 生成的 battleId 查找 battleInfo（含 squad）
      const crypt = await import("@utils/crypt");
      vi.mocked(crypt.decryptBattleData).mockResolvedValue({
        battleId: started.battleId,
        battleData: {
          stats: { enemyList: {}, autoReplayCancelled: false },
        },
        completeState: 3,
      } as any);
      await manager.finish({
        data: "encrypted_battle_data",
        battleData: { isCheat: "0", completeTime: 100 },
      } as any);

      expect(
        (mockPlayer._playerdata.troop!.chars as any)["1001"].favorPoint
      ).toBe(1);
    });
  });

  describe("start 保存助战好友信息", () => {
    async function lastSavedBattleInfo() {
      const { accountManager } = await import("@game/manager/AccountManager");
      const calls = vi.mocked(accountManager.saveBattleInfo).mock.calls;
      return calls[calls.length - 1][2];
    }

    it("应保存 assistFriend 到 battleInfo", async () => {
      const manager = new BattleManager(mockPlayer as any, mockTrigger as any);
      const assistFriend = {
        uid: "2",
        nickName: "好友",
        assistChar: [{ charId: "char_002", level: 50 }],
        assistSlotIndex: 1,
      };
      await manager.start({
        stageId: "main_01-07",
        usePracticeTicket: false,
        squad: { slots: [] },
        assistFriend,
      } as any);
      expect((await lastSavedBattleInfo()).assistFriend).toEqual(assistFriend);
    });

    it("无助战时不保存 assistFriend", async () => {
      const manager = new BattleManager(mockPlayer as any, mockTrigger as any);
      await manager.start({
        stageId: "main_01-07",
        usePracticeTicket: false,
        squad: { slots: [] },
        assistFriend: null,
      } as any);
      expect((await lastSavedBattleInfo()).assistFriend).toBeUndefined();
    });
  });

  describe("未知关卡守卫（2026-08-09 修复）", () => {
    it("battleStart 未知关卡应返回最小 battleId 而非 500", async () => {
      const manager = new BattleManager(mockPlayer as any, mockTrigger as any);
      const result = await manager.start({
        stageId: "act1arkhub_01",
        usePracticeTicket: false,
        squad: { slots: [] },
      } as any);
      expect(result).toBeDefined();
      expect(result.result).toBe(0);
      expect(result.battleId).toBeDefined();
      expect(result.apFailReturn).toBe(0);
    });
  });
});
