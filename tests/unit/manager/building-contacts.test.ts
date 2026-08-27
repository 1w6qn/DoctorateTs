import { describe, it, expect, vi, beforeEach } from "vitest";

/**
 * 人力办公室联络 + 会客室线索速度（批次⑤：2026-08-25 全量对齐）
 *
 * 覆盖（机制来自 prts.wiki 办公室页/会客室页）：
 * - hire-contacts.ts 纯函数：联络速度系数（12h/次、进度 +5%）结算
 * - clue-speed.ts 纯函数：氛围档 / 干员加成（稀有度/精英/非涣散）/ 总倍率
 * - _accrueHire：人脉库存充能（12h/次、上限 3、无人不恢复）
 * - _accrueMeeting：20h 阈值真实产线索、自有库满（10）停工
 * - recruit.refreshTags：消耗人脉库存（库存 0 拒绝；无人力办公室免消耗兜底）
 */

const excelMock = vi.hoisted(() => ({
  default: {
    BuildingData: {
      laborRecoverTime: 360,
      hireData: { phases: [{ economizeRate: 0, resSpeed: 100, refreshTimes: 3 }] },
      meetingData: { phases: [{ friendSlotInc: 10, maxVisitorNum: 10, gatheringSpeed: 100 }] },
      rooms: {
        HIRE: { phases: [{ buildCost: { items: [], time: 0, labor: 0 }, maxStationedNum: 1 }] },
        MEETING: { phases: [{ buildCost: { items: [], time: 0, labor: 0 }, maxStationedNum: 2 }] },
      },
    },
    GachaData: {},
    CharacterTable: {},
  },
}));
vi.mock("@excel/excel", () => excelMock);

const timeMock = vi.hoisted(() => ({ now: 1234567890 }));
vi.mock("@utils/time", () => ({ now: () => timeMock.now }));

vi.mock("@game/service/PlayerDataManager", () => ({
  PlayerDataManager: vi.fn(),
}));

import { mockPlayerData, mockTypedEventEmitter } from "../../helpers";
import {
  contactSpeedFactor,
  settleContactProgress,
  CONTACT_BASE_SECONDS,
} from "@game/domain/building/hire-contacts";
import {
  comfortClueBonus,
  charClueBonus,
  meetingSpeedMultiplier,
  MEETING_PHASE_EFFICIENCY,
} from "@game/domain/building/clue-speed";
import { BuildingManager } from "@game/domain/building/logic";
import { RecruitManager, RecruitTools } from "@game/service/player/recruit";

function makePlayer(building: any, extra: any = {}) {
  const mockPlayer = mockPlayerData({
    building,
    event: { building: 0 },
    pushFlags: { hasGifts: 0, hasFriendRequest: 0, hasClues: 0, hasFreeLevelGP: 0, status: 0 },
    ...extra,
  });
  const mockTrigger = mockTypedEventEmitter();
  mockPlayer._trigger = mockTrigger;
  mockPlayer.update = vi
    .fn()
    .mockImplementation(
      async (recipe: (draft: any) => Promise<any> | any) => {
        const draft = JSON.parse(JSON.stringify(mockPlayer._playerdata));
        const result = await recipe(draft);
        Object.assign(mockPlayer._playerdata, draft);
        return result;
      },
    );
  return { mockPlayer, mockTrigger };
}

function baseBuilding(): any {
  return {
    status: {
      labor: { buffSpeed: 0, processPoint: 0, value: 100, lastUpdateTime: 1000, maxValue: 225 },
      workshop: { bonusActive: 0, bonus: {} },
    },
    chars: {
      "1": { charId: "char_hire", ap: 8640000, lastApAddTime: 1000, roomSlotId: "slot_23", index: 0, changeScale: -65, bubble: {} },
    },
    roomSlots: {
      slot_23: { level: 1, state: 2, roomId: "HIRE", charInstIds: [1], completeConstructTime: -1 },
      slot_36: { level: 1, state: 2, roomId: "MEETING", charInstIds: [], completeConstructTime: -1 },
    },
    rooms: {
      CONTROL: {}, ELEVATOR: {}, POWER: {}, MANUFACTURE: {}, TRADING: {},
      CORRIDOR: {}, WORKSHOP: {}, DORMITORY: {},
      MEETING: {
        slot_36: {
          state: 1, speed: 100, processPoint: 0, lastUpdateTime: 1000,
          ownStock: [], receiveStock: [], board: {}, dailyReward: null,
        },
      },
      HIRE: { slot_23: { state: 1, speed: 100, processPoint: 0, lastUpdateTime: 1000 } },
      TRAINING: {}, PRIVATE: {},
    },
    furniture: {},
    diyPresetSolutions: {},
    assist: [-1, -1, -1],
    solution: { furnitureTs: {} },
    music: { inUse: false, selected: "bgm_default", state: {} },
  };
}

function draftOf(mockPlayer: any): any {
  return JSON.parse(JSON.stringify(mockPlayer._playerdata));
}

function setup() {
  const { mockPlayer, mockTrigger } = makePlayer(baseBuilding(), {
    status: { uid: "1", gold: 10000, androidDiamond: 100, socialPoint: 0, nickName: "A", nickNumber: "1" },
    inventory: {},
    troop: { chars: { "1": { charId: "char_hire", level: 10, evolvePhase: 0 } }, charGroup: {} },
  });
  const manager = new BuildingManager(mockPlayer as any, mockTrigger as any);
  return { mockPlayer, mockTrigger, manager };
}

  describe("hire-contacts.ts 纯函数（联络速度/进度结算）", () => {
  it("contactSpeedFactor：resSpeed/100 × (1 + 5% + 技能)", () => {
    expect(contactSpeedFactor(100, 0)).toBeCloseTo(1.05);
    expect(contactSpeedFactor(100, 0.2)).toBeCloseTo(1.25);
    expect(contactSpeedFactor(200, 0)).toBeCloseTo(2.1);
  });

  it("settleContactProgress：每满 12h 恢复 1 次，返回余数", () => {
    expect(settleContactProgress(0)).toEqual({ gained: 0, remainder: 0 });
    expect(settleContactProgress(CONTACT_BASE_SECONDS)).toEqual({ gained: 1, remainder: 0 });
    expect(settleContactProgress(CONTACT_BASE_SECONDS * 2 + 3600)).toEqual({
      gained: 2,
      remainder: 3600,
    });
    expect(settleContactProgress(-5)).toEqual({ gained: 0, remainder: 0 });
  });
});

describe("clue-speed.ts 纯函数（线索速度全公式）", () => {
  it("氛围档：≥2000/3000/4000 时 +5/10/15%", () => {
    expect(comfortClueBonus(1999)).toBe(0);
    expect(comfortClueBonus(2000)).toBeCloseTo(0.05);
    expect(comfortClueBonus(3000)).toBeCloseTo(0.1);
    expect(comfortClueBonus(4000)).toBeCloseTo(0.15);
  });

  it("干员加成：稀有度 + 精英阶段 + 非涣散 5%", () => {
    // 6星精2 非涣散 = 5% + 16% + 5%
    expect(charClueBonus({ rarityIndex: 5, evolvePhase: 2, dispersed: false })).toBeCloseTo(0.26);
    // 4星精0 非涣散 = 2% + 5%
    expect(charClueBonus({ rarityIndex: 3, evolvePhase: 0, dispersed: false })).toBeCloseTo(0.07);
    // 涣散 0；非涣散 +5%
    expect(charClueBonus({ rarityIndex: 0, evolvePhase: 0, dispersed: true })).toBe(0);
    // 3星及以下无稀有度加成
    expect(charClueBonus({ rarityIndex: 2, evolvePhase: 1, dispersed: false })).toBeCloseTo(0.13);
  });

  it("总倍率 = 相位效率 + 氛围档 + Σ干员 + meet 技能（加算）", () => {
    const mult = meetingSpeedMultiplier({
      roomLevel: 3,
      totalComfort: 4500,
      chars: [{ rarityIndex: 5, evolvePhase: 2, dispersed: false }],
      meetBonus: 0.2,
    });
    expect(mult).toBeCloseTo(1.11 + 0.15 + 0.26 + 0.2);
    expect(MEETING_PHASE_EFFICIENCY).toEqual([1.07, 1.09, 1.11]);
  });
});

describe("BuildingManager 人脉联络充能（_accrueHire）", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("进驻干员 12h 基准进度后 人脉库存 +1（速度系数 1.05）", () => {
    const { manager, mockPlayer } = setup();
    const draft = draftOf(mockPlayer);
    (manager as any)._accrueHire(draft, 1000); // 建立基准
    // 12h / 1.05 ≈ 41142.86s 实际时长后 基准进度恰满 12h
    (manager as any)._accrueHire(draft, 1000 + CONTACT_BASE_SECONDS / 1.05);
    const room = draft.building.rooms.HIRE.slot_23;
    expect(room.refreshStock).toBe(1);
    expect(room.contactSec).toBeLessThan(1);
  });

  it("人脉库存上限 3（达上限暂停累积）", () => {
    const { manager, mockPlayer } = setup();
    const draft = draftOf(mockPlayer);
    draft.building.rooms.HIRE.slot_23.refreshStock = 3;
    (manager as any)._accrueHire(draft, 1000);
    (manager as any)._accrueHire(draft, 1000 + CONTACT_BASE_SECONDS * 2);
    const room = draft.building.rooms.HIRE.slot_23;
    expect(room.refreshStock).toBe(3);
    expect(room.contactSec ?? 0).toBe(0);
  });

  it("无人进驻不恢复人脉（官方）", () => {
    const { manager, mockPlayer } = setup();
    const draft = draftOf(mockPlayer);
    draft.building.roomSlots.slot_23.charInstIds = [];
    (manager as any)._accrueHire(draft, 1000);
    (manager as any)._accrueHire(draft, 1000 + CONTACT_BASE_SECONDS * 2);
    expect(draft.building.rooms.HIRE.slot_23.refreshStock ?? 0).toBe(0);
  });
});

describe("BuildingManager 会客室线索产出（_accrueMeeting）", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("进度达 20h 基准阈值后 真实产出线索（长离线多份，余量保留）", () => {
    const { manager, mockPlayer } = setup();
    const draft = draftOf(mockPlayer);
    // 无进驻干员：mult = 相位 1.07 → speed 107；20h 实际时长 × 2.5 份进度
    (manager as any)._accrueMeeting(draft, 1000);
    (manager as any)._accrueMeeting(draft, 1000 + 72000 * 2.5);
    const room = draft.building.rooms.MEETING.slot_36;
    expect(room.ownStock).toHaveLength(2);
    expect(draft.pushFlags.hasClues).toBe(1);
    // 余量 = 2.5 份进度×7.2M - 2×7.2M ≈ 0.5 份（速度 107 时 elapsed×107 精确）
    expect(room.processPoint).toBe(72000 * 2.5 * 107 - 2 * 7200000);
  });

  it("自有库满（10）停工：进度不再累积", () => {
    const { manager, mockPlayer } = setup();
    const draft = draftOf(mockPlayer);
    draft.building.rooms.MEETING.slot_36.ownStock = Array.from({ length: 10 }, (_, i) => ({
      id: `1#${i}#0`, type: "RHINE", number: 1, uid: "1", name: "A", nickNum: "1",
      chars: [], inUse: 0, ts: 0,
    }));
    (manager as any)._accrueMeeting(draft, 1000);
    (manager as any)._accrueMeeting(draft, 1000 + 72000 * 3);
    const room = draft.building.rooms.MEETING.slot_36;
    expect(room.ownStock).toHaveLength(10); // 不新增
    expect(room.processPoint).toBe(0); // 不累积
  });
});

describe("RecruitManager 标签刷新消耗人脉（refreshTags）", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(RecruitTools, "refreshTagList").mockResolvedValue([1, 2, 3]);
  });

  function recruitSetup(building: any) {
    const { mockPlayer, mockTrigger } = makePlayer(building, {
      status: { uid: "1" },
      recruit: { normal: { slots: { "0": { tags: [] } } } },
    });
    const manager = new RecruitManager(mockPlayer as any, mockTrigger as any);
    return { mockPlayer, manager };
  }

  it("进驻人力办公室且库存 >0 时 消耗 1 次并刷新", async () => {
    const b = baseBuilding();
    b.rooms.HIRE.slot_23.refreshStock = 2;
    const { mockPlayer, manager } = recruitSetup(b);
    await manager.refreshTags({ slotId: 0 });
    expect(mockPlayer._playerdata.building.rooms.HIRE.slot_23.refreshStock).toBe(1);
    expect(mockPlayer._playerdata.recruit.normal.slots["0"].tags).toEqual([1, 2, 3]);
  });

  it("进驻但库存 0 时 拒绝刷新（人脉不足）", async () => {
    const b = baseBuilding();
    b.rooms.HIRE.slot_23.refreshStock = 0;
    const { mockPlayer, manager } = recruitSetup(b);
    await manager.refreshTags({ slotId: 0 });
    expect(mockPlayer._playerdata.recruit.normal.slots["0"].tags).toEqual([]);
  });

  it("无人进驻人力办公室时 私服兜底免消耗放行", async () => {
    const b = baseBuilding();
    b.roomSlots.slot_23.charInstIds = [];
    const { mockPlayer, manager } = recruitSetup(b);
    await manager.refreshTags({ slotId: 0 });
    expect(mockPlayer._playerdata.recruit.normal.slots["0"].tags).toEqual([1, 2, 3]);
  });
});
