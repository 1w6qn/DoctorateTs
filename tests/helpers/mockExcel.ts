import type {
  MissionTable,
  MedalData,
  StageTable,
  GachaData,
  GameDataConsts,
  CharacterData,
  ShopClientData,
  SkillDataBundle,
} from "@excel/types_excel_gen";
import type { ItemTable, ItemBundle } from "@excel/excel";

/**
 * 创建最小化的 excel 数据 Mock
 * 包含测试所需的基础数据结构，可按需扩展
 */
export function mockExcel() {
  return {
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
    } as unknown as MissionTable,

    MedalTable: {
      medalList: [],
      medalTypeData: {},
    } as MedalData,

    StageTable: {
      stages: {},
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
    } as unknown as StageTable,

    GachaTable: {} as GachaData,
    GameDataConst: {} as GameDataConsts,
    CharacterTable: {} as CharacterData,
    ItemTable: {} as ItemTable,
    ShopClientTable: {} as ShopClientData,
    SkillDataBundle: {} as SkillDataBundle,

    // —— 门面方法（与 excel.ts 实现一致，操作 mock 数据）——
    getItem(id: string) {
      return this.ItemTable?.items?.[id];
    },
    itemName(id: string): string {
      return this.getItem(id)?.name ?? id;
    },
    makeItem(id: string, count: number, type?: string) {
      return type
        ? ({ id, count, type } as unknown as ItemBundle)
        : ({ id, count } as unknown as ItemBundle);
    },
    charData(charId: string) {
      return this.CharacterTable?.[charId];
    },
    stageData(stageId: string) {
      return this.StageTable?.stages?.[stageId];
    },
  };
}

export type MockExcel = ReturnType<typeof mockExcel>;
