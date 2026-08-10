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
import type { ItemTable } from "@excel/item_table";

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
  };
}

export type MockExcel = ReturnType<typeof mockExcel>;
