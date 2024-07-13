import { ItemBundle } from "./character_table";

export interface StageTable {
    stages:                       { [key: string]: StageData };
    runeStageGroups:              {};
    mapThemes:                    { [key: string]: MapThemeData };
    tileInfo:                     { [key: string]: TileAppendInfo };
    forceOpenTable:               { [key: string]: WeeklyForceOpenTable };
    timelyStageDropInfo:          { [key: string]: TimelyDropTimeInfo };
    overrideDropInfo:             { [key: string]: OverrideDropInfo };
    overrideUnlockInfo:           { [key: string]: OverrideUnlockInfo };
    timelyTable:                  { [key: string]: TimelyDropInfo };
    stageValidInfo:               { [key: string]: StageValidInfo };
    stageFogInfo:                 { [key: string]: StageFogInfo };
    stageStartConds:              { [key: string]: StageStartCond };
    diffGroupTable:               { [key: string]: StageDiffGroupTable };
    storyStageShowGroup:          { [key: string]: { [key: string]: StoryStageShowGroup } };
    specialBattleFinishStageData: { [key: string]: SpecialBattleFinishStageData };
    recordRewardData:             null;
    apProtectZoneInfo:            { [key: string]: ApProtectZoneInfo };
    antiSpoilerDict:              { [key: string]: string };
    actCustomStageDatas:          { [key: string]: ActCustomStageData };
    spNormalStageIdFor4StarList:  string[];
}



export interface ActCustomStageData {
    overrideGameMode: string;
}


export interface ApProtectZoneInfo {
    zoneId:     string;
    timeRanges: TimeRange[];
}
export interface StageValidInfo {
    startTs: number;
    endTs:   number;
}
export interface TimeRange {
    startTs: number;
    endTs:   number;
}

export interface StageDiffGroupTable {
    normalId: string;
    toughId:  null | string;
    easyId:   string;
}

export interface WeeklyForceOpenTable {
    id:            string;
    startTime:     number;
    endTime:       number;
    forceOpenList: string[];
}


export interface MapThemeData {
    themeId:        string;
    unitColor:      string;
    buildableColor: null | string;
    themeType:      null | string;
    trapTintColor:  null | string;
}

export interface OverrideDropInfo {
    itemId:       string;
    startTs:      number;
    endTs:        number;
    zoneRange:    string;
    times:        number;
    name:         string;
    egName:       string;
    desc1:        string;
    desc2:        string;
    desc3:        string;
    dropTag:      string;
    dropTypeDesc: string;
    dropInfo:     { [key: string]: StageDropInfo };
}

export interface StageDropInfo {
    firstPassRewards:     null;
    firstCompleteRewards: null;
    passRewards:          null;
    completeRewards:      null;
    displayRewards:       DisplayRewards[];
    displayDetailRewards: DisplayDetailRewards[];
}

export interface DisplayRewards {
    type:        string;
    id:          string;
    dropType:    StageDropType;
}
export interface DisplayDetailRewards {
    occPercent: OccPercent;
    type:        string;
    id:          string;
    dropType:    StageDropType;
}
export enum StageDropType {
    Additional = "ADDITIONAL",
    Complete = "COMPLETE",
    Normal = "NORMAL",
    Once = "ONCE",
    OverrideDrop = "OVERRIDE_DROP",
    Special = "SPECIAL",
}

export enum OccPercent {
    Almost = "ALMOST",
    Always = "ALWAYS",
    Often = "OFTEN",
    Sometimes = "SOMETIMES",
    Usual = "USUAL",
}





export interface SpecialBattleFinishStageData {
    stageId:               string;
    skipAccomplishPerform: boolean;
}

export interface StageFogInfo {
    lockId:          string;
    fogType:         FogType;
    stageId:         string;
    lockName:        string;
    lockDesc:        string;
    unlockItemId:    string;
    unlockItemType:  string;
    unlockItemNum:   number;
    preposedStageId: string;
    preposedLockId:  null | string;
}

export enum FogType {
    Stage = "STAGE",
    Zone = "ZONE",
}


export interface StageStartCond {
    requireChars:   RequireChar[];
    excludeAssists: string[];
    isNotPass:      boolean;
}

export interface RequireChar {
    charId:      string;
    evolvePhase: string;
}

export interface StageData {
    stageType:                   StageType;
    difficulty:                  Difficulty;
    performanceStageFlag:        PerformanceStageFlag;
    diffGroup:                   StageDiffGroup;
    unlockCondition:             ConditionDesc[];
    stageId:                     string;
    levelId:                     null | string;
    zoneId:                      string;
    code:                        string;
    name:                        null | string;
    description:                 null | string;
    hardStagedId:                null | string;
    dangerLevel:                 null | string;
    dangerPoint:                 number;
    loadingPicId:                string;
    canPractice:                 boolean;
    canBattleReplay:             boolean;
    apCost:                      number;
    apFailReturn:                number;
    etItemId:                    null | string;
    etCost:                      number;
    etFailReturn:                number;
    etButtonStyle:               null | string;
    apProtectTimes:              number;
    diamondOnceDrop:             number;
    practiceTicketCost:          number;
    dailyStageDifficulty:        number;
    expGain:                     number;
    goldGain:                    number;
    loseExpGain:                 number;
    loseGoldGain:                number;
    passFavor:                   number;
    completeFavor:               number;
    slProgress:                  number;
    displayMainItem:             null | string;
    hilightMark:                 boolean;
    bossMark:                    boolean;
    isPredefined:                boolean;
    isHardPredefined:            boolean;
    isSkillSelectablePredefined: boolean;
    isStoryOnly:                 boolean;
    appearanceStyle:             AppearanceStyle;
    stageDropInfo:               StageDropInfo;
    canUseCharm:                 boolean;
    canUseTech:                  boolean;
    canUseTrapTool:              boolean;
    canUseBattlePerformance:     boolean;
    canContinuousBattle:         boolean;
    startButtonOverrideId:       string | null;
    isStagePatch:                boolean;
    mainStageId:                 null | string;
    extraCondition:              ExtraConditionDesc[] | null;
    extraInfo:                   SpecialStoryInfo[] | null;
}

export enum AppearanceStyle {
    HighDifficulty = "HIGH_DIFFICULTY",
    MainNormal = "MAIN_NORMAL",
    MainPredefined = "MAIN_PREDEFINED",
    MistOps = "MIST_OPS",
    SpecialStory = "SPECIAL_STORY",
    Sub = "SUB",
    Training = "TRAINING",
}

export enum StageDiffGroup {
    All = "ALL",
    Easy = "EASY",
    None = "NONE",
    Normal = "NORMAL",
    Tough = "TOUGH",
}

export enum Difficulty {
    FourStar = "FOUR_STAR",
    Normal = "NORMAL",
}

export interface ExtraConditionDesc {
    index:       number;
    template:    string;
    unlockParam: string[];
}

export interface SpecialStoryInfo {
    stageId:      string;
    rewards:      ItemBundle[];
    progressInfo: SpecialProgressInfo;
    imageId:      string;
}

export interface SpecialProgressInfo {
    progressType: string;
    descList:     { [key: string]: string } | null;
}


export enum PerformanceStageFlag {
    NormalStage = "NORMAL_STAGE",
    PerformanceStage = "PERFORMANCE_STAGE",
}

export enum StageType {
    Activity = "ACTIVITY",
    Campaign = "CAMPAIGN",
    ClimbTower = "CLIMB_TOWER",
    Daily = "DAILY",
    Guide = "GUIDE",
    Main = "MAIN",
    SpecialStory = "SPECIAL_STORY",
    Sub = "SUB",
}

export interface ConditionDesc {
    stageId:       string;
    completeState: PlayerBattleRank;
}

export enum PlayerBattleRank {
    Complete = "COMPLETE",
    Pass = "PASS",
}



export interface StoryStageShowGroup {
    displayRecordId:  string;
    stageId:          string;
    accordingStageId: null | string;
    diffGroup:        StageDiffGroup;
}


export interface TileAppendInfo {
    tileKey:      string;
    name:         string;
    description:  string;
    isFunctional: boolean;
}


export interface TimelyDropTimeInfo {
    startTs:               number;
    endTs:                 number;
    stagePic:              null | string;
    dropPicId:             null | string;
    stageUnlock:           string;
    entranceDownPicId:     null | string;
    entranceUpPicId:       null | string;
    timelyGroupId:         string;
    weeklyPicId:           null | string;
    isReplace:             boolean;
    apSupplyOutOfDateDict: { [key: string]: number };
}





export interface TimelyDropInfo {
    dropInfo: { [key: string]: StageDropInfo };
}
export interface OverrideUnlockInfo {
    groudId: string;
    startTime:number;
    endTime:number;
    unlockDict: { [key: string]: ConditionDesc[] };
}