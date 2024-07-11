import { ItemBundle } from "./character_table";

export interface StageTable {
    stages:                       { [key: string]: StageData };
    runeStageGroups:              {};
    mapThemes:                    { [key: string]: MapThemeData };
    tileInfo:                     { [key: string]: TileAppendInfo };
    forceOpenTable:               { [key: string]: WeeklyForceOpenTable };
    timelyStageDropInfo:          { [key: string]: TimelyDropTimeInfo };
    overrideDropInfo:             OverrideDropInfo;
    overrideUnlockInfo:           {};
    timelyTable:                  { [key: string]: TimelyTable };
    stageValidInfo:               { [key: string]: StageValidInfo };
    stageFogInfo:                 { [key: string]: StageFogInfo };
    stageStartConds:              StageStartConds;
    diffGroupTable:               { [key: string]: StageDiffGroupTable };
    storyStageShowGroup:          StoryStageShowGroup;
    specialBattleFinishStageData: SpecialBattleFinishStageData;
    recordRewardData:             null;
    apProtectZoneInfo:            ApProtectZoneInfo;
    antiSpoilerDict:              AntiSpoilerDict;
    actCustomStageDatas:          ActCustomStageDatas;
    spNormalStageIdFor4StarList:  string[];
}



export interface Act27SideSp0 {
    overrideGameMode: string;
}

export interface AntiSpoilerDict {
    main_14: string;
}

export interface ApProtectZoneInfo {
    main_10: Main1;
    main_11: Main1;
    main_12: Main1;
    main_13: Main1;
    main_14: Main1;
}

export interface Main1 {
    zoneId:     string;
    timeRanges: StageValidInfo[];
}

export interface StageValidInfo {
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
    Logistics_Special_Permit: LogisticsSpecialPermit;
}

export interface LogisticsSpecialPermit {
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





export interface Main0815 {
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

export interface StageStartConds {
    "main_08-16":  Easy1419;
    "main_14-19":  Easy1419;
    "easy_14-19":  Easy1419;
    "tough_14-19": Easy1419;
}

export interface Easy1419 {
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


export interface ExDropAct10D5 {
    startTs:               number;
    endTs:                 number;
    stagePic:              null | string;
    dropPicId:             null | string;
    stageUnlock:           StageUnlock;
    entranceDownPicId:     null | string;
    entranceUpPicId:       null | string;
    timelyGroupId:         string;
    weeklyPicId:           null | string;
    isReplace:             boolean;
    apSupplyOutOfDateDict: {};
}


export interface ExDropAct {
    startTs:               number;
    endTs:                 number;
    stagePic:              string;
    dropPicId:             string;
    stageUnlock:           StageUnlock;
    entranceDownPicId:     string;
    entranceUpPicId:       string;
    timelyGroupId:         string;
    weeklyPicId:           string;
    isReplace:             boolean;
    apSupplyOutOfDateDict: ApSupplyOutOfDateDict;
}



export interface TimelyTable {
    dropInfo: { [key: string]: StageDropInfo };
}
