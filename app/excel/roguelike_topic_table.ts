import { RoguelikeBuff } from "../game/model/rlv2";

export interface RoguelikeTopicTable {
    topics:        Topics;
    constant:      Constant;
    details:       Details;
    modules:       Modules;
    customizeData: CustomizeData;
}

export interface Constant {
    milestoneTokenRatio:           number;
    outerBuffTokenRatio:           number;
    relicTokenRatio:               number;
    rogueSystemUnlockStage:        string;
    ordiModeReOpenCoolDown:        number;
    monthModeReOpenCoolDown:       number;
    monthlyTaskUncompletedTime:    number;
    monthlyTaskManualRefreshLimit: number;
    monthlyTeamUncompletedTime:    number;
    bpPurchaseSystemUnlockTime:    number;
    predefinedChars:               { [key: string]: PredefinedChar };
}

export interface PredefinedChar {
    charId:      string;
    canBeFree:   boolean;
    uniEquipId:  null | string;
    recruitType: string;
}

export interface CustomizeData {
    rogue_1: CustomizeDataRogue1;
    rogue_2: CustomizeDataRogue2;
    rogue_3: CustomizeDataRogue3;
    rogue_4: CustomizeDataRogue4;
}

export interface CustomizeDataRogue1 {
    developments:      { [key: string]: Rogue1_Development };
    developmentTokens: { [key: string]: DevelopmentToken };
    endingText:        Rogue1_EndingText;
}

export interface DevelopmentToken {
    sortId:      number;
    displayForm: string;
    tokenDesc:   string;
}

export interface Rogue1_Development {
    buffId:          string;
    sortId:          number;
    nodeType:        string;
    nextNodeId:      string[];
    frontNodeId:     string[];
    tokenCost:       number;
    buffName:        string;
    buffIconId:      string;
    buffTypeName:    string;
    buffDisplayInfo: BuffDisplayInfo[];
}

export interface BuffDisplayInfo {
    displayType: string;
    displayNum:  number;
    displayForm: string;
    tokenDesc:   string;
    sortId:      number;
}

export interface Rogue1_EndingText {
    summaryVariation:        string;
    summaryDefeatBoss:       string;
    summaryAccidentMeet:     string;
    summaryCapsule:          string;
    summaryActiveTool:       string;
    summaryActor:            string;
    summaryTop:              string;
    summaryZone:             string;
    summaryEnding:           string;
    summaryDifficultyZone:   null;
    summaryDifficultyEnding: null;
    summaryMode:             string;
    summaryGroup:            string;
    summarySupport:          string;
    summaryNormalRecruit:    string;
    summaryDirectRecruit:    string;
    summaryFriendRecruit:    string;
    summaryFreeRecruit:      string;
    summaryMonthRecruit:     string;
    summaryUpgrade:          string;
    summaryCompleteEnding:   string;
    summaryEachZone:         string;
    summaryPerfectBattle:    string;
    summaryMeetBattle:       string;
    summaryMeetEvent:        string;
    summaryMeetShop:         string;
    summaryMeetTreasure:     string;
    summaryBuy:              string;
    summaryInvest:           string;
    summaryGet:              string;
    summaryRelic:            string;
    summarySafeHouse:        string;
    summaryFailEnd:          string;
}

export interface CustomizeDataRogue2 {
    developments:            { [key: string]: Rogue2_Development };
    developmentTokens:       { [key: string]: DevelopmentToken };
    developmentRawTextGroup: DevelopmentRawTextGroup[];
    developmentLines:        DevelopmentLine[];
    endingText:              Rogue2_EndingText;
}

export interface DevelopmentLine {
    fromNode:  string;
    toNode:    string;
    fromNodeP: number;
    fromNodeR: number;
    toNodeP:   number;
    toNodeR:   number;
    enrollId:  null | string;
}

export interface DevelopmentRawTextGroup {
    nodeIdList:    string[];
    useLevelMark?: boolean;
    groupIconId:   string;
    useUpBreak?:   boolean;
    sortId:        number;
}

export interface Rogue2_Development {
    buffId:          string;
    nodeType:        string;
    frontNodeId:     string[];
    nextNodeId:      string[];
    positionP:       number;
    positionR:       number;
    tokenCost:       number;
    buffName:        string;
    buffIconId:      string;
    effectType:      string;
    rawDesc:         string;
    buffDisplayInfo: BuffDisplayInfo[];
    enrollId:        null | string;
}

export interface Rogue2_EndingText {
    summaryMutation:            string;
    summaryDice:                string;
    summaryDiceResultGood:      string;
    summaryDiceResultNormal:    string;
    summaryDiceResultBad:       string;
    summaryDiceResultDesc:      string;
    summaryCommuDesc:           string;
    summaryHiddenDesc:          string;
    summaryKnightDesc:          string;
    summaryGoldDesc:            string;
    summaryPracticeDesc:        string;
    summaryCommuEmptyDesc:      string;
    summaryCommuNotEmptyDesc:   string;
    summaryHiddenPassedDesc:    string;
    summaryHiddenNotPassedDesc: string;
    summaryKnightPassedDesc:    string;
    summaryKnightNotPassedDesc: string;
    summaryGoldThreshold:       number;
    summaryGoldHighDesc:        string;
    summaryGoldLowDesc:         string;
    summaryPracticeThreshold:   number;
    summaryPracticeHighDesc:    string;
    summaryPracticeLowDesc:     string;
}

export interface CustomizeDataRogue3 {
    developments:                    { [key: string]: Rogue3_Development };
    developmentsTokens:              { [key: string]: DevelopmentToken };
    developmentRawTextGroup:         DevelopmentRawTextGroup[];
    developmentsDifficultyNodeInfos: Rogue3_DevelopmentsDifficultyNodeInfos;
    endingText:                      Rogue3_EndingText;
    difficulties:                    PurpleDifficulty[];
}

export interface Rogue3_Development {
    buffId:          string;
    nodeType:        string;
    frontNodeId:     string[];
    nextNodeId:      string[];
    positionRow:     number;
    positionOrder:   number;
    tokenCost:       number;
    buffName:        string;
    buffIconId?:     string;
    effectType:      string;
    rawDesc:         string[];
    buffDisplayInfo: BuffDisplayInfo[];
    groupId:         string;
    enrollId:        null;
    activeIconId?:   string;
    inactiveIconId?: string;
    bottomIconId?:   string;
}

export interface Rogue3_DevelopmentsDifficultyNodeInfos {
    rogue_3_difficulty_1: Rogue3__Difficulty;
    rogue_3_difficulty_2: Rogue3__Difficulty;
    rogue_3_difficulty_3: Rogue3__Difficulty;
}

export interface Rogue3__Difficulty {
    buffId:      string;
    nodeMap:     Rogue3_Difficulty1_NodeMap[];
    enableGrade: number;
}

export interface Rogue3_Difficulty1_NodeMap {
    frontNode: string;
    nextNode:  string;
}

export interface PurpleDifficulty {
    modeDifficulty: string;
    grade:          number;
    totemProb:      number;
    relicDevLevel:  null | string;
    buffs:          string[] | null;
    buffDesc:       string[];
}

export interface Rogue3_EndingText {
    summaryGetTotem:         string;
    summaryDemoPointUp:      string;
    summaryDemoPointDown:    string;
    summaryDemoGradeUp:      string;
    summaryDemoGradeDown:    string;
    summaryVisionPointUp:    string;
    summaryVisionPointDown:  string;
    summaryVisionGradeUp:    string;
    summaryVisionGradeDown:  string;
    summaryMeetTrade:        string;
    summaryFightWin:         string;
    summaryFightFail:        string;
    summaryExchangeTotem:    string;
    summaryExchangeRelic:    string;
    summaryMeetSecretpath:   string;
    summaryUseTotem:         string;
    summaryVisionGrade:      string;
    summaryActor:            string;
    summaryTop:              string;
    summaryZone:             string;
    summaryEnding:           string;
    summaryDifficultyZone:   null;
    summaryDifficultyEnding: null;
    summaryMode:             string;
    summaryGroup:            string;
    summarySupport:          string;
    summaryNormalRecruit:    string;
    summaryDirectRecruit:    string;
    summaryFriendRecruit:    string;
    summaryFreeRecruit:      string;
    summaryMonthRecruit:     string;
    summaryUpgrade:          string;
    summaryCompleteEnding:   string;
    summaryEachZone:         string;
    summaryPerfectBattle:    string;
    summaryMeetBattle:       string;
    summaryMeetEvent:        string;
    summaryMeetShop:         string;
    summaryMeetTreasure:     string;
    summaryBuy:              string;
    summaryInvest:           string;
    summaryGet:              string;
    summaryRelic:            string;
    summarySafeHouse:        string;
    summaryFailEnd:          string;
}

export interface CustomizeDataRogue4 {
    commonDevelopment: CommonDevelopment;
    difficulties:      FluffyDifficulty[];
    endingText:        { [key: string]: string };
}

export interface CommonDevelopment {
    developments:                    { [key: string]: Rogue3_Development };
    developmentsTokens:              { [key: string]: DevelopmentToken };
    developmentRawTextGroup:         DevelopmentRawTextGroup[];
    developmentsDifficultyNodeInfos: CommonDevelopmentDevelopmentsDifficultyNodeInfos;
}

export interface CommonDevelopmentDevelopmentsDifficultyNodeInfos {
    rogue_4_difficulty_1: Rogue4__Difficulty;
    rogue_4_difficulty_2: Rogue4__Difficulty;
    rogue_4_difficulty_3: Rogue4__Difficulty;
}

export interface Rogue4__Difficulty {
    buffId:      string;
    nodeMap:     Rogue4_Difficulty1_NodeMap[];
    enableGrade: number;
    enableDesc:  string;
    lightId:     string;
    decoId:      null;
}

export interface Rogue4_Difficulty1_NodeMap {
    frontNodes: string[];
    nextNode:   string;
}

export interface FluffyDifficulty {
    modeDifficulty:        string;
    grade:                 number;
    leftDisasterDesc:      string;
    leftOverweightDesc:    string;
    relicDevLevel:         string;
    weightStatusLimitDesc: string;
    buffs:                 string[] | null;
    buffDesc:              string[];
}

export interface Details {
    rogue_1: DetailsRogue1;
    rogue_2: DetailsRogue2;
    rogue_3: DetailsRogue3;
    rogue_4: DetailsRogue4;
}

export interface DetailsRogue1 {
    updates:                      Update[];
    enrolls:                      Rogue1_Enrolls;
    milestones:                   Milestone[];
    milestoneUpdates:             MilestoneUpdate[];
    grandPrizes:                  GrandPrize[];
    monthMission:                 MonthMission[];
    monthSquad:                   Rogue1_MonthSquad;
    challenges:                   Rogue1_Challenges;
    difficulties:                 Rogue1_Difficulty[];
    bankRewards:                  BankReward[];
    archiveComp:                  Rogue1_ArchiveComp;
    archiveUnlockCond:            ArchiveUnlockCond;
    detailConst:                  Rogue1_DetailConst;
    init:                         RoguelikeGameInitData[];
    stages:                       { [key: string]: Stage };
    zones:                        Rogue1_Zones;
    variation:                    BandRef;
    traps:                        Rogue1_Traps;
    recruitTickets:               Rogue1_RecruitTickets;
    upgradeTickets:               Rogue1_UpgradeTickets;
    customTickets:                BandRef;
    relics:                       { [key: string]: RoguelikeGameRelicData };
    relicParams:                  { [key: string]: RelicParam };
    recruitGrps:                  RecruitGrps;
    choices:                      { [key: string]: Choice };
    choiceScenes:                 { [key: string]: ChoiceScene };
    nodeTypeData:                 NodeTypeData;
    subTypeData:                  any[];
    variationData:                Rogue1_VariationData;
    charBuffData:                 BandRef;
    squadBuffData:                BandRef;
    taskData:                     BandRef;
    gameConst:                    Rogue1_GameConst;
    shopDialogData:               Rogue1_ShopDialogData;
    capsuleDict:                  { [key: string]: CapsuleDict };
    endings:                      Rogue1_Endings;
    battleSummeryDescriptions:    BattleSummeryDescriptions;
    battleLoadingTips:            BattleLoadingTip[];
    items:                        { [key: string]: RoguelikeGameItemData };
    bandRef:                      BandRef;
    endingDetailList:             EndingDetailList[];
    endingRelicDetailList:        any[];
    treasures:                    BandRef;
    difficultyUpgradeRelicGroups: BandRef;
    styles:                       BandRef;
    styleConfig:                  StyleConfig;
    exploreTools:                 BandRef;
    rollNodeData:                 BandRef;
}

export interface Rogue1_ArchiveComp {
    relic:    ArchiveCompRelic;
    capsule:  ArchiveCompCapsule;
    trap:     PurpleTrap;
    chat:     PurpleChat;
    endbook:  PurpleEndbook;
    buff:     PurpleBuff;
    totem:    null;
    chaos:    null;
    fragment: null;
    disaster: null;
}

export interface PurpleBuff {
    buff: BandRef;
}

export interface BandRef {
}

export interface ArchiveCompCapsule {
    capsule: { [key: string]: CapsuleValue };
}

export interface CapsuleValue {
    capsuleId:     string;
    capsuleSortId: number;
    englishName:   string;
    enrollId:      null;
}

export interface PurpleChat {
    chat: FluffyChat;
}

export interface FluffyChat {
    month_chat_rogue_1_1: MonthChatRogue;
    month_chat_rogue_1_2: MonthChatRogue;
    month_chat_rogue_1_3: MonthChatRogue;
    month_chat_rogue_1_4: MonthChatRogue;
    month_chat_rogue_1_5: MonthChatRogue;
    month_chat_rogue_1_6: MonthChatRogue;
    month_chat_rogue_1_7: MonthChatRogue;
    month_chat_rogue_1_8: MonthChatRogue;
}

export interface MonthChatRogue {
    sortId:             number;
    numChat:            number;
    clientChatItemData: ClientChatItemDatum[];
}

export interface ClientChatItemDatum {
    chatFloor:   number;
    chatDesc:    null | string;
    chatStoryId: string;
}

export interface PurpleEndbook {
    endbook: BandRef;
}

export interface ArchiveCompRelic {
    relic: { [key: string]: RelicRelic };
}

export interface RelicRelic {
    relicId:      string;
    relicSortId:  number;
    relicGroupId: number;
    orderId:      string;
    isSpRelic:    boolean;
    enrollId:     null | string;
}

export interface PurpleTrap {
    trap: TrapTrap;
}

export interface TrapTrap {
    rogue_1_active_tool_1: Rogue1__ActiveTool;
    rogue_1_active_tool_2: Rogue1__ActiveTool;
    rogue_1_active_tool_3: Rogue1__ActiveTool;
    rogue_1_active_tool_4: Rogue1__ActiveTool;
    rogue_1_active_tool_5: Rogue1__ActiveTool;
    rogue_1_active_tool_6: Rogue1__ActiveTool;
}

export interface Rogue1__ActiveTool {
    trapId:     string;
    trapSortId: number;
    orderId:    string;
    enrollId:   null;
}

export interface ArchiveUnlockCond {
    unlockCondDesc: { [key: string]: UnlockCondDesc };
    enroll:         { [key: string]: Enroll };
}

export interface Enroll {
    archiveType: string;
    enrollId:    null | string;
}

export interface UnlockCondDesc {
    archiveType: string;
    description: string;
}

export interface BankReward {
    rewardId:      string;
    unlockGoldCnt: number;
    rewardType:    string;
    desc:          string;
}

export interface BattleLoadingTip {
    tip:      string;
    weight:   number;
    category: string;
}

export interface BattleSummeryDescriptions {
    EASY:       Challenge;
    NORMAL:     Challenge;
    HARD:       Challenge;
    MONTH_TEAM: Challenge;
    CHALLENGE:  Challenge;
}

export interface Challenge {
    randomDescriptionList: string[];
}

export interface CapsuleDict {
    itemId:     string;
    maskType:   string;
    innerColor: string;
}

export interface Rogue1_Challenges {
    rogue_1_challenge_01: Rogue1_Challenge01;
    rogue_1_challenge_02: Rogue1_Challenge02;
    rogue_1_challenge_03: Rogue1_Challenge03;
    rogue_1_challenge_04: Rogue1_Challenge04;
    rogue_1_challenge_05: Rogue1_Challenge05;
    rogue_1_challenge_06: Rogue1_Challenge06;
    rogue_1_challenge_07: Rogue1_Challenge07;
    rogue_1_challenge_08: Rogue1_Challenge08;
    rogue_1_challenge_09: Rogue1_Challenge09;
    rogue_1_challenge_10: Rogue1_Challenge10;
    rogue_1_challenge_11: Rogue1_Challenge11;
    rogue_1_challenge_12: Rogue1_Challenge12;
}

export interface Rogue1_Challenge01 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       null;
    challengeUnlockDesc:      null;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue1_Challenge01_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue1_Challenge01_ChallengeTasks {
    rogue_1_task_01: Rogue1_Task01_Class;
}

export interface Rogue1_Task01_Class {
    taskId:           string;
    taskDes:          string;
    completionClass:  string;
    completionParams: string[];
}

export interface Reward {
    id:    string;
    count: number;
    type:  string;
}

export interface Rogue1_Challenge02 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       null;
    challengeUnlockDesc:      null;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue1_Challenge02_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue1_Challenge02_ChallengeTasks {
    rogue_1_task_02: Rogue1_Task01_Class;
}

export interface Rogue1_Challenge03 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       null;
    challengeUnlockDesc:      null;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue1_Challenge03_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue1_Challenge03_ChallengeTasks {
    rogue_1_task_03: Rogue1_Task01_Class;
}

export interface Rogue1_Challenge04 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       null;
    challengeUnlockDesc:      null;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue1_Challenge04_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue1_Challenge04_ChallengeTasks {
    rogue_1_task_04: Rogue1_Task01_Class;
}

export interface Rogue1_Challenge05 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       null;
    challengeUnlockDesc:      null;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue1_Challenge05_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue1_Challenge05_ChallengeTasks {
    rogue_1_task_05: Rogue1_Task01_Class;
}

export interface Rogue1_Challenge06 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       null;
    challengeUnlockDesc:      null;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue1_Challenge06_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue1_Challenge06_ChallengeTasks {
    rogue_1_task_06: Rogue1_Task01_Class;
}

export interface Rogue1_Challenge07 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       null;
    challengeUnlockDesc:      null;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue1_Challenge07_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue1_Challenge07_ChallengeTasks {
    rogue_1_task_07: Rogue1_Task01_Class;
}

export interface Rogue1_Challenge08 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       null;
    challengeUnlockDesc:      null;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue1_Challenge08_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue1_Challenge08_ChallengeTasks {
    rogue_1_task_08: Rogue1_Task01_Class;
}

export interface Rogue1_Challenge09 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       null;
    challengeUnlockDesc:      null;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue1_Challenge09_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue1_Challenge09_ChallengeTasks {
    rogue_1_task_09: Rogue1_Task01_Class;
}

export interface Rogue1_Challenge10 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       null;
    challengeUnlockDesc:      null;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue1_Challenge10_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue1_Challenge10_ChallengeTasks {
    rogue_1_task_10: Rogue1_Task01_Class;
}

export interface Rogue1_Challenge11 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       null;
    challengeUnlockDesc:      null;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue1_Challenge11_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue1_Challenge11_ChallengeTasks {
    rogue_1_task_11: Rogue1_Task01_Class;
}

export interface Rogue1_Challenge12 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       null;
    challengeUnlockDesc:      null;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue1_Challenge12_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue1_Challenge12_ChallengeTasks {
    rogue_1_task_12: Rogue1_Task01_Class;
}

export interface ChoiceScene {
    id:             string;
    title:          string;
    description:    string;
    background:     null | string;
    titleIcon:      null | string;
    subTypeId:      number;
    useHiddenMusic: boolean;
}

export interface Choice {
    id:                     string;
    title:                  string;
    description:            null | string;
    lockedCoverDesc:        null | string;
    type:                   string;
    leftDecoType:           string;
    nextSceneId:            null | string;
    icon:                   null | string;
    displayData:            DisplayData;
    forceShowWhenOnlyLeave: boolean;
}

export interface DisplayData {
    type:                          string;
    costHintType:                  string;
    effectHintType:                string;
    funcIconId:                    null | string;
    itemId:                        null | string;
    difficultyUpgradeRelicGroupId: null;
    taskId:                        null;
}

export interface Rogue1_DetailConst {
    playerLevelTable:                  { [key: string]: PlayerLevelTable };
    charUpgradeTable:                  { [key: string]: CharUpgradeTable };
    difficultyUpgradeRelicDescTable:   BandRef;
    predefinedLevelTable:              BandRef;
    tokenBpId:                         string;
    tokenOuterBuffId:                  string;
    previewedRewardsAccordingUpdateId: string;
    tipButtonName:                     string;
    collectButtonName:                 string;
    bpSystemName:                      string;
    autoSetKV:                         string;
    bpPurchaseActiveEnroll:            string;
    defaultSacrificeDesc:              null | string;
    defaultExpeditionSelectDesc:       null | string;
    gotCharBuffToast:                  null | string;
    gotSquadBuffToast:                 null | string;
    loseCharBuffToast:                 null | string;
    monthTeamSystemName:               string;
    battlePassUpdateName:              string;
    monthCharCardTagName:              string;
    monthTeamDescTagName:              string;
    outerBuffCompleteText:             string;
    outerProgressTextColor:            string;
    challengeTaskTargetName:           string;
    challengeTaskConditionName:        string;
    challengeTaskRewardName:           string;
    challengeTaskModeName:             string;
    challengeTaskName:                 string;
    outerBuffTokenSum:                 number;
    needAllFrontNode:                  boolean;
    showBlurBack:                      boolean;
    endingIconBorderDifficulty:        number;
    endingIconBorderCount:             number;
}

export interface CharUpgradeTable {
    evolvePhase:          string;
    skillLevel:           number;
    skillSpecializeLevel: number;
}

export interface PlayerLevelTable {
    exp:               number;
    populationUp:      number;
    squadCapacityUp:   number;
    battleCharLimitUp: number;
    maxHpUp:           number;
}

export interface Rogue1_Difficulty {
    modeDifficulty:       string;
    grade:                number;
    name:                 string;
    subName:              null | string;
    enrollId:             null | string;
    haveInitialRelicIcon: boolean;
    scoreFactor:          number;
    canUnlockItem:        boolean;
    doMonthTask:          boolean;
    ruleDesc:             string;
    ruleDescReplacements: RuleDescReplacement[] | null;
    failTitle:            string;
    failImageId:          string;
    failForceDesc:        string;
    sortId:               number;
    equivalentGrade:      number;
    color:                null | string;
    bpValue:              number;
    bossValue:            number;
    addDesc:              null | string;
    isHard:               boolean;
    unlockText:           null | string;
    displayIconId:        null | string;
    hideEndingStory:      boolean;
}

export interface RuleDescReplacement {
    enrollId: string;
    ruleDesc: string;
}

export interface EndingDetailList {
    textId:        string;
    text:          string;
    eventType:     string;
    showType:      string;
    choiceSceneId: null | string;
    paramList:     string[];
    otherPara1:    null;
}

export interface Rogue1_Endings {
    ro_ending_1: RoEnding1;
    ro_ending_2: RoEnding1;
    ro_ending_3: RoEnding1;
    ro_ending_4: RoEnding1;
}

export interface RoEnding1 {
    id:               string;
    familyId:         number;
    name:             string;
    desc:             string;
    bgId:             string;
    icons:            Icon[];
    priority:         number;
    changeEndingDesc: null | string;
    bossIconId:       null | string;
}

export interface Icon {
    level:  number;
    iconId: string;
}

export interface Rogue1_Enrolls {
    rogue_1_enroll_1: Rogue1_Enroll1_Class;
    rogue_1_enroll_2: Rogue1_Enroll1_Class;
}

export interface Rogue1_Enroll1_Class {
    enrollId:   string;
    enrollTime: number;
}

export interface Rogue1_GameConst {
    initSceneName:                     string;
    failSceneName:                     string;
    hpItemId:                          string;
    goldItemId:                        string;
    populationItemId:                  string;
    squadCapacityItemId:               string;
    expItemId:                         string;
    initialBandShowGradeFlag:          boolean;
    bankMaxGold:                       number;
    bankCostId:                        null | string;
    bankDrawCount:                     number;
    bankDrawLimit:                     number;
    mimicEnemyIds:                     string[];
    bossIds:                           string[];
    goldChestTrapId:                   string;
    normBoxTrapId:                     null | string;
    rareBoxTrapId:                     null | string;
    badBoxTrapId:                      null | string;
    maxHpItemId:                       null | string;
    shieldItemId:                      null | string;
    keyItemId:                         null | string;
    chestKeyCnt:                       number;
    chestKeyItemId:                    null | string;
    keyColorId:                        null | string;
    onceNodeTypeList:                  string[];
    gpScoreRatio:                      number;
    overflowUsageSquadBuff:            null | string;
    specialTrapId:                     null | string;
    trapRewardRelicId:                 null | string;
    unlockRouteItemId:                 null | string;
    unlockRouteItemCount:              number;
    hideBattleNodeName:                null;
    hideBattleNodeDescription:         null;
    hideNonBattleNodeName:             null;
    hideNonBattleNodeDescription:      null;
    charSelectExpeditionConflictToast: null | string;
    itemDropTagDict:                   PurpleItemDropTagDict;
    expeditionReturnDescCureUpgrade:   null | string;
    expeditionReturnDescUpgrade:       null | string;
    expeditionReturnDescCure:          null | string;
    expeditionReturnDesc:              null | string;
    expeditionSelectDescFormat:        null;
    expeditionReturnDescItem:          null | string;
    expeditionReturnRewardBlackList:   any[];
    travelLeaveToastFormat:            null;
    charSelectTravelConflictToast:     null;
    travelReturnDescUpgrade:           null;
    travelReturnDesc:                  null;
    travelReturnDescItem:              null;
    traderReturnTitle:                 null;
    traderReturnDesc:                  null;
    gainBuffDiffGrade:                 number;
    dsPredictTips:                     null;
    dsBuffActiveTips:                  null;
    totemDesc:                         null;
    relicDesc:                         null;
    buffDesc:                          null;
    refreshNodeItemId:                 null;
    portalZones:                       string[];
    exploreExpOnKill:                  null;
}

export interface PurpleItemDropTagDict {
    TREASURE: string;
}

export interface GrandPrize {
    grandPrizeDisplayId: string;
    sortId:              number;
    displayUnlockYear:   number;
    displayUnlockMonth:  number;
    acquireTitle:        string;
    purchaseTitle:       string;
    displayName:         string;
    displayDiscription:  string;
    bpLevelId:           string;
    itemBundle:          Reward | null;
    detailAnnounceTime:  null | string;
    picIdAftrerUnlock:   null | string;
}

export interface RoguelikeGameInitData {
    modeId:               string;
    modeGrade:            number;
    predefinedId:         null | string;
    predefinedStyle:      null | string;
    initialBandRelic:     string[];
    initialRecruitGroup:  string[] | null;
    initialHp:            number;
    initialPopulation:    number;
    initialGold:          number;
    initialSquadCapacity: number;
    initialShield:        number;
    initialMaxHp:         number;
    initialKey:           number;
}

export interface RoguelikeGameItemData {
    id:             string;
    name:           string;
    description:    null | string;
    usage:          string;
    obtainApproach: string;
    iconId:         string;
    type:           string;
    subType:        string;
    rarity:         string;
    value:          number;
    sortId:         number;
    canSacrifice:   boolean;
    unlockCondDesc: null | string;
}

export interface MilestoneUpdate {
    updateTime:        number;
    endTime:           number;
    maxBpLevel:        number;
    maxBpCount:        number;
    maxDisplayBpCount: number;
}

export interface Milestone {
    id:           string;
    level:        number;
    tokenNum:     number;
    nextTokenNum: number;
    itemID:       string;
    itemType:     string;
    itemCount:    number;
    isGoodPrize:  boolean;
    isGrandPrize: boolean;
}

export interface MonthMission {
    id:               string;
    taskName:         string;
    taskClass:        string;
    innerClassWeight: number;
    template:         string;
    paramList:        string[];
    desc:             string;
    tokenRewardNum:   number;
}

export interface Rogue1_MonthSquad {
    month_team_1: MonthTeam;
    month_team_2: MonthTeam;
    month_team_3: MonthTeam;
    month_team_4: MonthTeam;
    month_team_5: MonthTeam;
    month_team_6: MonthTeam;
    month_team_7: MonthTeam;
    month_team_8: MonthTeam;
}

export interface MonthTeam {
    id:             string;
    teamName:       string;
    teamSubName:    null | string;
    teamFlavorDesc: null | string;
    teamDes:        string;
    teamColor:      string;
    teamMonth:      string;
    teamYear:       string;
    teamIndex:      null | string;
    teamChars:      string[];
    zoneId:         null | string;
    chatId:         string;
    tokenRewardNum: number;
    items:          Reward[];
    startTime:      number;
    endTime:        number;
    taskDes:        null | string;
}

export interface NodeTypeData {
    BATTLE_NORMAL: BattleBoss;
    BATTLE_ELITE:  BattleBoss;
    BATTLE_BOSS:   BattleBoss;
    SHOP:          BattleBoss;
    REST:          BattleBoss;
    INCIDENT:      BattleBoss;
    TREASURE:      BattleBoss;
    ENTERTAINMENT: BattleBoss;
    UNKNOWN:       BattleBoss;
}

export interface BattleBoss {
    name:        string;
    description: string;
}

export interface RecruitGrps {
    recruit_group_random: RecruitGr;
    recruit_group_1:      RecruitGr;
    recruit_group_2:      RecruitGr;
    recruit_group_3:      RecruitGr;
    recruit_group_c4:     RecruitGr;
    recruit_group_c5:     RecruitGr;
}

export interface RecruitGr {
    id:         string;
    iconId:     string;
    name:       string;
    desc:       string;
    unlockDesc: null | string;
}

export interface Rogue1_RecruitTickets {
    rogue_1_recruit_ticket_pioneer:              RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_warrior:              RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_tank:                 RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_sniper:               RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_caster:               RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_support:              RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_medic:                RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_special:              RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_pioneer_sp:           RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_warrior_sp:           RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_tank_sp:              RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_sniper_sp:            RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_caster_sp:            RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_support_sp:           RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_medic_sp:             RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_special_sp:           RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_double_1:             RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_double_2:             RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_double_3:             RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_double_4:             RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_quad_melee:           RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_quad_ranged:          RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_all:                  RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_5star:                RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_all_premium:          RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_quad_melee_discount:  RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_quad_ranged_discount: RoguelikeRecruitTicketFeature;
    rogue_1_recruit_ticket_all_discount:         RoguelikeRecruitTicketFeature;
}


export interface RoguelikeRecruitTicketFeature {
    id:              string;
    profession:      string|number;
    rarity:          string|number;
    professionList:  string[];
    rarityList:      string[];
    extraEliteNum?:   number;
    extraFreeRarity?: string[];
    extraCharIds?:    string[];
}

export interface RelicParam {
    id:                 string;
    checkCharBoxTypes:  string[];
    checkCharBoxParams: CheckCharBoxParam[];
}

export interface CheckCharBoxParam {
    valueProfessionMask: string;
    valueStrs:           string[] | null;
    valueInt:            number;
}

export interface RoguelikeGameRelicData {
    id:    string;
    buffs: RoguelikeBuff[];
}

export interface Rogue1_ShopDialogData {
    types: PurpleTypes;
}

export interface PurpleTypes {
    BUY_SELECT:         BuySelect;
    BANK_ENTRY:         BankEntry;
    BANK_INVEST:        BankEntry;
    BANK_WITHDRAWAL:    BankEntry;
    BANK_FAULTY:        BankEntry;
    BANK_REWARD_UNLOCK: BankEntry;
    OUTER_NORMAL:       BankEntry;
    OUTER_REWARD:       BankEntry;
    FIGHT_BOSS?:        BankEntry;
}

export interface BankEntry {
    groups: BANKENTRYGroups;
}

export interface BANKENTRYGroups {
    NONE: None;
}

export interface None {
    content: string[];
}

export interface BuySelect {
    groups: BUYSELECTGroups;
}

export interface BUYSELECTGroups {
    NONE:           None;
    RECRUIT_TICKET: None;
    RELIC:          None;
    ACTIVE_TOOL:    None;
    VISION?:        None;
}

export interface Stage {
    id:            string;
    linkedStageId: string;
    levelId:       string;
    code:          string;
    name:          string;
    loadingPicId:  string;
    description:   string;
    eliteDesc:     null | string;
    isBoss:        number;
    isElite:       number;
    difficulty:    string;
    capsulePool:   null | string;
    capsuleProb:   number;
    vutresProb:    number[];
    boxProb:       number[];
    specialNodeId: null | string;
}

export interface StyleConfig {
    expStyleConfig: null;
}

export interface Rogue1_Traps {
    rogue_1_active_tool_1: Rogue1__ActiveTool1;
    rogue_1_active_tool_2: Rogue1__ActiveTool1;
    rogue_1_active_tool_3: Rogue1__ActiveTool1;
    rogue_1_active_tool_4: Rogue1__ActiveTool1;
    rogue_1_active_tool_5: Rogue1__ActiveTool1;
    rogue_1_active_tool_6: Rogue1__ActiveTool1;
}

export interface Rogue1__ActiveTool1 {
    itemId:   string;
    trapId:   string;
    trapDesc: string;
}

export interface Update {
    updateId:        string;
    topicUpdateTime: number;
    topicEndTime:    number;
}

export interface Rogue1_UpgradeTickets {
    rogue_1_upgrade_ticket_all:     RogueUpgradeTicketAll;
    rogue_1_upgrade_ticket_5star:   RogueUpgradeTicket5_Star;
    rogue_1_upgrade_ticket_pioneer: Rogue1_UpgradeTicketCasterClass;
    rogue_1_upgrade_ticket_warrior: Rogue1_UpgradeTicketCasterClass;
    rogue_1_upgrade_ticket_tank:    Rogue1_UpgradeTicketCasterClass;
    rogue_1_upgrade_ticket_sniper:  Rogue1_UpgradeTicketCasterClass;
    rogue_1_upgrade_ticket_caster:  Rogue1_UpgradeTicketCasterClass;
    rogue_1_upgrade_ticket_support: Rogue1_UpgradeTicketCasterClass;
    rogue_1_upgrade_ticket_medic:   Rogue1_UpgradeTicketCasterClass;
    rogue_1_upgrade_ticket_special: Rogue1_UpgradeTicketCasterClass;
}

export interface RogueUpgradeTicket5_Star {
    id:             string;
    profession:     number;
    rarity:         number;
    professionList: string[];
    rarityList:     string[];
}

export interface RogueUpgradeTicketAll {
    id:             string;
    profession:     number;
    rarity:         string;
    professionList: string[];
    rarityList:     string[];
}

export interface Rogue1_UpgradeTicketCasterClass {
    id:             string;
    profession:     string;
    rarity:         string;
    professionList: string[];
    rarityList:     string[];
}

export interface Rogue1_VariationData {
    variation_1: Variation1;
    variation_2: Variation1;
    variation_3: Variation1;
    variation_4: Variation1;
    variation_5: Variation1;
    variation_6: Variation1;
    variation_7: Variation1;
    variation_8: Variation1;
    variation_9: Variation1;
}

export interface Variation1 {
    id:           string;
    type?:        string;
    outerName:    string;
    innerName:    string;
    functionDesc: string;
    desc:         string;
    iconId:       null | string;
    sound?:       null | string;
    buffs?:       RoguelikeBuff[];
}

export interface Rogue1_Zones {
    zone_1: Zone;
    zone_2: Zone;
    zone_3: Zone;
    zone_4: Zone;
    zone_5: Zone;
    zone_6: Zone;
}

export interface Zone {
    id:                string;
    name:              string;
    clockPerformance:  null | string;
    displayTime:       null | string;
    description:       string;
    buffDescription:   null | string;
    endingDescription: string;
    backgroundId:      string;
    zoneIconId:        string;
    isHiddenZone:      boolean;
}

export interface DetailsRogue2 {
    updates:                      Update[];
    enrolls:                      Rogue2_Enrolls;
    milestones:                   Milestone[];
    milestoneUpdates:             MilestoneUpdate[];
    grandPrizes:                  GrandPrize[];
    monthMission:                 MonthMission[];
    monthSquad:                   Rogue1_MonthSquad;
    challenges:                   Rogue2_Challenges;
    difficulties:                 Rogue1_Difficulty[];
    bankRewards:                  BankReward[];
    archiveComp:                  Rogue2_ArchiveComp;
    archiveUnlockCond:            ArchiveUnlockCond;
    detailConst:                  Rogue1_DetailConst;
    init:                         RoguelikeGameInitData[];
    stages:                       { [key: string]: Stage };
    zones:                        Rogue2_Zones;
    variation:                    BandRef;
    traps:                        { [key: string]: Rogue1__ActiveTool1 };
    recruitTickets:               Rogue2_RecruitTickets;
    upgradeTickets:               Rogue2_UpgradeTickets;
    customTickets:                CustomTickets;
    relics:                       { [key: string]: RoguelikeGameRelicData };
    relicParams:                  { [key: string]: RelicParam };
    recruitGrps:                  { [key: string]: RecruitGr };
    choices:                      { [key: string]: Choice };
    choiceScenes:                 { [key: string]: ChoiceScene };
    nodeTypeData:                 { [key: string]: BattleBoss };
    subTypeData:                  any[];
    variationData:                Rogue2_VariationData;
    charBuffData:                 CharBuffData;
    squadBuffData:                { [key: string]: Variation1 };
    taskData:                     { [key: string]: TaskDatum };
    gameConst:                    Rogue1_GameConst;
    shopDialogData:               Rogue1_ShopDialogData;
    capsuleDict:                  null;
    endings:                      Rogue2_Endings;
    battleSummeryDescriptions:    BattleSummeryDescriptions;
    battleLoadingTips:            BattleLoadingTip[];
    items:                        { [key: string]: RoguelikeGameItemData };
    bandRef:                      { [key: string]: BandRefValue };
    endingDetailList:             EndingDetailList[];
    endingRelicDetailList:        any[];
    treasures:                    Treasures;
    difficultyUpgradeRelicGroups: BandRef;
    styles:                       BandRef;
    styleConfig:                  StyleConfig;
    exploreTools:                 BandRef;
    rollNodeData:                 BandRef;
}

export interface Rogue2_ArchiveComp {
    relic:    ArchiveCompRelic;
    capsule:  null;
    trap:     FluffyTrap;
    chat:     TentacledChat;
    endbook:  FluffyEndbook;
    buff:     FluffyBuff;
    totem:    null;
    chaos:    null;
    fragment: null;
    disaster: null;
}

export interface FluffyBuff {
    buff: { [key: string]: BuffValue };
}

export interface BuffValue {
    buffId:         string;
    buffGroupIndex: number;
    innerSortId:    number;
    name:           string;
    iconId:         string;
    usage:          string;
    desc:           string;
    color:          string;
}

export interface TentacledChat {
    chat: StickyChat;
}

export interface StickyChat {
    month_chat_rogue_2_1: MonthChatRogue;
    month_chat_rogue_2_2: MonthChatRogue;
    month_chat_rogue_2_3: MonthChatRogue;
    month_chat_rogue_2_4: MonthChatRogue;
    month_chat_rogue_2_5: MonthChatRogue;
    month_chat_rogue_2_6: MonthChatRogue;
    month_chat_rogue_2_7: MonthChatRogue;
    month_chat_rogue_2_8: MonthChatRogue;
}

export interface FluffyEndbook {
    endbook: TentacledEndbook;
}

export interface TentacledEndbook {
    endbook_rogue_2_1: EndbookRogue;
    endbook_rogue_2_2: EndbookRogue;
    endbook_rogue_2_3: EndbookRogue;
    endbook_rogue_2_4: EndbookRogue;
}

export interface EndbookRogue {
    endId:                  string;
    endingId:               string;
    sortId:                 number;
    title:                  string;
    cgId:                   string;
    backBlurId:             string;
    cardId:                 string;
    hasAvg:                 boolean;
    avgId:                  string;
    clientEndbookItemDatas: ClientEndbookItemData[];
}

export interface ClientEndbookItemData {
    endBookId:   string;
    sortId:      number;
    enrollId:    null | string;
    isLast:      boolean;
    endbookName: string;
    unlockDesc:  string;
    textId:      string;
}

export interface FluffyTrap {
    trap: BandRef;
}

export interface BandRefValue {
    itemId:       string;
    iconId:       string;
    description:  string;
    bandLevel:    number;
    normalBandId: string;
}

export interface Rogue2_Challenges {
    rogue_2_challenge_01: Rogue2_Challenge01;
    rogue_2_challenge_02: Rogue2_Challenge02;
    rogue_2_challenge_03: Rogue2_Challenge03;
    rogue_2_challenge_04: Rogue2_Challenge04;
    rogue_2_challenge_05: Rogue2_Challenge05;
    rogue_2_challenge_06: Rogue2_Challenge06;
    rogue_2_challenge_07: Rogue2_Challenge07;
    rogue_2_challenge_08: Rogue2_Challenge08;
    rogue_2_challenge_09: Rogue2_Challenge09;
    rogue_2_challenge_10: Rogue2_Challenge10;
    rogue_2_challenge_11: Rogue2_Challenge11;
    rogue_2_challenge_12: Rogue2_Challenge12;
}

export interface Rogue2_Challenge01 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      null;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue2_Challenge01_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue2_Challenge01_ChallengeTasks {
    rogue_2_task_01: Rogue1_Task01_Class;
}

export interface Rogue2_Challenge02 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: string;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue2_Challenge02_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue2_Challenge02_ChallengeTasks {
    rogue_2_task_02: Rogue1_Task01_Class;
}

export interface Rogue2_Challenge03 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: string;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue2_Challenge03_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue2_Challenge03_ChallengeTasks {
    rogue_2_task_03: Rogue1_Task01_Class;
}

export interface Rogue2_Challenge04 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: string;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue2_Challenge04_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue2_Challenge04_ChallengeTasks {
    rogue_2_task_04: Rogue1_Task01_Class;
}

export interface Rogue2_Challenge05 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      null;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue2_Challenge05_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue2_Challenge05_ChallengeTasks {
    rogue_2_task_05: Rogue1_Task01_Class;
}

export interface Rogue2_Challenge06 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: string;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue2_Challenge06_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue2_Challenge06_ChallengeTasks {
    rogue_2_task_06: Rogue1_Task01_Class;
}

export interface Rogue2_Challenge07 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: string;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue2_Challenge07_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue2_Challenge07_ChallengeTasks {
    rogue_2_task_07: Rogue1_Task01_Class;
}

export interface Rogue2_Challenge08 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: string;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue2_Challenge08_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue2_Challenge08_ChallengeTasks {
    rogue_2_task_08: Rogue1_Task01_Class;
}

export interface Rogue2_Challenge09 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      null;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue2_Challenge09_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue2_Challenge09_ChallengeTasks {
    rogue_2_task_09: Rogue1_Task01_Class;
}

export interface Rogue2_Challenge10 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: string;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue2_Challenge10_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue2_Challenge10_ChallengeTasks {
    rogue_2_task_10: Rogue1_Task01_Class;
}

export interface Rogue2_Challenge11 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: string;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue2_Challenge11_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue2_Challenge11_ChallengeTasks {
    rogue_2_task_11: Rogue1_Task01_Class;
}

export interface Rogue2_Challenge12 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: string;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue2_Challenge12_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         null;
}

export interface Rogue2_Challenge12_ChallengeTasks {
    rogue_2_task_12: Rogue1_Task01_Class;
}

export interface CharBuffData {
    rogue_2_mutation_1: Variation1;
    rogue_2_mutation_2: Variation1;
    rogue_2_mutation_3: Variation1;
    rogue_2_mutation_4: Variation1;
    rogue_2_mutation_5: Variation1;
    rogue_2_mutation_6: Variation1;
    rogue_2_mutation_7: Variation1;
    rogue_2_mutation_8: Variation1;
}

export interface CustomTickets {
    rogue_2_custom_ticket_purify: Rogue2_CustomTicketPurify;
}

export interface Rogue2_CustomTicketPurify {
    id:          string;
    subType:     string;
    discardText: string;
}

export interface Rogue2_Endings {
    ro2_ending_1: RoEnding1;
    ro2_ending_2: RoEnding1;
    ro2_ending_3: RoEnding1;
    ro2_ending_4: RoEnding1;
}

export interface Rogue2_Enrolls {
    rogue_2_enroll_1: Rogue1_Enroll1_Class;
    rogue_2_enroll_2: Rogue1_Enroll1_Class;
}

export interface Rogue2_RecruitTickets {
    rogue_2_recruit_ticket_pioneer:              RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_warrior:              RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_tank:                 RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_sniper:               RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_caster:               RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_support:              RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_medic:                RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_special:              RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_pioneer_sp:           RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_warrior_sp:           RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_tank_sp:              RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_sniper_sp:            RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_caster_sp:            RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_support_sp:           RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_medic_sp:             RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_special_sp:           RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_pioneer_vip:          RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_warrior_vip:          RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_tank_vip:             RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_sniper_vip:           RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_caster_vip:           RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_support_vip:          RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_medic_vip:            RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_special_vip:          RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_double_1:             RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_double_2:             RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_double_3:             RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_double_4:             RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_quad_melee:           RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_quad_ranged:          RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_all:                  RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_5star:                RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_all_premium:          RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_quad_melee_discount:  RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_quad_ranged_discount: RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_all_discount:         RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_temp_5_up:            RoguelikeRecruitTicketFeature;
    rogue_2_recruit_ticket_temp_6_up:            RoguelikeRecruitTicketFeature;
}

export interface TaskDatum {
    taskId:        string;
    taskName:      string;
    taskDesc:      string;
    rewardSceneId: string;
    taskRarity:    string;
}

export interface Treasures {
    rogue_2_treasure: Rogue2_Treasure[];
}

export interface Rogue2_Treasure {
    treasureId: string;
    groupId:    string;
    subIndex:   number;
    name:       string;
    usage:      string;
}

export interface Rogue2_UpgradeTickets {
    rogue_2_upgrade_ticket_all:     RogueUpgradeTicketAll;
    rogue_2_upgrade_ticket_5star:   RogueUpgradeTicket5_Star;
    rogue_2_upgrade_ticket_pioneer: Rogue1_UpgradeTicketCasterClass;
    rogue_2_upgrade_ticket_warrior: Rogue1_UpgradeTicketCasterClass;
    rogue_2_upgrade_ticket_tank:    Rogue1_UpgradeTicketCasterClass;
    rogue_2_upgrade_ticket_sniper:  Rogue1_UpgradeTicketCasterClass;
    rogue_2_upgrade_ticket_caster:  Rogue1_UpgradeTicketCasterClass;
    rogue_2_upgrade_ticket_support: Rogue1_UpgradeTicketCasterClass;
    rogue_2_upgrade_ticket_medic:   Rogue1_UpgradeTicketCasterClass;
    rogue_2_upgrade_ticket_special: Rogue1_UpgradeTicketCasterClass;
}

export interface Rogue2_VariationData {
    rogue_2_variation_1: Variation1;
    rogue_2_variation_2: Variation1;
    rogue_2_variation_3: Variation1;
    rogue_2_variation_4: Variation1;
    rogue_2_variation_5: Variation1;
    rogue_2_variation_6: Variation1;
    rogue_2_variation_7: Variation1;
    rogue_2_variation_8: Variation1;
}

export interface Rogue2_Zones {
    zone_1: Zone;
    zone_2: Zone;
    zone_3: Zone;
    zone_4: Zone;
    zone_5: Zone;
    zone_6: Zone;
    zone_7: Zone;
}

export interface DetailsRogue3 {
    updates:                      Update[];
    enrolls:                      Rogue3_Enrolls;
    milestones:                   Milestone[];
    milestoneUpdates:             MilestoneUpdate[];
    grandPrizes:                  GrandPrize[];
    monthMission:                 MonthMission[];
    monthSquad:                   Rogue1_MonthSquad;
    challenges:                   Rogue3_Challenges;
    difficulties:                 Rogue1_Difficulty[];
    bankRewards:                  BankReward[];
    archiveComp:                  Rogue3_ArchiveComp;
    archiveUnlockCond:            ArchiveUnlockCond;
    detailConst:                  Rogue3_DetailConst;
    init:                         RoguelikeGameInitData[];
    stages:                       { [key: string]: Stage };
    zones:                        { [key: string]: Zone };
    variation:                    BandRef;
    traps:                        Rogue3_Traps;
    recruitTickets:               Rogue3_RecruitTickets;
    upgradeTickets:               Rogue3_UpgradeTickets;
    customTickets:                BandRef;
    relics:                       { [key: string]: RoguelikeGameRelicData };
    relicParams:                  { [key: string]: RelicParam };
    recruitGrps:                  { [key: string]: RecruitGr };
    choices:                      { [key: string]: Choice };
    choiceScenes:                 { [key: string]: ChoiceScene };
    nodeTypeData:                 { [key: string]: BattleBoss };
    subTypeData:                  SubTypeDatum[];
    variationData:                Rogue3_VariationData;
    charBuffData:                 BandRef;
    squadBuffData:                BandRef;
    taskData:                     BandRef;
    gameConst:                    Rogue3_GameConst;
    shopDialogData:               Rogue1_ShopDialogData;
    capsuleDict:                  null;
    endings:                      Rogue3_Endings;
    battleSummeryDescriptions:    BattleSummeryDescriptions;
    battleLoadingTips:            BattleLoadingTip[];
    items:                        { [key: string]: RoguelikeGameItemData };
    bandRef:                      BandRef;
    endingDetailList:             EndingDetailList[];
    endingRelicDetailList:        any[];
    treasures:                    BandRef;
    difficultyUpgradeRelicGroups: { [key: string]: DifficultyUpgradeRelicGroup };
    styles:                       Rogue3_Styles;
    styleConfig:                  StyleConfig;
    exploreTools:                 ExploreTools;
    rollNodeData:                 BandRef;
}

export interface Rogue3_ArchiveComp {
    relic:    ArchiveCompRelic;
    capsule:  null;
    trap:     FluffyTrap;
    chat:     IndigoChat;
    endbook:  StickyEndbook;
    buff:     PurpleBuff;
    totem:    ArchiveCompTotem;
    chaos:    ArchiveCompChaos;
    fragment: null;
    disaster: null;
}

export interface ArchiveCompChaos {
    chaos: { [key: string]: Chao };
}

export interface Chao {
    id:       string;
    isHidden: boolean;
    enrollId: null;
    sortId:   number;
}

export interface IndigoChat {
    chat: IndecentChat;
}

export interface IndecentChat {
    month_chat_rogue_3_1: MonthChatRogue;
    month_chat_rogue_3_2: MonthChatRogue;
    month_chat_rogue_3_3: MonthChatRogue;
    month_chat_rogue_3_4: MonthChatRogue;
    month_chat_rogue_3_5: MonthChatRogue;
    month_chat_rogue_3_6: MonthChatRogue;
    month_chat_rogue_3_7: MonthChatRogue;
    month_chat_rogue_3_8: MonthChatRogue;
}

export interface StickyEndbook {
    endbook: IndigoEndbook;
}

export interface IndigoEndbook {
    endbook_rogue_3_1: EndbookRogue;
    endbook_rogue_3_2: EndbookRogue;
    endbook_rogue_3_3: EndbookRogue;
    endbook_rogue_3_4: EndbookRogue;
}

export interface ArchiveCompTotem {
    totem: { [key: string]: TotemValue };
}

export interface TotemValue {
    id:                string;
    type:              string;
    enrollConditionId: null | string;
    sortId:            number;
}

export interface Rogue3_Challenges {
    rogue_3_challenge_01: Rogue3_Challenge01;
    rogue_3_challenge_02: Rogue3_Challenge02;
    rogue_3_challenge_03: Rogue3_Challenge03;
    rogue_3_challenge_04: Rogue3_Challenge04;
    rogue_3_challenge_05: Rogue3_Challenge05;
    rogue_3_challenge_06: Rogue3_Challenge06;
    rogue_3_challenge_07: Rogue3_Challenge07;
    rogue_3_challenge_08: Rogue3_Challenge08;
    rogue_3_challenge_09: Rogue3_Challenge09;
    rogue_3_challenge_10: Rogue3_Challenge10;
    rogue_3_challenge_11: Rogue3_Challenge11;
    rogue_3_challenge_12: Rogue3_Challenge12;
    rogue_3_challenge_13: Rogue3_Challenge13;
}

export interface Rogue3_Challenge01 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      null;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue3_Challenge01_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         string;
}

export interface Rogue3_Challenge01_ChallengeTasks {
    rogue_3_task_01_1: Rogue1_Task01_Class;
    rogue_3_task_01_2: Rogue1_Task01_Class;
}

export interface Rogue3_Challenge02 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: string;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue3_Challenge02_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         string;
}

export interface Rogue3_Challenge02_ChallengeTasks {
    rogue_3_task_02_1: Rogue1_Task01_Class;
    rogue_3_task_02_2: Rogue1_Task01_Class;
}

export interface Rogue3_Challenge03 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue3_Challenge03_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         string;
}

export interface Rogue3_Challenge03_ChallengeTasks {
    rogue_3_task_03_1: Rogue1_Task01_Class;
    rogue_3_task_03_2: Rogue1_Task01_Class;
}

export interface Rogue3_Challenge04 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue3_Challenge04_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         string;
}

export interface Rogue3_Challenge04_ChallengeTasks {
    rogue_3_task_04_1: Rogue1_Task01_Class;
    rogue_3_task_04_2: Rogue1_Task01_Class;
}

export interface Rogue3_Challenge05 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue3_Challenge05_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         string;
}

export interface Rogue3_Challenge05_ChallengeTasks {
    rogue_3_task_05_1: Rogue1_Task01_Class;
    rogue_3_task_05_2: Rogue1_Task01_Class;
}

export interface Rogue3_Challenge06 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue3_Challenge06_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         string;
}

export interface Rogue3_Challenge06_ChallengeTasks {
    rogue_3_task_06_1: Rogue1_Task01_Class;
    rogue_3_task_06_2: Rogue1_Task01_Class;
}

export interface Rogue3_Challenge07 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue3_Challenge07_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         string;
}

export interface Rogue3_Challenge07_ChallengeTasks {
    rogue_3_task_07_1: Rogue1_Task01_Class;
    rogue_3_task_07_2: Rogue1_Task01_Class;
}

export interface Rogue3_Challenge08 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: string;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue3_Challenge08_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         string;
}

export interface Rogue3_Challenge08_ChallengeTasks {
    rogue_3_task_08_1: Rogue1_Task01_Class;
    rogue_3_task_08_2: Rogue1_Task01_Class;
}

export interface Rogue3_Challenge09 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue3_Challenge09_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         string;
}

export interface Rogue3_Challenge09_ChallengeTasks {
    rogue_3_task_09_1: Rogue1_Task01_Class;
    rogue_3_task_09_2: Rogue1_Task01_Class;
}

export interface Rogue3_Challenge10 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue3_Challenge10_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         string;
}

export interface Rogue3_Challenge10_ChallengeTasks {
    rogue_3_task_10_1: Rogue1_Task01_Class;
    rogue_3_task_10_2: Rogue1_Task01_Class;
}

export interface Rogue3_Challenge11 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: string;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue3_Challenge11_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         string;
}

export interface Rogue3_Challenge11_ChallengeTasks {
    rogue_3_task_11_1: Rogue1_Task01_Class;
    rogue_3_task_11_2: Rogue1_Task01_Class;
}

export interface Rogue3_Challenge12 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue3_Challenge12_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         string;
}

export interface Rogue3_Challenge12_ChallengeTasks {
    rogue_3_task_12_1: Rogue1_Task01_Class;
    rogue_3_task_12_2: Rogue1_Task01_Class;
}

export interface Rogue3_Challenge13 {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       string;
    challengeUnlockDesc:      string;
    challengeUnlockToastDesc: null;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           Rogue3_Challenge13_ChallengeTasks;
    defaultTaskId:            string;
    rewards:                  Reward[];
    challengeStoryId:         string;
}

export interface Rogue3_Challenge13_ChallengeTasks {
    rogue_3_task_13_1: Rogue1_Task01_Class;
    rogue_3_task_13_2: Rogue1_Task01_Class;
}

export interface Rogue3_DetailConst {
    playerLevelTable:                  { [key: string]: PlayerLevelTable };
    charUpgradeTable:                  { [key: string]: CharUpgradeTable };
    difficultyUpgradeRelicDescTable:   { [key: string]: string };
    predefinedLevelTable:              { [key: string]: PredefinedLevelTable };
    tokenBpId:                         string;
    tokenOuterBuffId:                  string;
    previewedRewardsAccordingUpdateId: string;
    tipButtonName:                     string;
    collectButtonName:                 string;
    bpSystemName:                      string;
    autoSetKV:                         string;
    bpPurchaseActiveEnroll:            string;
    defaultSacrificeDesc:              string;
    defaultExpeditionSelectDesc:       string;
    gotCharBuffToast:                  string;
    gotSquadBuffToast:                 string;
    loseCharBuffToast:                 string;
    monthTeamSystemName:               string;
    battlePassUpdateName:              string;
    monthCharCardTagName:              string;
    monthTeamDescTagName:              string;
    outerBuffCompleteText:             string;
    outerProgressTextColor:            string;
    challengeTaskTargetName:           string;
    challengeTaskConditionName:        string;
    challengeTaskRewardName:           string;
    challengeTaskModeName:             string;
    challengeTaskName:                 string;
    outerBuffTokenSum:                 number;
    needAllFrontNode:                  boolean;
    showBlurBack:                      boolean;
    endingIconBorderDifficulty:        number;
    endingIconBorderCount:             number;
}

export interface PredefinedLevelTable {
    levels: { [key: string]: PlayerLevelTable };
}

export interface DifficultyUpgradeRelicGroup {
    relicData: RelicDatum[];
}

export interface RelicDatum {
    relicId:         string;
    equivalentGrade: number;
}

export interface Rogue3_Endings {
    ro3_ending_1: RoEnding1;
    ro3_ending_2: RoEnding1;
    ro3_ending_3: RoEnding1;
    ro3_ending_c: RoEnding1;
    ro3_ending_4: RoEnding1;
}

export interface Rogue3_Enrolls {
    rogue_3_enroll_1: Rogue1_Enroll1_Class;
    rogue_3_enroll_2: Rogue1_Enroll1_Class;
}

export interface ExploreTools {
    rogue_3_explore_tool_1: Rogue1__ActiveTool1;
    rogue_3_explore_tool_2: Rogue1__ActiveTool1;
    rogue_3_explore_tool_3: Rogue1__ActiveTool1;
    rogue_3_explore_tool_4: Rogue1__ActiveTool1;
    rogue_3_explore_tool_5: Rogue1__ActiveTool1;
    rogue_3_explore_tool_6: Rogue1__ActiveTool1;
}

export interface Rogue3_GameConst {
    initSceneName:                     string;
    failSceneName:                     string;
    hpItemId:                          string;
    goldItemId:                        string;
    populationItemId:                  string;
    squadCapacityItemId:               string;
    expItemId:                         string;
    initialBandShowGradeFlag:          boolean;
    bankMaxGold:                       number;
    bankCostId:                        string;
    bankDrawCount:                     number;
    bankDrawLimit:                     number;
    mimicEnemyIds:                     string[];
    bossIds:                           string[];
    goldChestTrapId:                   string;
    normBoxTrapId:                     string;
    rareBoxTrapId:                     string;
    badBoxTrapId:                      string;
    maxHpItemId:                       string;
    shieldItemId:                      string;
    keyItemId:                         string;
    chestKeyCnt:                       number;
    chestKeyItemId:                    string;
    keyColorId:                        string;
    onceNodeTypeList:                  any[];
    gpScoreRatio:                      number;
    overflowUsageSquadBuff:            string;
    specialTrapId:                     string;
    trapRewardRelicId:                 string;
    unlockRouteItemId:                 string;
    unlockRouteItemCount:              number;
    hideBattleNodeName:                string;
    hideBattleNodeDescription:         string;
    hideNonBattleNodeName:             string;
    hideNonBattleNodeDescription:      string;
    charSelectExpeditionConflictToast: string;
    itemDropTagDict:                   FluffyItemDropTagDict;
    expeditionReturnDescCureUpgrade:   null;
    expeditionReturnDescUpgrade:       string;
    expeditionReturnDescCure:          null;
    expeditionReturnDesc:              string;
    expeditionSelectDescFormat:        string;
    expeditionReturnDescItem:          string;
    expeditionReturnRewardBlackList:   string[];
    travelLeaveToastFormat:            null;
    charSelectTravelConflictToast:     null;
    travelReturnDescUpgrade:           null;
    travelReturnDesc:                  null;
    travelReturnDescItem:              null;
    traderReturnTitle:                 null;
    traderReturnDesc:                  null;
    gainBuffDiffGrade:                 number;
    dsPredictTips:                     string;
    dsBuffActiveTips:                  string;
    totemDesc:                         string;
    relicDesc:                         string;
    buffDesc:                          string;
    refreshNodeItemId:                 null;
    portalZones:                       string[];
    exploreExpOnKill:                  string;
}

export interface FluffyItemDropTagDict {
    TREASURE:     string;
    TOTEM:        string;
    EXPLORE_TOOL: string;
}

export interface Rogue3_RecruitTickets {
    rogue_3_recruit_ticket_pioneer:              RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_warrior:              RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_tank:                 RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_sniper:               RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_caster:               RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_support:              RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_medic:                RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_special:              RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_pioneer_sp:           RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_warrior_sp:           RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_tank_sp:              RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_sniper_sp:            RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_caster_sp:            RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_support_sp:           RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_medic_sp:             RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_special_sp:           RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_pioneer_vip:          RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_warrior_vip:          RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_tank_vip:             RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_sniper_vip:           RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_caster_vip:           RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_support_vip:          RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_medic_vip:            RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_special_vip:          RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_double_1:             RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_double_2:             RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_double_3:             RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_double_4:             RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_quad_melee:           RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_quad_ranged:          RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_all:                  RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_5star:                RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_all_premium:          RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_quad_melee_discount:  RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_quad_ranged_discount: RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_all_discount:         RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_temp_5_up:            RoguelikeRecruitTicketFeature;
    rogue_3_recruit_ticket_temp_6_up:            RoguelikeRecruitTicketFeature;
}

export interface Rogue3_Styles {
    rogue_3_style_default:   Rogue3_StyleChallengeClass;
    rogue_3_style_challenge: Rogue3_StyleChallengeClass;
}

export interface Rogue3_StyleChallengeClass {
    styleId:     string;
    styleConfig: number;
}

export interface SubTypeDatum {
    eventType:   string;
    subTypeId:   number;
    iconId:      string;
    name:        null;
    description: string;
}

export interface Rogue3_Traps {
    rogue_3_active_tool_1: Rogue1__ActiveTool1;
    rogue_3_active_tool_2: Rogue1__ActiveTool1;
    rogue_3_active_tool_3: Rogue1__ActiveTool1;
    rogue_3_active_tool_4: Rogue1__ActiveTool1;
    rogue_3_active_tool_5: Rogue1__ActiveTool1;
    rogue_3_active_tool_6: Rogue1__ActiveTool1;
}

export interface Rogue3_UpgradeTickets {
    rogue_3_upgrade_ticket_all:     RogueUpgradeTicketAll;
    rogue_3_upgrade_ticket_5star:   RogueUpgradeTicket5_Star;
    rogue_3_upgrade_ticket_pioneer: Rogue1_UpgradeTicketCasterClass;
    rogue_3_upgrade_ticket_warrior: Rogue1_UpgradeTicketCasterClass;
    rogue_3_upgrade_ticket_tank:    Rogue1_UpgradeTicketCasterClass;
    rogue_3_upgrade_ticket_sniper:  Rogue1_UpgradeTicketCasterClass;
    rogue_3_upgrade_ticket_caster:  Rogue1_UpgradeTicketCasterClass;
    rogue_3_upgrade_ticket_support: Rogue1_UpgradeTicketCasterClass;
    rogue_3_upgrade_ticket_medic:   Rogue1_UpgradeTicketCasterClass;
    rogue_3_upgrade_ticket_special: Rogue1_UpgradeTicketCasterClass;
}

export interface Rogue3_VariationData {
    variation_1:       Variation1;
    variation_2:       Variation1;
    variation_3:       Variation1;
    variation_4:       Variation1;
    variation_5:       Variation1;
    variation_6:       Variation1;
    variation_shop:    Variation1;
    variation_shelter: Variation1;
}

export interface DetailsRogue4 {
    updates:                      Update[];
    enrolls:                      BandRef;
    milestones:                   Milestone[];
    milestoneUpdates:             MilestoneUpdate[];
    grandPrizes:                  GrandPrize[];
    monthMission:                 MonthMission[];
    monthSquad:                   Rogue4_MonthSquad;
    challenges:                   BandRef;
    difficulties:                 Rogue1_Difficulty[];
    bankRewards:                  BankReward[];
    archiveComp:                  Rogue4_ArchiveComp;
    archiveUnlockCond:            ArchiveUnlockCond;
    detailConst:                  Rogue4_DetailConst;
    init:                         RoguelikeGameInitData[];
    stages:                       { [key: string]: Stage };
    zones:                        { [key: string]: Zone };
    variation:                    BandRef;
    traps:                        Rogue4_Traps;
    recruitTickets:               {[key:string]:RoguelikeRecruitTicketFeature};
    upgradeTickets:               Rogue4_UpgradeTickets;
    customTickets:                BandRef;
    relics:                       { [key: string]: RoguelikeGameRelicData };
    relicParams:                  { [key: string]: RelicParam };
    recruitGrps:                  { [key: string]: RecruitGr };
    choices:                      { [key: string]: Choice };
    choiceScenes:                 { [key: string]: ChoiceScene };
    nodeTypeData:                 { [key: string]: BattleBoss };
    subTypeData:                  any[];
    variationData:                BandRef;
    charBuffData:                 BandRef;
    squadBuffData:                BandRef;
    taskData:                     BandRef;
    gameConst:                    Rogue4_GameConst;
    shopDialogData:               Rogue4_ShopDialogData;
    capsuleDict:                  null;
    endings:                      Rogue4_Endings;
    battleSummeryDescriptions:    BattleSummeryDescriptions;
    battleLoadingTips:            BattleLoadingTip[];
    items:                        { [key: string]: RoguelikeGameItemData };
    bandRef:                      { [key: string]: BandRefValue };
    endingDetailList:             EndingDetailList[];
    endingRelicDetailList:        EndingRelicDetailList[];
    treasures:                    BandRef;
    difficultyUpgradeRelicGroups: { [key: string]: DifficultyUpgradeRelicGroup };
    styles:                       Rogue4_Styles;
    styleConfig:                  StyleConfig;
    exploreTools:                 BandRef;
    rollNodeData:                 RollNodeData;
}

export interface Rogue4_ArchiveComp {
    relic:    ArchiveCompRelic;
    capsule:  null;
    trap:     FluffyTrap;
    chat:     HilariousChat;
    endbook:  IndecentEndbook;
    buff:     PurpleBuff;
    totem:    null;
    chaos:    null;
    fragment: ArchiveCompFragment;
    disaster: ArchiveCompDisaster;
}

export interface HilariousChat {
    chat: AmbitiousChat;
}

export interface AmbitiousChat {
    month_chat_rogue_4_1: MonthChatRogue;
}

export interface ArchiveCompDisaster {
    disasters: { [key: string]: DisasterValue };
}

export interface DisasterValue {
    disasterId:        string;
    sortId:            number;
    enrollConditionId: null;
    picSmallId:        string;
    picBigActiveId:    string;
    picBigInactiveId:  string;
}

export interface IndecentEndbook {
    endbook: HilariousEndbook;
}

export interface HilariousEndbook {
    endbook_rogue_4_1: EndbookRogue;
    endbook_rogue_4_2: EndbookRogue;
    endbook_rogue_4_3: EndbookRogue;
}

export interface ArchiveCompFragment {
    fragment: { [key: string]: FragmentValue };
}

export interface FragmentValue {
    fragmentId:        string;
    sortId:            number;
    enrollConditionId: null;
}

export interface Rogue4_DetailConst {
    playerLevelTable:                  { [key: string]: PlayerLevelTable };
    charUpgradeTable:                  { [key: string]: CharUpgradeTable };
    difficultyUpgradeRelicDescTable:   { [key: string]: string };
    predefinedLevelTable:              BandRef;
    tokenBpId:                         string;
    tokenOuterBuffId:                  string;
    previewedRewardsAccordingUpdateId: string;
    tipButtonName:                     string;
    collectButtonName:                 string;
    bpSystemName:                      string;
    autoSetKV:                         string;
    bpPurchaseActiveEnroll:            null;
    defaultSacrificeDesc:              string;
    defaultExpeditionSelectDesc:       string;
    gotCharBuffToast:                  string;
    gotSquadBuffToast:                 string;
    loseCharBuffToast:                 string;
    monthTeamSystemName:               string;
    battlePassUpdateName:              string;
    monthCharCardTagName:              string;
    monthTeamDescTagName:              string;
    outerBuffCompleteText:             string;
    outerProgressTextColor:            string;
    challengeTaskTargetName:           string;
    challengeTaskConditionName:        string;
    challengeTaskRewardName:           string;
    challengeTaskModeName:             string;
    challengeTaskName:                 string;
    outerBuffTokenSum:                 number;
    needAllFrontNode:                  boolean;
    showBlurBack:                      boolean;
    endingIconBorderDifficulty:        number;
    endingIconBorderCount:             number;
}

export interface EndingRelicDetailList {
    relicId:          string;
    summaryEventText: string;
}

export interface Rogue4_Endings {
    ro4_ending_1: RoEnding1;
    ro4_ending_2: RoEnding1;
    ro4_ending_3: RoEnding1;
}

export interface Rogue4_GameConst {
    initSceneName:                     string;
    failSceneName:                     string;
    hpItemId:                          string;
    goldItemId:                        string;
    populationItemId:                  string;
    squadCapacityItemId:               string;
    expItemId:                         string;
    initialBandShowGradeFlag:          boolean;
    bankMaxGold:                       number;
    bankCostId:                        string;
    bankDrawCount:                     number;
    bankDrawLimit:                     number;
    mimicEnemyIds:                     string[];
    bossIds:                           string[];
    goldChestTrapId:                   string;
    normBoxTrapId:                     string;
    rareBoxTrapId:                     string;
    badBoxTrapId:                      string;
    maxHpItemId:                       string;
    shieldItemId:                      string;
    keyItemId:                         string;
    chestKeyCnt:                       number;
    chestKeyItemId:                    string;
    keyColorId:                        string;
    onceNodeTypeList:                  any[];
    gpScoreRatio:                      number;
    overflowUsageSquadBuff:            string;
    specialTrapId:                     string;
    trapRewardRelicId:                 string;
    unlockRouteItemId:                 string;
    unlockRouteItemCount:              number;
    hideBattleNodeName:                string;
    hideBattleNodeDescription:         string;
    hideNonBattleNodeName:             string;
    hideNonBattleNodeDescription:      string;
    charSelectExpeditionConflictToast: string;
    itemDropTagDict:                   TentacledItemDropTagDict;
    expeditionReturnDescCureUpgrade:   null;
    expeditionReturnDescUpgrade:       string;
    expeditionReturnDescCure:          null;
    expeditionReturnDesc:              string;
    expeditionSelectDescFormat:        string;
    expeditionReturnDescItem:          string;
    expeditionReturnRewardBlackList:   string[];
    travelLeaveToastFormat:            string;
    charSelectTravelConflictToast:     string;
    travelReturnDescUpgrade:           string;
    travelReturnDesc:                  string;
    travelReturnDescItem:              string;
    traderReturnTitle:                 string;
    traderReturnDesc:                  string;
    gainBuffDiffGrade:                 number;
    dsPredictTips:                     string;
    dsBuffActiveTips:                  string;
    totemDesc:                         null;
    relicDesc:                         string;
    buffDesc:                          string;
    refreshNodeItemId:                 string;
    portalZones:                       string[];
    exploreExpOnKill:                  string;
}

export interface TentacledItemDropTagDict {
    TREASURE:     string;
    EXPLORE_TOOL: string;
}

export interface Rogue4_MonthSquad {
    month_team_1: MonthTeam;
}


export interface RollNodeData {
    zone_1:                Zone1;
    zone_2:                ZonePortalRevival3_Class;
    zone_3:                ZonePortalRevival3_Class;
    zone_4:                ZonePortalRevival3_Class;
    zone_5:                ZonePortalRevival3_Class;
    zone_6:                ZonePortalRevival3_Class;
    zone_portal_normal_1:  ZonePortal;
    zone_portal_normal_2:  ZonePortal;
    zone_portal_normal_3:  ZonePortal;
    zone_portal_normal_4:  ZonePortal;
    zone_portal_normal_5:  ZonePortal;
    zone_portal_normal_6:  ZonePortal;
    zone_portal_revival_3: ZonePortalRevival3_Class;
    zone_portal_revival_4: ZonePortalRevival3_Class;
    zone_portal_revival_5: ZonePortalRevival3_Class;
    zone_portal_travel_1:  ZonePortalRevival3_Class;
    zone_portal_end_1:     ZonePortal;
    zone_portal_end_2:     ZonePortal;
}

export interface Zone1 {
    zoneId: string;
    groups: Zone1_Groups;
}

export interface Zone1_Groups {
    BATTLE_NORMAL: BattleElite;
    BATTLE_ELITE:  BattleElite;
    INCIDENT:      BattleElite;
    BATTLE_SHOP:   BattleElite;
}

export interface BattleElite {
    nodeType: string;
}

export interface ZonePortalRevival3_Class {
    zoneId: string;
    groups: Zone2_Groups;
}

export interface Zone2_Groups {
    BATTLE_NORMAL:  BattleElite;
    BATTLE_ELITE:   BattleElite;
    INCIDENT:       BattleElite;
    REST:           BattleElite;
    SACRIFICE?:     BattleElite;
    EXPEDITION:     BattleElite;
    BATTLE_SHOP:    BattleElite;
    WISH:           BattleElite;
    ENTERTAINMENT?: BattleElite;
    DUEL?:          BattleElite;
}

export interface ZonePortal {
    zoneId: string;
    groups: ZonePortalEnd1_Groups;
}

export interface ZonePortalEnd1_Groups {
    BATTLE_NORMAL: BattleElite;
    BATTLE_ELITE:  BattleElite;
    REST:          BattleElite;
    EXPEDITION:    BattleElite;
    DUEL:          BattleElite;
    WISH:          BattleElite;
}

export interface Rogue4_ShopDialogData {
    types: FluffyTypes;
}

export interface FluffyTypes {
    BUY_SELECT:         BuySelect;
    BANK_ENTRY:         BankEntry;
    BANK_INVEST:        BankEntry;
    BANK_WITHDRAWAL:    BankEntry;
    BANK_FAULTY:        BankEntry;
    BANK_REWARD_UNLOCK: BankEntry;
    OUTER_NORMAL:       BankEntry;
    OUTER_REWARD:       BankEntry;
    FIGHT_BOSS:         BankEntry;
    RECYCLE_SELECT:     BankEntry;
    RECYCLE_CONFIRM:    BankEntry;
    BUY_CONFIRM:        BankEntry;
    RECYCLE_CHANGE:     BankEntry;
}

export interface Rogue4_Styles {
    rogue_4_style_default:   Rogue3_StyleChallengeClass;
    rogue_4_style_challenge: Rogue3_StyleChallengeClass;
}

export interface Rogue4_Traps {
    rogue_4_active_tool_1: Rogue1__ActiveTool1;
    rogue_4_active_tool_2: Rogue1__ActiveTool1;
    rogue_4_active_tool_3: Rogue1__ActiveTool1;
    rogue_4_active_tool_4: Rogue1__ActiveTool1;
    rogue_4_active_tool_5: Rogue1__ActiveTool1;
    rogue_4_active_tool_6: Rogue1__ActiveTool1;
}

export interface Rogue4_UpgradeTickets {
    rogue_4_upgrade_ticket_all:     RogueUpgradeTicketAll;
    rogue_4_upgrade_ticket_5star:   RogueUpgradeTicket5_Star;
    rogue_4_upgrade_ticket_pioneer: Rogue1_UpgradeTicketCasterClass;
    rogue_4_upgrade_ticket_warrior: Rogue1_UpgradeTicketCasterClass;
    rogue_4_upgrade_ticket_tank:    Rogue1_UpgradeTicketCasterClass;
    rogue_4_upgrade_ticket_sniper:  Rogue1_UpgradeTicketCasterClass;
    rogue_4_upgrade_ticket_caster:  Rogue1_UpgradeTicketCasterClass;
    rogue_4_upgrade_ticket_support: Rogue1_UpgradeTicketCasterClass;
    rogue_4_upgrade_ticket_medic:   Rogue1_UpgradeTicketCasterClass;
    rogue_4_upgrade_ticket_special: Rogue1_UpgradeTicketCasterClass;
}

export interface Modules {
    rogue_1: ModulesRogue1;
    rogue_2: ModulesRogue1;
    rogue_3: ModulesRogue1;
    rogue_4: ModulesRogue1;
}

export interface ModulesRogue1 {
    moduleTypes: string[];
    sanCheck:    SANCheck | null;
    dice:        Dice | null;
    chaos:       Rogue1_Chaos | null;
    totemBuff:   TotemBuff | null;
    vision:      Vision | null;
    fragment:    Rogue1_Fragment | null;
    disaster:    Rogue1_Disaster | null;
    nodeUpgrade: NodeUpgrade | null;
}

export interface Rogue1_Chaos {
    chaosDatas:    { [key: string]: ChaosData };
    chaosRanges:   ChaosRange[];
    levelInfoDict: LevelInfoDict;
    moduleConsts:  ChaosModuleConsts;
}

export interface ChaosData {
    chaosId:      string;
    level:        number;
    nextChaosId:  null | string;
    prevChaosId:  null | string;
    iconId:       string;
    name:         string;
    functionDesc: string;
    desc:         string;
    sound:        string;
    sortId:       number;
}

export interface ChaosRange {
    chaosMax:           number;
    chaosDungeonEffect: string;
}

export interface LevelInfoDict {
    rule_1: { [key: string]: Rule };
    rule_2: { [key: string]: Rule };
    rule_3: { [key: string]: Rule };
}

export interface Rule {
    chaosLevelBeginNum: number;
    chaosLevelEndNum:   number;
}

export interface ChaosModuleConsts {
    maxChaosLevel:           number;
    maxChaosSlot:            number;
    chaosNotMaxDescription:  string;
    chaosMaxDescription:     string;
    chaosPredictDescription: string;
}

export interface Dice {
    dice:           { [key: string]: Die };
    diceEvents:     { [key: string]: DiceEvent };
    diceChoices:    DiceChoices;
    diceRuleGroups: { [key: string]: DiceRuleGroup };
    dicePredefines: DicePredefine[];
}

export interface Die {
    diceId:        string;
    description:   string;
    isUpgradeDice: number;
    upgradeDiceId: null | string;
    diceFaceCount: number;
    battleDiceId:  string;
}

export interface DiceChoices {
    choice_ro2_wish_1:     string;
    choice_ro2_wish_2:     string;
    choice_ro2_wish_3:     string;
    choice_ro2_wish_4:     string;
    choice_ro2_wish_5:     string;
    choice_ro2_wish_6:     string;
    choice_ro2_wish_7:     string;
    choice_ro2_recruit1_3: string;
    choice_ro2_9_1:        string;
    choice_ro2_9_3:        string;
    choice_ro2_9_4:        string;
    choice_ro2_9_5:        string;
    choice_ro2_9_6:        string;
    choice_ro2_9_7:        string;
    choice_ro2_9_8:        string;
    choice_ro2_9_9:        string;
    choice_ro2_9_10:       string;
    choice_ro2_9_11:       string;
    choice_ro2_9_12:       string;
    choice_ro2_king_1:     string;
    choice_ro2_king_3:     string;
    choice_ro2_liar1_1:    string;
    choice_ro2_bossa1_2:   string;
}

export interface DiceEvent {
    dicePointMax:    number;
    diceResultClass: string;
    diceGroupId:     string;
    diceEventId:     string;
    resultDesc:      string;
    showType:        string;
    canReroll:       boolean;
    diceEndingScene: string;
    diceEndingDesc:  string;
    sound:           string;
}

export interface DicePredefine {
    modeId:           string;
    modeGrade:        number;
    predefinedId:     null | string;
    initialDiceCount: number;
}

export interface DiceRuleGroup {
    ruleGroupId: string;
    minGoodNum:  number;
}

export interface Rogue1_Disaster {
    disasterData: { [key: string]: DisasterDatum };
}

export interface DisasterDatum {
    id:           string;
    iconId:       string;
    toastIconId:  string;
    level:        number;
    name:         string;
    levelName:    string;
    type:         string;
    functionDesc: string;
    desc:         string;
    sound:        null;
}

export interface Rogue1_Fragment {
    fragmentData:       { [key: string]: FragmentDatum };
    fragmentTypeData:   FragmentTypeData;
    moduleConsts:       FragmentModuleConsts;
    fragmentBuffData:   { [key: string]: FragmentBuffDatum };
    alchemyData:        { [key: string]: AlchemyDatum };
    alchemyFormulaData: { [key: string]: AlchemyFormulaDatum };
    fragmentLevelData:  { [key: string]: FragmentLevelDatum };
}

export interface AlchemyDatum {
    fragmentTypeList:  string[];
    fragmentSquareSum: number;
    poolRarity:        string;
    relicProp:         number;
    shieldProp:        number;
    populationProp:    number;
}

export interface AlchemyFormulaDatum {
    fragmentIds:    string[];
    rewardId:       string;
    rewardCount:    number;
    rewardItemType: string;
}

export interface FragmentBuffDatum {
    itemId:   string;
    maskType: string;
    desc:     null | string;
}

export interface FragmentDatum {
    id:     string;
    type:   string;
    value:  number;
    weight: number;
}

export interface FragmentLevelDatum {
    weightUp: number;
}

export interface FragmentTypeData {
    WISH:        Idea;
    INSPIRATION: Idea;
    IDEA:        Idea;
}

export interface Idea {
    type:       string;
    typeName:   string;
    typeDesc:   string;
    typeIconId: string;
}

export interface FragmentModuleConsts {
    weightStatusSafeDesc:            string;
    weightStatusLimitDesc:           string;
    weightStatusOverweightDesc:      string;
    charWeightSlot:                  number;
    limitWeightThresholdValue:       number;
    overWeightThresholdValue:        number;
    maxAlchemyField:                 number;
    maxAlchemyCount:                 number;
    fragmentBagWeightLimitTips:      string;
    fragmentBagWeightOverWeightTips: string;
    weightUpgradeToastFormat:        string;
}

export interface NodeUpgrade {
    nodeUpgradeDataMap: NodeUpgradeDataMap;
}

export interface NodeUpgradeDataMap {
    REST:        Alchemy;
    BATTLE_SHOP: Alchemy;
    ALCHEMY:     Alchemy;
}

export interface Alchemy {
    nodeType:     string;
    sortId:       number;
    permItemList: PermItemList[];
    tempItemList: TempItemList[];
}

export interface PermItemList {
    upgradeId:     string;
    nodeType:      string;
    nodeLevel:     number;
    costItemId:    string;
    costItemCount: number;
    desc:          string;
    nodeName:      string;
}

export interface TempItemList {
    upgradeId:     string;
    nodeType:      string;
    sortId:        number;
    costItemId:    string;
    costItemCount: number;
    desc:          string;
}

export interface SANCheck {
    sanRanges:    SANRange[];
    moduleConsts: SANCheckModuleConsts;
}

export interface SANCheckModuleConsts {
    sanDecreaseToast: string;
}

export interface SANRange {
    sanMax:           number;
    diceGroupId:      string;
    description:      string;
    sanDungeonEffect: string;
    sanEffectRank:    string;
    sanEndingDesc:    null;
}

export interface TotemBuff {
    totemBuffDatas: { [key: string]: TotemBuffData };
    subBuffs:       SubBuffs;
    moduleConsts:   TotemBuffModuleConsts;
}

export interface TotemBuffModuleConsts {
    totemPredictDescription:    string;
    colorCombineDesc:           ColorCombineDesc;
    bossCombineDesc:            string;
    battleNoPredictDescription: string;
    shopNoGoodsDescription:     string;
}

export interface ColorCombineDesc {
    RED:   string;
    GREEN: string;
    BLUE:  string;
}

export interface SubBuffs {
    rogue_3_totem_enchant_1: Rogue3__TotemEnchant;
    rogue_3_totem_enchant_2: Rogue3__TotemEnchant;
    rogue_3_totem_enchant_3: Rogue3__TotemEnchant;
    rogue_3_totem_enchant_4: Rogue3__TotemEnchant;
}

export interface Rogue3__TotemEnchant {
    subBuffId:    string;
    name:         string;
    desc:         string;
    combinedDesc: string;
    info:         string;
}

export interface TotemBuffData {
    totemId:                  string;
    color:                    string;
    pos:                      string;
    rhythm:                   string;
    normalDesc:               string;
    synergyDesc:              string;
    archiveDesc:              string;
    combineGroupName:         string;
    bgIconId:                 string;
    isManual:                 boolean;
    linkedNodeTypeData:       LinkedNodeTypeData;
    distanceMin:              number;
    distanceMax:              number;
    vertPassable:             boolean;
    expandLength:             number;
    onlyForVert:              boolean;
    portalLinkedNodeTypeData: LinkedNodeTypeData;
}

export interface LinkedNodeTypeData {
    effectiveNodeTypes: string[];
    blurNodeTypes:      string[];
}

export interface Vision {
    visionDatas:   { [key: string]: VisionData };
    visionChoices: { [key: string]: VisionChoice };
    moduleConsts:  VisionModuleConsts;
}

export interface VisionModuleConsts {
    maxVision:              number;
    totemBottomDescription: string;
    chestBottomDescription: string;
    goodsBottomDescription: string;
}

export interface VisionChoice {
    value: number;
    type:  string;
}

export interface VisionData {
    sightNum:   number;
    level:      number;
    canForesee: boolean;
    dividedDis: number;
    status:     string;
    clr:        string;
    desc1:      string;
    desc2:      string;
    icon:       string;
}

export interface Topics {
    rogue_1: TopicsRogue1;
    rogue_2: TopicsRogue1;
    rogue_3: TopicsRogue1;
    rogue_4: TopicsRogue1;
}

export interface TopicsRogue1 {
    id:                        string;
    name:                      string;
    startTime:                 number;
    disappearTimeOnMainScreen: number;
    sort:                      number;
    showMedalId:               string;
    medalGroupId:              string;
    fullStoredTime:            number;
    lineText:                  string;
    homeEntryDisplayData:      HomeEntryDisplayDatum[];
    moduleTypes:               string[];
    config:                    Config;
}

export interface Config {
    loadCharCardPlugin:        boolean;
    webBusType:                string;
    monthChatTrigType:         string;
    loadRewardHpDecoPlugin:    boolean;
    loadRewardExtraInfoPlugin: boolean;
}

export interface HomeEntryDisplayDatum {
    topicId:   string;
    displayId: string;
    startTs:   number;
    endTs:     number;
}
