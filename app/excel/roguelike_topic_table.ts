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
    recruitType: RecruitType;
}

export type RecruitType = "FREE" | "THIRD_LOW" | "THIRD";

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
    displayForm: DisplayForm;
    tokenDesc:   string;
}

export type DisplayForm = "PERCENTAGE" | "ABSOLUTE_VAL";

export interface Rogue1_Development {
    buffId:          string;
    sortId:          number;
    nodeType:        PurpleNodeType;
    nextNodeId:      string[];
    frontNodeId:     string[];
    tokenCost:       number;
    buffName:        string;
    buffIconId:      BuffIconID;
    buffTypeName:    string;
    buffDisplayInfo: BuffDisplayInfo[];
}

export interface BuffDisplayInfo {
    displayType: string;
    displayNum:  number;
    displayForm: DisplayForm;
    tokenDesc:   string;
    sortId:      number;
}

export type BuffIconID = "rogue_1_grow_icon_attack" | "rogue_1_grow_icon_def" | "rogue_1_grow_icon_hp" | "rogue_1_grow_icon_gold" | "rogue_1_grow_icon_mixed";

export type PurpleNodeType = "BRANCH" | "KEY";

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
    enrollId:  BpPurchaseActiveEnroll | null;
}

export type BpPurchaseActiveEnroll = "rogue_1_enroll_2" | "rogue_2_enroll_2" | "rogue_3_enroll_2" | "";

export interface DevelopmentRawTextGroup {
    nodeIdList:    string[];
    useLevelMark?: boolean;
    groupIconId:   string;
    useUpBreak?:   boolean;
    sortId:        number;
}

export interface Rogue2_Development {
    buffId:          string;
    nodeType:        FluffyNodeType;
    frontNodeId:     string[];
    nextNodeId:      string[];
    positionP:       number;
    positionR:       number;
    tokenCost:       number;
    buffName:        string;
    buffIconId:      string;
    effectType:      EffectType;
    rawDesc:         string;
    buffDisplayInfo: BuffDisplayInfo[];
    enrollId:        BpPurchaseActiveEnroll | null;
}

export type EffectType = "BUFF" | "RAW_TEXT_EFFECT" | "RAW_TEXT_BAND";

export type FluffyNodeType = "SMALL" | "NORMAL" | "LARGE_RHODES" | "LARGE_ABYSSAL" | "LARGE_IBERIA";

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
    nodeType:        TentacledNodeType;
    frontNodeId:     string[];
    nextNodeId:      string[];
    positionRow:     number;
    positionOrder:   number;
    tokenCost:       number;
    buffName:        string;
    buffIconId?:     string;
    effectType:      EffectType;
    rawDesc:         string[];
    buffDisplayInfo: BuffDisplayInfo[];
    groupId:         GroupID;
    enrollId:        null;
    activeIconId?:   string;
    inactiveIconId?: string;
    bottomIconId?:   string;
}

export type GroupID = "group_1" | "group_2" | "group_3" | "group_4";

export type TentacledNodeType = "DIFFICULTY" | "NORMAL" | "KEY";

export interface Rogue3_DevelopmentsDifficultyNodeInfos {
    rogue_3_difficulty_1: Rogue3__Difficulty;
    rogue_3_difficulty_2: Rogue3__Difficulty;
    rogue_3_difficulty_3: Rogue3__Difficulty;
}

export interface Rogue3__Difficulty {
    buffId:      Rogue3_Difficulty1_BuffID;
    nodeMap:     Rogue3_Difficulty1_NodeMap[];
    enableGrade: number;
}

export type Rogue3_Difficulty1_BuffID = "rogue_3_difficulty_1" | "rogue_3_difficulty_2" | "rogue_3_difficulty_3";

export interface Rogue3_Difficulty1_NodeMap {
    frontNode: string;
    nextNode:  string;
}

export interface PurpleDifficulty {
    modeDifficulty: Mode;
    grade:          number;
    totemProb:      number;
    relicDevLevel:  PurpleRelicDevLevel | null;
    buffs:          Rogue3_Difficulty1_BuffID[] | null;
    buffDesc:       string[];
}

export type Mode = "NORMAL" | "MONTH_TEAM" | "CHALLENGE" | "EASY" | "HARD";

export type PurpleRelicDevLevel = "常态化" | "高寒化" | "冻土化" | "极地化";

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
    buffId:      Rogue4_Difficulty1_BuffID;
    nodeMap:     Rogue4_Difficulty1_NodeMap[];
    enableGrade: number;
    enableDesc:  string;
    lightId:     string;
    decoId:      null;
}

export type Rogue4_Difficulty1_BuffID = "rogue_4_difficulty_1" | "rogue_4_difficulty_2" | "rogue_4_difficulty_3";

export interface Rogue4_Difficulty1_NodeMap {
    frontNodes: string[];
    nextNode:   string;
}

export interface FluffyDifficulty {
    modeDifficulty:        Mode;
    grade:                 number;
    leftDisasterDesc:      LeftDisasterDesc;
    leftOverweightDesc:    LeftOverweightDesc;
    relicDevLevel:         FluffyRelicDevLevel;
    weightStatusLimitDesc: WeightStatusLimitDesc;
    buffs:                 Rogue4_Difficulty1_BuffID[] | null;
    buffDesc:              string[];
}

export type LeftDisasterDesc = "成型期" | "扩张期" | "鼎盛期";

export type LeftOverweightDesc = "轻松" | "标准" | "沉重";

export type FluffyRelicDevLevel = "实在的" | "巧思的" | "幻想的" | "架空的";

export type WeightStatusLimitDesc = "每前进一步，失去1点目标生命（不会使目标生命低于1）" | "每前进一步，失去1点目标生命（不会使目标生命低于1），进入战斗时，所有单位部署费用+2" | "每前进一步，失去1点目标生命（不会使目标生命低于1），进入战斗时，所有单位部署费用+3";

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
    init:                         Init[];
    stages:                       { [key: string]: Stage };
    zones:                        Rogue1_Zones;
    variation:                    BandRef;
    traps:                        Rogue1_Traps;
    recruitTickets:               Rogue1_RecruitTickets;
    upgradeTickets:               Rogue1_UpgradeTickets;
    customTickets:                BandRef;
    relics:                       { [key: string]: Rogue1_Relic };
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
    items:                        { [key: string]: Item };
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
    enrollId:     BpPurchaseActiveEnroll | null;
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
    archiveType: ArchiveType;
    enrollId:    BpPurchaseActiveEnroll | null;
}

export type ArchiveType = "AVG" | "MUSIC" | "PIC" | "ENDBOOK";

export interface UnlockCondDesc {
    archiveType: ArchiveType;
    description: UnlockCondDescDescription;
}

export type UnlockCondDescDescription = "" | "需要触发某个故事" | "继续探索以解锁";

export interface BankReward {
    rewardId:      string;
    unlockGoldCnt: number;
    rewardType:    RewardType;
    desc:          string;
}

export type RewardType = "ADD_SHOP_POS" | "UNLOCK_ITEM" | "UNLOCK_WITHDRAW" | "UNLOCK_SHOP_BATTLE";

export interface BattleLoadingTip {
    tip:      string;
    weight:   number;
    category: Category;
}

export type Category = "ALL" | "TIER_5" | "TIER_6";

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
    type:  ItemTypeEnum;
}

export type ItemTypeEnum = "MATERIAL" | "CARD_EXP" | "GOLD" | "CHAR" | "CHAR_SKIN" | "HOME_THEME" | "PLAYER_AVATAR" | "UNI_COLLECTION" | "FURN" | "HOME_BACKGROUND" | "ITEM_PACK" | "VOUCHER_SKILL_SPECIALLEVELMAX_6";

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
    titleIcon:      TitleIcon | null;
    subTypeId:      number;
    useHiddenMusic: boolean;
}

export type TitleIcon = "title_icon_task" | "title_icon_task_reward";

export interface Choice {
    id:                     string;
    title:                  string;
    description:            null | string;
    lockedCoverDesc:        null | string;
    type:                   ChoiceType;
    leftDecoType:           LeftDecoType;
    nextSceneId:            null | string;
    icon:                   IconEnum | null;
    displayData:            DisplayData;
    forceShowWhenOnlyLeave: boolean;
}

export interface DisplayData {
    type:                          DisplayDataType;
    costHintType:                  THintType;
    effectHintType:                THintType;
    funcIconId:                    IconEnum | null;
    itemId:                        null | string;
    difficultyUpgradeRelicGroupId: null;
    taskId:                        null;
}

export type THintType = "NONE" | "CHAOS" | "VISION" | "ITEM" | "EXPEDITION" | "SACRIFICE" | "SACRIFICE_TOTEM" | "FRAGMENT";

export type IconEnum = "unknown" | "leave" | "gold" | "battle" | "population" | "hp" | "relic" | "recruit" | "member" | "initial_reward_hp" | "initial_reward_population" | "initial_reward_gold" | "initial_reward_unknown" | "hpmax" | "san" | "key" | "dice" | "shield" | "adventure" | "sacrifice" | "initial_reward_shield" | "initial_reward_dice" | "teleport" | "totem" | "sacrifice_totem" | "vision" | "chaos_purify" | "fragment" | "disaster" | "weight" | "duel" | "";

export type DisplayDataType = "NORMAL" | "ITEM";

export type LeftDecoType = "NONE" | "DICE" | "TASK" | "TASK_REWARD" | "VISION";

export type ChoiceType = "TRADE_PROB" | "NEXT" | "NEXT_PROB" | "LEAVE" | "TRADE" | "EXPEDITION" | "SACRIFICE" | "TRADE_PROB_SHOW" | "TELEPORT" | "WISH" | "SACRIFICE_TOTEM";

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
    bpPurchaseActiveEnroll:            BpPurchaseActiveEnroll;
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
    modeDifficulty:       Mode;
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
    failTitle:            FailTitle;
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
    displayIconId:        DisplayIconID | null;
    hideEndingStory:      boolean;
}

export type DisplayIconID = "icon_difficulty_0" | "icon_difficulty_1" | "icon_difficulty_2" | "icon_difficulty_3";

export type FailTitle = "联系中断" | "小队解散" | "调查终止" | "暂时撤退";

export interface RuleDescReplacement {
    enrollId: BpPurchaseActiveEnroll;
    ruleDesc: string;
}

export interface EndingDetailList {
    textId:        string;
    text:          string;
    eventType:     Type;
    showType:      EndingDetailListShowType;
    choiceSceneId: null | string;
    paramList:     string[];
    otherPara1:    null;
}

export type Type = "INCIDENT" | "ENTERTAINMENT" | "BATTLE_BOSS" | "BATTLE_NORMAL" | "BATTLE_ELITE" | "REST" | "WISH" | "SACRIFICE" | "EXPEDITION" | "BATTLE_SHOP" | "PORTAL" | "STORY" | "STORY_HIDDEN" | "UNKNOWN";

export type EndingDetailListShowType = "SUM" | "SHOW_CONST" | "SHOW_CHOICE" | "SHOW_BOSS_END";

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
    icons:            IconElement[];
    priority:         number;
    changeEndingDesc: null | string;
    bossIconId:       null | string;
}

export interface IconElement {
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
    portalZones:                       PortalZone[];
    exploreExpOnKill:                  null;
}

export interface PurpleItemDropTagDict {
    TREASURE: string;
}

export type PortalZone = "zone_3" | "zone_1" | "zone_2" | "zone_4" | "zone_5" | "zone_6" | "zone_7" | "zone_secret" | "icon_zone_1" | "icon_zone_2" | "icon_zone_3" | "icon_zone_4" | "icon_zone_5" | "icon_zone_6" | "icon_zone_7" | "zone_portal_travel_1";

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

export interface Init {
    modeId:               Mode;
    modeGrade:            number;
    predefinedId:         null | string;
    predefinedStyle:      PredefinedStyle | null;
    initialBandRelic:     string[];
    initialRecruitGroup:  IconID[] | null;
    initialHp:            number;
    initialPopulation:    number;
    initialGold:          number;
    initialSquadCapacity: number;
    initialShield:        number;
    initialMaxHp:         number;
    initialKey:           number;
}

export type IconID = "recruit_group_1" | "recruit_group_2" | "recruit_group_3" | "recruit_group_random" | "recruit_group_c4" | "recruit_group_c5" | "recruit_group_m1" | "recruit_group_m2" | "recruit_group_m3" | "recruit_group_m4" | "recruit_group_m5" | "recruit_group_m6" | "recruit_group_m7" | "recruit_group_m8" | "ro3_recruit_group_c1";

export type PredefinedStyle = "rogue_3_style_default" | "rogue_3_style_challenge" | "rogue_4_style_default";

export interface Item {
    id:             string;
    name:           string;
    description:    null | string;
    usage:          string;
    obtainApproach: "在集成战略模式中获得";
    iconId:         string;
    type:           RewardItemTypeEnum;
    subType:        SubType;
    rarity:         Rarity;
    value:          number;
    sortId:         number;
    canSacrifice:   boolean;
    unlockCondDesc: null | string;
}

export type Rarity = "NORMAL" | "BORN" | "NONE" | "SUPER_RARE" | "RARE";

export type SubType = "NONE" | "CURSE" | "TEMP_TICKET" | "TOTEM_UPPER" | "TOTEM_LOWER";

export type RewardItemTypeEnum = "ACTIVE_TOOL" | "BAND" | "CAPSULE" | "EXP" | "GOLD" | "HP" | "POPULATION" | "RECRUIT_TICKET" | "RELIC" | "SQUAD_CAPACITY" | "UPGRADE_TICKET" | "CUSTOM_TICKET" | "DICE_POINT" | "DICE_TYPE" | "HPMAX" | "KEY_POINT" | "SAN_POINT" | "SHIELD" | "LOCKED_TREASURE" | "TOTEM_EFFECT" | "CHAOS" | "CHAOS_LEVEL" | "CHAOS_PURIFY" | "EXPLORE_TOOL" | "FEATURE" | "TOTEM" | "VISION" | "DISASTER" | "DISASTER_TYPE" | "ABSTRACT_DISASTER" | "FRAGMENT" | "MAX_WEIGHT";

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
    itemType:     ItemTypeEnum;
    itemCount:    number;
    isGoodPrize:  boolean;
    isGrandPrize: boolean;
}

export interface MonthMission {
    id:               string;
    taskName:         string;
    taskClass:        TaskClass;
    innerClassWeight: number;
    template:         string;
    paramList:        string[];
    desc:             string;
    tokenRewardNum:   number;
}

export type TaskClass = "C" | "B" | "A";

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
    zoneId:         PortalZone | null;
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
    id:         IconID;
    iconId:     IconID;
    name:       string;
    desc:       string;
    unlockDesc: null | string;
}

export interface Rogue1_RecruitTickets {
    rogue_1_recruit_ticket_pioneer:              Rogue1_RecruitTicketCasterClass;
    rogue_1_recruit_ticket_warrior:              Rogue1_RecruitTicketCasterClass;
    rogue_1_recruit_ticket_tank:                 Rogue1_RecruitTicketCasterClass;
    rogue_1_recruit_ticket_sniper:               Rogue1_RecruitTicketCasterClass;
    rogue_1_recruit_ticket_caster:               Rogue1_RecruitTicketCasterClass;
    rogue_1_recruit_ticket_support:              Rogue1_RecruitTicketCasterClass;
    rogue_1_recruit_ticket_medic:                Rogue1_RecruitTicketCasterClass;
    rogue_1_recruit_ticket_special:              Rogue1_RecruitTicketCasterClass;
    rogue_1_recruit_ticket_pioneer_sp:           Rogue1_RecruitTicketCasterClass;
    rogue_1_recruit_ticket_warrior_sp:           Rogue1_RecruitTicketCasterClass;
    rogue_1_recruit_ticket_tank_sp:              Rogue1_RecruitTicketCasterClass;
    rogue_1_recruit_ticket_sniper_sp:            Rogue1_RecruitTicketCasterClass;
    rogue_1_recruit_ticket_caster_sp:            Rogue1_RecruitTicketCasterClass;
    rogue_1_recruit_ticket_support_sp:           Rogue1_RecruitTicketCasterClass;
    rogue_1_recruit_ticket_medic_sp:             Rogue1_RecruitTicketCasterClass;
    rogue_1_recruit_ticket_special_sp:           Rogue1_RecruitTicketCasterClass;
    rogue_1_recruit_ticket_double_1:             Rogue1_RecruitTicketAllClass;
    rogue_1_recruit_ticket_double_2:             Rogue1_RecruitTicketAllClass;
    rogue_1_recruit_ticket_double_3:             Rogue1_RecruitTicketAllClass;
    rogue_1_recruit_ticket_double_4:             Rogue1_RecruitTicketAllClass;
    rogue_1_recruit_ticket_quad_melee:           Rogue1_RecruitTicketAllClass;
    rogue_1_recruit_ticket_quad_ranged:          Rogue1_RecruitTicketAllClass;
    rogue_1_recruit_ticket_all:                  Rogue1_RecruitTicketAllClass;
    rogue_1_recruit_ticket_5star:                RogueRecruitTicket5_Star;
    rogue_1_recruit_ticket_all_premium:          Rogue1_RecruitTicketAllClass;
    rogue_1_recruit_ticket_quad_melee_discount:  Rogue1_RecruitTicketAllClass;
    rogue_1_recruit_ticket_quad_ranged_discount: Rogue1_RecruitTicketAllClass;
    rogue_1_recruit_ticket_all_discount:         Rogue1_RecruitTicketAllClass;
}

export interface RogueRecruitTicket5_Star {
    id:              string;
    profession:      number;
    rarity:          number;
    professionList:  Profession[];
    rarityList:      RarityList[];
    extraEliteNum:   number;
    extraFreeRarity: any[];
    extraCharIds:    ExtraCharID[];
}

export type ExtraCharID = "char_504_rguard" | "char_507_rsnipe" | "char_505_rcast" | "char_506_rmedic" | "char_514_rdfend";

export type Profession = "WARRIOR" | "SNIPER" | "TANK" | "MEDIC" | "SUPPORT" | "CASTER" | "SPECIAL" | "PIONEER" | "NONE";

export type RarityList = "TIER_1" | "TIER_2" | "TIER_3" | "TIER_4" | "TIER_5" | "TIER_6";

export interface Rogue1_RecruitTicketAllClass {
    id:              string;
    profession:      number;
    rarity:          Category;
    professionList:  Profession[];
    rarityList:      RarityList[];
    extraEliteNum:   number;
    extraFreeRarity: any[];
    extraCharIds:    ExtraCharID[];
}

export interface Rogue1_RecruitTicketCasterClass {
    id:              string;
    profession:      Profession;
    rarity:          Category;
    professionList:  Profession[];
    rarityList:      RarityList[];
    extraEliteNum:   number;
    extraFreeRarity: RarityList[];
    extraCharIds:    ExtraCharID[];
}

export interface RelicParam {
    id:                 string;
    checkCharBoxTypes:  CheckCharBoxType[];
    checkCharBoxParams: CheckCharBoxParam[];
}

export interface CheckCharBoxParam {
    valueProfessionMask: Profession;
    valueStrs:           string[] | null;
    valueInt:            number;
}

export type CheckCharBoxType = "PROFESSION" | "SUB_PROFESSION" | "UPGRADE";

export interface Rogue1_Relic {
    id:    string;
    buffs: RelicBuff[];
}

export interface RelicBuff {
    key:        string;
    blackboard: Blackboard[];
}

export interface Blackboard {
    key:      string;
    value:    number;
    valueStr: null | string;
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
    code:          Code;
    name:          string;
    loadingPicId:  LoadingPicID;
    description:   string;
    eliteDesc:     null | string;
    isBoss:        number;
    isElite:       number;
    difficulty:    DifficultyEnum;
    capsulePool:   "pool_capsule_default" | null;
    capsuleProb:   number;
    vutresProb:    number[];
    boxProb:       number[];
    specialNodeId: null | string;
}

export type Code = "ISW-DF" | "ISW-NO" | "ISW-SP" | "ISW-DU";

export type DifficultyEnum = "NORMAL" | "FOUR_STAR";

export type LoadingPicID = "loading_PCS" | "loading_SY" | "loading_SM_RL" | "loading_SKZ_RL";

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
    professionList: Profession[];
    rarityList:     RarityList[];
}

export interface RogueUpgradeTicketAll {
    id:             string;
    profession:     number;
    rarity:         Category;
    professionList: Profession[];
    rarityList:     RarityList[];
}

export interface Rogue1_UpgradeTicketCasterClass {
    id:             string;
    profession:     Profession;
    rarity:         Category;
    professionList: Profession[];
    rarityList:     RarityList[];
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
    type?:        Variation1_Type;
    outerName:    string;
    innerName:    string;
    functionDesc: string;
    desc:         string;
    iconId:       null | string;
    sound?:       null | string;
    buffs?:       RelicBuff[];
}

export type Variation1_Type = "MAP" | "RES" | "BAT";

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
    zoneIconId:        PortalZone;
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
    init:                         Init[];
    stages:                       { [key: string]: Stage };
    zones:                        Rogue2_Zones;
    variation:                    BandRef;
    traps:                        { [key: string]: Rogue1__ActiveTool1 };
    recruitTickets:               Rogue2_RecruitTickets;
    upgradeTickets:               Rogue2_UpgradeTickets;
    customTickets:                CustomTickets;
    relics:                       { [key: string]: Rogue1_Relic };
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
    items:                        { [key: string]: Item };
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
    color:          BuffColor;
}

export type BuffColor = "#9266b2" | "#b43b3b" | "#0098dc";

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
    enrollId:    BpPurchaseActiveEnroll | null;
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
    rogue_2_recruit_ticket_pioneer:              Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_warrior:              Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_tank:                 Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_sniper:               Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_caster:               Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_support:              Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_medic:                Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_special:              Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_pioneer_sp:           Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_warrior_sp:           Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_tank_sp:              Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_sniper_sp:            Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_caster_sp:            Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_support_sp:           Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_medic_sp:             Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_special_sp:           Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_pioneer_vip:          Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_warrior_vip:          Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_tank_vip:             Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_sniper_vip:           Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_caster_vip:           Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_support_vip:          Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_medic_vip:            Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_special_vip:          Rogue1_RecruitTicketCasterClass;
    rogue_2_recruit_ticket_double_1:             Rogue1_RecruitTicketAllClass;
    rogue_2_recruit_ticket_double_2:             Rogue1_RecruitTicketAllClass;
    rogue_2_recruit_ticket_double_3:             Rogue1_RecruitTicketAllClass;
    rogue_2_recruit_ticket_double_4:             Rogue1_RecruitTicketAllClass;
    rogue_2_recruit_ticket_quad_melee:           Rogue1_RecruitTicketAllClass;
    rogue_2_recruit_ticket_quad_ranged:          Rogue1_RecruitTicketAllClass;
    rogue_2_recruit_ticket_all:                  Rogue1_RecruitTicketAllClass;
    rogue_2_recruit_ticket_5star:                RogueRecruitTicket5_Star;
    rogue_2_recruit_ticket_all_premium:          Rogue1_RecruitTicketAllClass;
    rogue_2_recruit_ticket_quad_melee_discount:  Rogue1_RecruitTicketAllClass;
    rogue_2_recruit_ticket_quad_ranged_discount: Rogue1_RecruitTicketAllClass;
    rogue_2_recruit_ticket_all_discount:         Rogue1_RecruitTicketAllClass;
    rogue_2_recruit_ticket_temp_5_up:            Rogue1_RecruitTicketAllClass;
    rogue_2_recruit_ticket_temp_6_up:            Rogue1_RecruitTicketAllClass;
}

export interface TaskDatum {
    taskId:        string;
    taskName:      string;
    taskDesc:      string;
    rewardSceneId: RewardSceneID;
    taskRarity:    Rarity;
}

export type RewardSceneID = "scene_ro2_taskreward3_enter" | "scene_ro2_taskreward2_enter" | "scene_ro2_taskreward1_enter";

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
    init:                         Init[];
    stages:                       { [key: string]: Stage };
    zones:                        { [key: string]: Zone };
    variation:                    BandRef;
    traps:                        Rogue3_Traps;
    recruitTickets:               Rogue3_RecruitTickets;
    upgradeTickets:               Rogue3_UpgradeTickets;
    customTickets:                BandRef;
    relics:                       { [key: string]: Rogue1_Relic };
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
    items:                        { [key: string]: Item };
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
    type:              PosEnum;
    enrollConditionId: BpPurchaseActiveEnroll | null;
    sortId:            number;
}

export type PosEnum = "LOCATION" | "EFFECT" | "AFFIX";

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
    bpPurchaseActiveEnroll:            BpPurchaseActiveEnroll;
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
    rogue_3_recruit_ticket_pioneer:              Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_warrior:              Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_tank:                 Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_sniper:               Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_caster:               Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_support:              Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_medic:                Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_special:              Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_pioneer_sp:           Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_warrior_sp:           Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_tank_sp:              Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_sniper_sp:            Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_caster_sp:            Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_support_sp:           Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_medic_sp:             Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_special_sp:           Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_pioneer_vip:          Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_warrior_vip:          Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_tank_vip:             Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_sniper_vip:           Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_caster_vip:           Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_support_vip:          Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_medic_vip:            Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_special_vip:          Rogue1_RecruitTicketCasterClass;
    rogue_3_recruit_ticket_double_1:             Rogue1_RecruitTicketAllClass;
    rogue_3_recruit_ticket_double_2:             Rogue1_RecruitTicketAllClass;
    rogue_3_recruit_ticket_double_3:             Rogue1_RecruitTicketAllClass;
    rogue_3_recruit_ticket_double_4:             Rogue1_RecruitTicketAllClass;
    rogue_3_recruit_ticket_quad_melee:           Rogue1_RecruitTicketAllClass;
    rogue_3_recruit_ticket_quad_ranged:          Rogue1_RecruitTicketAllClass;
    rogue_3_recruit_ticket_all:                  Rogue1_RecruitTicketAllClass;
    rogue_3_recruit_ticket_5star:                RogueRecruitTicket5_Star;
    rogue_3_recruit_ticket_all_premium:          Rogue1_RecruitTicketAllClass;
    rogue_3_recruit_ticket_quad_melee_discount:  Rogue1_RecruitTicketAllClass;
    rogue_3_recruit_ticket_quad_ranged_discount: Rogue1_RecruitTicketAllClass;
    rogue_3_recruit_ticket_all_discount:         Rogue1_RecruitTicketAllClass;
    rogue_3_recruit_ticket_temp_5_up:            Rogue1_RecruitTicketAllClass;
    rogue_3_recruit_ticket_temp_6_up:            Rogue1_RecruitTicketAllClass;
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
    eventType:   Type;
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
    init:                         Init[];
    stages:                       { [key: string]: Stage };
    zones:                        { [key: string]: Zone };
    variation:                    BandRef;
    traps:                        Rogue4_Traps;
    recruitTickets:               Rogue4_RecruitTickets;
    upgradeTickets:               Rogue4_UpgradeTickets;
    customTickets:                BandRef;
    relics:                       { [key: string]: Rogue1_Relic };
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
    items:                        { [key: string]: Item };
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
    keyItemId:                         "rogue_4_fragment_I_1";
    chestKeyCnt:                       number;
    chestKeyItemId:                    string;
    keyColorId:                        string;
    onceNodeTypeList:                  any[];
    gpScoreRatio:                      number;
    overflowUsageSquadBuff:            string;
    specialTrapId:                     string;
    trapRewardRelicId:                 string;
    unlockRouteItemId:                 "rogue_4_fragment_I_1";
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
    refreshNodeItemId:                 "rogue_4_fragment_I_1";
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

export interface Rogue4_RecruitTickets {
    rogue_4_recruit_ticket_pioneer:              Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_warrior:              Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_tank:                 Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_sniper:               Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_caster:               Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_support:              Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_medic:                Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_special:              Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_pioneer_sp:           Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_warrior_sp:           Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_tank_sp:              Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_sniper_sp:            Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_caster_sp:            Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_support_sp:           Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_medic_sp:             Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_special_sp:           Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_pioneer_vip:          Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_warrior_vip:          Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_tank_vip:             Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_sniper_vip:           Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_caster_vip:           Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_support_vip:          Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_medic_vip:            Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_special_vip:          Rogue1_RecruitTicketCasterClass;
    rogue_4_recruit_ticket_double_1:             Rogue1_RecruitTicketAllClass;
    rogue_4_recruit_ticket_double_2:             Rogue1_RecruitTicketAllClass;
    rogue_4_recruit_ticket_double_3:             Rogue1_RecruitTicketAllClass;
    rogue_4_recruit_ticket_double_4:             Rogue1_RecruitTicketAllClass;
    rogue_4_recruit_ticket_double_1_vip:         Rogue1_RecruitTicketAllClass;
    rogue_4_recruit_ticket_double_2_vip:         Rogue1_RecruitTicketAllClass;
    rogue_4_recruit_ticket_double_3_vip:         Rogue1_RecruitTicketAllClass;
    rogue_4_recruit_ticket_double_4_vip:         Rogue1_RecruitTicketAllClass;
    rogue_4_recruit_ticket_quad_melee:           Rogue1_RecruitTicketAllClass;
    rogue_4_recruit_ticket_quad_ranged:          Rogue1_RecruitTicketAllClass;
    rogue_4_recruit_ticket_all:                  Rogue1_RecruitTicketAllClass;
    rogue_4_recruit_ticket_5star:                RogueRecruitTicket5_Star;
    rogue_4_recruit_ticket_all_premium:          Rogue1_RecruitTicketAllClass;
    rogue_4_recruit_ticket_quad_melee_discount:  Rogue1_RecruitTicketAllClass;
    rogue_4_recruit_ticket_quad_ranged_discount: Rogue1_RecruitTicketAllClass;
    rogue_4_recruit_ticket_all_discount:         Rogue1_RecruitTicketAllClass;
    rogue_4_recruit_ticket_temp_5_up:            Rogue1_RecruitTicketAllClass;
    rogue_4_recruit_ticket_temp_6_up:            Rogue1_RecruitTicketAllClass;
}

export interface RollNodeData {
    zone_1:                Zone1;
    zone_2:                ZonePortalTravel1_Class;
    zone_3:                ZonePortalTravel1_Class;
    zone_4:                ZonePortalTravel1_Class;
    zone_5:                ZonePortalTravel1_Class;
    zone_6:                ZonePortalTravel1_Class;
    zone_portal_normal_1:  ZonePortal;
    zone_portal_normal_2:  ZonePortal;
    zone_portal_normal_3:  ZonePortal;
    zone_portal_normal_4:  ZonePortal;
    zone_portal_normal_5:  ZonePortal;
    zone_portal_normal_6:  ZonePortal;
    zone_portal_revival_3: ZonePortalRevival;
    zone_portal_revival_4: ZonePortalRevival;
    zone_portal_revival_5: ZonePortalRevival;
    zone_portal_travel_1:  ZonePortalTravel1_Class;
    zone_portal_end_1:     ZonePortal;
    zone_portal_end_2:     ZonePortal;
}

export interface Zone1 {
    zoneId: PortalZone;
    groups: Zone1_Groups;
}

export interface Zone1_Groups {
    BATTLE_NORMAL: BattleElite;
    BATTLE_ELITE:  BattleElite;
    INCIDENT:      BattleElite;
    BATTLE_SHOP:   BattleElite;
}

export interface BattleElite {
    nodeType: BATTLEELITENodeType;
}

export type BATTLEELITENodeType = "BATTLE_ELITE" | "BATTLE_NORMAL" | "BATTLE_SHOP" | "INCIDENT" | "EXPEDITION" | "REST" | "SACRIFICE" | "WISH" | "DUEL" | "ENTERTAINMENT";

export interface ZonePortalTravel1_Class {
    zoneId: PortalZone;
    groups: Zone2_Groups;
}

export interface Zone2_Groups {
    BATTLE_NORMAL:  BattleElite;
    BATTLE_ELITE:   BattleElite;
    INCIDENT?:      BattleElite;
    REST:           BattleElite;
    SACRIFICE?:     BattleElite;
    EXPEDITION:     BattleElite;
    BATTLE_SHOP?:   BattleElite;
    WISH:           BattleElite;
    ENTERTAINMENT?: BattleElite;
    DUEL?:          BattleElite;
}

export interface ZonePortal {
    zoneId: string;
    groups: Zone2_Groups;
}

export interface ZonePortalRevival {
    zoneId: string;
    groups: ZonePortalRevival3_Groups;
}

export interface ZonePortalRevival3_Groups {
    BATTLE_NORMAL: BattleElite;
    BATTLE_ELITE:  BattleElite;
    REST:          BattleElite;
    EXPEDITION:    BattleElite;
    DUEL:          BattleElite;
    INCIDENT:      BattleElite;
    BATTLE_SHOP:   BattleElite;
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
    sound:        ChaosDataSound;
    sortId:       number;
}

export type ChaosDataSound = "ON_ROGUELIKE_VARIATION1" | "ON_ROGUELIKE_VARIATION2";

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
    description:   DieDescription;
    isUpgradeDice: number;
    upgradeDiceId: null | string;
    diceFaceCount: number;
    battleDiceId:  BattleDiceID;
}

export type BattleDiceID = "rogue_2_dice_battle1" | "rogue_2_dice_battle2" | "rogue_2_dice_battle3";

export type DieDescription = "随处可见的六面骰子。投下后似乎能决定什么。" | "并不常有的八面骰子。投下后似乎能决定什么。" | "极为少见的十二面骰子。投下后似乎能决定什么。";

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
    diceResultClass: DiceResultClass;
    diceGroupId:     string;
    diceEventId:     string;
    resultDesc:      string;
    showType:        DiceEventShowType;
    canReroll:       boolean;
    diceEndingScene: string;
    diceEndingDesc:  string;
    sound:           DiceEventSound;
}

export type DiceResultClass = "BEST" | "GOOD" | "NORMAL" | "BAD" | "VERYBAD";

export type DiceEventShowType = "VIRTUE" | "RAW_TEXT" | "MUTATION";

export type DiceEventSound = "ON_ROGUELIKE_DICEGREAT" | "ON_ROGUELIKE_DICENORMAL" | "ON_ROGUELIKE_DICEBAD";

export interface DicePredefine {
    modeId:           Mode;
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
    levelName:    LeftDisasterDesc;
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
    fragmentTypeList:  TypeElement[];
    fragmentSquareSum: number;
    poolRarity:        Rarity;
    relicProp:         number;
    shieldProp:        number;
    populationProp:    number;
}

export type TypeElement = "WISH" | "INSPIRATION" | "IDEA";

export interface AlchemyFormulaDatum {
    fragmentIds:    string[];
    rewardId:       string;
    rewardCount:    number;
    rewardItemType: RewardItemTypeEnum;
}

export interface FragmentBuffDatum {
    itemId:   string;
    maskType: MaskType;
    desc:     null | string;
}

export type MaskType = "ALL" | "BATTLES";

export interface FragmentDatum {
    id:     string;
    type:   TypeElement;
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
    type:       TypeElement;
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
    nodeType:     ALCHEMYNodeType;
    sortId:       number;
    permItemList: PermItemList[];
    tempItemList: TempItemList[];
}

export type ALCHEMYNodeType = "ALCHEMY" | "BATTLE_SHOP" | "REST";

export interface PermItemList {
    upgradeId:     string;
    nodeType:      ALCHEMYNodeType;
    nodeLevel:     number;
    costItemId:    "rogue_4_fragment_I_1";
    costItemCount: number;
    desc:          string;
    nodeName:      string;
}

export interface TempItemList {
    upgradeId:     string;
    nodeType:      ALCHEMYNodeType;
    sortId:        number;
    costItemId:    "rogue_4_fragment_I_1";
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
    color:                    TotemBuffDataColor;
    pos:                      PosEnum;
    rhythm:                   string;
    normalDesc:               string;
    synergyDesc:              string;
    archiveDesc:              string;
    combineGroupName:         CombineGroupName;
    bgIconId:                 BgIconID;
    isManual:                 boolean;
    linkedNodeTypeData:       LinkedNodeTypeData;
    distanceMin:              number;
    distanceMax:              number;
    vertPassable:             boolean;
    expandLength:             number;
    onlyForVert:              boolean;
    portalLinkedNodeTypeData: LinkedNodeTypeData;
}

export type BgIconID = "bg_all" | "bg_blue" | "bg_green" | "bg_red" | "bg_boss";

export type TotemBuffDataColor = "ALL" | "BLUE" | "GREEN" | "RED" | "NONE";

export type CombineGroupName = "normal" | "boss";

export interface LinkedNodeTypeData {
    effectiveNodeTypes: Type[];
    blurNodeTypes:      BlurNodeType[];
}

export type BlurNodeType = "BATTLE" | "NO_BATTLE" | "NONE";

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
    type:  "LOWER";
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
