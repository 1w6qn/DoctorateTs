import { RoguelikeBuff } from "@game/model/rlv2";
import { ItemBundle } from "./character_table";

export interface RoguelikeTopicTable {
    topics:        {[key:string]:RoguelikeTopicBasicData};
    constant:      RoguelikeTopicConst;
    details:       {[key: string]:RoguelikeTopicDetail};
    modules:       {[key: string]:RoguelikeModule};
    customizeData: CustomizeData;
}

export interface RoguelikeTopicConst {
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
    predefinedChars:               { [key: string]: RoguelikeTopicConst.PredefinedChar };
}
export namespace RoguelikeTopicConst{
    export interface PredefinedChar {
    charId:      string;
    canBeFree:   boolean;
    uniEquipId:  null | string;
    recruitType: string;
}
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

export interface RoguelikeTopicDetail {
    updates:                      RoguelikeTopicUpdate[];
    enrolls:                      {[key: string]: RoguelikeTopicEnroll};
    milestones:                   RoguelikeTopicBP[];
    milestoneUpdates:             RoguelikeTopicMilestoneUpdateData[];
    grandPrizes:                  RoguelikeTopicBPGrandPrize[];
    monthMission:                 RoguelikeTopicMonthMission[];
    monthSquad:                   {[key:string]:RoguelikeTopicMonthSquad};
    challenges:                   {[key:string]:RoguelikeTopicChallenge};
    difficulties:                 RoguelikeTopicDifficulty[];
    bankRewards:                  RoguelikeTopicBankReward[];
    archiveComp:                  RoguelikeArchiveComponentData;
    archiveUnlockCond:            RoguelikeArchiveUnlockCondData;
    detailConst:                  RoguelikeTopicDetailConst;
    init:                         RoguelikeGameInitData[];
    stages:                       { [key: string]: RoguelikeGameStageData };
    zones:                        {[key:string]:RoguelikeGameZoneData};
    variation:                    {[key:string]:{}};
    traps:                        {[key:string]:RoguelikeGameTrapData};
    recruitTickets:               {[key:string]:RoguelikeGameRecruitTicketData};
    upgradeTickets:               {[key:string]:RoguelikeGameUpgradeTicketData};
    customTickets:                {[key:string]:RoguelikeGameCustomTicketData};
    relics:                       { [key: string]: RoguelikeGameRelicData };
    relicParams:                  { [key: string]: RoguelikeGameRelicParamData };
    recruitGrps:                  {[key:string]:RoguelikeGameRecruitGrpData};
    choices:                      { [key: string]: RoguelikeGameChoiceData };
    choiceScenes:                 { [key: string]: RoguelikeGameChoiceSceneData };
    nodeTypeData:                 {[key:string]:RoguelikeGameNodeTypeData};
    subTypeData:                  RoguelikeGameNodeSubTypeData[];
    variationData:                {[key:string]:RoguelikeGameVariationData};
    charBuffData:                 {[key:string]:RoguelikeGameCharBuffData};
    squadBuffData:                {[key:string]:RoguelikeGameCharBuffData};
    taskData:                     {[key:string]:RoguelikeTaskData};
    gameConst:                    RoguelikeGameConst;
    shopDialogData:               RoguelikeGameShopDialogData;
    capsuleDict:                  { [key: string]: RoguelikeTopicCapsule }|null;
    endings:                      {[key:string]:RoguelikeGameEndingData};
    battleSummeryDescriptions:    {[key:string]:RoguelikeBattleSummeryDescriptionData};
    battleLoadingTips:            TipData[];
    items:                        { [key: string]: RoguelikeGameItemData };
    bandRef:                      {[key:string]:RoguelikeBandRefData};
    endingDetailList:             RoguelikeEndingDetailText[];
    endingRelicDetailList:        RoguelikeEndingRelicDetailText[];
    treasures:                    {[key:string]:RoguelikeGameTreasureData[]};
    difficultyUpgradeRelicGroups: {[key:string]:RoguelikeDifficultyUpgradeRelicGroupData};
    styles:                       {[key:string]:RoguelikePredefinedStyleData};
    styleConfig:                  RoguelikePredefinedConstStyleData;
    exploreTools:                 {[key: string]:RoguelikeGameExploreToolData};
    rollNodeData:                 { [key: string]: RoguelikeRollNodeData };
}

export interface RoguelikeArchiveComponentData {
    relic:    ActArchiveRelicData;
    capsule:  null|ActArchiveCapsuleData;
    trap:     ActArchiveTrapData;
    chat:     ActArchiveChatData;
    endbook:  ActArchiveEndbookData;
    buff:     ActArchiveBuffData;
    totem:    null|ActArchiveTotemData;
    chaos:    null|ActArchiveChaosData;
    fragment: null|ActArchiveFragmentData;
    disaster: null|ActArchiveDisasterData;
}

export interface ActArchiveBuffData {
    buff: {[key:string]:ActArchiveBuffItemData};
}

export interface BandRef {
}

export interface ActArchiveCapsuleData {
    capsule: { [key: string]: ActArchiveCapsuleItemData };
}

export interface ActArchiveCapsuleItemData {
    capsuleId:     string;
    capsuleSortId: number;
    englishName:   string;
    enrollId:      null|string;
}

export interface ActArchiveChatData {
    chat: {[key:string]:ActArchiveChatGroupData};
}



export interface ActArchiveChatGroupData {
    sortId:             number;
    numChat:            number;
    clientChatItemData: ActArchiveChatItemData[];
}

export interface ActArchiveChatItemData {
    chatFloor:   number;
    chatDesc:    null | string;
    chatStoryId: string;
}

export interface ActArchiveEndbookData {
    endbook: {[key:string]:ActArchiveEndbookGroupData};
}

export interface ActArchiveRelicData {
    relic: { [key: string]: ActArchiveRelicItemData };
}

export interface ActArchiveRelicItemData {
    relicId:      string;
    relicSortId:  number;
    relicGroupId: number;
    orderId:      string;
    isSpRelic:    boolean;
    enrollId:     null | string;
}

export interface ActArchiveTrapData {
    trap: {[key:string]:ActArchiveTrapItemData};
}


export interface ActArchiveTrapItemData {
    trapId:     string;
    trapSortId: number;
    orderId:    string;
    enrollId:   null|string;
}

export interface RoguelikeArchiveUnlockCondData {
    unlockCondDesc: { [key: string]: RoguelikeArchiveUnlockCondDesc };
    enroll:         { [key: string]: RoguelikeArchiveEnroll };
}

export interface RoguelikeArchiveEnroll {
    archiveType: string;
    enrollId:    null | string;
}

export interface RoguelikeArchiveUnlockCondDesc {
    archiveType: string;
    description: string;
}

export interface RoguelikeTopicBankReward {
    rewardId:      string;
    unlockGoldCnt: number;
    rewardType:    string;
    desc:          string;
}

export interface TipData {
    tip:      string;
    weight:   number;
    category: string;
}

export interface RoguelikeBattleSummeryDescriptionData {
    randomDescriptionList: string[];
}

export interface RoguelikeTopicCapsule {
    itemId:     string;
    maskType:   string;
    innerColor: string;
}



export interface RoguelikeTopicChallenge {
    challengeId:              string;
    sortId:                   number;
    challengeName:            string;
    challengeGroup:           number;
    challengeGroupSortId:     number;
    challengeGroupName:       null|string;
    challengeUnlockDesc:      null|string;
    challengeUnlockToastDesc: null|string;
    challengeDes:             string;
    challengeConditionDes:    string[];
    challengeTasks:           {[key:string]:RoguelikeTopicChallengeTask};
    defaultTaskId:            string;
    rewards:                  ItemBundle[];
    challengeStoryId:         null|string;
}
export interface RoguelikeTopicChallengeTask {
    taskId:           string;
    taskDes:          string;
    completionClass:  string;
    completionParams: string[];
}


export interface RoguelikeGameChoiceSceneData {
    id:             string;
    title:          string;
    description:    string;
    background:     null | string;
    titleIcon:      null | string;
    subTypeId:      number;
    useHiddenMusic: boolean;
}

export interface RoguelikeGameChoiceData {
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

export interface RoguelikeTopicDetailConst {
    playerLevelTable:                  { [key: string]: PlayerLevelData };
    charUpgradeTable:                  { [key: string]: CharUpgradeData };
    difficultyUpgradeRelicDescTable:   { [key: string]: string };
    predefinedLevelTable:              { [key: string]: PredefinedPlayerLevelData };
    tokenBpId:                         string;
    tokenOuterBuffId:                  string;
    previewedRewardsAccordingUpdateId: string;
    tipButtonName:                     string;
    collectButtonName:                 string;
    bpSystemName:                      string;
    autoSetKV:                         string;
    bpPurchaseActiveEnroll:            string|null;
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

export interface CharUpgradeData {
    evolvePhase:          string;
    skillLevel:           number;
    skillSpecializeLevel: number;
}

export interface PlayerLevelData {
    exp:               number;
    populationUp:      number;
    squadCapacityUp:   number;
    battleCharLimitUp: number;
    maxHpUp:           number;
}

export interface RoguelikeTopicDifficulty {
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

export interface RoguelikeEndingDetailText {
    textId:        string;
    text:          string;
    eventType:     string;
    showType:      string;
    choiceSceneId: null | string;
    paramList:     string[];
    otherPara1:    null|string;
}

export interface RoguelikeGameEndingData {
    id:               string;
    familyId:         number;
    name:             string;
    desc:             string;
    bgId:             string;
    icons:            LevelIcon[];
    priority:         number;
    changeEndingDesc: null | string;
    bossIconId:       null | string;
}

export interface LevelIcon {
    level:  number;
    iconId: string;
}

export interface RoguelikeTopicEnroll {
    enrollId:   string;
    enrollTime: number;
}

export interface RoguelikeGameConst {
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
    hideBattleNodeName:                null| string;
    hideBattleNodeDescription:         null| string;
    hideNonBattleNodeName:             null| string;
    hideNonBattleNodeDescription:      null| string;
    charSelectExpeditionConflictToast: null | string;
    itemDropTagDict:                   {[key:string]:string};
    expeditionReturnDescCureUpgrade:   null | string;
    expeditionReturnDescUpgrade:       null | string;
    expeditionReturnDescCure:          null | string;
    expeditionReturnDesc:              null | string;
    expeditionSelectDescFormat:        null| string;
    expeditionReturnDescItem:          null | string;
    expeditionReturnRewardBlackList:   string[];
    travelLeaveToastFormat:            null| string;
    charSelectTravelConflictToast:     null| string;
    travelReturnDescUpgrade:           null| string;
    travelReturnDesc:                  null| string;
    travelReturnDescItem:              null| string;
    traderReturnTitle:                 null| string;
    traderReturnDesc:                  null| string;
    gainBuffDiffGrade:                 number;
    dsPredictTips:                     null| string;
    dsBuffActiveTips:                  null| string;
    totemDesc:                         null| string;
    relicDesc:                         null| string;
    buffDesc:                          null| string;
    refreshNodeItemId:                 null| string;
    portalZones:                       string[];
    exploreExpOnKill:                  null| string;
}

export interface RoguelikeTopicBPGrandPrize {
    grandPrizeDisplayId: string;
    sortId:              number;
    displayUnlockYear:   number;
    displayUnlockMonth:  number;
    acquireTitle:        string;
    purchaseTitle:       string;
    displayName:         string;
    displayDiscription:  string;
    bpLevelId:           string;
    itemBundle:          ItemBundle | null;
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

export interface RoguelikeTopicMilestoneUpdateData {
    updateTime:        number;
    endTime:           number;
    maxBpLevel:        number;
    maxBpCount:        number;
    maxDisplayBpCount: number;
}

export interface RoguelikeTopicBP {
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

export interface RoguelikeTopicMonthMission {
    id:               string;
    taskName:         string;
    taskClass:        string;
    innerClassWeight: number;
    template:         string;
    paramList:        string[];
    desc:             string;
    tokenRewardNum:   number;
}

export interface RoguelikeTopicMonthSquad {
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
    items:          ItemBundle[];
    startTime:      number;
    endTime:        number;
    taskDes:        null | string;
}


export interface RoguelikeGameNodeTypeData {
    name:        string;
    description: string;
}

export interface RoguelikeGameRecruitGrpData {
    id:         string;
    iconId:     string;
    name:       string;
    desc:       string;
    unlockDesc: null | string;
}


export interface RoguelikeGameRecruitTicketData {
    id:              string;
    profession:      string|number;
    rarity:          string|number;
    professionList:  string[];
    rarityList:      string[];
    extraEliteNum?:   number;
    extraFreeRarity?: string[];
    extraCharIds?:    string[];
}

export interface RoguelikeGameRelicParamData {
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

export interface RoguelikeGameShopDialogData {
    types: {[key:string]:RoguelikeGameShopDialogTypeData};
}


export interface RoguelikeGameShopDialogTypeData {
    groups: {[key:string]:RoguelikeGameShopDialogGroupData};
}

export interface RoguelikeGameShopDialogGroupData {
    content: string[];
}

export interface RoguelikeGameStageData {
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

export interface RoguelikePredefinedConstStyleData {
    expStyleConfig: null;
}


export interface RoguelikeGameTrapData {
    itemId:   string;
    trapId:   string;
    trapDesc: string;
}
export type RoguelikeGameExploreToolData=RoguelikeGameTrapData
export interface RoguelikeTopicUpdate {
    updateId:        string;
    topicUpdateTime: number;
    topicEndTime:    number;
}

export interface RoguelikeGameUpgradeTicketData {
    id:             string;
    profession:     number|string;
    rarity:         number|string;
    professionList: string[];
    rarityList:     string[];
}


export interface RoguelikeGameVariationData {
    id:           string;
    type:        string;
    outerName:    string;
    innerName:    string;
    functionDesc: string;
    desc:         string;
    iconId:       null | string;
    sound:       null | string;
}
export interface RoguelikeGameCharBuffData {
    id:           string;
    outerName:    string;
    innerName:    string;
    functionDesc: string;
    desc:         string;
    iconId:       null | string;
    buffs:       RoguelikeBuff[];
}
export type RoguelikeGameSquadBuffData=RoguelikeGameCharBuffData;
export interface RoguelikeGameZoneData {
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

export interface ActArchiveBuffItemData {
    buffId:         string;
    buffGroupIndex: number;
    innerSortId:    number;
    name:           string;
    iconId:         string;
    usage:          string;
    desc:           string;
    color:          string;
}

export interface ActArchiveEndbookGroupData {
    endId:                  string;
    endingId:               string;
    sortId:                 number;
    title:                  string;
    cgId:                   string;
    backBlurId:             string;
    cardId:                 string;
    hasAvg:                 boolean;
    avgId:                  string;
    clientEndbookItemDatas: ActArchiveEndbookItemData[];
}

export interface ActArchiveEndbookItemData {
    endBookId:   string;
    sortId:      number;
    enrollId:    null | string;
    isLast:      boolean;
    endbookName: string;
    unlockDesc:  string;
    textId:      string;
}

export interface RoguelikeBandRefData {
    itemId:       string;
    iconId:       string;
    description:  string;
    bandLevel:    number;
    normalBandId: string;
}


export interface RoguelikeGameCustomTicketData {
    id:          string;
    subType:     string;
    discardText: string;
}

export interface RoguelikeTaskData {
    taskId:        string;
    taskName:      string;
    taskDesc:      string;
    rewardSceneId: string;
    taskRarity:    string;
}

export interface RoguelikeGameTreasureData {
    treasureId: string;
    groupId:    string;
    subIndex:   number;
    name:       string;
    usage:      string;
}
export interface ActArchiveChaosData {
    chaos: { [key: string]: ActArchiveChaosItemData };
}

export interface ActArchiveChaosItemData {
    id:       string;
    isHidden: boolean;
    enrollId: null|string;
    sortId:   number;
}

export interface ActArchiveTotemData {
    totem: { [key: string]: ActArchiveTotemItemData };
}

export interface ActArchiveTotemItemData {
    id:                string;
    type:              string;
    enrollConditionId: null | string;
    sortId:            number;
}

export interface PredefinedPlayerLevelData {
    levels: { [key: string]: PlayerLevelData };
}

export interface RoguelikeDifficultyUpgradeRelicGroupData {
    relicData: RoguelikeDifficultyUpgradeRelicData[];
}

export interface RoguelikeDifficultyUpgradeRelicData {
    relicId:         string;
    equivalentGrade: number;
}


export interface RoguelikePredefinedStyleData {
    styleId:     string;
    styleConfig: number;
}

export interface RoguelikeGameNodeSubTypeData {
    eventType:   string;
    subTypeId:   number;
    iconId:      string;
    name:        null;
    description: string;
}


export interface ActArchiveDisasterData {
    disasters: { [key: string]: ActArchiveDisasterItemData };
}

export interface ActArchiveDisasterItemData {
    disasterId:        string;
    sortId:            number;
    enrollConditionId: null|string;
    picSmallId:        string;
    picBigActiveId:    string;
    picBigInactiveId:  string;
}



export interface ActArchiveFragmentData {
    fragment: { [key: string]: ActArchiveFragmentItemData };
}

export interface ActArchiveFragmentItemData {
    fragmentId:        string;
    sortId:            number;
    enrollConditionId: null|string;
}


export interface RoguelikeEndingRelicDetailText {
    relicId:          string;
    summaryEventText: string;
}


export interface RoguelikeRollNodeData {
    zoneId: string;
    groups: {[key:string]:RoguelikeRollNodeGroupData};
}
export interface RoguelikeRollNodeGroupData {
    nodeType: string;
}


export interface RoguelikeModule {
    moduleTypes: string[];
    sanCheck:    RoguelikeSanCheckModuleData | null;
    dice:        RoguelikeDiceModuleData | null;
    chaos:       RoguelikeChaosModuleData | null;
    totemBuff:   RoguelikeTotemBuffModuleData | null;
    vision:      RoguelikeVisionModuleData | null;
    fragment:    RoguelikeFragmentModuleData | null;
    disaster:    RoguelikeDisasterModuleData | null;
    nodeUpgrade: RoguelikeNodeUpgradeModuleData | null;
}

export interface RoguelikeChaosModuleData {
    chaosDatas:    { [key: string]: RoguelikeChaosData };
    chaosRanges:   RoguelikeChaosRangeData[];
    levelInfoDict: {[key:string]:{ [key: string]: RoguelikeChaosPredefineLevelInfo }};
    moduleConsts:  RoguelikeChaosModuleConsts;
}

export interface RoguelikeChaosData {
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

export interface RoguelikeChaosRangeData {
    chaosMax:           number;
    chaosDungeonEffect: string;
}

export interface RoguelikeChaosPredefineLevelInfo {
    chaosLevelBeginNum: number;
    chaosLevelEndNum:   number;
}

export interface RoguelikeChaosModuleConsts {
    maxChaosLevel:           number;
    maxChaosSlot:            number;
    chaosNotMaxDescription:  string;
    chaosMaxDescription:     string;
    chaosPredictDescription: string;
}

export interface RoguelikeDiceModuleData {
    dice:           { [key: string]: RoguelikeDiceData };
    diceEvents:     { [key: string]: RoguelikeDiceRuleData };
    diceChoices:    { [key: string]: string };
    diceRuleGroups: { [key: string]: RoguelikeDiceRuleGroupData };
    dicePredefines: RoguelikeDicePredefineData[];
}

export interface RoguelikeDiceData {
    diceId:        string;
    description:   string;
    isUpgradeDice: number;
    upgradeDiceId: null | string;
    diceFaceCount: number;
    battleDiceId:  string;
}


export interface RoguelikeDiceRuleData {
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

export interface RoguelikeDicePredefineData {
    modeId:           string;
    modeGrade:        number;
    predefinedId:     null | string;
    initialDiceCount: number;
}

export interface RoguelikeDiceRuleGroupData {
    ruleGroupId: string;
    minGoodNum:  number;
}

export interface RoguelikeDisasterModuleData {
    disasterData: { [key: string]: RoguelikeDisasterData };
}

export interface RoguelikeDisasterData {
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

export interface RoguelikeFragmentModuleData {
    fragmentData:       { [key: string]: RoguelikeFragmentData };
    fragmentTypeData:   {[key:string]:RoguelikeFragmentTypeData};
    moduleConsts:       RoguelikeFragmentModuleConsts;
    fragmentBuffData:   { [key: string]: RoguelikeFragmentBuffData };
    alchemyData:        { [key: string]: RoguelikeAlchemyData };
    alchemyFormulaData: { [key: string]: RoguelikeAlchemyFormulationData };
    fragmentLevelData:  { [key: string]: RoguelikeFragmentLevelRelatedData };
}

export interface RoguelikeAlchemyData {
    fragmentTypeList:  string[];
    fragmentSquareSum: number;
    poolRarity:        string;
    relicProp:         number;
    shieldProp:        number;
    populationProp:    number;
}

export interface RoguelikeAlchemyFormulationData {
    fragmentIds:    string[];
    rewardId:       string;
    rewardCount:    number;
    rewardItemType: string;
}

export interface RoguelikeFragmentBuffData {
    itemId:   string;
    maskType: string;
    desc:     null | string;
}

export interface RoguelikeFragmentData {
    id:     string;
    type:   string;
    value:  number;
    weight: number;
}

export interface RoguelikeFragmentLevelRelatedData {
    weightUp: number;
}



export interface RoguelikeFragmentTypeData {
    type:       string;
    typeName:   string;
    typeDesc:   string;
    typeIconId: string;
}

export interface RoguelikeFragmentModuleConsts {
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

export interface RoguelikeNodeUpgradeModuleData {
    nodeUpgradeDataMap: {[key:string]:RoguelikeNodeUpgradeData};
}


export interface RoguelikeNodeUpgradeData {
    nodeType:     string;
    sortId:       number;
    permItemList: RoguelikePermNodeUpgradeItemData[];
    tempItemList: RoguelikeTempNodeUpgradeItemData[];
}

export interface RoguelikePermNodeUpgradeItemData {
    upgradeId:     string;
    nodeType:      string;
    nodeLevel:     number;
    costItemId:    string;
    costItemCount: number;
    desc:          string;
    nodeName:      string;
}

export interface RoguelikeTempNodeUpgradeItemData {
    upgradeId:     string;
    nodeType:      string;
    sortId:        number;
    costItemId:    string;
    costItemCount: number;
    desc:          string;
}

export interface RoguelikeSanCheckModuleData {
    sanRanges:    RoguelikeSanRangeData[];
    moduleConsts: RoguelikeSanCheckConsts;
}

export interface RoguelikeSanCheckConsts {
    sanDecreaseToast: string;
}

export interface RoguelikeSanRangeData {
    sanMax:           number;
    diceGroupId:      string;
    description:      string;
    sanDungeonEffect: string;
    sanEffectRank:    string;
    sanEndingDesc:    null|string;
}

export interface RoguelikeTotemBuffModuleData {
    totemBuffDatas: { [key: string]: RoguelikeTotemBuffData };
    subBuffs:       { [key: string]: RoguelikeTotemSubBuffData };
    moduleConsts:   RoguelikeTotemModuleConsts;
}

export interface RoguelikeTotemModuleConsts {
    totemPredictDescription:    string;
    colorCombineDesc:           { [key: string]: string };
    bossCombineDesc:            string;
    battleNoPredictDescription: string;
    shopNoGoodsDescription:     string;
}

export interface RoguelikeTotemSubBuffData {
    subBuffId:    string;
    name:         string;
    desc:         string;
    combinedDesc: string;
    info:         string;
}

export interface RoguelikeTotemBuffData {
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
    linkedNodeTypeData:       RoguelikeTotemLinkedNodeTypeData;
    distanceMin:              number;
    distanceMax:              number;
    vertPassable:             boolean;
    expandLength:             number;
    onlyForVert:              boolean;
    portalLinkedNodeTypeData: RoguelikeTotemLinkedNodeTypeData;
}

export interface RoguelikeTotemLinkedNodeTypeData {
    effectiveNodeTypes: string[];
    blurNodeTypes:      string[];
}

export interface RoguelikeVisionModuleData {
    visionDatas:   { [key: string]: RoguelikeVisionData };
    visionChoices: { [key: string]: VisionChoiceConfig };
    moduleConsts:  RoguelikeVisionModuleConsts;
}

export interface RoguelikeVisionModuleConsts {
    maxVision:              number;
    totemBottomDescription: string;
    chestBottomDescription: string;
    goodsBottomDescription: string;
}

export interface VisionChoiceConfig {
    value: number;
    type:  string;
}

export interface RoguelikeVisionData {
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

export interface RoguelikeTopicBasicData {
    id:                        string;
    name:                      string;
    startTime:                 number;
    disappearTimeOnMainScreen: number;
    sort:                      number;
    showMedalId:               string;
    medalGroupId:              string;
    fullStoredTime:            number;
    lineText:                  string;
    homeEntryDisplayData:      HomeEntryDisplayData[];
    moduleTypes:               string[];
    config:                    RoguelikeTopicConfig;
}

export interface RoguelikeTopicConfig {
    loadCharCardPlugin:        boolean;
    webBusType:                string;
    monthChatTrigType:         string;
    loadRewardHpDecoPlugin:    boolean;
    loadRewardExtraInfoPlugin: boolean;
}

export interface HomeEntryDisplayData {
    topicId:   string;
    displayId: string;
    startTs:   number;
    endTs:     number;
}
