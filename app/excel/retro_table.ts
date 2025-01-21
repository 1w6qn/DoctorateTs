import { Blackboard, ItemBundle } from "@excel/character_table";

export interface RetroStageTable {
  zoneToRetro: { [key: string]: string };
  stageValidInfo: { [key: string]: StageValidInfo };
  stages: null;
  retroActList: { [key: string]: RetroActData };
  retroTrailList: { [key: string]: RetroTrailData };
  stageList: { [key: string]: StageData };
  ruleData: RetroTrailRuleData;
  customData: ActivityCustomData;
  initRetroCoin: number;
  retroCoinPerWeek: number;
  retroCoinMax: number;
  retroUnlockCost: number;
  retroDetail: string;
  retroPreShowTime: number;
}

export interface ActivityCustomData {
  typeAct17Side: { [key: string]: Act17sideData };
  typeAct25Side: { [key: string]: Act25sideCustomData };
  typeAct20Side: { [key: string]: Act20SideData };
  typeAct21Side: { [key: string]: Act21SideData };
}

export interface Act20SideData {
  zoneAdditionDataMap: { [key: string]: string };
  residentCartDatas: { [key: string]: ResidentCartData };
}

export interface ResidentCartData {
  residentPic: string;
}

export interface Act21SideData {
  zoneAdditionDataMap: { [key: string]: ZoneAddtionData };
  constData: Act21sideDataConstData;
}

export interface Act21sideDataConstData {
  lineConnectZone: string;
}

export interface ZoneAddtionData {
  zoneID: string;
  unlockText: string;
  stageUnlockText: null | string;
  entryID: string;
}

export interface Act25sideCustomData {
  battlePerformanceData: { [key: string]: BattlePerformanceData };
}

export interface BattlePerformanceData {
  itemID: string;
  sortID: number;
  itemName: string;
  itemIcon: string;
  itemDesc: string;
  itemTechType: string;
  runeData: PackedRuneData;
}

export interface PackedRuneData {
  id: string;
  points: number;
  mutexGroupKey: null;
  description: string;
  runes: RuneData[];
}

export interface RuneData {
  key: string;
  selector: Selector;
  blackboard: Blackboard;
}

export interface Selector {
  professionMask: string;
  buildableMask: string;
  playerSideMask: string;
  charIDFilter: null | Array<string>;
  enemyIDFilter: null | Array<string>;
  enemyIDExcludeFilter: null | Array<string>;
  enemyLevelTypeFilter: null | Array<string>;
  enemyActionHiddenGroupFilter: null | Array<string>;
  skillIDFilter: null | Array<string>;
  tileKeyFilter: null | Array<string>;
  groupTagFilter: null | Array<string>;
  filterTagFilter: null | Array<string>;
  filterTagExcludeFilter: null | Array<string>;
  subProfessionExcludeFilter: null | Array<string>;
  mapTagFilter: null | Array<string>;
}

export interface RetroActData {
  retroID: string;
  type: string;
  linkedActID: string[];
  startTime: number;
  trailStartTime: number;
  index: number;
  name: string;
  detail: string;
  haveTrail: boolean;
  customActID: null | string;
  customActType: string;
  isRecommend: boolean;
  recommendTagRemoveStage: null | string;
}

export interface RetroTrailData {
  retroID: string;
  trailStartTime: number;
  trailRewardList: RetroTrailRewardItem[];
  stageList: string[];
  relatedChar: string;
  relatedFullPotentialItemID: null;
  themeColor: string;
  fullPotentialItemID: null | string;
}

export interface RetroTrailRewardItem {
  trailRewardID: string;
  starCount: number;
  rewardItem: ItemBundle;
}

export interface RetroTrailRuleData {
  title: string[];
  desc: string[];
}

export interface StageData {
  stageType: string;
  difficulty: string;
  performanceStageFlag: string;
  diffGroup: string;
  unlockCondition: ConditionDesc[];
  stageID: string;
  levelID: null | string;
  zoneID: string;
  code: string;
  name: string;
  description: string;
  hardStagedID: null | string;
  dangerLevel: null | string;
  dangerPoint: number;
  loadingPicID: string;
  canPractice: boolean;
  canBattleReplay: boolean;
  apCost: number;
  apFailReturn: number;
  etItemID: string;
  etCost: number;
  etFailReturn: number;
  etButtonStyle: null;
  apProtectTimes: number;
  diamondOnceDrop: number;
  practiceTicketCost: number;
  dailyStageDifficulty: number;
  expGain: number;
  goldGain: number;
  loseExpGain: number;
  loseGoldGain: number;
  passFavor: number;
  completeFavor: number;
  slProgress: number;
  displayMainItem: null;
  hilightMark: boolean;
  bossMark: boolean;
  isPredefined: boolean;
  isHardPredefined: boolean;
  isSkillSelectablePredefined: boolean;
  isStoryOnly: boolean;
  appearanceStyle: string;
  stageDropInfo: StageDropInfo;
  canUseCharm: boolean;
  canUseTech: boolean;
  canUseTrapTool: boolean;
  canUseBattlePerformance: boolean;
  canUseFirework: boolean;
  canContinuousBattle: boolean;
  startButtonOverrideID: null;
  isStagePatch: boolean;
  mainStageID: string;
  extraCondition: null;
  extraInfo: null;
}

export interface StageDropInfo {
  firstPassRewards: null | ItemBundle[];
  firstCompleteRewards: null | ItemBundle[];
  passRewards: null;
  completeRewards: null;
  displayRewards: DisplayRewards[];
  displayDetailRewards: DisplayDetailRewards[];
}

export interface DisplayRewards {
  type: string;
  id: string;
  dropType: string;
}

export interface DisplayDetailRewards extends DisplayRewards {
  occPercent: string;
}

export interface ConditionDesc {
  stageID: string;
  completeState: string;
}

export interface StageValidInfo {
  startTs: number;
  endTs: number;
}

export interface Act17sideData {
  placeDataMap: { [key: string]: PlaceData };
  nodeInfoDataMap: { [key: string]: NodeInfoData };
  landmarkNodeDataMap: { [key: string]: LandmarkNodeData };
  storyNodeDataMap: { [key: string]: StoryNodeData };
  battleNodeDataMap: { [key: string]: BattleNodeData };
  treasureNodeDataMap: { [key: string]: TreasureNodeData };
  eventNodeDataMap: { [key: string]: EventNodeData };
  techNodeDataMap: { [key: string]: TechNodeData };
  choiceNodeDataMap: { [key: string]: ChoiceNodeData };
  eventDataMap: { [key: string]: EventData };
  archiveItemUnlockDataMap: { [key: string]: ArchiveItemUnlockData };
  techTreeDataMap: { [key: string]: TechTreeData };
  techTreeBranchDataMap: { [key: string]: TechTreeBranchData };
  mainlineChapterDataMap: { [key: string]: MainlineChapterData };
  mainlineDataMap: { [key: string]: MainlineData };
  zoneDataList: ZoneData[];
  constData: Act17sideDataConstData;
}

export interface ArchiveItemUnlockData {
  itemID: string;
  itemType: string;
  unlockCondition: string;
  nodeID: null | string;
  stageParam: string;
  chapterID: null | string;
}

export interface BattleNodeData {
  nodeID: string;
  stageID: string;
}

export interface ChoiceNodeData {
  nodeID: string;
  choicePic: null;
  isDisposable: boolean;
  choiceSpecialPic: null;
  choiceName: string;
  choiceDESList: string[];
  cancelDES: string;
  choiceNum: number;
  optionList: ChoiceNodeOptionData[];
}

export interface ChoiceNodeOptionData {
  canRepeat: boolean;
  eventID: string;
  des: string;
  unlockDES: null | string;
  unlockCondType: null;
  unlockParams: null;
}

export interface Act17sideDataConstData {
  techTreeUnlockEventID: string;
}

export interface EventData {
  eventID: string;
  eventPic: null;
  eventSpecialPic: null | string;
  eventTitle: string;
  eventDESList: string[];
}

export interface EventNodeData {
  nodeID: string;
  eventID: string;
  endEventID: string;
}

export interface LandmarkNodeData {
  nodeID: string;
  landmarkID: string;
  landmarkName: string;
  landmarkPic: null;
  landmarkSpecialPic: string;
  landmarkDESList: string[];
}

export interface MainlineChapterData {
  chapterID: string;
  chapterDES: string;
  chapterIcon: string;
  unlockDES: string;
  id: string;
}

export interface MainlineData {
  mainlineID: string;
  nodeID: null | string;
  sortID: number;
  missionSort: string;
  zoneID: string;
  mainlineDES: string;
  focusNodeID: null | string;
}

export interface NodeInfoData {
  nodeID: string;
  nodeType: string;
  sortID: number;
  placeID: string;
  isPointPlace: boolean;
  chapterID: string;
  trackPointType: string;
  unlockCondType: null;
  unlockParams: null;
}

export interface PlaceData {
  placeID: string;
  placeDesc: string;
  lockEventID: null | string;
  zoneID: string;
  visibleCondType: null;
  visibleParams: null;
}

export interface StoryNodeData {
  nodeID: string;
  storyID: string;
  storyKey: string;
  storyName: string;
  storyPic: null | string;
  confirmDES: string;
  storyDESList: string[];
}

export interface TechNodeData {
  nodeID: string;
  techTreeID: string;
  techTreeName: string;
  techPic: null;
  techSpecialPic: string;
  endEventID: string;
  confirmDES: string;
  techDESList: string[];
  missionIDList: string[];
}

export interface TechTreeBranchData {
  techTreeBranchID: string;
  techTreeID: string;
  techTreeBranchName: string;
  techTreeBranchIcon: string;
  techTreeBranchDesc: string;
  runeData: PackedRuneData;
}

export interface TechTreeData {
  techTreeID: string;
  sortID: number;
  techTreeName: string;
  defaultBranchID: string;
  lockDES: string;
}

export interface TreasureNodeData {
  nodeID: string;
  treasureID: string;
  treasureName: string;
  treasurePic: null | string;
  treasureSpecialPic: null;
  endEventID: string;
  confirmDES: string;
  treasureDESList: string[];
  missionIDList: string[];
  rewardList: ItemBundle[];
  treasureType: string;
}

export interface ZoneData {
  zoneID: string;
  unlockPlaceID: null | string;
  unlockText: string;
}
