import { PlayerActivity } from "./activity";
import {
  AvatarInfo,
  PlayerFriendAssist,
  PlayerSquadItem,
  PlayerTroop,
} from "./character";
import { ItemBundle } from "@excel/character_table";

export interface PlayerDataModel {
  dungeon: PlayerDungeon;
  activity: PlayerActivity;
  status: PlayerStatus;
  troop: PlayerTroop;
  npcAudio: { [key: string]: { npcShowAudioInfoFlag: string } };
  pushFlags: PlayerPushFlags;
  equipment: PlayerEquipment;
  skin: PlayerSkins;
  shop: PlayerDataShop;
  mission: MissionPlayerData;
  social: PlayerSocial;
  building: PlayerBuilding;
  dexNav: PlayerDexNav;
  crisis: Crisis;
  crisisV2: CrisisV2;
  nameCardStyle: PlayerNameCardStyle;
  tshop: { [key: string]: PlayerTemplateShop };
  gacha: PlayerGacha;
  backflow: PlayerReturnData;
  mainline: PlayerMainlineRecord;
  avatar: PlayerAvatar;
  background: PlayerHomeBackground;
  homeTheme: PlayerHomeTheme;
  rlv2: any;
  deepSea: PlayerDeepSea;
  tower: PlayerTower;
  siracusaMap: PlayerSiracusaMap;
  sandboxPerm: any;
  storyreview: PlayerStoryReview;
  medal: PlayerMedal;
  event: PlayerDataEvent;
  retro: PlayerRetro;
  share: PlayerCrossAppShare;
  roguelike: {
    current: null;
    stable: null;
  };
  ticket: { [key: string]: PlayerConsumableItem };
  aprilFool: PlayerAprilFool;
  consumable: { [key: string]: { [key: string]: PlayerConsumableItem } };
  charm: CharmStatus;
  carousel: PlayerCarousel;
  openServer: PlayerOpenServer;
  car: PlayerCartInfo;
  recruit: PlayerRecruit;
  templateTrap: PlayerTemplateTrap;
  checkIn: PlayerCheckIn;
  inventory: { [key: string]: number };
  campaignsV2: PlayerCampaign;
  setting: PlayerSetting;
  checkMeta: {
    version: number;
    ts: number;
  };
  limitedBuff: PlayerLimitedDropBuff;
  collectionReward: PlayerCollection;
  trainingGround: PlayerTrainingCamp;
  charRotation: PlayerCharRotation;
}
export interface PlayerStatus {
  nickName: string;
  nickNumber: string;
  level: number;
  exp: number;
  socialPoint: number;
  gachaTicket: number;
  tenGachaTicket: number;
  instantFinishTicket: number;
  hggShard: number;
  lggShard: number;
  recruitLicense: number;
  progress: number;
  buyApRemainTimes: number;
  apLimitUpFlag: number;
  uid: string;
  flags: { [key: string]: number };
  ap: number;
  maxAp: number;
  androidDiamond: number;
  iosDiamond: number;
  diamondShard: number;
  gold: number;
  practiceTicket: number;
  lastRefreshTs: number;
  lastApAddTime: number;
  mainStageProgress: null | string;
  registerTs: number;
  lastOnlineTs: number;
  serverName: string;
  avatarId: string;
  resume: string;
  friendNumLimit: number;
  monthlySubscriptionStartTime: number;
  monthlySubscriptionEndTime: number;
  secretary: string;
  secretarySkinId: string;
  tipMonthlyCardExpireTs: number;
  avatar: AvatarInfo;
  globalVoiceLan: string;
  classicShard: number;
  classicGachaTicket: number;
  classicTenGachaTicket: number;
}

export interface PlayerDungeon {
  stages: { [key: string]: PlayerStage };
  //zones?:               { [key: string]: PlayerZone };
  cowLevel: { [key: string]: PlayerSpecialStage };
  hideStages: { [key: string]: PlayerHiddenStage };
  mainlineBannedStages: string[];
}

export interface PlayerSpecialStage {
  id: string;
  type: string;
  val: Array<number[] | boolean>;
  fts: number;
  rts: number;
}

export interface PlayerHiddenStage {
  missions: BaseProgress[];
  unlock: number;
}

export interface PlayerStage {
  stageId: string;
  completeTimes: number;
  startTimes: number;
  practiceTimes: number;
  state: number;
  hasBattleReplay: number;
  noCostCnt: number;
}

export interface PlayerEquipment {
  missions: { [key: string]: PlayerEquipMission };
}
export interface PlayerEquipMission {
  target: number;
  value: number;
}

export interface PlayerSkins {
  characterSkins: { [key: string]: number };
  skinTs: { [key: string]: number };
}

export interface PlayerPosition {
  x: number;
  y: number;
}

export interface PlayerAprilFool {
  act3fun: PlayerActFun3;
  act4fun: PlayerActFun4;
  act5fun: PlayerActFun5;
}

export interface PlayerActFun3 {
  stages: { [key: string]: PlayerActFunStage };
}

export interface PlayerActFunStage {
  state: number;
  scores: number[];
}

export interface PlayerActFun4 {
  stages: { [key: string]: PlayerActFun4Stage };
  liveEndings: { [key: string]: number };
  cameraLv: number;
  fans: number;
  posts: number;
  missions: { [key: string]: PlayerActFun4Mission };
}

export interface PlayerActFun4Mission {
  value: number;
  target: number;
  finished: boolean;
  hasRecv: boolean;
}

export interface PlayerActFun4Stage {
  state: number;
  liveTimes: number;
}

export interface PlayerActFun5 {
  stageState: { [key: string]: number };
  highScore: number;
}

export interface PlayerAvatar {
  avatar_icon: { [key: string]: PlayerAvatarBlock };
}

export interface PlayerAvatarBlock {
  ts: number;
  src: string;
}

export interface PlayerReturnData {
  open: boolean;
  current: null;
}

export interface PlayerHomeBackground {
  selected: string;
  bgs: { [key: string]: PlayerHomeUnlockStatus };
}

export interface PlayerHomeUnlockStatus {
  unlock?: number; //unlockTime
  conditions?: { [key: string]: PlayerHomeConditionProgress };
}

export interface PlayerHomeConditionProgress {
  v: number; //curProgress
  t: number; //total
}

export interface PlayerBuilding {
  status: PlayerBuildingStatus;
  chars: { [key: string]: PlayerBuildingChar };
  roomSlots: { [key: string]: PlayerBuildingRoomSlot };
  rooms: PlayerBuildingRoom;
  furniture: { [key: string]: PlayerBuildingFurnitureInfo };
  diyPresetSolutions: {};
  assist: number[];
  solution: PlayerBuildingSolution;
}

export interface PlayerBuildingChar {
  charId: string;
  lastApAddTime: number;
  ap: number;
  roomSlotId: string;
  index: number;
  changeScale: number;
  bubble: PlayerBuildingChar.BubbleContainer;
  workTime: number;
}
export namespace PlayerBuildingChar {
  export interface BubbleContainer {
    normal: PlayerBuildingCharBubble;
    assist: PlayerBuildingCharBubble;
  }
}
export interface PlayerBuildingCharBubble {
  add: number;
  ts: number;
}

export interface PlayerBuildingFurnitureInfo {
  count: number;
  inUse: number;
}

export interface PlayerBuildingRoomSlot {
  level: number;
  state: number;
  roomId: string;
  charInstIds: number[];
  completeConstructTime: number;
}

export interface PlayerBuildingRoom {
  CONTROL: { [key: string]: PlayerBuildingControl };
  ELEVATOR: { [key: string]: {} };
  POWER: { [key: string]: PlayerBuildingPower };
  MANUFACTURE: { [key: string]: PlayerBuildingManufacture };
  TRADING: { [key: string]: PlayerBuildingTrading };
  CORRIDOR: { [key: string]: {} };
  WORKSHOP: { [key: string]: PlayerBuildingWorkshop };
  DORMITORY: { [key: string]: PlayerBuildingDormitory };
  MEETING: { [key: string]: PlayerBuildingMeeting };
  HIRE: { [key: string]: PlayerBuildingHire };
  TRAINING: { [key: string]: PlayerBuildingTraining };
}

export interface PlayerBuildingControl {
  buff: PlayerBuildingControlBuff;
  apCost: number;
  lastUpdateTime: number;
}

export interface PlayerBuildingControlBuff {
  global: PlayerBuildingControlBuff.Global;
  manufacture: PurpleManufacture;
  trading: Trading;
  meeting: PurpleMeeting;
  apCost: { [key: string]: number };
  point: { [key: string]: number };
  hire: Hire;
  power: Power;
  dormitory: Dormitory;
  training: BuffTraining;
}
export namespace PlayerBuildingControlBuff {
  export interface Global {
    apCost: number;
    roomCnt: object;
  }
}
export interface Dormitory {
  recover: number;
}

export interface Hire {
  spUp: SPUp;
  apCost: number;
}

export interface SPUp {
  base: number;
  up: number;
}

export interface PurpleManufacture {
  speed: number;
  sSpeed: number;
  roomSpeed: {};
  apCost: number;
}

export interface PurpleMeeting {
  clue: number;
  speedUp: number;
  sSpeed: number;
  weight: {};
  apCost: number;
  notOwned: number;
}

export interface Power {
  apCost: number;
}

export interface Trading {
  speed: number;
  sSpeed: number;
  roomSpeed: {};
  charSpeed: {};
  charLimit: {};
  apCost: number;
  roomLimit: {};
}

export interface BuffTraining {
  speed: number;
}

export interface PlayerBuildingDormitory {
  buff: PlayerBuildingDormitory.Buff;
  comfort: number;
  diySolution: PlayerBuildingDIYSolution;
}
export namespace PlayerBuildingDormitory {
  export interface Buff {
    apCost: Buff.ApCost;
    point: {};
  }

  export namespace Buff {
    export interface ApCost {
      all: number;
      single: ApCost.SingleTarget;
      self: {};
      exclude: {};
    }

    export namespace ApCost {
      export interface SingleTarget {
        target: number | null;
        value: number;
      }
    }
  }
}

export interface BaseProgress {
  target: number | null;
  value: number;
}

export interface PlayerBuildingDIYSolution {
  wallPaper: string;
  floor: string;
  carpet: PlayerBuildingFurniturePositionInfo[];
  other: PlayerBuildingFurniturePositionInfo[];
}

export interface PlayerBuildingFurniturePositionInfo {
  id: string;
  coordinate: PlayerBuildingGridPosition;
}

export interface PlayerBuildingGridPosition {
  x: number;
  y: number;
  dir?: number;
}

export interface PlayerBuildingHire {
  buff: PlayerBuildingHireBuff;
  state: number;
  refreshCount: number;
  lastUpdateTime: number;
  processPoint: number;
  speed: number;
  completeWorkTime: number;
}

export interface PlayerBuildingHireBuff {
  speed: number;
  meeting: FluffyMeeting;
  stack: Stack;
  point: {};
  apCost: FluffyApCost;
}

export interface FluffyApCost {
  self: {};
}

export interface FluffyMeeting {
  speedUp: number;
}

export interface Stack {
  clueWeight: {};
  char: StackChar[];
}

export interface StackChar {
  refresh: number;
}

export interface PlayerBuildingManufacture {
  buff: PlayerBuildingManufactureBuff;
  state: number;
  formulaId: string;
  remainSolutionCnt: number;
  outputSolutionCnt: number;
  lastUpdateTime: number;
  saveTime: number;
  tailTime: number;
  apCost: number;
  completeWorkTime: number;
  capacity: number;
  processPoint: number;
  display: BuildingBuffDisplay;
}

export interface PlayerBuildingManufactureBuff {
  apCost: TentacledApCost;
  speed: number;
  capacity: number;
  sSpeed: number;
  tSpeed: {};
  cSpeed: number;
  capFrom: { [key: string]: number };
  maxSpeed: number;
  point: {};
  flag: {};
  skillExtend: { [key: string]: string[] };
}

export interface TentacledApCost {
  self: { [key: string]: number };
  all: number;
}

export interface BuildingBuffDisplay {
  base: number;
  buff: number;
}

export interface PlayerBuildingMeeting {
  buff: PlayerBuildingMeetingBuff;
  state: number;
  speed: number;
  processPoint: number;
  ownStock: PlayerBuildingMeetingClue[];
  receiveStock: PlayerBuildingMeetingClue[];
  board: { [key: string]: string };
  socialReward: PlayerBuildingMeetingSocialReward;
  dailyReward: null | PlayerBuildingMeetingClue;
  expiredReward: number;
  received: number;
  infoShare: PlayerBuildingMeetingInfoShareState;
  lastUpdateTime: number;
  mfc: {};
  completeWorkTime: number;
  startApCounter: {};
  mustgetClue: any[];
}

export interface PlayerBuildingMeetingBuff {
  speed: number;
  weight: { [key: string]: number };
  flag: {};
  apCost: FluffyApCost;
  notOwned: number;
  owned: number;
}

export interface PlayerBuildingMeetingInfoShareState {
  ts: number;
  reward: number;
}

export interface PlayerBuildingMeetingClue {
  id: string;
  type: string;
  number: number;
  uid: string;
  name: string;
  nickNum: string;
  chars: PlayerBuildingMeetingClueChar[];
  inUse: number;
  ts?: number;
}

export interface PlayerBuildingMeetingClueChar {
  charId: string;
  level: number;
  skin: string;
  evolvePhase: number;
}

export interface PlayerBuildingMeetingSocialReward {
  daily: number;
  search: number;
}

export interface PlayerBuildingPower {
  buff: PlayerBuildingPowerBuff;
}

export interface PlayerBuildingPowerBuff {
  laborSpeed: number;
  apCost: FluffyApCost;
  global: { roomCnt: {} };
  manufacture: { charSpeed: {} };
}

export interface PlayerBuildingTrading {
  buff: PlayerBuildingTradingBuff;
  state: number;
  lastUpdateTime: number;
  strategy: string;
  stockLimit: number;
  apCost: number;
  stock: any[];
  next: PlayerBuildingTradingNext;
  completeWorkTime: number;
  display: BuildingBuffDisplay;
}

export interface PlayerBuildingTradingBuff {
  speed: number;
  limit: number;
  apCost: IndigoApCost;
  rate: {};
  tgw: any[];
  point: {};
  manuLines: {};
  orderBuff: any[];
  violatedInfo: ViolatedInfo;
  orderWtBuff: any[];
}

export interface IndigoApCost {
  all: number;
  single: {};
  self: { [key: string]: number };
}

export interface ViolatedInfo {
  orderChecker: OrderChecker[];
  cntBuff: CntBuff[];
}

export interface CntBuff {
  ordTyp: string;
  itemId: string;
  itemCnt: number;
  coinId: string;
  coinCnt: number;
}

export interface OrderChecker {
  ordTyp: string;
  itemId: string;
  cnt: number;
}

export interface PlayerBuildingTradingNext {
  order: number;
  processPoint: number;
  maxPoint: number;
  speed: number;
}

export interface PlayerBuildingTraining {
  buff: PlayerBuildingTrainingBuff;
  state: number;
  lastUpdateTime: number;
  trainee: PlayerBuildingTrainee;
  trainer: PlayerBuildingTrainer;
}

export interface PlayerBuildingTrainingBuff {
  speed: number;
  lvEx: {};
  lvCost: {};
  reduce: Reduce;
  reduceTimeBd: PlayerBuildingTrainingReduceTimeBd;
}

export interface Reduce {
  target: null;
  progress: number;
  cut: number;
}

export interface PlayerBuildingTrainingReduceTimeBd {
  fulltime: boolean;
  activated: boolean;
  cnt: number;
  reset: boolean;
}

export interface PlayerBuildingTrainee {
  charInstId: number;
  state: number;
  targetSkill: number;
  processPoint: number;
  speed: number;
}

export interface PlayerBuildingTrainer {
  charInstId: number;
  state: number;
}

export interface PlayerBuildingWorkshop {
  buff: PlayerBuildingWorkshopBuff;
  statistic: Statistic;
}

export interface PlayerBuildingWorkshopBuff {
  rate: { [key: string]: number };
  apRate: { [key: string]: { [key: string]: number } };
  frate: PlayerBuildingWorkshopBuff.Frate[];
  goldFree: { [key: string]: number };
  cost: PlayerBuildingWorkshopBuff.Cost;
  costRe: PlayerBuildingWorkshopBuff.CostRe;
  costForce: PlayerBuildingWorkshopBuff.CostForce;
  costDevide: PlayerBuildingWorkshopBuff.CostDevide;
  recovery: Recovery;
  fFix: FFix;
  activeBonus: {};
}

export namespace PlayerBuildingWorkshopBuff {
  export interface Frate {
    fid: string;
    rate: number;
  }

  export interface Cost {
    type: string;
    limit: number;
    reduction: number;
  }

  export interface CostRe {
    type: string;
    from: number;
    change: number;
  }

  export interface CostDevide {
    type: string;
    limit: number;
    denominator: number;
  }

  export interface CostForce {
    type: string;
    cost: number;
  }
}

export interface FFix {
  asRarity: {};
}

export interface Recovery {
  type: string;
  pace: number;
  recover: number;
}

export interface Statistic {
  noAddition: number;
}

export interface PlayerBuildingSolution {
  furnitureTs: { [key: string]: number };
}

export interface PlayerBuildingStatus {
  labor: PlayerBuildingLabor;
  workshop: PlayerBuildingWorkshopStatus;
}

export interface PlayerBuildingLabor {
  buffSpeed: number;
  processPoint: number;
  value: number;
  lastUpdateTime: number;
  maxValue: number;
}

export interface PlayerBuildingWorkshopStatus {
  bonusActive: number;
  bonus: { [key: string]: number[] };
}

export interface PlayerCampaign {
  campaignCurrentFee: number;
  campaignTotalFee: number;
  lastRefreshTs: number;
  instances: { [key: string]: PlayerCampaign.Stage };
  open: PlayerCampaign.StageOpenInfo;
  missions: { [key: string]: number };
  sweepMaxKills: { [key: string]: number };
}
export namespace PlayerCampaign {
  export interface Stage {
    maxKills: number;
    rewardStatus: number[];
  }

  export interface StageOpenInfo {
    permanent: string[];
    rotate: string;
    rGroup: string;
    training: string[];
    tGroup: string;
    tAllOpen: string;
  }
}

export interface PlayerCartInfo {
  battleCar: Cart;
  exhibitionCar: Cart;
  accessories: { [key: string]: CompInfo };
}

export interface CompInfo {
  id: string;
  num: number;
}

export interface Cart {
  ROOF: null | string;
  HEADSTOCK: null | string;
  TRUNK_01: null | string;
  CAR_OS_01: null | string;
  TRUNK_02: null | string;
  CAR_OS_02: null | string;
}

export interface PlayerCarousel {
  furnitureShop: PlayerCarouselFurnitureShopData;
}

export interface PlayerCarouselFurnitureShopData {
  goods: { [key: string]: number };
  groups: { [key: string]: number };
}

export interface CharmStatus {
  charms: { [key: string]: number };
  squad: string[];
}

export interface PlayerCheckIn {
  canCheckIn: number;
  checkInGroupId: string;
  checkInRewardIndex: number;
  checkInHistory: number[];
  newbiePackage: PlayerCheckIn.PlayerNewbiePackage;
}
export namespace PlayerCheckIn {
  export interface PlayerNewbiePackage {
    open: boolean;
    groupId: string;
    finish: number;
    stopSale: number;
    checkInHistory: number[]; //boolean[]
  }
}

export interface PlayerCollection {
  team: { [key: string]: number };
}

export interface PlayerConsumableItem {
  ts: number;
  count: number;
}

export interface Crisis {
  current: string;
  lst: number;
  nst: number;
  map: { [key: string]: MapValue };
  shop: CrisisShop;
  training: CrisisTraining;
  season: CrisisSeason;
  box: any[];
}

export interface MapValue {
  rank: number;
  confirmed: number;
}

export interface CrisisSeason {
  rune_season_1_1: RuneSeason;
  rune_season_2_1: RuneSeason;
  rune_season_3_1: RuneSeason;
  rune_season_4_1: RuneSeason;
  rune_season_5_1: RuneSeason5_1;
  rune_season_6_1: RuneSeason6_1;
  rune_season_8_1: RuneSeason8_1;
  rune_season_9_1: RuneSeason;
  rune_season_10_1: RuneSeason;
  rune_season_11_1: RuneSeason;
  rune_season_12_1: RuneSeason;
}

export interface RuneSeason {
  coin: number;
  tCoin: number;
  permanent: RuneSeason10_1_Permanent;
  temporary: RuneSeason10_1_Temporary;
  sInfo: SInfo;
}

export interface RuneSeason10_1_Permanent {
  nst: number;
  rune: { [key: string]: number };
  point: number;
  challenge: PurpleChallenge;
}

export interface PurpleChallenge {
  taskList: PurpleTaskList;
  topPoint: number;
  pointList: { [key: string]: number };
}

export interface PurpleTaskList {
  normalTask_1: Story12_FceSet1;
  normalTask_2: Story12_FceSet1;
  normalTask_3: Story12_FceSet1;
  normalTask_4: Story12_FceSet1;
  normalTask_5: Story12_FceSet1;
  normalTask_6: Story12_FceSet1;
  normalTask_7: Story12_FceSet1;
  normalTask_8: Story12_FceSet1;
}

export interface Story12_FceSet1 {
  fts: number;
  rts: number;
}

export interface SInfo {
  assistCnt: number;
  maxPnt: number;
  chars: SInfoChar[];
  history: {};
}

export interface SInfoChar {
  charId: string;
  cnt: number;
}

export interface RuneSeason10_1_Temporary {
  schedule: string;
  nst: number;
  point: number;
  challenge: FluffyChallenge;
}

export interface FluffyChallenge {
  taskList: FluffyTaskList;
  topPoint: number;
  pointList: { [key: string]: number };
}

export interface FluffyTaskList {
  dailyTask_13: Story12_FceSet1;
}

export interface RuneSeason5_1 {
  coin: number;
  tCoin: number;
  permanent: RuneSeason10_1_Permanent;
  temporary: RuneSeason5_1_Temporary;
  sInfo: SInfo;
}

export interface RuneSeason5_1_Temporary {
  schedule: string;
  nst: number;
  point: number;
  challenge: TentacledChallenge;
}

export interface TentacledChallenge {
  taskList: TentacledTaskList;
  topPoint: number;
  pointList: { [key: string]: number };
}

export interface TentacledTaskList {
  dailyTask_12: Story12_FceSet1;
}

export interface RuneSeason6_1 {
  coin: number;
  tCoin: number;
  permanent: RuneSeason10_1_Permanent;
  temporary: RuneSeason6_1_Temporary;
  sInfo: SInfo;
}

export interface RuneSeason6_1_Temporary {
  schedule: string;
  nst: number;
  point: number;
  challenge: StickyChallenge;
}

export interface StickyChallenge {
  taskList: StickyTaskList;
  topPoint: number;
  pointList: { [key: string]: number };
}

export interface StickyTaskList {
  dailyTask_9: Story12_FceSet1;
}

export interface RuneSeason8_1 {
  coin: number;
  tCoin: number;
  permanent: RuneSeason10_1_Permanent;
  temporary: RuneSeason8_1_Temporary;
  sInfo: SInfo;
}

export interface RuneSeason8_1_Temporary {
  schedule: string;
  nst: number;
  point: number;
  challenge: IndigoChallenge;
}

export interface IndigoChallenge {
  taskList: IndigoTaskList;
  topPoint: number;
  pointList: { [key: string]: number };
}

export interface IndigoTaskList {
  dailyTask_10: Story12_FceSet1;
}

export interface CrisisShop {
  coin: number;
  info: Info[];
  progressInfo: ShopProgressInfo;
}

export interface Info {
  id: string;
  count: number;
}

export interface ShopProgressInfo {
  char_bibeak_progress: CharBibeakProgress;
  char_folivo_progress: CharBibeakProgress;
  char_tuye_progress: CharBibeakProgress;
  char_erato_progress: CharBibeakProgress;
}

export interface CharBibeakProgress {
  count: number;
  order: number;
}

export interface CrisisTraining {
  currentStage: string[];
  stage: { [key: string]: TrainingStage };
  nst: number;
}

export interface TrainingStage {
  point: number;
}

export interface CrisisV2 {
  current: string;
  seasons: Seasons;
  shop: CrisisShop;
  newRecordTs: number;
  nst: number;
}

export interface Seasons {
  crisis_v2_season_1_1: CrisisV2Season1_1;
  crisis_v2_season_2_1: CrisisV2Season2_1;
}

export interface CrisisV2Season1_1 {
  permanent: CrisisV2Season1_1_Permanent;
  temporary: CrisisV2Season1_1_Temporary;
  social: CrisisV2Season1_1_Social;
}

export interface CrisisV2Season1_1_Permanent {
  state: number;
  scoreTotal: number[];
  scoreSingle: number[];
  comment: string[];
  rune: PermanentRune;
  exRunes: ExRunes;
  runePack: PurpleRunePack;
  challenge: {};
  reward: PurpleReward;
}

export interface ExRunes {
  node_51: number;
  node_21: number;
  node_53: number;
  node_55: number;
  node_52: number;
  node_57: number;
}

export interface PurpleReward {
  reward_1: Reward1;
}

export interface Reward1 {
  state: number;
  progress: BaseProgress | number | null;
}

export interface PermanentRune {
  node_4: number;
  node_2: number;
  node_5: number;
  node_3: number;
  node_10: number;
  node_9: number;
  node_11: number;
  node_12: number;
}

export interface PurpleRunePack {
  pack_1: number;
  pack_2: number;
}

export interface CrisisV2Season1_1_Social {
  assistCnt: number;
  maxPnt: string;
  chars: SInfoChar[];
}

export interface CrisisV2Season1_1_Temporary {
  "crisis_v2_01-02": CrisisV20;
  "crisis_v2_01-03": CrisisV20103;
  "crisis_v2_01-05": CrisisV20;
  "crisis_v2_01-07": CrisisV2010;
}

export interface CrisisV20 {
  state: number;
  scoreTotal: number[];
  rune: { [key: string]: number };
  challenge: CrisisV20102_Challenge;
}

export interface CrisisV20102_Challenge {
  keypoint_1: number;
  keypoint_2: number;
  keypoint_3: number;
}

export interface CrisisV20103 {
  state: number;
  scoreTotal: number[];
  rune: CrisisV20103_Rune;
  challenge: CrisisV20102_Challenge;
}

export interface CrisisV20103_Rune {
  node_11: number;
  node_0: number;
  node_3: number;
  node_4: number;
  node_9: number;
  node_8: number;
  node_10: number;
  node_14: number;
  node_12: number;
}

export interface CrisisV2010 {
  state: number;
  scoreTotal: any[];
  rune: {};
  challenge: {};
}

export interface CrisisV2Season2_1 {
  permanent: CrisisV2Season2_1_Permanent;
  temporary: CrisisV2Season2_1_Temporary;
  social: CrisisV2Season1_1_Social;
}

export interface CrisisV2Season2_1_Permanent {
  state: number;
  scoreTotal: number[];
  scoreSingle: number[];
  comment: string[];
  rune: { [key: string]: number };
  exRunes: ExRunes;
  runePack: FluffyRunePack;
  challenge: CrisisV20102_Challenge;
  reward: FluffyReward;
}

export interface FluffyReward {
  reward_3: Reward1;
  reward_1: Reward1;
  reward_2: Reward1;
}

export interface FluffyRunePack {
  pack_3: number;
  pack_4: number;
  pack_5: number;
  pack_6: number;
  pack_34: number;
  pack_1: number;
  pack_2: number;
  pack_7: number;
}

export interface CrisisV2Season2_1_Temporary {
  "crisis_v2_02-02": CrisisV20;
  "crisis_v2_02-03": CrisisV20;
  "crisis_v2_01-02_b": CrisisV20;
  "crisis_v2_01-04_b": CrisisV2010;
}

export interface PlayerDeepSea {
  places: { [key: string]: number };
  nodes: { [key: string]: number };
  choices: { [key: string]: number[] };
  events: { [key: string]: number };
  treasures: { [key: string]: number };
  stories: { [key: string]: number };
  techTrees: { [key: string]: TechData };
  logs: { [key: string]: string[] };
}

export interface TechData {
  state: number;
  branch: string;
}

export interface PlayerDexNav {
  character: { [key: string]: PlayerCharacterRecord };
  formula: PlayerFormulaUnlockRecord;
  enemy: PlayerEnemyHandBook;
  teamV2: { [key: string]: { [key: string]: number } };
}

export interface PlayerCharacterRecord {
  charInstId: number;
  count: number;
  classicCount?: number;
}

export interface PlayerEnemyHandBook {
  enemies: { [key: string]: number };
  stage: { [key: string]: string[] };
}

export interface PlayerFormulaUnlockRecord {
  shop: {};
  manufacture: { [key: string]: number };
  workshop: { [key: string]: number };
}

export interface PlayerDataEvent {
  building: number;
}

export interface PlayerGacha {
  newbee: PlayerNewbeeGachaPool;
  normal: { [key: string]: PlayerGachaPool };
  limit: { [key: string]: PlayerFreeLimitGacha };
  linkage: { [key: string]: any };
  attain: { [key: string]: PlayerAttainGacha };
  single: { [key: string]: PlayerSingleGacha };
  fesClassic: { [key: string]: PlayerFesClassicGacha };
}
export interface PlayerAttainGacha {
  attain6Count: number;
}

export interface PlayerFesClassicGacha {
  upChar: { [key: string]: string[] };
}

export interface PlayerFreeLimitGacha {
  leastFree: number;
  poolCnt?: number;
  recruitedFreeChar?: boolean;
}

export interface Linkage {
  LINKAGE_17_0_1: LINKAGE17_0_1_Class;
  LINKAGE_36_0_1: Linkage36_0_1;
  LINKAGE_48_0_1: LINKAGE17_0_1_Class;
  LINKAGE_48_0_3: LINKAGE17_0_1_Class;
}

export interface LINKAGE17_0_1_Class {
  LINKAGE_R6_01: Linkage01;
}

export interface Linkage01 {
  next5: boolean;
  next5Char: string;
  must6: boolean;
  must6Char: string;
  must6Count: number;
  must6Level: number;
}

export interface Linkage36_0_1 {
  LINKAGE_MH_01: Linkage01;
}

export interface PlayerNewbeeGachaPool {
  openFlag: number;
  cnt: number;
  poolId: string;
}

export interface PlayerGachaPool {
  cnt: number;
  maxCnt: number;
  rarity: number;
  avail: boolean;
}

export interface PlayerSingleGacha {
  singleEnsureCnt: number;
  singleEnsureUse: boolean;
  singleEnsureChar: string;
}

export interface PlayerHomeTheme {
  selected: string;
  themes: { [key: string]: PlayerHomeUnlockStatus };
}

export interface PlayerLimitedDropBuff {
  dailyUsage: { [key: string]: DailyUsage };
  inventory: { [key: string]: LimitedBuffGroup };
}

export interface DailyUsage {
  times: number;
  ts: number;
}

export interface LimitedBuffGroup {
  ts: number;
  count: number;
}

export interface PlayerMainlineRecord {
  record: { [key: string]: number };
  cache: ItemBundle[];
  version: number;
  additionalMission: { [key: string]: PlayerZoneRecordMissionData };
  charVoiceRecord: { [key: string]: CharVoiceRecordData };
  explore: PlayerMainlineExplore;
}

export interface PlayerZoneRecordMissionData {
  state: number;
  process: BaseProgress;
}

export interface CharVoiceRecordData {
  isOpen: boolean;
  confirmEnterReward: boolean;
  nodes: { [key: string]: number };
}

export interface PlayerMainlineExplore {
  game: null;
  outer: PlayerExploreOuterContext;
}

export interface PlayerExploreOuterContext {
  isOpen: boolean;
  lastGameResult: PlayerExploreGameResult;
  historyPaths: PlayerExploreOuterContextHistoryPath[];
  mission: { [key: string]: PlayerExploreOuterContextMissionState };
}

export interface PlayerExploreOuterContextHistoryPath {
  success: boolean;
  path: PlayerExploreGameContextMapDisplay;
}

export interface PlayerExploreGameContextMapDisplay {
  pathSeed: number;
  nodeSeed: number;
  controlPoints: PlayerExploreGameContextMapControlPoint[];
}

export interface PlayerExploreGameContextMapControlPoint {
  stageId: string;
  pos: PlayerPosition;
}

export interface PlayerExploreGameResult {
  groupId: string;
  groupCode: string;
  heritageAbilities: { [key: string]: number };
}

export interface PlayerExploreOuterContextMissionState {
  state: number;
  progress: number[];
}

export interface PlayerMedal {
  medals: { [key: string]: PlayerPerMedal };
  custom: PlayerMedalCustom;
}

export interface PlayerMedalCustom {
  currentIndex: string;
  customs: { [key: string]: PlayerMedalCustomLayout };
}

export interface PlayerMedalCustomLayout {
  layout: PlayerMedalCustomLayoutItem[];
}
export interface PlayerMedalCustomLayoutItem {
  id: string;
  pos: number[];
}
export interface PlayerPerMedal {
  id: string;
  val: number[][];
  fts: number;
  rts: number;
  reward?: string;
}

export interface MissionPlayerData {
  missions: MissionPlayerDataGroup;
  missionRewards: MissionDailyRewards;
  missionGroups: { [key: string]: number };
}

export interface MissionDailyRewards {
  dailyPoint: number;
  weeklyPoint: number;
  rewards: { [key: string]: { [key: string]: number } };
}

export interface MissionPlayerDataGroup {
  [key: string]: { [key: string]: MissionPlayerState };
}

export interface MissionPlayerState {
  state: number;
  progress: BaseProgress[];
}

export interface PlayerNameCardStyle {
  componentOrder: string[];
  skin: NameCardSkin;
  misc: NameCardMisc;
}

export interface NameCardSkin {
  selected: string;
  state: { [key: string]: SkinState };
}
export interface NameCardMisc {
  showDetail: boolean;
  showBirthday: boolean;
}

export interface SkinState {
  unlock: boolean;
  progress: Array<number[]> | null;
}

export interface PlayerOpenServer {
  checkIn: OpenServerCheckIn;
  chainLogin: OpenServerChainLogin;
}

export interface OpenServerChainLogin {
  isAvailable: boolean;
  nowIndex: number;
  history: number[];
}

export interface OpenServerCheckIn {
  isAvailable: boolean;
  history: number[];
}

export interface PlayerPushFlags {
  hasGifts: number;
  hasFriendRequest: number;
  hasClues: number;
  hasFreeLevelGP: number;
  status: number;
}

export interface PlayerRecruit {
  normal: NormalModel;
}

export interface NormalModel {
  slots: { [key: string]: SlotModel };
}

export interface SlotModel {
  state: number;
  tags: number[];
  selectTags: TagItem[];
  startTs: number;
  durationInSec: number;
  maxFinishTs: number;
  realFinishTs: number;
}
export interface TagItem {
  tagId: number;
  pick: number;
}

export interface PlayerRetro {
  coin: number;
  supplement: number;
  block: { [key: string]: PlayerRetroBlock };
  lst: number;
  nst: number;
  trail: { [key: string]: { [key: string]: number } };
  rewardPerm: string[];
}

export interface PlayerRetroBlock {
  locked: number;
  open: number;
}

export interface SandboxPerm {
  template: Template;
  isClose: boolean;
}

export interface Template {
  SANDBOX_V2: SandboxV2;
}

export interface SandboxV2 {
  sandbox_1: SANDBOXV2Sandbox1;
}

export interface SANDBOXV2Sandbox1 {
  status: Sandbox1_Status;
  base: Base;
  main: Main;
  rift: null;
  riftInfo: RiftInfo;
  quest: Quest;
  mission: Sandbox1_Mission;
  troop: Sandbox1_Troop;
  cook: Cook;
  build: Build;
  bag: Sandbox1_Bag;
  tech: TechClass;
  bank: Sandbox1_Bank;
  buff: Sandbox1_Buff;
  archive: Archive;
  supply: Supply;
  shop: Sandbox1_Shop;
  month: Month;
  collect: Sandbox1_Collect;
  challenge: Sandbox1_Challenge;
  racing: Racing;
}

export interface Archive {
  save: Save[];
  nextLoadTs: number;
  loadTimes: number;
  loadTs: number;
}

export interface Save {
  slot: number;
  day: number;
  maxAp: number;
  season: SaveSeason;
  ts: number;
}

export interface SaveSeason {
  type: number;
  remain: number;
  total: number;
}

export interface Sandbox1_Bag {
  material: { [key: string]: number };
  craft: string[];
}

export interface Sandbox1_Bank {
  book: string[];
  coin: Coin;
}

export interface Coin {
  sandbox_1_gold: number;
  sandbox_1_dimensioncoin: number;
}

export interface Base {
  baseLv: number;
  upgradeProgress: Array<number[]>;
  trapLimit: { [key: string]: number };
  portableUnlock: boolean;
  outpostUnlock: boolean;
  repairDiscount: number;
  bossKill: any[];
}

export interface Sandbox1_Buff {
  rune: BuffRune;
}

export interface BuffRune {
  global: string[];
  node: { [key: string]: string[] };
  char: {};
}

export interface Build {
  book: { [key: string]: number };
  building: { [key: string]: number };
  tactical: BuildTactical;
  animal: {};
}

export interface BuildTactical {
  sandbox_1_tactical_15: number;
  sandbox_1_tactical_16: number;
  sandbox_1_tactical_17: number;
  sandbox_1_tactical_20: number;
  sandbox_1_tactical_19: number;
  sandbox_1_tactical_18: number;
  sandbox_1_tactical_10: number;
}

export interface Sandbox1_Challenge {
  status: number;
  unlock: Unlock;
  hasSettleDayDoc: boolean;
  cur: null;
  best: null;
  last: null;
  reward: {};
  hasEnteredOnce: boolean;
}

export interface Unlock {
  challenge_unlock_1: number[];
  challenge_unlock_2: number[];
}

export interface Sandbox1_Collect {
  pending: CollectPending;
  complete: Complete;
}

export interface Complete {
  achievement: string[];
  quest: string[];
  music: string[];
}

export interface CollectPending {
  achievement: { [key: string]: number[] };
}

export interface Cook {
  drink: number;
  extraDrink: number;
  book: {};
  food: {};
}

export interface Main {
  game: MainGame;
  map: MainMap;
  stage: MainStage;
  enemy: MainEnemy;
  npc: Npc;
  report: Report;
  event: MainEvent;
}

export interface MainEnemy {
  enemyRush: EnemyEnemyRush;
  rareAnimal: {};
}

export interface EnemyEnemyRush {
  er_11: Er1;
  er_12: Er1;
}

export interface Er1 {
  enemyRushType: number;
  groupKey: string;
  state: number;
  day: number;
  path: string[];
  enemy: Array<number[]>;
  badge: number;
  src: SrcClass;
}

export interface SrcClass {
  type: number;
  id: ID;
}

export type ID = "" | "quest_gate3_event" | "rift_fixed_3" | "mainline2_2";

export interface MainEvent {
  node: { [key: string]: NodeElement[] };
  effect: any[];
}

export interface NodeElement {
  instId: number;
  id: string;
  scene: string;
  state: number;
  badge: number;
  src: SrcClass;
}

export interface MainGame {
  mapId: string;
  day: number;
  maxDay: number;
  ap: number;
  maxAp: number;
}

export interface MainMap {
  season: SaveSeason;
  zone: { [key: string]: ZoneValue };
  node: { [key: string]: MapNode };
}

export interface MapNode {
  zone: ZoneEnum;
  type: number;
  state: number;
  relate: Relate;
  stageId: string;
  weatherLv: number;
}

export interface Relate {
  pos: number[];
  adj: string[];
  depth: number;
}

export type ZoneEnum =
  | "z_1_1"
  | "z_1_5"
  | "z_1_4"
  | "z_1_2"
  | "z_1_0"
  | "z_1_3";

export interface ZoneValue {
  state: number;
  weather: number;
}

export interface Npc {
  node: NpcNode;
  favor: {};
}

export interface NpcNode {
  n80F5: N80F5[];
  n2D0A: N2D0A[];
  n918E: N918E[];
}

export interface N2D0A {
  instId: number;
  id: string;
  type: number;
  enable: boolean;
  day: number;
  dialog: N2D0ADialog;
  badge: number;
  src: SrcClass;
}

export interface N2D0ADialog {
  "2": {};
}

export interface N80F5 {
  instId: number;
  id: string;
  type: number;
  enable: boolean;
  day: number;
  dialog: N80F5Dialog;
  badge: number;
  src: SrcClass;
}

export interface N80F5Dialog {
  "3": object;
}

export interface N918E {
  instId: number;
  id: string;
  type: number;
  enable: boolean;
  day: number;
  dialog: N918EDialog;
  badge: number;
  src: SrcClass;
}

export interface N918EDialog {
  "2": The2;
}

export interface The2 {
  gacha?: GachaElement[];
}

export interface GachaElement {
  id: string;
  count: number;
  idx: number;
}

export interface Report {
  settle: Settle;
  daily: Daily;
}

export interface Daily {
  isLoad: boolean;
  fromDay: number;
  seasonChange: boolean;
  mission: null;
  baseProduct: Info[];
}

export interface Settle {
  score: number;
  scoreRatio: string;
  techToken: number;
  techCent: number;
  shopCoin: number;
  shopCoinMax: boolean;
  detail: Detail;
}

export interface Detail {
  dayScore: number;
  apScore: number;
  exploreScore: number;
  hasRift: boolean;
  riftScore: number;
  enemyRush: DetailEnemyRush;
  home: { [key: string]: number };
  make: Make;
}

export interface DetailEnemyRush {
  "1": number[];
}

export interface Make {
  tactical: number;
  food: number;
}

export interface MainStage {
  node: StageNode;
}

export interface StageNode {
  nB32E: NB32E;
  n3259: N2D12;
  n8340: N2D12;
  n6368: N2D12;
  n12B9: N12B9;
  n88A8: N07D6;
  n1060: N1060;
  n35C1: N0446;
  nD7CE: N2D12;
  n918E: N2D12;
  n2259: N0446;
  n20CB: N0446;
  n97C7: N07D6;
  n3740: N2D12;
  nD54F: N07D6;
  n9EF3: N07D6;
  nED84: N07D6;
  nA659: N07D6;
  nA226: N07D6;
  nEFA5: N2D12;
  n2D12: N2D12;
  n9096: N07D6;
  n0446: N0446;
  n8375: N07D6;
  n4121: N1060;
  nEA6F: N07D6;
  n607D: N2D12;
  n14BC: N07D6;
  n6831: N07D6;
  n10AD: N07D6;
  nA1C6: N2D12;
  n1B64: N0446;
  nA1CE: N07D6;
  n3809: N1060;
  n2BA6: N2BA6;
  nE095: N2D12;
  n4B29: N07D6;
  n71D1: N07D6;
  n9542: N07D6;
  nF0F5: N2D12;
  n74C3: N07D6;
  nDDDC: N07D6;
  nCFA1: N07D6;
  n4244: N07D6;
  nAB04: N07D6;
  nF294: N07D6;
  n2AF0: N1060;
  n9B77: N07D6;
  n6829: N07D6;
  n0FB8: N0446;
  nC69C: N2D12;
  nDEF4: N2D12;
  n9C6A: N07D6;
  nF5F6: N2D12;
  nA1AD: N07D6;
  nB55F: N07D6;
  n07D6: N07D6;
  nE038: N07D6;
  n81E8: N07D6;
  nF586: N07D6;
  nCA3B: N2D12;
  n9688: N07D6;
  n80F5: N07D6;
}

export interface N0446 {
  id: string;
  state: number;
  view: string;
  mine?: MineElement[];
  trap?: GateElement[];
  collect?: CollectElement[];
  action: Array<number[]>;
  actionKill?: any[];
  hunt?: Hunt[];
  insect?: MineElement[];
}

export interface CollectElement {
  key: CollectKey;
  pos: number[];
  count: number[];
  hpRatio: number;
  isDead: number;
  extraParam: number;
}

export type CollectKey =
  | "trap_409_xbwood"
  | "trap_410_xbstone"
  | "trap_460_xbdiam"
  | "trap_411_xbiron";

export interface Hunt {
  key: string;
  count: number[];
}

export interface MineElement {
  key: string;
  pos: number[];
  count?: number[];
  hpRatio: number;
  isDead?: number;
  extraParam?: number;
  dir?: number;
}

export interface GateElement {
  key: TrapKey;
  pos: number[];
  hpRatio: number;
  isDead: number;
}

export type TrapKey =
  | "trap_459_xblight"
  | "trap_416_gtreasure"
  | "trap_414_vegetation"
  | "trap_440_xbalis"
  | "trap_413_hiddenstone"
  | "trap_461_xbhydr"
  | "trap_412_redtower"
  | "trap_422_streasure"
  | "trap_437_poachr"
  | "trap_441_xbmgbird";

export interface N07D6 {
  id: string;
  state: number;
  view: string;
  trap?: GateElement[];
  nest?: GateElement[];
  action: Array<number[]>;
  insect?: N07D6Insect[];
  hunt?: Hunt[];
  actionKill?: Array<number[]>;
  collect?: CollectElement[];
  cave?: MineElement[];
  gate?: GateElement[];
  building?: MineElement[];
  mine?: MineElement[];
}

export interface N07D6Insect {
  key: string;
  pos: number[];
  count: number[];
  hpRatio: number;
  isDead: number;
}

export interface N1060 {
  id: string;
  state: number;
  view: string;
  gate?: GateElement[];
  insect?: MineElement[];
  collect: MineElement[];
  action: Array<number[]>;
  actionKill: any[];
  building?: BuildingElement[];
  trap?: MineElement[];
  hunt?: Hunt[];
}

export interface BuildingElement {
  key: string;
  pos: number[];
  hpRatio: number;
  dir: number;
}

export interface N12B9 {
  id: string;
  state: number;
  view: string;
  port: MineElement[];
  action: any[];
  building: MineElement[];
}

export interface N2BA6 {
  id: string;
  state: number;
  view: string;
  trap: MineElement[];
  insect: MineElement[];
  cave: MineElement[];
  action: Array<number[]>;
}

export interface N2D12 {
  id: string;
  state: number;
  view: View;
  action: Array<number[]>;
  hunt?: Hunt[];
  trap?: MineElement[];
}

export type View = "" | "AAAEfOCPf/7jBw==";

export interface NB32E {
  id: string;
  state: number;
  view: string;
  base: MineElement[];
  trap: MineElement[];
  building: MineElement[];
  action: any[];
  animal: any[];
}

export interface Sandbox1_Mission {
  squad: MissionSquad[];
}

export interface MissionSquad {
  id: string;
  day: number;
  char: number[];
}

export interface Month {
  rushPass: any[];
}

export interface Quest {
  pending: PendingElement[];
  complete: string[];
}

export interface PendingElement {
  id: string;
  state: number;
  progress: Array<number[]>;
  progIdx: number;
}

export interface Racing {
  unlock: boolean;
  token: number;
  bag: BagTmpClass;
  bagTmp: BagTmpClass;
}

export interface BagTmpClass {
  racer: {};
  cap: number;
}

export interface RiftInfo {
  isUnlocked: boolean;
  randomRemain: number;
  difficultyLvMax: number;
  teamLv: number;
  fixFinish: string[];
  reservation: null;
  gameInfo: null;
  settleInfo: null;
}

export interface Sandbox1_Shop {
  unlock: boolean;
  day: number;
  slots: Info[];
}

export interface Sandbox1_Status {
  ver: number;
  state: number;
  ts: number;
  isRift: boolean;
  isGuide: boolean;
  exploreMode: boolean;
  isChallenge: boolean;
}

export interface Supply {
  unlock: boolean;
  enable: boolean;
  slotCnt: number;
  char: number[];
}

export interface TechClass {
  token: number;
  cent: number;
  unlock: string[];
}

export interface Sandbox1_Troop {
  food: {};
  squad: PurpleSquad[];
  usedChar: any[];
}
export interface PurpleSquad {
  slots: PlayerSquadItem[];
  tools: string[];
}

export interface PlayerSetting {
  perf: PlayerSettingPerf;
}

export interface PlayerSettingPerf {
  lowPower: number;
}

export interface PlayerCrossAppShare {
  shareMissions: { [key: string]: ShareMissionData };
}

export interface ShareMissionData {
  counter: number;
}
export interface PlayerDataShop {
  LS: Ls;
  HS: Hs;
  ES: Es;
  CASH: Cash;
  GP: Gp;
  FURNI: Furni;
  SOCIAL: Social;
  EPGS: Cash;
  REP: Cash;
  CLASSIC: Classic;
}

export interface Cash {
  info: Info[];
}

export interface Classic {
  info: Info[];
  progressInfo: { [key: string]: CharBibeakProgress };
}

export interface Es {
  curShopId: string;
  info: Info[];
  lastClick: number;
}

export interface Furni {
  info: Info[];
  groupInfo: { [key: string]: number };
}

export interface Gp {
  oneTime: Cash;
  level: Cash;
  weekly: Monthly;
  monthly: Monthly;
  choose: Cash;
}

export interface Monthly {
  curGroupId: string;
  info: any[];
}

export interface Hs {
  curShopId: string;
  info: Info[];
  progressInfo: { [key: string]: CharBibeakProgress };
}

export interface Ls {
  curShopId: string;
  curGroupId: string;
  info: Info[];
}

export interface Social {
  curShopId: string;
  info: Info[];
  charPurchase: CharPurchase;
}

export interface CharPurchase {
  char_198_blackd: number;
  char_187_ccheal: number;
  char_260_durnar: number;
}

export interface PlayerSiracusaMap {
  select: string | null;
  card: { [key: string]: CharCard };
  opera: Opera;
  area: { [key: string]: number };
}

export interface CharCard {
  items: { [key: string]: number };
  taskRing: { [key: string]: TaskRing };
}

export interface TaskRing {
  task: { [key: string]: TaskInfo };
  state: number;
}

export interface TaskInfo {
  state: number;
  option: string[];
  progress: BattleProgress;
}

export interface BattleProgress {
  value: number;
  target: number;
}
export interface Opera {
  total: number;
  show: string | null;
  release: { [key: string]: number };
  like: { [key: string]: string };
}

export interface PlayerSocial {
  assistCharList: PlayerFriendAssist[];
  yesterdayReward: PlayerSocialReward;
  yCrisisSs: string; //yesterdayCrisisSeasonId
  medalBoard: PlayerMedalBoard;
  yCrisisV2Ss: string; //yesterdayCrisisSeasonId
}

export interface PlayerMedalBoard {
  type: string;
  custom: null | string;
  template: string | null;
  templateMedalList: string[] | null;
}

export interface PlayerSocialReward {
  canReceive: number;
  assistAmount: number;
  comfortAmount: number;
  first: number;
}

export interface PlayerStoryReview {
  groups: { [key: string]: PlayerStoryReviewUnlockInfo };
  tags: { [key: string]: number };
}

export interface StoryReviewUnlockInfo {
  id: string;
  uts: number;
  rc: number;
}
export interface PlayerStoryReviewUnlockInfo {
  rts: number;
  stories: StoryReviewUnlockInfo[];
  trailRewards?: string[];
}

export interface PlayerTemplateTrap {
  domains: { [key: string]: Domain };
}

export interface Domain {
  traps: { [key: string]: Trap };
  squad: string[];
}

export interface Trap {
  count: number;
}

export interface PlayerTower {
  current: TowerCurrent;
  outer: TowerOuter;
  season: TowerSeason;
}

export interface TowerCurrent {
  status: CurrentStatus;
  layer: Layer[];
  cards: { [key: string]: CardValue };
  godCard: GodCard;
  halftime: Halftime;
  trap: CurrentTrap[];
  reward: CurrentReward;
}

export interface CardValue {
  instId: string;
  type: "CHAR";
  charId: string;
  relation: string;
  evolvePhase: number;
  level: number;
  favorPoint: number;
  potentialRank: number;
  mainSkillLvl: number;
  skills: any[];
  defaultSkillIndex: number;
  currentEquip: null | string;
  equip: { [key: string]: any };
  skin: string;
}

export interface GodCard {
  id: string;
  subGodCardId: string;
}

export interface Halftime {
  count: number;
  candidate: any[];
  canGiveUp: boolean;
}

export interface Layer {
  id: string;
  try: number;
  pass: boolean;
}

export interface CurrentReward {
  high: number;
  low: number;
}

export interface CurrentStatus {
  state: string;
  tower: string;
  coord: number;
  tactical: StatusTactical;
  strategy: string;
  start: number;
  isHard: boolean;
}

export interface StatusTactical {
  PIONEER: string;
  WARRIOR: string;
  TANK: string;
  SNIPER: string;
  CASTER: string;
  SUPPORT: string;
  MEDIC: string;
  SPECIAL: string;
}

export interface CurrentTrap {
  id: string;
  alias: string;
}

export interface TowerOuter {
  training: OuterTraining;
  towers: { [key: string]: TowerValue };
  hasTowerPass: number;
  pickedGodCard: { [key: string]: string[] };
  tactical: StatusTactical;
  strategy: string;
}

export interface TowerValue {
  best: number;
  reward: number[];
  unlockHard: boolean;
  hardBest: number;
}

export interface OuterTraining {
  tower_tr_01: number;
  tower_tr_02: number;
  tower_tr_03: number;
}

export interface TowerSeason {
  id: string;
  finishTs: number;
  missions: { [key: string]: TowerSeasonMission };
  passWithGodCard: {};
  slots: Slots;
  period: Period;
}

export interface TowerSeasonMission {
  value: number;
  target: number;
  hasRecv: boolean;
}
export interface Period {
  termTs: number;
  items: {};
  cur: number;
  len: number;
}

export interface Slots {
  tower_n_13: TowerN13[];
}

export interface TowerN13 {
  godCardId: string;
  squad: PlayerSquadItem[];
}

export interface PlayerTemplateShop {
  coin: number;
  info: PlayerGoodItemData[];
  progressInfo: { [key: string]: PlayerGoodProgressData };
}

export interface PlayerGoodItemData {
  id: string;
  count: number;
}

export interface PlayerGoodProgressData {
  count: number;
  order: number;
}

export interface PlayerCharRotation {
  current: string;
  preset: { [key: string]: PlayerCharRotationPreset };
}

export interface PlayerCharRotationPreset {
  name: string;
  background: string;
  homeTheme: string;
  profile: string;
  profileInst: number;
  slots: PlayerCharRotationSlot[];
}

export interface PlayerCharRotationSlot {
  charId: string;
  skinId: string;
}

export interface PlayerTrainingCamp {
  stages: { [key: string]: PlayerTrainingCampStage };
}

export interface PlayerTrainingCampStage {
  stageId: string;
  state: number;
  rts: number;
}
