import { PlayerActivity } from "./activity";
import { AvatarInfo, PlayerFriendAssist, PlayerSquadItem, PlayerTroop } from "./character";

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
    tshop: Tshop;
    gacha: PlayerGacha;
    backflow: Backflow;
    mainline: Mainline;
    avatar: PlayerAvatar;
    background: PlayerHomeBackground;
    homeTheme: PlayerHomeTheme;
    rlv2: any;
    deepSea: DeepSea;
    tower: PlayerDataTower;
    siracusaMap: SiracusaMap;
    sandboxPerm: any;
    storyreview: PlayerStoryReview;
    medal: PlayerMedal;
    event: PlayerDataEvent;
    retro: Retro;
    share: Share;
    roguelike: {
        current: null,
        stable: null
    };
    ticket: Ticket;
    aprilFool: AprilFoolClass;
    consumable: { [key: string]: { [key: string]: PlayerConsumableItem } };
    charm: Charm;
    carousel: Carousel;
    openServer: PlayerOpenServer;
    car: Car;
    recruit: PlayerRecruit;
    templateTrap: TemplateTrap;
    checkIn: PlayerCheckIn;
    inventory: { [key: string]: number };
    campaignsV2: CampaignsV2;
    setting: PlayerSetting;
    checkMeta: CheckMeta;
    limitedBuff: LimitedBuff;
    collectionReward: PlayerCollection;
    trainingGround?: any
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
    missions: MissionCalcState[];
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
export interface Matrix {
    x: number;
    y: number;
}






export interface AprilFoolClass {
    act3fun: Act3Fun;
    act4fun: Act4Fun;
    act5fun: Act5Fun;
}

export interface Act3Fun {
    stages: { [key: string]: Act3FunStage };
}

export interface Act3FunStage {
    state: number;
    scores: number[];
}

export interface Act4Fun {
    stages: { [key: string]: Act4FunStage };
    liveEndings: LiveEndings;
    cameraLv: number;
    fans: number;
    posts: number;
    missions: Act4FunMissions;
}

export interface LiveEndings {
    badending_2: number;
    badending_3: number;
    badending_5: number;
    badending_1: number;
    badending_4: number;
    goodending_1: number;
    badending_6: number;
}

export interface Act4FunMissions {
    mission_1: Mission1_Value;
    mission_2: Mission1_Value;
    mission_3: Mission1_Value;
    mission_4: Mission1_Value;
    mission_5: Mission1_Value;
    mission_6: Mission1_Value;
    mission_7: Mission1_Value;
}

export interface Mission1_Value {
    value: number;
    target: number;
    finished?: boolean;
    hasRecv: boolean;
}

export interface Act4FunStage {
    state: number;
    liveTimes: number;
}

export interface Act5Fun {
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

export interface Backflow {
    open: boolean;
    current: null;
}

export interface PlayerHomeBackground {
    selected: string;
    bgs: { [key: string]: PlayerHomeUnlockStatus };
}


export interface PlayerHomeUnlockStatus {
    unlock?: number;//unlockTime
    conditions?: { [key: string]: PlayerHomeConditionProgress };
}


export interface PlayerHomeConditionProgress {
    v: number;//curProgress
    t: number;//total
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
    DORMITORY: {[key:string]:PlayerBuildingDormitory};
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
    point: {[key:string]:number};
    hire: Hire;
    power: Power;
    dormitory: Dormitory;
    training: BuffTraining;
}
export namespace PlayerBuildingControlBuff {
    export interface Global {
        apCost: number;
        roomCnt: {};
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
export interface MissionCalcState {
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


export interface CampaignsV2 {
    campaignCurrentFee: number;
    campaignTotalFee: number;
    lastRefreshTs: number;
    instances: { [key: string]: Instance };
    open: Open;
    missions: CampaignsV2Missions;
    sweepMaxKills: { [key: string]: number };
}

export interface Instance {
    maxKills: number;
    rewardStatus: number[];
}

export interface CampaignsV2Missions {
    exterminateActivity_1: number;
    exterminateActivity_2: number;
    exterminateActivity_3: number;
    exterminateActivity_4: number;
}

export interface Open {
    permanent: string[];
    rotate: string;
    rGroup: string;
    training: string[];
    tGroup: string;
    tAllOpen: string;
}

export interface Car {
    battleCar: BattleCarClass;
    exhibitionCar: BattleCarClass;
    accessories: { [key: string]: Accessory };
}

export interface Accessory {
    id: string;
    num: number;
}

export interface BattleCarClass {
    ROOF: null | string;
    HEADSTOCK: null | string;
    TRUNK_01: null | string;
    CAR_OS_01: null | string;
    TRUNK_02: null | string;
    CAR_OS_02: null | string;
}

export interface Carousel {
    furnitureShop: FurnitureShop;
}

export interface FurnitureShop {
    goods: { [key: string]: number };
    groups: { [key: string]: number };
}

export interface Charm {
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
        checkInHistory: number[];//boolean[]
    }
}
export interface CheckMeta {
    version: number;
    ts: number;
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
    progress: MissionCalcState | number | null;
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

export interface DeepSea {
    places: { [key: string]: number };
    nodes: { [key: string]: number };
    choices: { [key: string]: number[] };
    events: { [key: string]: number };
    treasures: { [key: string]: number };
    stories: { [key: string]: number };
    techTrees: TechTrees;
    logs: { [key: string]: string[] };
}

export interface TechTrees {
    tech_1: Tech;
    tech_2: Tech;
    tech_3: Tech;
    tech_4: Tech;
    tech_5: Tech;
}

export interface Tech {
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

export interface LimitedBuff {
    dailyUsage: {};
    inventory: LimitedBuffInventory;
}

export interface LimitedBuffInventory {
    Logistics_Special_Permit: PlayerConsumableItem;
}

export interface Mainline {
    record: { [key: string]: number };
    cache: any[];
    version: number;
    additionalMission: AdditionalMission;
    charVoiceRecord: CharVoiceRecord;
    explore: Explore;
}

export interface AdditionalMission {
    "tough_12-06": Tough12;
    "tough_12-11": Tough12;
    "tough_12-18": Tough12;
}

export interface Tough12 {
    state: number;
    process: MissionCalcState;
}

export interface CharVoiceRecord {
    mission_archive_main_14: MissionArchiveMain14;
}

export interface MissionArchiveMain14 {
    isOpen: boolean;
    confirmEnterReward: boolean;
    nodes: Nodes;
}

export interface Nodes {
    main_node_1: number;
    main_node_2: number;
    main_node_3: number;
    main_node_4: number;
    main_node_5: number;
}

export interface Explore {
    game: null;
    outer: ExploreOuter;
}

export interface ExploreOuter {
    isOpen: boolean;
    lastGameResult: LastGameResult;
    historyPaths: HistoryPath[];
    mission: { [key: string]: CHALLENGEValue };
}

export interface HistoryPath {
    success: boolean;
    path: Path;
}

export interface Path {
    pathSeed: number;
    nodeSeed: number;
    controlPoints: ControlPoint[];
}

export interface ControlPoint {
    stageId: string;
    pos: Matrix;
}

export interface LastGameResult {
    groupId: string;
    groupCode: string;
    heritageAbilities: HeritageAbilities;
}

export interface HeritageAbilities {
    TEAMVALUE_1: number;
    TEAMVALUE_2: number;
    TEAMVALUE_3: number;
}

export interface CHALLENGEValue {
    state: number;
    progress: number[];
}

export interface PlayerMedal {
    medals: { [key: string]: PlayerPerMedal };
    custom: PlayerMedalCustom;
}

export interface PlayerMedalCustom {
    currentIndex: string;
    customs: {[key: string]: PlayerMedalCustomLayout};
}



export interface PlayerMedalCustomLayout {
    layout: PlayerMedalCustomLayoutItem[];
}
export interface PlayerMedalCustomLayoutItem {
    id:string,
    pos:number[]
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
    progress: MissionCalcState[];
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
export interface Retro {
    coin: number;
    supplement: number;
    block: { [key: string]: Block };
    lst: number;
    nst: number;
    trail: Trail;
    rewardPerm: any[];
}

export interface Block {
    locked: number;
    open: number;
}

export interface Trail {
    permanent_sidestory_2_Heart_Of_Surging_Flame: PermanentSidestory2_HeartOfSurgingFlame;
    permanent_sidestory_1_Grani_And_The_Treasure_Of_Knights: PermanentSidestory1_GraniAndTheTreasureOfKnights;
    permanent_sidestory_3_Code_Of_Brawl: PermanentSidestory3_CodeOfBrawl;
    permanent_sub_1_Darknights_Memoir: PermanentS;
    permanent_sidestory_4_Twilight_Of_Wolumonde: PermanentS;
    permanent_sidestory_5_The_Great_Chief_Returns: PermanentSidestory5_TheGreatChiefReturns;
    permanent_sidestory_6_Maria_Nearl: PermanentSidestory6_MariaNearl;
    permanent_sidestory_7_Mansfield_Break: PermanentSidestory7_MansfieldBreak;
    permanent_sidestory_8_Who_is_Real: PermanentSidestory8_WhoIsReal;
    permanent_sub_2_A_Walk_In_The_Dust: PermanentSub2_AWalkInTheDust;
    permanent_sub_3_Under_Tides: PermanentSub3_UnderTides;
    permanent_sidestory_9_Dossoles_Holiday: PermanentSidestory9_DossolesHoliday;
    permanent_sidestory_10_Near_Light: PermanentSidestory10_NearLight;
    permanent_sidestory_11_Break_The_Ice: PermanentSidestory11_BreakTheIce;
    permanent_sidestory_12_Invitation_To_Wine: PermanentSidestory12_InvitationToWine;
    permanent_sidestory_13_Guiding_Ahead: PermanentSidestory13_GuidingAhead;
    permanent_sub_4_Stultifera_Navis: PermanentSub4_StultiferaNavis;
}

export interface PermanentSidestory10_NearLight {
    trailReward_sub_10_1: number;
    trailReward_sub_10_2: number;
    trailReward_sub_10_3: number;
    trailReward_sub_10_4: number;
    trailReward_sub_10_5: number;
}

export interface PermanentSidestory11_BreakTheIce {
    trailReward_sidestory_11_1: number;
    trailReward_sidestory_11_2: number;
    trailReward_sidestory_11_3: number;
    trailReward_sidestory_11_4: number;
    trailReward_sidestory_11_5: number;
}

export interface PermanentSidestory12_InvitationToWine {
    trailReward_sidestory_12_1: number;
    trailReward_sidestory_12_2: number;
    trailReward_sidestory_12_3: number;
    trailReward_sidestory_12_4: number;
    trailReward_sidestory_12_5: number;
}

export interface PermanentSidestory13_GuidingAhead {
    trailReward_sidestory_13_1: number;
    trailReward_sidestory_13_2: number;
    trailReward_sidestory_13_3: number;
    trailReward_sidestory_13_4: number;
    trailReward_sidestory_13_5: number;
}

export interface PermanentSidestory1_GraniAndTheTreasureOfKnights {
    trailReward_sidestory_1_1: number;
    trailReward_sidestory_1_2: number;
    trailReward_sidestory_1_3: number;
    trailReward_sidestory_1_4: number;
    trailReward_sidestory_1_5: number;
}

export interface PermanentSidestory2_HeartOfSurgingFlame {
    trailReward_sidestory_2_1: number;
    trailReward_sidestory_2_2: number;
    trailReward_sidestory_2_3: number;
    trailReward_sidestory_2_4: number;
    trailReward_sidestory_2_5: number;
    trailReward_sidestory_2_6: number;
}

export interface PermanentSidestory3_CodeOfBrawl {
    trailReward_sidestory_3_1: number;
    trailReward_sidestory_3_2: number;
    trailReward_sidestory_3_3: number;
    trailReward_sidestory_3_4: number;
}

export interface PermanentS {
    trailReward_sub_1_1: number;
    trailReward_sub_1_2: number;
    trailReward_sub_1_3: number;
    trailReward_sub_1_4: number;
    trailReward_sub_1_5: number;
}

export interface PermanentSidestory5_TheGreatChiefReturns {
    trailReward_sidestory_5_1: number;
    trailReward_sidestory_5_2: number;
    trailReward_sidestory_5_3: number;
    trailReward_sidestory_5_4: number;
    trailReward_sidestory_5_5: number;
}

export interface PermanentSidestory6_MariaNearl {
    trailReward_sidestory_6_1: number;
    trailReward_sidestory_6_2: number;
    trailReward_sidestory_6_3: number;
    trailReward_sidestory_6_4: number;
    trailReward_sidestory_6_5: number;
    trailReward_sidestory_6_6: number;
}

export interface PermanentSidestory7_MansfieldBreak {
    trailReward_sidestory_7_1: number;
    trailReward_sidestory_7_2: number;
    trailReward_sidestory_7_3: number;
    trailReward_sidestory_7_4: number;
    trailReward_sidestory_7_5: number;
}

export interface PermanentSidestory8_WhoIsReal {
    trailReward_sidestory_8_1: number;
    trailReward_sidestory_8_2: number;
    trailReward_sidestory_8_3: number;
    trailReward_sidestory_8_4: number;
    trailReward_sidestory_8_5: number;
}

export interface PermanentSidestory9_DossolesHoliday {
    trailReward_sidestory_9_1: number;
    trailReward_sidestory_9_2: number;
    trailReward_sidestory_9_3: number;
    trailReward_sidestory_9_4: number;
    trailReward_sidestory_9_5: number;
    trailReward_sidestory_9_6: number;
}

export interface PermanentSub2_AWalkInTheDust {
    trailReward_sub_2_1: number;
    trailReward_sub_2_2: number;
    trailReward_sub_2_3: number;
    trailReward_sub_2_4: number;
    trailReward_sub_2_5: number;
}

export interface PermanentSub3_UnderTides {
    trailReward_sub_3_1: number;
    trailReward_sub_3_2: number;
    trailReward_sub_3_3: number;
    trailReward_sub_3_4: number;
    trailReward_sub_3_5: number;
}

export interface PermanentSub4_StultiferaNavis {
    trailReward_sub_4_1: number;
    trailReward_sub_4_2: number;
    trailReward_sub_4_3: number;
    trailReward_sub_4_4: number;
    trailReward_sub_4_5: number;
    trailReward_sub_4_6: number;
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

export type ZoneEnum = "z_1_1" | "z_1_5" | "z_1_4" | "z_1_2" | "z_1_0" | "z_1_3";

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
    "3": {};
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

export type CollectKey = "trap_409_xbwood" | "trap_410_xbstone" | "trap_460_xbdiam" | "trap_411_xbiron";

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

export type TrapKey = "trap_459_xblight" | "trap_416_gtreasure" | "trap_414_vegetation" | "trap_440_xbalis" | "trap_413_hiddenstone" | "trap_461_xbhydr" | "trap_412_redtower" | "trap_422_streasure" | "trap_437_poachr" | "trap_441_xbmgbird";

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

export interface Share {
    shareMissions: {};
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

export interface SiracusaMap {
    select: null;
    card: SiracusaMapCard;
    opera: Opera;
    area: Area;
}

export interface Area {
    area_centro: number;
    area_rione: number;
    area_saluzzo: number;
    area_teatro: number;
    area_torre: number;
    area_rossati: number;
    area_comando: number;
    area_municipio: number;
    area_bellone: number;
}

export interface SiracusaMapCard {
    char_card_Texas: CharCardTexas;
    char_card_Lavinia: CharCardLavinia;
    char_card_Leontuzzo: CharCardLeontuzzo;
    char_card_Lappland: CharCardLappland;
    char_card_Giovanna: CharCardGiovanna;
    char_card_Agenir: CharCardAgenir;
    char_card_Sora: CharCardSora;
    char_card_Demetri: CharCardDemetri;
    char_card_Danbrown: CharCardDanbrown;
    char_card_Ben: CharCardBen;
}

export interface CharCardAgenir {
    item: {};
    taskRing: CharCardAgenirTaskRing;
    state: number;
}

export interface CharCardAgenirTaskRing {
    taskRing_Agenir_1: TaskRingAgenir1;
    taskRing_Agenir_2: TaskRingAgenir2;
    taskRing_Agenir_3: TaskRingAgenir3;
}

export interface TaskRingAgenir1 {
    task: TaskRingAgenir1_Task;
    state: number;
}

export interface TaskRingAgenir1_Task {
    task_Agenir_1_1: Task;
    task_Agenir_1_2: Task;
    task_Agenir_1_3: Task;
}

export interface Task {
    state: number;
    option: string[];
}

export interface TaskRingAgenir2 {
    task: TaskRingAgenir2_Task;
    state: number;
}

export interface TaskRingAgenir2_Task {
    task_Agenir_2_1: Task;
}

export interface TaskRingAgenir3 {
    task: TaskRingAgenir3_Task;
    state: number;
}

export interface TaskRingAgenir3_Task {
    task_Agenir_3_1: Task;
    task_Agenir_3_2: Task;
}

export interface CharCardBen {
    item: {};
    taskRing: CharCardBenTaskRing;
    state: number;
}

export interface CharCardBenTaskRing {
    taskRing_Ben_1: TaskRingBen1;
    taskRing_Ben_2: TaskRingBen2;
    taskRing_Ben_3: TaskRingBen3;
}

export interface TaskRingBen1 {
    task: TaskRingBen1_Task;
    state: number;
}

export interface TaskRingBen1_Task {
    task_Ben_1_1: Task;
}

export interface TaskRingBen2 {
    task: TaskRingBen2_Task;
    state: number;
}

export interface TaskRingBen2_Task {
    task_Ben_2_1: Task;
}

export interface TaskRingBen3 {
    task: TaskRingBen3_Task;
    state: number;
}

export interface TaskRingBen3_Task {
    task_Ben_3_1: Task;
    task_Ben_3_2: Task;
}

export interface CharCardDanbrown {
    item: {};
    taskRing: CharCardDanbrownTaskRing;
    state: number;
}

export interface CharCardDanbrownTaskRing {
    taskRing_Danbrown_1: TaskRingDanbrown1;
    taskRing_Danbrown_2: TaskRingDanbrown2;
    taskRing_Danbrown_3: TaskRingDanbrown3;
    taskRing_Danbrown_4: TaskRingDanbrown4;
    taskRing_Danbrown_5: TaskRingDanbrown5;
    taskRing_Danbrown_6: TaskRingDanbrown6;
}

export interface TaskRingDanbrown1 {
    task: TaskRingDanbrown1_Task;
    state: number;
}

export interface TaskRingDanbrown1_Task {
    task_Danbrown_1_1: Task;
    task_Danbrown_1_2: Reward1;
}

export interface TaskRingDanbrown2 {
    task: TaskRingDanbrown2_Task;
    state: number;
}

export interface TaskRingDanbrown2_Task {
    task_Danbrown_2_1: Task;
    task_Danbrown_2_2: Task;
    task_Danbrown_2_3: Task;
}

export interface TaskRingDanbrown3 {
    task: TaskRingDanbrown3_Task;
    state: number;
}

export interface TaskRingDanbrown3_Task {
    task_Danbrown_3_1: Task;
    task_Danbrown_3_2: Task;
}

export interface TaskRingDanbrown4 {
    task: TaskRingDanbrown4_Task;
    state: number;
}

export interface TaskRingDanbrown4_Task {
    task_Danbrown_4_1: Task;
    task_Danbrown_4_2: Task;
}

export interface TaskRingDanbrown5 {
    task: TaskRingDanbrown5_Task;
    state: number;
}

export interface TaskRingDanbrown5_Task {
    task_Danbrown_5_1: Task;
    task_Danbrown_5_2: Reward1;
}

export interface TaskRingDanbrown6 {
    task: TaskRingDanbrown6_Task;
    state: number;
}

export interface TaskRingDanbrown6_Task {
    task_Danbrown_6_1: Task;
}

export interface CharCardDemetri {
    item: {};
    taskRing: CharCardDemetriTaskRing;
    state: number;
}

export interface CharCardDemetriTaskRing {
    taskRing_Demetri_1: TaskRingDemetri1;
    taskRing_Demetri_2: TaskRingDemetri2;
    taskRing_Demetri_3: TaskRingDemetri3;
    taskRing_Demetri_4: TaskRingDemetri4;
}

export interface TaskRingDemetri1 {
    task: TaskRingDemetri1_Task;
    state: number;
}

export interface TaskRingDemetri1_Task {
    task_Demetri_1_1: Task;
}

export interface TaskRingDemetri2 {
    task: TaskRingDemetri2_Task;
    state: number;
}

export interface TaskRingDemetri2_Task {
    task_Demetri_2_1: Task;
    task_Demetri_2_2: Task;
    task_Demetri_2_3: Task;
    task_Demetri_2_4: Task;
}

export interface TaskRingDemetri3 {
    task: TaskRingDemetri3_Task;
    state: number;
}

export interface TaskRingDemetri3_Task {
    task_Demetri_3_1: Task;
    task_Demetri_3_2: Reward1;
}

export interface TaskRingDemetri4 {
    task: TaskRingDemetri4_Task;
    state: number;
}

export interface TaskRingDemetri4_Task {
    task_Demetri_4_1: Task;
}

export interface CharCardGiovanna {
    item: CharCardGiovannaItem;
    taskRing: CharCardGiovannaTaskRing;
    state: number;
}

export interface CharCardGiovannaItem {
    item_bribery: number;
    item_officetoken: number;
    item_inspiration: number;
}

export interface CharCardGiovannaTaskRing {
    taskRing_Giovanna_1: TaskRingGiovanna1;
    taskRing_Giovanna_2: TaskRingGiovanna2;
    taskRing_Giovanna_3: TaskRingGiovanna3;
    taskRing_Giovanna_4: TaskRingGiovanna4;
    taskRing_Giovanna_5: TaskRingGiovanna5;
}

export interface TaskRingGiovanna1 {
    task: TaskRingGiovanna1_Task;
    state: number;
}

export interface TaskRingGiovanna1_Task {
    task_Giovanna_1_1: Task;
    task_Giovanna_1_2: Task;
    task_Giovanna_1_3: Task;
}

export interface TaskRingGiovanna2 {
    task: TaskRingGiovanna2_Task;
    state: number;
}

export interface TaskRingGiovanna2_Task {
    task_Giovanna_2_1: Task;
    task_Giovanna_2_2: Reward1;
    task_Giovanna_2_3: Task;
    task_Giovanna_2_4: Task;
}

export interface TaskRingGiovanna3 {
    task: TaskRingGiovanna3_Task;
    state: number;
}

export interface TaskRingGiovanna3_Task {
    task_Giovanna_3_1: Task;
}

export interface TaskRingGiovanna4 {
    task: TaskRingGiovanna4_Task;
    state: number;
}

export interface TaskRingGiovanna4_Task {
    task_Giovanna_4_1: Task;
    task_Giovanna_4_2: Task;
}

export interface TaskRingGiovanna5 {
    task: TaskRingGiovanna5_Task;
    state: number;
}

export interface TaskRingGiovanna5_Task {
    task_Giovanna_5_1: Task;
    task_Giovanna_5_2: Task;
}

export interface CharCardLappland {
    item: {};
    taskRing: CharCardLapplandTaskRing;
    state: number;
}

export interface CharCardLapplandTaskRing {
    taskRing_Lappland_1: TaskRingLappland1;
    taskRing_Lappland_2: TaskRingLappland2;
    taskRing_Lappland_3: TaskRingLappland3;
    taskRing_Lappland_4: TaskRingLappland4;
    taskRing_Lappland_5: TaskRingLappland5;
}

export interface TaskRingLappland1 {
    task: TaskRingLappland1_Task;
    state: number;
}

export interface TaskRingLappland1_Task {
    task_Lappland_1_1: Task;
    task_Lappland_1_2: Reward1;
}

export interface TaskRingLappland2 {
    task: TaskRingLappland2_Task;
    state: number;
}

export interface TaskRingLappland2_Task {
    task_Lappland_2_1: Reward1;
    task_Lappland_2_2: Reward1;
}

export interface TaskRingLappland3 {
    task: TaskRingLappland3_Task;
    state: number;
}

export interface TaskRingLappland3_Task {
    task_Lappland_3_1: Task;
    task_Lappland_3_2: Task;
}

export interface TaskRingLappland4 {
    task: TaskRingLappland4_Task;
    state: number;
}

export interface TaskRingLappland4_Task {
    task_Lappland_4_1: Task;
    task_Lappland_4_2: Reward1;
    task_Lappland_4_3: Task;
}

export interface TaskRingLappland5 {
    task: TaskRingLappland5_Task;
    state: number;
}

export interface TaskRingLappland5_Task {
    task_Lappland_5_1: Task;
    task_Lappland_5_2: Task;
}

export interface CharCardLavinia {
    item: CharCardLaviniaItem;
    taskRing: CharCardLaviniaTaskRing;
    state: number;
}

export interface CharCardLaviniaItem {
    item_thankflower: number;
    item_borrow: number;
    item_resume: number;
}

export interface CharCardLaviniaTaskRing {
    taskRing_Lavinia_1: TaskRingLavinia1;
    taskRing_Lavinia_2: TaskRingLavinia2;
    taskRing_Lavinia_3: TaskRingLavinia3;
    taskRing_Lavinia_4: TaskRingLavinia4;
    taskRing_Lavinia_5: TaskRingLavinia5;
}

export interface TaskRingLavinia1 {
    task: TaskRingLavinia1_Task;
    state: number;
}

export interface TaskRingLavinia1_Task {
    task_Lavinia_1_1: Task;
    task_Lavinia_1_2: Reward1;
}

export interface TaskRingLavinia2 {
    task: TaskRingLavinia2_Task;
    state: number;
}

export interface TaskRingLavinia2_Task {
    task_Lavinia_2_1: Task;
    task_Lavinia_2_2: Task;
}

export interface TaskRingLavinia3 {
    task: TaskRingLavinia3_Task;
    state: number;
}

export interface TaskRingLavinia3_Task {
    task_Lavinia_3_1: Task;
    task_Lavinia_3_2: Task;
}

export interface TaskRingLavinia4 {
    task: TaskRingLavinia4_Task;
    state: number;
}

export interface TaskRingLavinia4_Task {
    task_Lavinia_4_1: Task;
    task_Lavinia_4_2: Task;
}

export interface TaskRingLavinia5 {
    task: TaskRingLavinia5_Task;
    state: number;
}

export interface TaskRingLavinia5_Task {
    task_Lavinia_5_1: Task;
    task_Lavinia_5_2: Task;
}

export interface CharCardLeontuzzo {
    item: {};
    taskRing: CharCardLeontuzzoTaskRing;
    state: number;
}

export interface CharCardLeontuzzoTaskRing {
    taskRing_Leontuzzo_1: TaskRingLeontuzzo1;
    taskRing_Leontuzzo_2: TaskRingLeontuzzo2;
    taskRing_Leontuzzo_3: TaskRingLeontuzzo3;
    taskRing_Leontuzzo_4: TaskRingLeontuzzo4;
    taskRing_Leontuzzo_5: TaskRingLeontuzzo5;
    taskRing_Leontuzzo_6: TaskRingLeontuzzo6;
    taskRing_Leontuzzo_7: TaskRingLeontuzzo7;
}

export interface TaskRingLeontuzzo1 {
    task: TaskRingLeontuzzo1_Task;
    state: number;
}

export interface TaskRingLeontuzzo1_Task {
    task_Leontuzzo_1_1: Task;
    task_Leontuzzo_1_2: Task;
}

export interface TaskRingLeontuzzo2 {
    task: TaskRingLeontuzzo2_Task;
    state: number;
}

export interface TaskRingLeontuzzo2_Task {
    task_Leontuzzo_2_1: Task;
}

export interface TaskRingLeontuzzo3 {
    task: TaskRingLeontuzzo3_Task;
    state: number;
}

export interface TaskRingLeontuzzo3_Task {
    task_Leontuzzo_3_1: Task;
    task_Leontuzzo_3_2: Task;
}

export interface TaskRingLeontuzzo4 {
    task: TaskRingLeontuzzo4_Task;
    state: number;
}

export interface TaskRingLeontuzzo4_Task {
    task_Leontuzzo_4_1: Task;
    task_Leontuzzo_4_2: Task;
    task_Leontuzzo_4_3: Task;
}

export interface TaskRingLeontuzzo5 {
    task: TaskRingLeontuzzo5_Task;
    state: number;
}

export interface TaskRingLeontuzzo5_Task {
    task_Leontuzzo_5_1: Task;
    task_Leontuzzo_5_2: Task;
    task_Leontuzzo_5_3: Task;
}

export interface TaskRingLeontuzzo6 {
    task: TaskRingLeontuzzo6_Task;
    state: number;
}

export interface TaskRingLeontuzzo6_Task {
    task_Leontuzzo_6_1: Task;
    task_Leontuzzo_6_2: Task;
    task_Leontuzzo_6_3: Task;
}

export interface TaskRingLeontuzzo7 {
    task: TaskRingLeontuzzo7_Task;
    state: number;
}

export interface TaskRingLeontuzzo7_Task {
    task_Leontuzzo_7_1: Task;
}

export interface CharCardSora {
    item: CharCardSoraItem;
    taskRing: CharCardSoraTaskRing;
    state: number;
}

export interface CharCardSoraItem {
    item_flower: number;
    item_chain: number;
    item_drink: number;
}

export interface CharCardSoraTaskRing {
    taskRing_Sora_1: TaskRingSora1;
    taskRing_Sora_2: TaskRingSora2;
    taskRing_Sora_3: TaskRingSora3;
    taskRing_Sora_4: TaskRingSora4;
}

export interface TaskRingSora1 {
    task: TaskRingSora1_Task;
    state: number;
}

export interface TaskRingSora1_Task {
    task_Sora_1_1: Task;
    task_Sora_1_2: Task;
}

export interface TaskRingSora2 {
    task: TaskRingSora2_Task;
    state: number;
}

export interface TaskRingSora2_Task {
    task_Sora_2_1: Task;
    task_Sora_2_2: Task;
    task_Sora_2_3: Task;
}

export interface TaskRingSora3 {
    task: TaskRingSora3_Task;
    state: number;
}

export interface TaskRingSora3_Task {
    task_Sora_3_1: Task;
    task_Sora_3_2: Task;
}

export interface TaskRingSora4 {
    task: TaskRingSora4_Task;
    state: number;
}

export interface TaskRingSora4_Task {
    task_Sora_4_1: Task;
    task_Sora_4_2: Task;
    task_Sora_4_3: Task;
}

export interface CharCardTexas {
    item: CharCardTexasItem;
    taskRing: CharCardTexasTaskRing;
    state: number;
}

export interface CharCardTexasItem {
    item_poster: number;
    item_redwine: number;
    item_surprise: number;
}

export interface CharCardTexasTaskRing {
    taskRing_Texas_1: TaskRingTexas1;
    taskRing_Texas_2: TaskRingTexas2;
    taskRing_Texas_3: TaskRingTexas3;
    taskRing_Texas_4: TaskRingTexas4;
    taskRing_Texas_5: TaskRingTexas5;
    taskRing_Texas_6: TaskRingTexas6;
    taskRing_Texas_7: TaskRingTexas7;
}

export interface TaskRingTexas1 {
    task: TaskRingTexas1_Task;
    state: number;
}

export interface TaskRingTexas1_Task {
    task_Texas_1_1: Task;
    task_Texas_1_2: Reward1;
}

export interface TaskRingTexas2 {
    task: TaskRingTexas2_Task;
    state: number;
}

export interface TaskRingTexas2_Task {
    task_Texas_2_1: Task;
    task_Texas_2_2: Task;
}

export interface TaskRingTexas3 {
    task: TaskRingTexas3_Task;
    state: number;
}

export interface TaskRingTexas3_Task {
    task_Texas_3_1: Task;
    task_Texas_3_2: Task;
    task_Texas_3_3: Reward1;
}

export interface TaskRingTexas4 {
    task: TaskRingTexas4_Task;
    state: number;
}

export interface TaskRingTexas4_Task {
    task_Texas_4_1: Reward1;
    task_Texas_4_2: Task;
}

export interface TaskRingTexas5 {
    task: TaskRingTexas5_Task;
    state: number;
}

export interface TaskRingTexas5_Task {
    task_Texas_5_1: Task;
    task_Texas_5_2: Task;
    task_Texas_5_3: Reward1;
}

export interface TaskRingTexas6 {
    task: TaskRingTexas6_Task;
    state: number;
}

export interface TaskRingTexas6_Task {
    task_Texas_6_1: Task;
    task_Texas_6_2: Task;
}

export interface TaskRingTexas7 {
    task: TaskRingTexas7_Task;
    state: number;
}

export interface TaskRingTexas7_Task {
    task_Texas_7_1: Task;
    task_Texas_7_2: Reward1;
}

export interface Opera {
    total: number;
    show: null;
    release: Release;
    like: Like;
}

export interface Like {
    char_card_Texas: string;
    char_card_Sora: string;
    char_card_Lappland: string;
    char_card_Ben: string;
    char_card_Lavinia: string;
    char_card_Giovanna: string;
    char_card_Danbrown: string;
    char_card_Agenir: string;
    char_card_Demetri: string;
    char_card_Leontuzzo: string;
}

export interface Release {
    opera_5: number;
    opera_4: number;
    opera_3: number;
    opera_2: number;
    opera_1: number;
}



export interface PlayerSocial {
    assistCharList: PlayerFriendAssist[];
    yesterdayReward: PlayerSocialReward;
    yCrisisSs: string;//yesterdayCrisisSeasonId
    medalBoard: PlayerMedalBoard;
    yCrisisV2Ss: string;//yesterdayCrisisSeasonId
}

export interface PlayerMedalBoard {
    type: string;
    custom: null;
    template: string;
    templateMedalList: string[];
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


export interface TemplateTrap {
    domains: Domains;
}

export interface Domains {
    act32side: Act32Side;
}

export interface Act32Side {
    traps: Traps;
    squad: string[];
}

export interface Traps {
    trap_rnfcar: Trap;
    trap_ads: Trap;
    trap_edd: Trap;
}

export interface Trap {
    count: number;
}

export interface Ticket {
    et_ObsidianPass_rep_1: PlayerConsumableItem;
}

export interface PlayerDataTower {
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
    missions: { [key: string]: Mission1_Value };
    passWithGodCard: {};
    slots: Slots;
    period: Period;
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


export interface Tshop {
    shop_act9d0: ShopAct;
    shop_act10d5: ShopAct10D5;
    shop_act11d0: ShopAct;
    shop_act12d0: ShopAct;
    shop_act13d0: ShopAct13D0;
    shop_act13d2: ShopAct;
    shop_act13d5: ShopAct;
    shop_act15d0: ShopAct;
    shop_act15d5: ShopAct;
    shop_act16d5: ShopAct;
    shop_act17d0: ShopAct;
    shop_act17d5: ShopAct17D5;
    shop_act18d0: ShopAct;
    shop_act18d3: ShopAct;
    shop_act7mini: ShopAct7Mini;
    shop_act5sre: ShopAct;
    shop_act8mini: ShopAct;
    shop_act6sre: ShopAct;
    shop_act12side: ShopAct;
    shop_act7sre: ShopAct;
    shop_act9mini: ShopAct;
    shop_act13side: ShopAct;
    shop_act14side: ShopAct;
    shop_act8sre: ShopAct;
    shop_act9sre: ShopAct;
    shop_act15side: ShopAct;
    shop_act10mini: ShopAct;
    shop_act16side: ShopAct;
    shop_act10sre: ShopAct;
    shop_act17side: ShopAct17S;
    shop_act11sre: ShopAct;
    shop_act18side: ShopAct;
    shop_act19side: ShopAct;
    shop_act11mini: ShopAct;
    shop_act12sre: ShopAct;
    shop_act20side: ShopAct;
    shop_act12mini: ShopAct;
    shop_act13mini: ShopAct;
    shop_act13sre: ShopAct;
    shop_act21side: ShopAct;
    shop_act14sre: ShopAct;
    shop_act22side: ShopAct;
    shop_act15sre: ShopAct;
    shop_act23side: ShopAct;
    shop_act14mini: ShopAct;
    shop_act16sre: ShopAct;
    shop_act17sre: ShopAct17S;
    shop_act25side: ShopAct;
    shop_act38d1: ShopAct;
    shop_act26side: ShopAct;
    shop_act18sre: ShopAct;
    shop_act15mini: ShopAct;
    shop_act19sre: ShopAct19Sre;
    shop_act27side: ShopAct;
    shop_act20sre: ShopAct;
    shop_act28side: ShopAct;
    shop_act21sre: ShopAct;
    shop_act29side: ShopAct;
    shop_act30side: ShopAct;
    shop_act22sre: ShopAct;
    shop_act16mini: ShopAct;
    shop_act23sre: ShopAct;
    shop_act31side: ShopAct31Side;
    sandbox_1: TshopSandbox1;
    shop_act32side: ShopAct;
    shop_act1r6sre: ShopAct;
    shop_act33side: ShopAct;
    shop_act1mainss: ShopAct1Mainss;
}

export interface TshopSandbox1 {
    coin: number;
    info: Info[];
    progressInfo: Sandbox1_ProgressInfo;
}

export interface Sandbox1_ProgressInfo {
    char_rfalcn_progress: CharBibeakProgress;
}

export interface ShopAct10D5 {
    coin: number;
    info: Info[];
    progressInfo: ShopAct10D5ProgressInfo;
}

export interface ShopAct10D5ProgressInfo {
    char_asbin_progress: CharBibeakProgress;
}

export interface ShopAct {
    coin: number;
    info: Info[];
    progressInfo: {};
}

export interface ShopAct13D0 {
    coin: number;
    info: Info[];
    progressInfo: ShopAct13D0ProgressInfo;
}

export interface ShopAct13D0ProgressInfo {
    char_mint_progress: CharBibeakProgress;
}

export interface ShopAct17D5 {
    coin: number;
    info: Info[];
    progressInfo: ShopAct17D5ProgressInfo;
}

export interface ShopAct17D5ProgressInfo {
    char_sidero_progress: CharBibeakProgress;
}

export interface ShopAct17S {
    coin: number;
    info: Info[];
    progressInfo: ShopAct17SideProgressInfo;
}

export interface ShopAct17SideProgressInfo {
    char_lumen_progress: CharBibeakProgress;
}

export interface ShopAct19Sre {
    coin: number;
    info: Info[];
    progressInfo: ShopAct19SreProgressInfo;
}

export interface ShopAct19SreProgressInfo {
    char_halo_progress: CharBibeakProgress;
}

export interface ShopAct1Mainss {
    coin: number;
    info: Info[];
    progressInfo: ShopAct1MainssProgressInfo;
}

export interface ShopAct1MainssProgressInfo {
    char_folivo_progress: CharBibeakProgress;
}

export interface ShopAct31Side {
    coin: number;
    info: Info[];
    progressInfo: ShopAct31SideProgressInfo;
}

export interface ShopAct31SideProgressInfo {
    char_bibeak_progress: CharBibeakProgress;
}

export interface ShopAct7Mini {
    coin: number;
    info: Info[];
    progressInfo: ShopAct7MiniProgressInfo;
}

export interface ShopAct7MiniProgressInfo {
    char_bena_progress: CharBibeakProgress;
}
