import { PlayerActivity } from "./activity";
import { PlayerSquadItem, PlayerTroop } from "./character";

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
    mission: PlayerDataMission;
    social: PlayerDataSocial;
    building: PlayerDataBuilding;
    dexNav: DexNav;
    crisis: Crisis;
    crisisV2: CrisisV2;
    nameCardStyle: NameCardStyle;
    tshop: Tshop;
    gacha: PlayerDataGacha;
    backflow: Backflow;
    mainline: Mainline;
    avatar: PlayerDataAvatar;
    background: PlayerHomeBackground;
    homeTheme: PlayerHomeTheme;
    rlv2: any;
    deepSea: DeepSea;
    tower: PlayerDataTower;
    siracusaMap: SiracusaMap;
    sandboxPerm: any;
    storyreview: PlayerStoryReview;
    medal: PlayerDataMedal;
    event: PlayerDataEvent;
    retro: Retro;
    share: Share;
    roguelike: {
        current: null,
        stable: null
    };
    ticket: Ticket;
    aprilFool: AprilFoolClass;
    consumable: Consumable;
    charm: Charm;
    carousel: Carousel;
    openServer: PlayerOpenServer;
    car: Car;
    recruit: PlayerDataRecruit;
    templateTrap: TemplateTrap;
    checkIn: PlayerCheckIn;
    inventory: { [key: string]: number };
    campaignsV2: CampaignsV2;
    setting: Setting;
    checkMeta: CheckMeta;
    limitedBuff: LimitedBuff;
    collectionReward: PlayerCollection;
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

export interface AvatarInfo {
    type: string;
    id: string;
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

export interface PlayerDataAvatar {
    avatar_icon: { [key: string]: AvatarIcon };
}

export interface AvatarIcon {
    ts: number;
    src: SrcEnum;
}

export type SrcEnum = "other" | "initial";

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

export interface PlayerDataBuilding {
    status: BuildingStatus;
    chars: { [key: string]: BuildingChar };
    roomSlots: { [key: string]: RoomSlot };
    rooms: Rooms;
    furniture: { [key: string]: Furniture };
    diyPresetSolutions: {};
    assist: number[];
    solution: Solution;
}

export interface BuildingChar {
    charId: string;
    lastApAddTime: number;
    ap: number;
    roomSlotId: string;
    index: number;
    changeScale: number;
    bubble: Bubble;
    workTime: number;
}

export interface Bubble {
    normal: Assist;
    assist: Assist;
}

export interface Assist {
    add: number;
    ts: number;
}

export interface Furniture {
    count: number;
    inUse: number;
}

export interface RoomSlot {
    level: number;
    state: number;
    roomId: string;
    charInstIds: number[];
    completeConstructTime: number;
}

export interface Rooms {
    CONTROL: Control;
    ELEVATOR: { [key: string]: {} };
    POWER: POWERClass;
    MANUFACTURE: Manufacture;
    TRADING: TRADINGClass;
    CORRIDOR: Corridor;
    WORKSHOP: Workshop;
    DORMITORY: DORMITORYClass;
    MEETING: Meeting;
    HIRE: HIREClass;
    TRAINING: Training;
}

export interface Control {
    slot_34: Slot34;
}

export interface Slot34 {
    buff: Slot34_Buff;
    apCost: number;
    lastUpdateTime: number;
}

export interface Slot34_Buff {
    global: PurpleGlobal;
    manufacture: PurpleManufacture;
    trading: Trading;
    meeting: PurpleMeeting;
    apCost: { [key: string]: number };
    point: Point;
    hire: Hire;
    power: Power;
    dormitory: Dormitory;
    training: BuffTraining;
}

export interface Dormitory {
    recover: number;
}

export interface PurpleGlobal {
    apCost: number;
    roomCnt: {};
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

export interface Point {
    bd_ash: number;
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

export interface Corridor {
    slot_29: {};
    slot_31: {};
    slot_17: {};
    slot_19: {};
    slot_22: {};
    slot_12: {};
    slot_10: {};
    slot_2: {};
}

export interface DORMITORYClass {
    slot_28: Slot2;
    slot_20: Slot2;
    slot_9: Slot3_Class;
    slot_3: Slot3_Class;
}

export interface Slot2 {
    buff: Slot20_Buff;
    comfort: number;
    diySolution: Slot20_DiySolution;
}

export interface Slot20_Buff {
    apCost: PurpleApCost;
    point: {};
}

export interface PurpleApCost {
    all: number;
    single: MissionCalcState;
    self: {};
    exclude: {};
}

export interface MissionCalcState {
    target: number | null;
    value: number;
}

export interface Slot20_DiySolution {
    wallPaper: string;
    floor: string;
    carpet: PurpleCarpet[];
    other: PurpleCarpet[];
}

export interface PurpleCarpet {
    id: string;
    coordinate: Coordinate;
}

export interface Coordinate {
    x: number;
    y: number;
    dir: number;
}

export interface Slot3_Class {
    buff: Slot20_Buff;
    comfort: number;
    diySolution: Slot3_DiySolution;
}

export interface Slot3_DiySolution {
    wallPaper: string;
    floor: string;
    carpet: FluffyCarpet[];
    other: FluffyCarpet[];
}

export interface FluffyCarpet {
    id: string;
    coordinate: Matrix;
}

export interface HIREClass {
    slot_23: Slot23;
}

export interface Slot23 {
    buff: Slot23_Buff;
    state: number;
    refreshCount: number;
    lastUpdateTime: number;
    processPoint: number;
    speed: number;
    completeWorkTime: number;
}

export interface Slot23_Buff {
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

export interface Manufacture {
    slot_25: Slot25;
    slot_5: Slot5;
    slot_15: Slot15;
}

export interface Slot15 {
    buff: Slot15_Buff;
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
    display: Display;
}

export interface Slot15_Buff {
    apCost: TentacledApCost;
    speed: number;
    capacity: number;
    sSpeed: number;
    tSpeed: {};
    cSpeed: number;
    capFrom: {};
    maxSpeed: number;
    point: {};
    flag: {};
    skillExtend: {};
}

export interface TentacledApCost {
    self: {};
    all: number;
}

export interface Display {
    base: number;
    buff: number;
}

export interface Slot25 {
    buff: Slot25_Buff;
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
    display: Display;
}

export interface Slot25_Buff {
    apCost: TentacledApCost;
    speed: number;
    capacity: number;
    sSpeed: number;
    tSpeed: {};
    cSpeed: number;
    capFrom: {};
    maxSpeed: number;
    point: {};
    flag: {};
    skillExtend: SkillExtend;
}

export interface SkillExtend {
    "manu_prod_spd[000]": string[];
    "manu_prod_spd[010]": string[];
}

export interface Slot5 {
    buff: Slot5_Buff;
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
    display: Display;
}

export interface Slot5_Buff {
    apCost: StickyApCost;
    speed: number;
    capacity: number;
    sSpeed: number;
    tSpeed: {};
    cSpeed: number;
    capFrom: CapFrom;
    maxSpeed: number;
    point: {};
    flag: {};
    skillExtend: {};
}

export interface StickyApCost {
    self: CapFrom;
    all: number;
}

export interface CapFrom {
    "92": number;
}

export interface Meeting {
    slot_36: Slot36;
}

export interface Slot36 {
    buff: Slot36_Buff;
    state: number;
    speed: number;
    processPoint: number;
    ownStock: Stock[];
    receiveStock: Stock[];
    board: Board;
    socialReward: SocialReward;
    dailyReward: null;
    expiredReward: number;
    received: number;
    infoShare: InfoShare;
    lastUpdateTime: number;
    mfc: {};
    completeWorkTime: number;
    startApCounter: {};
    mustgetClue: any[];
}

export interface Board {
    PENGUIN: string;
    BLACKSTEEL: string;
    RHODES: string;
}

export interface Slot36_Buff {
    speed: number;
    weight: Weight;
    flag: {};
    apCost: FluffyApCost;
    notOwned: number;
    owned: number;
}

export interface Weight {
    RHINE: number;
    PENGUIN: number;
    BLACKSTEEL: number;
    URSUS: number;
    GLASGOW: number;
    KJERAG: number;
    RHODES: number;
}

export interface InfoShare {
    ts: number;
    reward: number;
}

export interface Stock {
    id: string;
    type: string;
    number: number;
    uid: string;
    name: string;
    nickNum: string;
    chars: OwnStockChar[];
    inUse: number;
    ts?: number;
}

export interface OwnStockChar {
    charId: string;
    level: number;
    skin: string;
    evolvePhase: number;
}

export interface SocialReward {
    daily: number;
    search: number;
}

export interface POWERClass {
    slot_26: Slot16_Class;
    slot_16: Slot16_Class;
    slot_7: Slot16_Class;
}

export interface Slot16_Class {
    buff: Slot16_Buff;
}

export interface Slot16_Buff {
    laborSpeed: number;
    apCost: FluffyApCost;
    global: FluffyGlobal;
    manufacture: FluffyManufacture;
}

export interface FluffyGlobal {
    roomCnt: {};
}

export interface FluffyManufacture {
    charSpeed: {};
}

export interface TRADINGClass {
    slot_24: Slot24_Class;
    slot_14: Slot14;
    slot_6: Slot24_Class;
}

export interface Slot14 {
    buff: Slot14_Buff;
    state: number;
    lastUpdateTime: number;
    strategy: string;
    stockLimit: number;
    apCost: number;
    stock: any[];
    next: Next;
    completeWorkTime: number;
    display: Display;
}

export interface Slot14_Buff {
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

export interface Next {
    order: number;
    processPoint: number;
    maxPoint: number;
    speed: number;
}

export interface Slot24_Class {
    buff: Slot24_Buff;
    state: number;
    lastUpdateTime: number;
    strategy: string;
    stockLimit: number;
    apCost: number;
    stock: any[];
    next: Next;
    completeWorkTime: number;
    display: Display;
}

export interface Slot24_Buff {
    speed: number;
    limit: number;
    apCost: IndecentApCost;
    rate: {};
    tgw: any[];
    point: {};
    manuLines: {};
    orderBuff: any[];
    violatedInfo: ViolatedInfo;
    orderWtBuff: any[];
}

export interface IndecentApCost {
    all: number;
    single: {};
    self: {};
}

export interface Training {
    slot_13: Slot13;
}

export interface Slot13 {
    buff: Slot13_Buff;
    state: number;
    lastUpdateTime: number;
    trainee: Trainee;
    trainer: Trainer;
}

export interface Slot13_Buff {
    speed: number;
    lvEx: {};
    lvCost: {};
    reduce: Reduce;
    reduceTimeBd: ReduceTimeBd;
}

export interface Reduce {
    target: null;
    progress: number;
    cut: number;
}

export interface ReduceTimeBd {
    fulltime: boolean;
    activated: boolean;
    cnt: number;
    reset: boolean;
}

export interface Trainee {
    charInstId: number;
    state: number;
    targetSkill: number;
    processPoint: number;
    speed: number;
}

export interface Trainer {
    charInstId: number;
    state: number;
}

export interface Workshop {
    slot_32: Slot32;
}

export interface Slot32 {
    buff: Slot32_Buff;
    statistic: Statistic;
}

export interface Slot32_Buff {
    rate: Rate;
    cost: Cost;
    costRe: CostRe;
    frate: any[];
    recovery: Recovery;
    goldFree: GoldFree;
    costForce: CostForce;
    fFix: FFix;
    activeBonus: {};
    apRate: ApRate;
    costDevide: CostDevide;
}

export interface ApRate {
    all: All;
}

export interface All {
    "2880000": number;
}

export interface Cost {
    type: string;
    limit: number;
    reduction: number;
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

export interface CostRe {
    type: string;
    from: number;
    change: number;
}

export interface FFix {
    asRarity: {};
}

export interface GoldFree {
    W_EVOLVE: number;
}

export interface Rate {
    all: number;
    W_EVOLVE: number;
    W_BUILDING: number;
    W_ASC: number;
    W_SKILL: number;
}

export interface Recovery {
    type: string;
    pace: number;
    recover: number;
}

export interface Statistic {
    noAddition: number;
}

export interface Solution {
    furnitureTs: FurnitureTs;
}

export interface FurnitureTs {
    furni_act50d0_hourGlass_01: number;
    furni_laundry_poor_01: number;
    furni_Airship_partitionwall_01: number;
    furni_Airship_wallpaper_01: number;
    furni_Airship_floor_01: number;
    furni_Airship_ceilinglamp_01: number;
    furni_Airship_controldesk_01: number;
}

export interface BuildingStatus {
    labor: Labor;
    workshop: WorkshopClass;
}

export interface Labor {
    buffSpeed: number;
    processPoint: number;
    value: number;
    lastUpdateTime: number;
    maxValue: number;
}

export interface WorkshopClass {
    bonusActive: number;
    bonus: Bonus;
}

export interface Bonus {
    ws_bonus1_40: number[];
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

export interface Consumable {
    LIMITED_TKT_GACHA_10_903: {};
    LMTGS_COIN_903: {};
    ap_supply_lt_100: {};
    ap_supply_lt_010: ApSupplyLt010;
    randomMaterial_3: RandomMaterial3;
    randomMaterial_1: RandomMaterial1;
    randomMaterialRune_1: RandomMaterialRune1;
    randomMaterialRune_2: RandomMaterialRune2;
    voucher_recruitR5_pick2: VoucherRecruitR5Pick2;
    randomDiamondShd_2: {};
    LIMITED_TKT_GACHA_10_1401: {};
    LMTGS_COIN_1401: {};
    randomMaterial_4: RandomMaterial4;
    randomMaterialRune_3: RandomMaterialRune3;
    LMTGS_COIN_601: {};
    LIMITED_TKT_GACHA_10_1601: {};
    LMTGS_COIN_1601: {};
    randomMaterialRune_4: RandomMaterialRune4;
    LINKAGE_TKT_GACHA_10_1701: {};
    renamingCard: RenamingCard;
    LMTGS_COIN_1803: {};
    voucher_item_4pick1_1803: VoucherItem4Pick11803;
    voucher_recruitR5_pick1803: VoucherRecruitR5Pick1803;
    LIMITED_TKT_GACHA_10_1803: {};
    ap_supply_lt_60: {};
    randomMaterialRune_5: RandomMaterialRune5;
    LIMITED_TKT_GACHA_10_2101: {};
    LMTGS_COIN_2101: {};
    LIMITED_TKT_GACHA_10_2301: {};
    LMTGS_COIN_2301: {};
    randomMaterialRune_6: RandomMaterialRune6;
    LIMITED_TKT_GACHA_10_2501: {};
    LMTGS_COIN_2501: {};
    ap_supply_lt_100_2022_5: {};
    ap_supply_lt_100_2022_4: {};
    ap_supply_lt_100_2022_3: {};
    ap_supply_lt_100_2022_2: {};
    ap_supply_lt_100_2022_1: {};
    randomMaterialRune_8: RandomMaterialRune8;
    randomMaterial_6: RandomMaterial6;
    voucher_recruitR5_pick2701: VoucherRecruitR5Pick2701;
    LIMITED_TKT_GACHA_10_2701: {};
    ap_supply_lt_120: { [key: string]: EtObsidianPassRep1 };
    LMTGS_COIN_2701: {};
    EXTERMINATION_AGENT: ExterminationAgent;
    randomMaterialRune_9: RandomMaterialRune9;
    LIMITED_TKT_GACHA_10_3001: {};
    LMTGS_COIN_3001: {};
    ap_supply_lt_120_2022_4: {};
    randomMaterialRune_10: RandomMaterialRune10;
    randomMaterial_7: RandomMaterial7;
    LIMITED_TKT_GACHA_10_3301: {};
    LMTGS_COIN_3301: {};
    ap_supply_lt_80: ApSupplyLt80;
    randomMaterialRune_11: RandomMaterialRune11;
    LIMITED_TKT_GACHA_10_3501: {};
    LMTGS_COIN_3501: {};
    ap_supply_lt_100_2023_5: {};
    ap_supply_lt_100_2023_4: {};
    ap_supply_lt_100_2023_3: {};
    ap_supply_lt_100_2023_2: {};
    ap_supply_lt_100_2023_1: {};
    LINKAGE_TKT_GACHA_10_3601: {};
    LINKAGE_TKT_GACHA_10_3602: {};
    randomMaterialRune_12: RandomMaterialRune12;
    randomMaterial_8: RandomMaterial8;
    LIMITED_TKT_GACHA_10_3801: {};
    voucher_recruitR5_pick3801: VoucherRecruitR5Pick3801;
    LMTGS_COIN_3801: {};
    randomMaterial_rhine2: RandomMaterialRhine2;
    LIMITED_TKT_GACHA_10_4101: {};
    LMTGS_COIN_4101: {};
    randomMaterial_siesta2: RandomMaterialSiesta2;
    ap_supply_lt_120_2023_3: {};
    randomMaterial_9: RandomMaterial9;
    LIMITED_TKT_GACHA_10_4401: {};
    LMTGS_COIN_4401: {};
    randomMaterial_leith2: RandomMaterialLeith2;
    LIMITED_TKT_GACHA_10_4701: {};
    LMTGS_COIN_4701: {};
    ap_supply_lt_100_2024_3: {};
    ap_supply_lt_100_2024_2: {};
    ap_supply_lt_100_2024_1: {};
    ap_supply_lt_100_2024_5: {};
    ap_supply_lt_100_2024_4: {};
    LINKAGE_TKT_GACHA_10_4801: {};
    LIMITED_TKT_GACHA_10_5001: {};
    voucher_recruitR5_pick5001: VoucherRecruitR5Pick5001;
    LMTGS_COIN_5001: LmtgsCoin5001;
    randomMaterial_10: RandomMaterial10;
    premium_material_issue_voucher: PremiumMaterialIssueVoucher;
}

export interface ExterminationAgent {
    "499": EtObsidianPassRep1;
}

export interface EtObsidianPassRep1 {
    ts: number;
    count: number;
}

export interface LmtgsCoin5001 {
    "495": EtObsidianPassRep1;
}

export interface ApSupplyLt010 {
    "496": EtObsidianPassRep1;
}

export interface ApSupplyLt80 {
    "489": EtObsidianPassRep1;
}

export interface PremiumMaterialIssueVoucher {
    "501": EtObsidianPassRep1;
}

export interface RandomMaterialRune1 {
    "17": EtObsidianPassRep1;
}

export interface RandomMaterialRune10 {
    "216": EtObsidianPassRep1;
}

export interface RandomMaterialRune11 {
    "275": EtObsidianPassRep1;
}

export interface RandomMaterialRune12 {
    "338": EtObsidianPassRep1;
}

export interface RandomMaterialRune2 {
    "30": EtObsidianPassRep1;
}

export interface RandomMaterialRune3 {
    "66": EtObsidianPassRep1;
}

export interface RandomMaterialRune4 {
    "80": EtObsidianPassRep1;
}

export interface RandomMaterialRune5 {
    "104": EtObsidianPassRep1;
}

export interface RandomMaterialRune6 {
    "124": EtObsidianPassRep1;
}

export interface RandomMaterialRune8 {
    "142": EtObsidianPassRep1;
}

export interface RandomMaterialRune9 {
    "170": EtObsidianPassRep1;
}

export interface RandomMaterial1 {
    "14": EtObsidianPassRep1;
}

export interface RandomMaterial10 {
    "497": EtObsidianPassRep1;
}

export interface RandomMaterial3 {
    "5": EtObsidianPassRep1;
}

export interface RandomMaterial4 {
    "52": EtObsidianPassRep1;
}

export interface RandomMaterial6 {
    "148": EtObsidianPassRep1;
}

export interface RandomMaterial7 {
    "234": EtObsidianPassRep1;
}

export interface RandomMaterial8 {
    "339": EtObsidianPassRep1;
}

export interface RandomMaterial9 {
    "409": EtObsidianPassRep1;
}

export interface RandomMaterialLeith2 {
    "419": EtObsidianPassRep1;
}

export interface RandomMaterialRhine2 {
    "351": EtObsidianPassRep1;
}

export interface RandomMaterialSiesta2 {
    "385": EtObsidianPassRep1;
}

export interface RenamingCard {
    "89": EtObsidianPassRep1;
}

export interface VoucherItem4Pick11803 {
    "98": EtObsidianPassRep1;
}

export interface VoucherRecruitR5Pick1803 {
    "99": EtObsidianPassRep1;
}

export interface VoucherRecruitR5Pick2 {
    "32": EtObsidianPassRep1;
}

export interface VoucherRecruitR5Pick2701 {
    "152": EtObsidianPassRep1;
}

export interface VoucherRecruitR5Pick3801 {
    "349": EtObsidianPassRep1;
}

export interface VoucherRecruitR5Pick5001 {
    "494": EtObsidianPassRep1;
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

export interface DexNav {
    character: Character;
    formula: Formula;
    enemy: DexNavEnemy;
    teamV2: TeamV2;
}

export interface Character {
    char_002_amiya: Char002_AmiyaClass;
    char_502_nblade: Char002_AmiyaClass;
    char_500_noirc: Char003_KaltsClass;
    char_503_rang: Char002_AmiyaClass;
    char_185_frncat: Char003_KaltsClass;
    char_120_hibisc: Char003_KaltsClass;
    char_190_clour: Char003_KaltsClass;
    char_298_susuro: Char003_KaltsClass;
    char_281_popka: Char003_KaltsClass;
    char_277_sqrrel: Char003_KaltsClass;
    char_210_stward: Char003_KaltsClass;
    char_109_fmout: Char003_KaltsClass;
    char_113_cqbw: Char002_AmiyaClass;
    char_126_shotst: Char003_KaltsClass;
    char_181_flower: Char003_KaltsClass;
    char_183_skgoat: Char003_KaltsClass;
    char_117_myrrh: Char003_KaltsClass;
    char_118_yuki: Char003_KaltsClass;
    char_208_melan: Char003_KaltsClass;
    char_130_doberm: Char003_KaltsClass;
    char_150_snakek: Char003_KaltsClass;
    char_240_wyvern: Char003_KaltsClass;
    char_147_shining: Char002_AmiyaClass;
    char_103_angel: Char002_AmiyaClass;
    char_211_adnach: Char003_KaltsClass;
    char_236_rope: Char003_KaltsClass;
    char_253_greyy: Char003_KaltsClass;
    char_196_sunbr: Char003_KaltsClass;
    char_282_catap: Char003_KaltsClass;
    char_301_cutter: Char003_KaltsClass;
    char_164_nightm: Char003_KaltsClass;
    char_278_orchid: Char003_KaltsClass;
    char_235_jesica: Char003_KaltsClass;
    char_123_fang: Char003_KaltsClass;
    char_192_falco: Char003_KaltsClass;
    char_501_durin: Char003_KaltsClass;
    char_009_12fce: Char003_KaltsClass;
    char_121_lava: Char003_KaltsClass;
    char_122_beagle: Char003_KaltsClass;
    char_212_ansel: Char003_KaltsClass;
    char_376_therex: Char003_KaltsClass;
    char_124_kroos: Char003_KaltsClass;
    char_285_medic2: Char002_AmiyaClass;
    char_333_sidero: Char002_AmiyaClass;
    char_173_slchan: Char003_KaltsClass;
    char_284_spot: Char003_KaltsClass;
    char_237_gravel: Char003_KaltsClass;
    char_193_frostl: Char003_KaltsClass;
    char_198_blackd: Char002_AmiyaClass;
    char_283_midn: Char003_KaltsClass;
    char_279_excu: Char002_AmiyaClass;
    char_289_gyuki: Char003_KaltsClass;
    char_141_nights: Char003_KaltsClass;
    char_290_vigna: Char003_KaltsClass;
    char_187_ccheal: Char002_AmiyaClass;
    char_137_brownb: Char003_KaltsClass;
    char_355_ethan: Char002_AmiyaClass;
    char_209_ardign: Char003_KaltsClass;
    char_110_deepcl: Char003_KaltsClass;
    char_337_utage: Char003_KaltsClass;
    char_340_shwaz: Char002_AmiyaClass;
    char_226_hmau: Char002_AmiyaClass;
    char_149_scave: Char003_KaltsClass;
    char_148_nearl: Char002_AmiyaClass;
    char_171_bldsk: Char003_KaltsClass;
    char_250_phatom: Char002_AmiyaClass;
    char_260_durnar: Char002_AmiyaClass;
    char_405_absin: Char002_AmiyaClass;
    char_252_bibeak: Char002_AmiyaClass;
    char_286_cast3: Char003_KaltsClass;
    char_258_podego: Char003_KaltsClass;
    char_401_elysm: Char002_AmiyaClass;
    char_129_bluep: Char002_AmiyaClass;
    char_345_folnic: Char002_AmiyaClass;
    char_294_ayer: Char002_AmiyaClass;
    char_199_yak: Char003_KaltsClass;
    char_163_hpsts: Char002_AmiyaClass;
    char_151_myrtle: Char003_KaltsClass;
    char_180_amgoat: Char002_AmiyaClass;
    char_204_platnm: Char002_AmiyaClass;
    char_336_folivo: Char002_AmiyaClass;
    char_348_ceylon: Char002_AmiyaClass;
    char_218_cuttle: Char003_KaltsClass;
    char_155_tiger: Char002_AmiyaClass;
    char_328_cammou: Char003_KaltsClass;
    char_411_tomimi: Char002_AmiyaClass;
    char_158_milu: Char003_KaltsClass;
    char_143_ghost: Char002_AmiyaClass;
    char_302_glaze: Char003_KaltsClass;
    char_195_glassb: Char002_AmiyaClass;
    char_133_mm: Char003_KaltsClass;
    char_378_asbest: Char003_KaltsClass;
    char_272_strong: Char003_KaltsClass;
    char_400_weedy: Char002_AmiyaClass;
    char_388_mint: Char002_AmiyaClass;
    char_220_grani: Char002_AmiyaClass;
    char_416_zumama: Char003_KaltsClass;
    char_107_liskam: Char002_AmiyaClass;
    char_242_otter: Char003_KaltsClass;
    char_265_sophia: Char002_AmiyaClass;
    char_136_hsguma: Char002_AmiyaClass;
    char_215_mantic: Char003_KaltsClass;
    char_202_demkni: Char002_AmiyaClass;
    char_436_whispr: Char002_AmiyaClass;
    char_347_jaksel: Char003_KaltsClass;
    char_145_prove: Char002_AmiyaClass;
    char_271_spikes: Char003_KaltsClass;
    char_356_broca: Char002_AmiyaClass;
    char_391_rosmon: Char002_AmiyaClass;
    char_381_bubble: Char003_KaltsClass;
    char_127_estell: Char002_AmiyaClass;
    char_225_haak: Char002_AmiyaClass;
    char_144_red: Char002_AmiyaClass;
    char_325_bison: Char002_AmiyaClass;
    char_326_glacus: Char003_KaltsClass;
    char_248_mgllan: Char002_AmiyaClass;
    char_451_robin: Char002_AmiyaClass;
    char_440_pinecn: Char003_KaltsClass;
    char_214_kafka: Char003_KaltsClass;
    char_338_iris: Char003_KaltsClass;
    char_172_svrash: Char003_KaltsClass;
    char_452_bstalk: Char003_KaltsClass;
    char_402_tuye: Char002_AmiyaClass;
    char_102_texas: Char002_AmiyaClass;
    char_366_acdrop: Char003_KaltsClass;
    char_344_beewax: Char002_AmiyaClass;
    char_455_nothin: Char002_AmiyaClass;
    char_1011_lava2: Char002_AmiyaClass;
    char_362_saga: Char002_AmiyaClass;
    char_254_vodfox: Char002_AmiyaClass;
    char_222_bpipe: Char003_KaltsClass;
    char_459_tachak: Char003_KaltsClass;
    char_379_sesa: Char002_AmiyaClass;
    char_456_ash: Char002_AmiyaClass;
    char_140_whitew: Char003_KaltsClass;
    char_159_peacok: Char002_AmiyaClass;
    char_304_zebra: Char002_AmiyaClass;
    char_1012_skadi2: Char002_AmiyaClass;
    char_230_savage: Char003_KaltsClass;
    char_108_silent: Char002_AmiyaClass;
    char_128_plosis: Char003_KaltsClass;
    char_474_glady: Char002_AmiyaClass;
    char_475_akafyu: Char003_KaltsClass;
    char_219_meteo: Char002_AmiyaClass;
    char_179_cgbird: Char002_AmiyaClass;
    char_243_waaifu: Char003_KaltsClass;
    char_469_indigo: Char003_KaltsClass;
    char_385_finlpp: Char003_KaltsClass;
    char_369_bena: Char002_AmiyaClass;
    char_263_skadi: Char002_AmiyaClass;
    char_421_crow: Char002_AmiyaClass;
    char_1013_chen2: Char002_AmiyaClass;
    char_115_headbr: Char002_AmiyaClass;
    char_486_takila: Char002_AmiyaClass;
    char_489_serum: Char002_AmiyaClass;
    char_131_flameb: Char002_AmiyaClass;
    char_420_flamtl: Char002_AmiyaClass;
    char_4000_jnight: Char003_KaltsClass;
    char_496_wildmn: Char002_AmiyaClass;
    char_010_chen: Char002_AmiyaClass;
    char_383_snsant: Char002_AmiyaClass;
    char_112_siege: Char003_KaltsClass;
    char_241_panda: Char002_AmiyaClass;
    char_4019_ncdeer: Char002_AmiyaClass;
    char_437_mizuki: Char002_AmiyaClass;
    char_4025_aprot2: Char002_AmiyaClass;
    char_293_thorns: Char002_AmiyaClass;
    char_343_tknogi: Char003_KaltsClass;
    char_4004_pudd: Char002_AmiyaClass;
    char_1021_kroos2: Char002_AmiyaClass;
    char_346_aosta: Char002_AmiyaClass;
    char_484_robrta: Char003_KaltsClass;
    char_476_blkngt: Char002_AmiyaClass;
    char_2023_ling: Char002_AmiyaClass;
    char_308_swire: Char002_AmiyaClass;
    char_213_mostma: Char003_KaltsClass;
    char_4036_forcer: Char002_AmiyaClass;
    char_2013_cerber: Char002_AmiyaClass;
    char_134_ifrit: Char002_AmiyaClass;
    char_4041_chnut: Char003_KaltsClass;
    char_306_leizi: Char002_AmiyaClass;
    char_4016_kazema: Char003_KaltsClass;
    char_433_windft: Char002_AmiyaClass;
    char_4042_lumen: Char002_AmiyaClass;
    char_274_astesi: Char002_AmiyaClass;
    char_1023_ghost2: Char002_AmiyaClass;
    char_449_glider: Char003_KaltsClass;
    char_4043_erato: Char002_AmiyaClass;
    char_4047_pianst: Char003_KaltsClass;
    char_1024_hbisc2: Char002_AmiyaClass;
    char_135_halo: Char003_KaltsClass;
    char_188_helage: Char002_AmiyaClass;
    char_377_gdglow: Char002_AmiyaClass;
    char_311_mudrok: Char002_AmiyaClass;
    char_322_lmlee: Char002_AmiyaClass;
    char_4055_bgsnow: Char002_AmiyaClass;
    char_497_ctable: Char003_KaltsClass;
    char_4054_malist: Char003_KaltsClass;
    char_1026_gvial2: Char002_AmiyaClass;
    char_264_f12yin: Char002_AmiyaClass;
    char_4032_provs: Char003_KaltsClass;
    char_4067_lolxh: Char002_AmiyaClass;
    char_4040_rockr: Char002_AmiyaClass;
    char_332_archet: Char002_AmiyaClass;
    char_4066_highmo: Char002_AmiyaClass;
    char_4062_totter: Char003_KaltsClass;
    char_4045_heidi: Char002_AmiyaClass;
    char_4014_lunacu: Char002_AmiyaClass;
    char_373_lionhd: Char003_KaltsClass;
    char_1028_texas2: Char002_AmiyaClass;
    char_4063_quartz: Char002_AmiyaClass;
    char_466_qanik: Char002_AmiyaClass;
    char_427_vigil: Char002_AmiyaClass;
    char_101_sora: Char002_AmiyaClass;
    char_174_slbell: Char002_AmiyaClass;
    char_4013_kjera: Char002_AmiyaClass;
    char_472_pasngr: Char002_AmiyaClass;
    char_4017_puzzle: Char003_KaltsClass;
    char_423_blemsh: Char002_AmiyaClass;
    char_493_firwhl: Char003_KaltsClass;
    char_4078_bdhkgt: Char003_KaltsClass;
    char_2024_chyue: Char002_AmiyaClass;
    char_106_franka: Char002_AmiyaClass;
    char_003_kalts: Char003_KaltsClass;
    char_1030_noirc2: Char002_AmiyaClass;
    char_1029_yato2: Char002_AmiyaClass;
    char_4077_palico: Char002_AmiyaClass;
    char_492_quercu: Char003_KaltsClass;
    char_4039_horn: Char002_AmiyaClass;
    char_4091_ulika: Char002_AmiyaClass;
    char_017_huang: Char003_KaltsClass;
    char_4083_chimes: Char003_KaltsClass;
    char_201_moeshd: Char003_KaltsClass;
    char_358_lisa: Char003_KaltsClass;
    char_157_dagda: Char003_KaltsClass;
    char_154_morgan: Char003_KaltsClass;
    char_4006_melnte: Char003_KaltsClass;
    char_491_humus: Char003_KaltsClass;
    char_4027_heyak: Char003_KaltsClass;
    char_1031_slent2: Char003_KaltsClass;
    char_473_mberry: Char003_KaltsClass;
    char_350_surtr: Char003_KaltsClass;
    char_498_inside: Char003_KaltsClass;
    char_4071_peper: Char003_KaltsClass;
    char_261_sddrag: Char003_KaltsClass;
    char_4102_threye: Char003_KaltsClass;
    char_488_buildr: Char003_KaltsClass;
    char_1016_agoat2: Char003_KaltsClass;
    char_4106_bryota: Char003_KaltsClass;
    char_464_cement: Char003_KaltsClass;
    char_291_aglina: Char003_KaltsClass;
    char_4104_coldst: Char003_KaltsClass;
    char_4087_ines: Char003_KaltsClass;
    char_4110_delphn: Char003_KaltsClass;
    char_4109_baslin: Char003_KaltsClass;
    char_245_cello: Char003_KaltsClass;
    char_4098_vvana: Char003_KaltsClass;
    char_4011_lessng: Char003_KaltsClass;
    char_4100_caper: Char003_KaltsClass;
    char_206_gnosis: Char003_KaltsClass;
    char_4114_harold: Char003_KaltsClass;
    char_4116_blkkgt: Char003_KaltsClass;
    char_1027_greyy2: Char003_KaltsClass;
    char_478_kirara: Char003_KaltsClass;
    char_4122_grabds: Char003_KaltsClass;
    char_4119_wanqin: Char003_KaltsClass;
    char_197_poca: Char003_KaltsClass;
    char_341_sntlla: Char003_KaltsClass;
    char_4023_rfalcn: Char003_KaltsClass;
    char_4121_zuole: Char003_KaltsClass;
    char_4124_iana: Char003_KaltsClass;
    char_4125_rdoc: Char003_KaltsClass;
    char_4123_ela: Char003_KaltsClass;
    char_4126_fuze: Char003_KaltsClass;
    char_4131_odda: Char003_KaltsClass;
    char_1036_fang2: Char003_KaltsClass;
    char_4130_luton: Char003_KaltsClass;
    char_1035_wisdel: Char003_KaltsClass;
    char_4133_logos: Char003_KaltsClass;
    char_4134_cetsyr: Char003_KaltsClass;
    char_4136_phonor: Char003_KaltsClass;
    char_479_sleach: Char003_KaltsClass;
}

export interface Char002_AmiyaClass {
    charInstId: number;
    count: number;
}

export interface Char003_KaltsClass {
    charInstId: number;
    count: number;
    classicCount: number;
}

export interface DexNavEnemy {
    enemies: { [key: string]: number };
    stage: { [key: string]: string[] };
}

export interface Formula {
    shop: {};
    manufacture: { [key: string]: number };
    workshop: { [key: string]: number };
}

export interface TeamV2 {
    rhodes: { [key: string]: number };
    action4: { [key: string]: number };
    victoria: { [key: string]: number };
    reserve1: { [key: string]: number };
    siracusa: { [key: string]: number };
    reserve6: { [key: string]: number };
    lungmen: { [key: string]: number };
    reserve4: { [key: string]: number };
    sami: { [key: string]: number };
    babel: { [key: string]: number };
    kazimierz: { [key: string]: number };
    leithanien: { [key: string]: number };
    higashi: { [key: string]: number };
    columbia: { [key: string]: number };
    blacksteel: { [key: string]: number };
    followers: { [key: string]: number };
    penguin: { [key: string]: number };
    student: { [key: string]: number };
    ursus: { [key: string]: number };
    laterano: { [key: string]: number };
    karlan: { [key: string]: number };
    kjerag: { [key: string]: number };
    siesta: { [key: string]: number };
    lee: { [key: string]: number };
    sweep: { [key: string]: number };
    rim: { [key: string]: number };
    sargon: { [key: string]: number };
    abyssal: { [key: string]: number };
    glasgow: { [key: string]: number };
    rhine: { [key: string]: number };
    lgd: { [key: string]: number };
    chiave: { [key: string]: number };
    elite: { [key: string]: number };
    yan: { [key: string]: number };
    rainbow: { [key: string]: number };
    egir: { [key: string]: number };
    iberia: { [key: string]: number };
    bolivar: { [key: string]: number };
    pinus: { [key: string]: number };
    sui: { [key: string]: number };
    minos: Minos;
}

export interface Minos {
    "188": number;
}



export interface PlayerDataEvent {
    building: number;
}

export interface PlayerDataGacha {
    newbee: Newbee;
    normal: { [key: string]: NormalValue };
    limit: Limit;
    linkage: Linkage;
    attain: Attain;
    single: Single;
    fesClassic: FesClassic;
}

export interface Attain {
    ATTAIN_24_0_3: ATTAIN24_0_3_Class;
    ATTAIN_34_0_3: ATTAIN24_0_3_Class;
    ATTAIN_45_0_5: ATTAIN24_0_3_Class;
}

export interface ATTAIN24_0_3_Class {
    attain6Count: number;
}

export interface FesClassic {
    FESCLASSIC_38_0_2: Fesclassic0_2;
    FESCLASSIC_41_0_2: Fesclassic0_2;
}

export interface Fesclassic0_2 {
    upChar: { [key: string]: string[] };
}

export interface Limit {
    LIMITED_9_0_3: Limited;
    LIMITED_14_0_1: Limited;
    LIMITED_16_0_1: Limited;
    LIMITED_16_0_4: Limited;
    LIMITED_18_0_3: Limited;
    LIMITED_21_0_1: Limited;
    LIMITED_23_0_1: Limited;
    LIMITED_25_0_1: Limited;
    LIMITED_27_0_3: Limited;
    LIMITED_30_0_1: Limited;
    LIMITED_33_0_1: Limited;
    LIMITED_35_0_1: Limited;
    LIMITED_38_0_1: Limited;
    LIMITED_41_0_1: Limited;
    LIMITED_44_0_1: Limited;
    LIMITED_47_0_1: Limited;
    LIMITED_50_0_1: Limited50_0_1;
}

export interface Limited {
    leastFree: number;
}

export interface Limited50_0_1 {
    poolCnt: number;
    recruitedFreeChar: boolean;
    leastFree: number;
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

export interface Newbee {
    openFlag: number;
    cnt: number;
    poolId: string;
}

export interface NormalValue {
    cnt: number;
    maxCnt: number;
    rarity: number;
    avail: boolean;
}

export interface Single {
    SINGLE_37_0_1: SINGLE37_0_1_Class;
    SINGLE_40_0_1: SINGLE37_0_1_Class;
    SINGLE_45_0_1: SINGLE37_0_1_Class;
    SINGLE_45_0_4: SINGLE37_0_1_Class;
}

export interface SINGLE37_0_1_Class {
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
    Logistics_Special_Permit: EtObsidianPassRep1;
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

export interface PlayerDataMedal {
    medals: { [key: string]: MedalValue };
    custom: Custom;
}

export interface Custom {
    currentIndex: string;
    customs: Customs;
}

export interface Customs {
    "1": Customs1;
}

export interface Customs1 {
    layout: any[];
}

export interface MedalValue {
    id: string;
    val: Array<number[]>;
    fts: number;
    rts: number;
    reward?: string;
}

export interface PlayerDataMission {
    missions: MissionMissions;
    missionRewards: MissionRewards;
    missionGroups: { [key: string]: number };
}

export interface MissionRewards {
    dailyPoint: number;
    weeklyPoint: number;
    rewards: Rewards;
}

export interface Rewards {
    DAILY: { [key: string]: number };
    WEEKLY: { [key: string]: number };
}

export interface MissionMissions {
    OPENSERVER: { [key: string]: ACTIVITYValue };
    DAILY: { [key: string]: ACTIVITYValue };
    WEEKLY: { [key: string]: ACTIVITYValue };
    GUIDE: { [key: string]: ACTIVITYValue };
    MAIN: { [key: string]: ACTIVITYValue };
    ACTIVITY: { [key: string]: ACTIVITYValue };
    SUB: { [key: string]: ACTIVITYValue };
}

export interface ACTIVITYValue {
    state: number;
    progress: MissionCalcState[];
}

export interface NameCardStyle {
    componentOrder: string[];
    skin: NameCardStyleSkin;
}

export interface NameCardStyleSkin {
    selected: string;
    state: State;
}

export interface State {
    nc_rhodes_default: Nc;
    nc_rhodes_light: Nc;
    nc_sandbox_1: Nc;
}

export interface Nc {
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

export interface PlayerDataRecruit {
    normal: RecruitNormal;
}

export interface RecruitNormal {
    slots: { [key: string]: Slot };
}

export interface Slot {
    state: number;
    tags: number[];
    selectTags: any[];
    startTs: number;
    durationInSec: number;
    maxFinishTs: number;
    realFinishTs: number;
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

export interface Setting {
    perf: Perf;
}

export interface Perf {
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
    progressInfo: CLASSICProgressInfo;
}

export interface CLASSICProgressInfo {
    AAA3: CharBibeakProgress;
    OLD1: CharBibeakProgress;
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



export interface PlayerDataSocial {
    assistCharList: PlayerSquadItem[];
    yesterdayReward: YesterdayReward;
    yCrisisSs: string;
    medalBoard: MedalBoard;
    yCrisisV2Ss: string;
}

export interface MedalBoard {
    type: string;
    custom: null;
    template: string;
    templateMedalList: string[];
}

export interface YesterdayReward {
    canReceive: number;
    assistAmount: number;
    comfortAmount: number;
    first: number;
}


export interface PlayerStoryReview {
    groups: {[key: string]:PlayerStoryReviewUnlockInfo};
    tags: {[key: string]:number};
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
    et_ObsidianPass_rep_1: EtObsidianPassRep1;
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
