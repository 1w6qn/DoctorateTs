import { ItemBundle } from "./character_table";

export interface BuildingData {
    controlSlotId:                string;
    meetingSlotId:                string;
    initMaxLabor:                 number;
    laborRecoverTime:             number;
    manufactInputCapacity:        number;
    shopCounterCapacity:          number;
    comfortLimit:                 number;
    creditInitiativeLimit:        number;
    creditPassiveLimit:           number;
    creditComfortFactor:          number;
    creditGuaranteed:             number;
    creditCeiling:                number;
    manufactUnlockTips:           string;
    shopUnlockTips:               string;
    manufactStationBuff:          number;
    comfortManpowerRecoverFactor: number;
    manpowerDisplayFactor:        number;
    shopOutputRatio:              null;
    shopStackRatio:               null;
    basicFavorPerDay:             number;
    humanResourceLimit:           number;
    tiredApThreshold:             number;
    processedCountRatio:          number;
    tradingStrategyUnlockLevel:   number;
    tradingReduceTimeUnit:        number;
    tradingLaborCostUnit:         number;
    manufactReduceTimeUnit:       number;
    manufactLaborCostUnit:        number;
    laborAssistUnlockLevel:       number;
    apToLaborUnlockLevel:         number;
    apToLaborRatio:               number;
    socialResourceLimit:          number;
    socialSlotNum:                number;
    furniDuplicationLimit:        number;
    assistFavorReport:            number;
    manufactManpowerCostByNum:    number[];
    tradingManpowerCostByNum:     number[];
    trainingBonusMax:             number;
    roomUnlockConds:              { [key: string]: RoomUnlockCond };
    rooms:                        { [key: string]: RoomData };
    layouts:                      { [key: string]: LayoutData };
    prefabs:                      { [key: string]: PrefabInfo };
    controlData:                  ControlRoomBean;
    manufactData:                 ManufactRoomBean;
    shopData:                     RoomBean<ShopPhase>;
    hireData:                     HireRoomBean;
    dormData:                     RoomBean<DormPhase>;
    meetingData:                  MeetingRoomBean;
    tradingData:                  TradingRoomBean;
    workshopData:                 RoomBean<WorkshopPhase>;
    trainingData:                 TrainingBean;
    powerData:                    PowerRoomBean;
    chars:                        { [key: string]: BuildingCharacter };
    buffs:                        { [key: string]: BuildingBuff };
    workshopBonus:                { [key: string]: string[] };
    customData:                   CustomData;
    manufactFormulas:             { [key: string]: ManufactFormula };
    shopFormulas:                 { [key: string]: ShopFormula };
    workshopFormulas:             { [key: string]: WorkshopFormula };
    creditFormula:                CreditFormula;
    goldItems:                    { [key: string]: number };
    assistantUnlock:              number[];
}

export interface BuildingBuff {
    buffId:       string;
    buffName:     string;
    buffIcon:     BuffIcon;
    skillIcon:    string;
    sortId:       number;
    buffColor:    BuffColor;
    textColor:    TextColor;
    buffCategory: BuffCategory;
    roomType:     RoomType;
    description:  string;
}

export enum BuffCategory {
    Function = "FUNCTION",
    Output = "OUTPUT",
    Recovery = "RECOVERY",
}


export enum BuffIcon {
    Control = "control",
    Dormitory = "dormitory",
    Hire = "hire",
    Manufacture = "manufacture",
    Meeting = "meeting",
    Power = "power",
    Trading = "trading",
    Training = "training",
    Workshop = "workshop",
}

export enum RoomType {
    Control = "CONTROL",
    Corridor = "CORRIDOR",
    Dormitory = "DORMITORY",
    Elevator = "ELEVATOR",
    Functional = "FUNCTIONAL",
    Hire = "HIRE",
    Manufacture = "MANUFACTURE",
    Meeting = "MEETING",
    None = "NONE",
    Power = "POWER",
    Trading = "TRADING",
    Training = "TRAINING",
    Workshop = "WORKSHOP",
}


export interface BuildingCharacter {
    charId:      string;
    maxManpower: number;
    buffChar:    BuffChar[];
}

export interface BuffChar {
    buffData: BuffDatum[];
}

export interface BuffDatum {
    buffId: string;
    cond:   Cond;
}

export interface Cond {
    phase: PhaseEnum;
    level: number;
}

export enum PhaseEnum {
    Phase0 = "PHASE_0",
    Phase1 = "PHASE_1",
    Phase2 = "PHASE_2",
}



export interface CreditFormula {
    initiative: ShopFormulas;
    passive:    ShopFormulas;
}



export interface CustomData {
    furnitures:         { [key: string]: FurnitureData };
    themes:             { [key: string]: ThemeData };
    groups:             { [key: string]: GroupData };
    types:              { [key: string]: FurnitureTypeData };
    subTypes:           { [key: string]: FurnitureSubTypeData };
    defaultFurnitures:  { [key: string]: DormitoryDefaultFurnitureItem[] };
    interactGroups:     InteractGroups;
    diyUISortTemplates: DiyUISortTemplates;
}


export interface DormitoryDefaultFurnitureItem {
    furnitureId:     string;
    xOffset:         number;
    yOffset:         number;
    defaultPrefabId: string;
}

export interface DiyUISortTemplates {
    THEME:              FURNITUREClass;
    FURNITURE:          FURNITUREClass;
    FURNITURE_IN_THEME: FURNITUREClass;
    RECENT_THEME:       FURNITUREClass;
    RECENT_FURNITURE:   FURNITUREClass;
}

export interface FURNITUREClass {
    FOLD:   Expand;
    EXPAND: Expand;
}

export interface Expand {
    diyUIType:            string;
    expandState:          ExpandState;
    defaultTemplateIndex: number;
    defaultTemplateOrder: EOrder;
    templates:            Template[];
}

export enum EOrder {
    Asc = "ASC",
    Desc = "DESC",
}

export enum ExpandState {
    Expand = "EXPAND",
    Fold = "FOLD",
}

export interface Template {
    name:                string;
    sequences:           Sequence[];
    stableSequence:      StableSequence;
    stableSequenceOrder: EOrder;
}


export enum Sequence {
    FurnitureAtomsphere = "FurnitureAtomsphere",
    FurnitureRecentAquireTime = "FurnitureRecentAquireTime",
    FurnitureSortID = "FurnitureSortId",
    ThemeAtomsphere = "ThemeAtomsphere",
    ThemeCollectionProgress = "ThemeCollectionProgress",
    ThemeRecentAquireTime = "ThemeRecentAquireTime",
    ThemeSortID = "ThemeSortId",
}

export enum StableSequence {
    FurnitureGroupID = "FurnitureGroupId",
    FurnitureIsSingle = "FurnitureIsSingle",
    None = "None",
}

export interface FurnitureData {
    id:                           string;
    sortId:                       number;
    name:                         string;
    iconId:                       string;
    interactType:                 FurnitureInteract;
    musicId:                      string;
    type:                         FurnitureType;
    subType:                      FurnitureSubType;
    location:                     FurnitureLocation;
    category:                     FurnitureCategory;
    validOnRotate:                boolean;
    enableRotate:                 boolean;
    rarity:                       number;
    themeId:                      string;
    groupId:                      string;
    width:                        number;
    depth:                        number;
    height:                       number;
    comfort:                      number;
    usage:                        string;
    description:                  string;
    obtainApproach:               string;
    processedProductId:           string;
    processedProductCount:        number;
    processedByProductPercentage: number;
    processedByProductGroup:      WorkshopExtraWeightItem[];
    canBeDestroy:                 boolean;
    isOnly:                       number;
    quantity:                     number;
}

export enum FurnitureCategory {
    Floor = "FLOOR",
    Furniture = "FURNITURE",
    Wall = "WALL",
}

export enum FurnitureInteract {
    Animator = "ANIMATOR",
    Music = "MUSIC",
    None = "NONE",
}

export enum FurnitureLocation {
    Carpet = "CARPET",
    Ceiling = "CEILING",
    Ceilingdecal = "CEILINGDECAL",
    Floor = "FLOOR",
    None = "NONE",
    Poster = "POSTER",
    Wall = "WALL",
}

export enum FurnitureSubType {
    Annihilation = "ANNIHILATION",
    ArtD = "ART_D",
    ArtWd = "ART_WD",
    Barstool = "BARSTOOL",
    Bench = "BENCH",
    BoardD = "BOARD_D",
    BoardWd = "BOARD_WD",
    Catering = "CATERING",
    Chair = "CHAIR",
    Column = "COLUMN",
    Contract = "CONTRACT",
    Contract2 = "CONTRACT_2",
    Cooking = "COOKING",
    Curtain = "CURTAIN",
    CurtainC = "CURTAIN_C",
    DecorationC = "DECORATION_C",
    Device = "DEVICE",
    DeviceC = "DEVICE_C",
    Dressing = "DRESSING",
    Entertainment = "ENTERTAINMENT",
    Floorlamp = "FLOORLAMP",
    InstrumentD = "INSTRUMENT_D",
    InstrumentWd = "INSTRUMENT_WD",
    Light = "LIGHT",
    None = "NONE",
    OrtherC = "ORTHER_C",
    OrtherD = "ORTHER_D",
    OrtherS = "ORTHER_S",
    OrtherWd = "ORTHER_WD",
    Partition = "PARTITION",
    Plant = "PLANT",
    Plaque = "PLAQUE",
    Poster = "POSTER",
    Shelf = "SHELF",
    Sofa = "SOFA",
    Stool = "STOOL",
    Storage = "STORAGE",
    Warm = "WARM",
    Wash = "WASH",
}

export enum FurnitureType {
    Bedding = "BEDDING",
    Cabinet = "CABINET",
    Carpet = "CARPET",
    Ceiling = "CEILING",
    Ceilinglamp = "CEILINGLAMP",
    Decoration = "DECORATION",
    Floor = "FLOOR",
    Seating = "SEATING",
    Table = "TABLE",
    Walldeco = "WALLDECO",
    Walllamp = "WALLLAMP",
    Wallpaper = "WALLPAPER",
}

export interface GroupData {
    id:        string;
    sortId:    number;
    name:      string;
    themeId:   string;
    comfort:   number;
    count:     number;
    furniture: string[];
}

export interface InteractGroups {
    swimsuit: Swimsuit[];
}

export interface Swimsuit {
    skinId: string;
}

export interface SubTypeValue {
    subType: SubTypeEnum;
    name:    string;
    type:    FurnitureType;
    sortId:  number;
}

export interface ThemeData {
    id:         string;
    sortId:     number;
    name:       string;
    themeType:  string;
    desc:       string;
    quickSetup: ThemeQuickSetupItem[];
    groups:     string[];
    furnitures: string[];
}

export interface ThemeQuickSetupItem {
    furnitureId: string;
    pos0:        number;
    pos1:        number;
    dir:         number;
}

export enum ThemeType {
    Event = "EVENT",
    Initial = "INITIAL",
    Linkage = "LINKAGE",
    Lucky = "LUCKY",
    Normal = "NORMAL",
}

export interface TypeValue {
    type: FurnitureType;
    name: string;
}

export interface DormDataClass {
    phases: DormDataPhase[] | null;
}

export interface DormDataPhase {
    manpowerRecover?: number;
    decorationLimit?: number;
    manpowerFactor?:  number;
}

export interface HireDataClass {
    basicSpeedBuff: number;
    phases:         HireDataPhase[] | null;
}

export interface HireDataPhase {
    economizeRate?:     number;
    resSpeed?:          number;
    refreshTimes?:      number;
    orderSpeed?:        number;
    orderLimit?:        number;
    orderRarity?:       number;
    specSkillLvlLimit?: number;
}

export interface LayoutData {
    id:         string;
    slots:      { [key: string]: RoomSlot };
    cleanCosts: { [key: string]: SlotCleanCost};
    storeys:    { [key: string]: StoreyData};
}



export interface SlotCleanCost {
    id:     string;
    number: { [key: string]: CountCost };
}

export interface CountCost {
    items: ItemBundle[];
}

export interface Cost {
    id:    string;
    count: number;
    type:  CostType;
}

export enum CostType {
    Gold = "GOLD",
    Material = "MATERIAL",
}


export interface RoomSlot {
    id:           string;
    cleanCostId:  string;
    costLabor:    number;
    provideLabor: number;
    size:         GridPosition;
    offset:       GridPosition;
    category:     RoomCategory;
    storeyId:     string;
}

export enum RoomCategory {
    Corridor = "CORRIDOR",
    Custom = "CUSTOM",
    Elevator = "ELEVATOR",
    Function = "FUNCTION",
    Output = "OUTPUT",
    Special = "SPECIAL",
}

export interface GridPosition {
    row: number;
    col: number;
}


export interface StoreyData {
    id:                 string;
    yOffset:            number;
    unlockControlLevel: number;
    type:               string;
}
export interface RoomBeanParam {}
export interface ControlRoomPhase extends RoomBeanParam {}
export interface RoomBean<TParam> {
    phases: TParam[];
}
export interface ControlRoomBean extends RoomBean<ControlRoomPhase> {
    basicCostBuff: number;
}
export interface ManufactRoomBean extends RoomBean<ManufactPhase> {
    basicSpeedBuff: number;
}
export interface ManufactPhase extends RoomBeanParam {
    speed:          number;
    outputCapacity: number;
}
export interface ShopPhase extends RoomBeanParam {}
export interface HireRoomBean extends RoomBean<HirePhase> {
    basicSpeedBuff: number;
}
export interface HirePhase extends RoomBeanParam {
    economizeRate: number;
    resSpeed: number;
    refreshTimes:number;
}
export interface DormPhase extends RoomBeanParam {
    manpowerRecover: number;
    decorationLimit: number;
}
export interface MeetingRoomBean extends RoomBean<MeetingPhase> {
    basicSpeedBuff: number;
}
export interface MeetingPhase extends RoomBeanParam {
    friendSlotInc: number;
    maxVisitorNum: number;
    gatheringSpeed:number;
}
export interface TradingRoomBean extends RoomBean<TradingPhase> {
    basicSpeedBuff: number;
}
export interface TradingPhase extends RoomBeanParam {
    orderSpeed: number;
    orderLimit: number;
    orderRarity:number;
}
export interface WorkshopPhase extends RoomBeanParam {
    manpowerFactor: number;
}
export interface TrainingBean extends RoomBean<TrainingPhase> {
    basicSpeedBuff: number;
}
export interface TrainingPhase extends RoomBeanParam {
    specSkillLvlLimit: number;
}
export interface PowerRoomBean extends RoomBean<PowerPhase> {
    basicSpeedBuff: number;
}
export interface PowerPhase extends RoomBeanParam {}
export interface ManufactFormula {
    formulaId:     string;
    itemId:        string;
    count:         number;
    weight:        number;
    costPoint:     number;
    formulaType:   string;
    buffType:      string;
    costs:         Cost[];
    requireRooms:  RequireRoom[];
    requireStages: any[];
}

export interface RequireRoom {
    roomId:    RoomType;
    roomLevel: number;
    roomCount: number;
}

export interface MeetingData {
    basicSpeedBuff: number;
    phases:         MeetingDataPhase[];
}

export interface MeetingDataPhase {
    friendSlotInc:  number;
    maxVisitorNum:  number;
    gatheringSpeed: number;
}

export interface PrefabInfo {
    id:                      string;
    blueprintRoomOverrideId: null;
    size:                    GridPosition;
    floorGridSize:           GridPosition;
    backWallGridSize:        GridPosition;
    obstacleId:              null;
}


export interface RoomUnlockCond {
    id:     string;
    number: { [key: string]: CondItem };
}

export interface CondItem {
    type:  RoomType;
    level: number;
    count: number;
}



export interface RoomData {
    id:              RoomType;
    name:            string;
    description:     null | string;
    defaultPrefabId: string;
    canLevelDown:    boolean;
    maxCount:        number;
    category:        RoomCategory;
    size:            GridPosition;
    phases:          PhaseData[];
}

export interface PhaseData {
    overrideName:     null;
    overridePrefabId: null;
    unlockCondId:     string;
    buildCost:        BuildCost;
    electricity:      number;
    maxStationedNum:  number;
    manpowerCost:     number;
}

export interface BuildCost {
    items: ItemBundle[];
    time:  number;
    labor: number;
}


export interface WorkshopFormula {
    sortId:            number;
    formulaId:         string;
    rarity:            number;
    itemId:            string;
    count:             number;
    goldCost:          number;
    apCost:            number;
    formulaType:       FormulaType;
    buffType:          BuffType;
    extraOutcomeRate:  number;
    extraOutcomeGroup: ExtraOutcomeGroup[];
    costs:             Cost[];
    requireRooms:      RequireRoom[];
    requireStages:     RequireStage[];
}

export enum BuffType {
    WAsc = "W_ASC",
    WBuilding = "W_BUILDING",
    WEvolve = "W_EVOLVE",
    WSkill = "W_SKILL",
}

export interface ExtraOutcomeGroup {
    weight:    number;
    itemId:    string;
    itemCount: number;
}

export enum FormulaType {
    FAsc = "F_ASC",
    FBuilding = "F_BUILDING",
    FEvolve = "F_EVOLVE",
    FSkill = "F_SKILL",
}

export interface RequireStage {
    stageId: string;
    rank:    number;
}
