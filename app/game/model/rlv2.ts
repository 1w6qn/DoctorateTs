import exp from "constants"
import { PlayerCharacter, SharedCharData } from "./character"

export interface PlayerRoguelikeV2 {
    current: CurrentData
    outer: { [key: string]: OuterData }
    pinned?: string
}
export interface OuterData {
    bp: BattlePass
    buff: Buff1
    mission: Mission
    collect: Collection
    bank: Bank
    record: Record
    monthTeam: MonthTeam
    challenge: Challenge
}
export interface Record {
    last: number
    stageCnt: { [key: string]: number }
    bandCnt: { [key: string]: { [key: string]: number } }
    bandGrade: { [key: string]: { [key: string]: number } }
}

export interface BattlePass {
    point: number
    reward: { [key: string]: number }
}
export interface Mission {
    updateId: string
    refresh: number
    list: MissionSlot[]
}
export interface MissionSlot {
    type: string//RoguelikeGameMonthTaskClass
    mission: MissionItem
}
export interface MissionItem {
    type: string//RoguelikeGameMonthTaskClass
    id: string
    state: number
    target: number
    value: number
}
export interface TotemCollection {
    totem: { [key: string]: ItemUnlockInfo }
    affix: { [key: string]: ItemUnlockInfo }
}
export interface Collection {
    band: { [key: string]: ItemUnlockInfo }
    relic: { [key: string]: ItemUnlockInfo }
    capsule: { [key: string]: ItemUnlockInfo }
    activeTool: { [key: string]: ItemUnlockInfo }
    mode: { [key: string]: ItemUnlockInfo }
    modeGrade: { [key: string]: { [key: string]: DifficultyUnlockInfo } }
    recruitSet: { [key: string]: ItemUnlockInfo }
    bgm: { [key: string]: number }
    pic: { [key: string]: number }
    chat: { [key: string]: number }
    endbook: { [key: string]: ItemUnlockInfo }
    buff: { [key: string]: ItemUnlockInfo }
    totem: TotemCollection
    chaos: { [key: string]: ItemUnlockInfo }
    fragment: { [key: string]: ItemUnlockInfo }
    disaster: { [key: string]: ItemUnlockInfo }
    nodeUpgrade: { [key: string]: NodeUpgradeInfo }
}
export interface DifficultyUnlockInfo {
    state: number
}
export interface ItemUnlockInfo {
    state: number
    progress: number[]
}
export interface NodeUpgradeInfo {
    unlockList: string[]
}
export interface Bank {
    show: boolean
    current: number
    record: number
    reward: { [key: string]: number }
}
export interface Buff1 {
    pointOwned: number
    pointCost: number
    unlocked: { [key: string]: number }
}
export interface MonthTeam {
    reward: { [key: string]: number }
    mission: { [key: string]: number[] }
}
export interface Challenge {
    reward: { [key: string]: number }
    grade: { [key: string]: number }
    collect: ChallengeCollection
}
export interface ChallengeCollection {
    exploreTool: { [key: string]: ItemUnlockInfo }
}

export interface CurrentData {
    player: PlayerStatus|null
    record: any|null
    map: PlayerRoguelikeV2Dungeon|null
    inventory: Inventory|null
    game: Game|null
    troop: Troop|null
    buff: Buff|null
    module: Module|null
}
export namespace CurrentData {

}
export interface Buff {
    tmpHP: number
    capsule: Capsule|null
    squadBuff: string[]
}
export interface Capsule {
    id: string
    ts: number
    active: boolean
}
export interface Troop {
    chars: { [key: string]: any }
    expedition: string[]
    expeditionDetails: { [key: string]: number/*ExpedType*/ }
    expeditionReturn: ExpeditionReturn|null
    hasExpeditionReturn: boolean
}
export interface ExpeditionReturn {
    charList: ExpeditionReturn.Char[]
    rewards: ExpeditionReturn.Reward[]
}
namespace ExpeditionReturn {
    export interface Char {
        instId: string
        isUpgrade: boolean
        isCure: boolean
    }
    export interface Reward {
        id: string
        count: number
        instId: string
    }
}
export interface Game {
    uid: string
    theme: string
    mode: string
    modeGrade: number
    equivalentGrade: number
    predefined: string
    difficult: number
    outerBuff: OuterBuff
    start: number
}
export interface OuterBuff { }

export interface Inventory {
    relic: { [key: string]: Relic }
    recruit: { [key: string]: Recruit }
    trap: Trap|null
    exploreTool: { [key: string]: ExploreTool }
    consumable: { [key: string]: number }
}

export interface Trap {
    id: string
    ts: number
}
export interface ExploreTool {
    id: string
    ts: number
}
export interface Relic {
    index: string
    id: string
    count: number
    layer: number
    ts: number
    used: boolean
}
export interface RecruitChar extends PlayerCharacter {
    type: string//RoguelikeCharState
    upgradePhase: number
    upgradeLimited: boolean
    population: number
    isUpgrade: boolean
    troopInstId: number
}
export interface Recruit {
    index: string
    id: string
    state: string//State
    list: RecruitChar[]
    result: RecruitChar
    ts: number
    needAssist: boolean
    assistList: { [key: string]: FriendAssistData[] }
}
export interface FriendAssistData {
    orig: OrigChar
    recruit: RecruitChar
}
export interface OrigChar extends FriendCommonData {
    assistSlotIndex: number
    aliasName: string
    assistCharList: SharedCharData[]
    isFriend: boolean
    canRequestFriend: boolean
}

export interface FriendCommonData {
    nickName: string
    uid: string
    serverName: string
    nickNumber: string
    level: number
    lastOnlineTime: Date
    recentVisited: boolean
    avatar: AvatarInfo
}
export interface AvatarInfo {
    type: string//PlayerAvatarType
    id: string
}
export interface PlayerStatus {
    state: string//PlayerRoguelikePlayerState
    property: PlayerStatus.Properties
    cursor: PlayerStatus.NodePosition
    pending: PlayerRoguelikePendingEvent[]
    trace: PlayerStatus.NodePosition[]
    status: PlayerStatus.Status;
    toEnding: string
    chgEnding: boolean
    innerMission?: PlayerStatus.InnerMission[]
    nodeMission?: PlayerStatus.NodeMission
    zoneReward?: { [key: string]: PlayerStatus.ZoneRewardItem }
    traderReturn?: { [key: string]: PlayerStatus.ZoneRewardItem }
}
export namespace PlayerStatus {
    export interface Properties {
        exp: number
        level: number
        maxLevel: number
        hp: Properties.Hp
        shield: number
        gold: number
        capacity: number
        population: Properties.Population
        conPerfectBattle: number
        hpShowState:string
    }
    export namespace Properties {
        export interface Hp {
            current: number
            max: number
        }
        export interface Population {
            cost: number
            max: number
        }
        //RewardHpShowStatus
    }
    export interface NodePosition {
        zone: number
        position: RoguelikeNodePosition|null
    }
    export interface Status {
        bankPut: number
    }
    export interface InnerMission {
        tmpl: string
        id: string
        progress: number[]
    }
    export interface NodeMission {
        id: string
        state: string//NodeMissionState
        tip: boolean
        progress: number[]
    }
    export interface ZoneRewardItem {
        id: string
        count: number
        instId: string
    }

}



export interface RoguelikeNodePosition {
    x: number
    y: number
}


export interface PlayerRoguelikePendingEvent {
    index:string
    type: string//PlayerRoguelikePlayerEventType
    content: any//___WIP___//Content
}
/**

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.BattleRewardContent : System.Object
{
    System.Collections.Generic.List<Torappu.RoguelikeReward> rewards; // 0x8
    Torappu.RoguelikeStageEarn earn; // 0xc
    System.String show; // 0x10
    System.Int32 state; // 0x14
    System.Int32 isPerfect; // 0x18
    System.Void .ctor(); // 0x01215e1f
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.BattleContent : System.Object
{
    System.Int32 state; // 0x8
    System.Int32 chestCnt; // 0xc
    System.Int32 goldTrapCnt; // 0x10
    System.Collections.Generic.List<Torappu.PlayerRoguelikeV2.CurrentData.Char> tmpChar; // 0x14
    System.Collections.Generic.List<Torappu.RoguelikeBuff> unKeepBuff; // 0x18
    System.Collections.Generic.List<System.Int32> diceRoll; // 0x1c
    System.Int32 sanity; // 0x20
    System.Collections.Generic.Dictionary<System.String,System.Int32> boxInfo; // 0x24
    System.Boolean isFailProtect; // 0x28
    System.Void .ctor(); // 0x01215df9
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.InitRecruitContent : System.Object
{
    System.Int32[] step; // 0x8
    System.String[] tickets; // 0xc
    Torappu.PlayerRoguelikePendingEvent.InitRecruitContent.ShowChar[] showChar; // 0x10
    System.String team; // 0x14
    System.Void .ctor(); // 0x01216063
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.InitRecruitContent.ShowChar : System.Object
{
    System.String charId; // 0x8
    System.String uniEquipIdOfChar; // 0xc
    Torappu.RoguelikeCharState type; // 0x10
    System.Void .ctor(); // 0x01216089
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.InitRecruitSetContent : System.Object
{
    System.Int32[] step; // 0x8
    System.String[] option; // 0xc
    System.Void .ctor(); // 0x012160af
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.InitRelicContent : System.Object
{
    System.Int32[] step; // 0x8
    System.Collections.Generic.Dictionary<System.String,Torappu.RoguelikeItemBundle> items; // 0xc
    System.Void .ctor(); // 0x012160d5
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.InitModeRelic : System.Object
{
    System.Int32[] step; // 0x8
    System.Collections.Generic.List<System.String> items; // 0xc
    System.Void .ctor(); // 0x01215fec
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.InitTeam : System.Object
{
    System.Int32[] step; // 0x8
    System.Collections.Generic.List<Torappu.PlayerRoguelikePendingEvent.InitTeam.Char> chars; // 0xc
    System.String team; // 0x10
    System.Void .ctor(); // 0x01216166
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.InitTeam.Char : System.Object
{
    System.String charId; // 0x8
    System.String uniEquipIdOfChar; // 0xc
    Torappu.RoguelikeCharState type; // 0x10
    System.Void .ctor(); // 0x012161dd
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.InitSupport : System.Object
{
    System.Int32[] step; // 0x8
    Torappu.PlayerRoguelikePendingEvent.SceneContent scene; // 0xc
    System.Void .ctor(); // 0x012160fb
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.InitExploreTool : System.Object
{
    System.Int32[] step; // 0x8
    System.Collections.Generic.Dictionary<System.String,Torappu.RoguelikeItemBundle> items; // 0xc
    System.Void .ctor(); // 0x01215fc6
}

// Assembly-CSharp
enum Torappu.PlayerRoguelikePendingEvent.PlayerRoguelikeChoiceRewardType : System.Enum
{
    System.Int32 value__; // 0x8
    static Torappu.PlayerRoguelikePendingEvent.PlayerRoguelikeChoiceRewardType NONE = 0;
    static Torappu.PlayerRoguelikePendingEvent.PlayerRoguelikeChoiceRewardType ITEM = 1;
    static Torappu.PlayerRoguelikePendingEvent.PlayerRoguelikeChoiceRewardType MISSION = 2;
    
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.ChoiceAddition : System.Object
{
    System.Collections.Generic.List<Torappu.PlayerRoguelikePendingEvent.ChoiceAddition.Reward> rewards; // 0x8
    System.Void .ctor(); // 0x01215e45
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.ChoiceAddition.Reward : System.Object
{
    System.String id; // 0x8
    Torappu.PlayerRoguelikePendingEvent.PlayerRoguelikeChoiceRewardType type; // 0xc
    System.Void .ctor(); // 0x01215ebc
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.SceneContent : System.Object
{
    System.String id; // 0x8
    System.Collections.Generic.Dictionary<System.String,System.Boolean> choices; // 0xc
    System.Collections.Generic.Dictionary<System.String,Torappu.PlayerRoguelikePendingEvent.ChoiceAddition> choiceAdditional; // 0x10
    System.Void .ctor(); // 0x01215abc
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.Recruit : System.Object
{
    System.String ticket; // 0x8
    System.Void .ctor(); // 0x01216203
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.Dice : System.Object
{
    Torappu.PlayerRoguelikePendingEvent.Dice.Result result; // 0x8
    System.Int32 rerollCount; // 0xc
    System.Void .ctor(); // 0x01215ee2
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.Dice.Result : System.Object
{
    System.String diceEventId; // 0x8
    System.Int32 diceRoll; // 0xc
    Torappu.PlayerRoguelikePendingEvent.Dice.MutationResult mutation; // 0x10
    System.String[] virtue; // 0x14
    System.Void .ctor(); // 0x01215f2e
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.Dice.MutationResult : System.Object
{
    System.String id; // 0x8
    System.String[] chars; // 0xc
    System.Void .ctor(); // 0x01215f08
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.ShopContent : System.Object
{
    Torappu.PlayerRoguelikePendingEvent.ShopContent.Bank bank; // 0x8
    System.String id; // 0xc
    System.Collections.Generic.List<Torappu.PlayerRoguelikePendingEvent.ShopContent.Goods> goods; // 0x10
    System.Boolean canBattle; // 0x14
    System.Boolean hasBoss; // 0x15
    System.Boolean showRefresh; // 0x16
    System.Int32 refreshCnt; // 0x18
    System.Collections.Generic.List<Torappu.PlayerRoguelikePendingEvent.ShopContent.Goods> recycleGoods; // 0x1c
    System.Int32 recycleCount; // 0x20
    System.Void .ctor(); // 0x0121624f
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.ShopContent.Bank : System.Object
{
    System.Int32 cost; // 0x8
    System.Boolean open; // 0xc
    System.Boolean canPut; // 0xd
    System.Boolean canWithdraw; // 0xe
    System.Int32 withdraw; // 0x10
    System.Int32 withdrawLimit; // 0x14
    System.Void .ctor(); // 0x01216281
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.ShopContent.Goods : System.Object
{
    System.String index; // 0x8
    System.String itemId; // 0xc
    System.Int32 count; // 0x10
    System.String priceId; // 0x14
    System.Int32 priceCount; // 0x18
    System.Int32 origCost; // 0x1c
    System.Boolean displayPriceChg; // 0x20
    System.Void .ctor(); // 0x012162a7
}

// Assembly-CSharp
enum Torappu.PlayerRoguelikePendingEvent.PlayerRoguelikeSacrificeType : System.Enum
{
    System.Int32 value__; // 0x8
    static Torappu.PlayerRoguelikePendingEvent.PlayerRoguelikeSacrificeType RELIC = 0;
    static Torappu.PlayerRoguelikePendingEvent.PlayerRoguelikeSacrificeType TOTEM = 1;
    
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.SacrificeContent : System.Object
{
    Torappu.PlayerRoguelikePendingEvent.PlayerRoguelikeSacrificeType type; // 0x8
    System.Void .ctor(); // 0x01216229
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.EndingResult : System.Object
{
    Torappu.PlayerRoguelikePendingEvent.EndingBrief brief; // 0x8
    Torappu.PlayerRoguelikePendingEvent.EndingRecord record; // 0xc
    System.Void .ctor(); // 0x01215fa0
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.EndingBrief : System.Object
{
    System.Int32 level; // 0x8
    System.Int32 success; // 0xc
    System.String ending; // 0x10
    System.String theme; // 0x14
    Torappu.RoguelikeTopicMode mode; // 0x18
    System.String predefined; // 0x1c
    System.String band; // 0x20
    System.Int64 startTs; // 0x24
    System.Int64 endTs; // 0x2c
    System.String endZoneId; // 0x34
    System.Int32 modeGrade; // 0x38
    System.Void .ctor(); // 0x01215f54
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.EndingRecord : System.Object
{
    System.Int32 cntZone; // 0x8
    System.Collections.Generic.List<System.String> relicList; // 0xc
    System.Collections.Generic.List<System.String> capsuleList; // 0x10
    System.Collections.Generic.List<System.String> activeToolList; // 0x14
    System.Collections.Generic.List<System.String> charBuff; // 0x18
    System.Collections.Generic.List<System.String> squadBuff; // 0x1c
    System.Collections.Generic.List<System.String> totemList; // 0x20
    System.Collections.Generic.List<System.String> exploreToolList; // 0x24
    System.Collections.Generic.List<System.String> fragmentList; // 0x28
    System.Void .ctor(); // 0x01215f7a
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.AlchemyContent : System.Object
{
    System.Boolean canAlchemy; // 0x8
    System.Void .ctor(); // 0x01215dad
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.AlchemyRewardContent : System.Object
{
    System.Collections.Generic.List<Torappu.RoguelikeItemBundle> items; // 0x8
    System.Boolean isSSR; // 0xc
    System.Boolean isFail; // 0xd
    System.Void .ctor(); // 0x01215dd3
}

// Assembly-CSharp
class Torappu.PlayerRoguelikePendingEvent.Content : System.Object
{
    Torappu.PlayerRoguelikePendingEvent.SceneContent scene; // 0x8
    Torappu.PlayerRoguelikePendingEvent.InitRecruitContent initRecruit; // 0xc
    Torappu.PlayerRoguelikePendingEvent.BattleContent battle; // 0x10
    Torappu.PlayerRoguelikePendingEvent.InitRelicContent initRelic; // 0x14
    Torappu.PlayerRoguelikePendingEvent.InitRecruitSetContent initRecruitSet; // 0x18
    Torappu.PlayerRoguelikePendingEvent.InitModeRelic initModeRelic; // 0x1c
    Torappu.PlayerRoguelikePendingEvent.InitTeam initTeam; // 0x20
    Torappu.PlayerRoguelikePendingEvent.InitSupport initSupport; // 0x24
    Torappu.PlayerRoguelikePendingEvent.InitExploreTool initExploreTool; // 0x28
    Torappu.PlayerRoguelikePendingEvent.BattleRewardContent battleReward; // 0x2c
    Torappu.PlayerRoguelikePendingEvent.Recruit recruit; // 0x30
    Torappu.PlayerRoguelikePendingEvent.Dice dice; // 0x34
    Torappu.PlayerRoguelikePendingEvent.ShopContent shop; // 0x38
    Torappu.PlayerRoguelikePendingEvent.EndingResult result; // 0x3c
    Torappu.PlayerRoguelikePendingEvent.ShopContent battleShop; // 0x40
    Torappu.PlayerRoguelikePendingEvent.SacrificeContent sacrifice; // 0x44
    System.String detailStr; // 0x48
    System.Boolean popReport; // 0x4c
    Torappu.PlayerRoguelikePendingEvent.AlchemyContent alchemy; // 0x50
    Torappu.PlayerRoguelikePendingEvent.AlchemyRewardContent alchemyReward; // 0x54
    System.Boolean done; // 0x58
    System.Void .ctor(); // 0x01215d87
}

 */
export interface Content {
    scene: SceneContent
    initRecruit: InitRecruitContent
    battle: BattleContent
    initRelic: InitRelicContent
    initRecruitSet: InitRecruitSetContent
    initModeRelic: InitModeRelic
    initTeam: InitTeam
    initSupport: InitSupport
    initExploreTool: InitExploreTool
    battleReward: any
    recruit: Recruit
    dice: any
    shop: any
    result: any
    battleShop: any
    sacrifice: any
    detailStr: string
    popReport: boolean
    alchemy: any
    alchemyReward: any
    done: boolean
}
export interface InitRecruitContent {
    step: number[]
    tickets: string[]
    showChar: ShowChar[]
    team: string
}
export interface ShowChar {
    charId: string
    uniEquipIdOfChar: string
    type: string//RoguelikeCharState
}
export interface InitRecruitSetContent {
    step: number[]
    option: string[]
}
export interface InitRelicContent {
    step: number[]
    items: any[]
}
export interface InitModeRelic {
    step: number[]
    items: string[]
}
export interface InitTeam {
    step: number[]
    chars: any[]
    team: string
}
export interface InitSupport {
    step: number[]
    support: string[]
    showChar: ShowChar[]
    team: string
}
export interface InitExploreTool {
    step: number[]
    exploreTool: string[]
}
export interface BattleContent {
}
export interface SceneContent {
    id: string
    choices: { [key: string]: boolean }
    choiceAdditional: { [key: string]: ChoiceAddition }
}
export interface ChoiceAddition {
    rewards: Reward[]
}
export interface Reward {
    id: string
    type: string//PlayerRoguelikeChoiceRewardType
}


export interface PlayerRoguelikeV2Dungeon {
    zones: { [key: string]: PlayerRoguelikeV2Zone }
}
export interface PlayerRoguelikeV2Zone {
    id: string
    nodes: { [key: string]: PlayerRoguelikeNode }
    variation: string[]
}

export interface PlayerRoguelikeNode {
    pos: RoguelikeNodePosition
    next: RoguelikeNodeLine[]
    type: string//RoguelikeEventType
    fts: number
    realContent: PlayerNodeDetailContent
    attach: string[]
    shop: RoguelikeShop
    scenes: SceneContent
    stage: string
    visibility: string//PlayerNodeForesightType
    refresh: PlayerNodeRollInfo
}
export interface RoguelikeShop {
    goods: RoguelikeGoods[]
}
export interface RoguelikeGoods {
    instId: string
    itemId: string
    count: number
    priceId: string
    priceCount: number
}
export interface RoguelikeNodeLine {
    x: number
    y: number
    hidden: string//HiddenType
    key: boolean
}
export interface PlayerNodeDetailContent {
    scene: string
    battleShop: BattleShop
    wish: string[]
    battle: string[]
    hasShopBoss: boolean
}
export interface BattleShop {
    hasShopBoss: boolean
    goods: string[]
}
export interface PlayerNodeRollInfo {
    count: number
    cost: number
}