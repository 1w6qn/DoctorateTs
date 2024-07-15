export interface PlayerRoguelikeV2{
    current:CurrentData
    outer:{[key:string]:OuterData}
    pinned:string
}
export interface CurrentData{
    player:PlayerStatus
    map:PlayerRoguelikeV2Dungeon
    inventory:Inventory
    game:Game
    troop:Troop
    buff:Buff
    module:Module
}
export interface PlayerStatus{
    state:string//PlayerRoguelikePlayerState
    property:Properties
    cursor:NodePosition
    pending:PlayerRoguelikePendingEvent[]
    trace:NodePosition[]
    status:Status;
    toEnding:string
    chgEnding:boolean
    innerMission:InnerMission[]
    nodeMission:NodeMission
    zoneReward:{[key:string]:ZoneRewardItem}
    traderReturn:{[key:string]:ZoneRewardItem}
}
export interface Properties{
    exp:number
    level:number
    maxLevel:number
    hp:Hp
    shield:number
    gold:number
    capacity:number
    population:Population
    conPerfectBattle:number
}
export interface Hp{
    current:number
    max:number
}
export interface Population{
    cost:number
    max:number
}
//RewardHpShowStatus
export interface NodePosition{
    zone:number
    position:RoguelikeNodePosition
}
export interface RoguelikeNodePosition{
    x:number
    y:number
}
export interface Status{
    bankPut:number
}
export interface InnerMission{
    tmpl:string
    id:string
    progress:number[]
}
export interface NodeMission{
    id:string
    state:string//NodeMissionState
    tip:boolean
    progress:number[]
}
export interface ZoneRewardItem{
    id:string
    count:number
    instId:string
}
export interface PlayerRoguelikePendingEvent{
    type:string//PlayerRoguelikePlayerEventType
    content:any//___WIP___//Content
}
export interface Char{}

export interface Module{

}