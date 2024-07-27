import { Init } from "v8"
import { OrigChar, PlayerCharacter, SharedCharData } from "./character"
import { Blackboard } from "../../excel/character_table"

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
    scenes: PlayerRoguelikePendingEvent.SceneContent
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
    battleShop: PlayerNodeDetailContent.BattleShop
    wish: string[]
    battle: string[]
    hasShopBoss: boolean
}
export namespace PlayerNodeDetailContent {
    export interface BattleShop {
        hasShopBoss: boolean
        goods: string[]
    }
}

export interface PlayerNodeRollInfo {
    count: number
    cost: number
}
export interface PlayerRoguelikeV2 {
    current: PlayerRoguelikeV2.CurrentData
    outer: { [key: string]: PlayerRoguelikeV2.OuterData }
    pinned?: string
}
export namespace PlayerRoguelikeV2 {
    export interface CurrentData {
        player: CurrentData.PlayerStatus | null
        record: any | null
        map: PlayerRoguelikeV2Dungeon | null
        inventory: CurrentData.Inventory | null
        game: CurrentData.Game | null
        troop: CurrentData.Troop | null
        buff: CurrentData.Buff | null
        module: CurrentData.Module | null
    }

    export namespace CurrentData {
        export interface Buff {
            tmpHP: number
            capsule: Capsule | null
            squadBuff: string[]
        }
        export interface Capsule {
            id: string
            ts: number
            active: boolean
        }
        export interface ExpeditionReturn {
            charList: ExpeditionReturn.Char[]
            rewards: ExpeditionReturn.Reward[]
        }
        export namespace ExpeditionReturn {
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
                hpShowState: string
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
                position: RoguelikeNodePosition | null
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
        export interface Troop {
            chars: { [key: string]: Char }
            expedition: string[]
            expeditionDetails: { [key: string]: number/*ExpedType*/ }
            expeditionReturn: ExpeditionReturn | null
            hasExpeditionReturn: boolean
        }
        export interface Char extends PlayerCharacter {
            upgradePhase: number
            upgradeLimited: boolean
            type: number//RoguelikeCharState
            charBuff: string[]

        }
        export interface RecruitChar extends PlayerCharacter {
            type: string//RoguelikeCharState
            upgradePhase: number
            upgradeLimited: boolean
            population: number
            isUpgrade: boolean
            isCure?: boolean
            charBuff?:any[]
            troopInstId: number


        }

        export interface Game {
            uid: string
            theme: string
            mode: string
            modeGrade: number
            equivalentGrade: number
            predefined: string
            difficult: number
            outerBuff: {}
            start: number
        }
        export interface Inventory {
            relic: { [key: string]: Relic }
            recruit: { [key: string]: Recruit }
            trap: Trap | null
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
            layer?: number
            ts: number
            used?: boolean
        }
        export interface Recruit {
            index: string
            id: string
            state: number//State
            list: RecruitChar[]
            result: RecruitChar|null
            ts: number
            from: string
            mustExtra:number
            needAssist: boolean
            assistList?: { [key: string]: FriendAssistData[] }
        }
        export interface Module {
            san?: Module.San
            dice?: Module.Dice
            totem?: Module.Totem
            vision?: Module.Vision
            chaos?: Module.Chaos
            fragment?: Module.Fragment
            disaster?: Module.Disaster
            nodeUpgrade?: Module.NodeUpgrade
        }
        export namespace Module {
            export interface San {
                sanity: number
            }
            export interface Dice {
                id: string,
                count: number
            }
            export interface InventoryTotem {
                id: string,
                instId: string,
                used: boolean,
                affix: string,
                ts: number
            }
            export interface Totem {
                totemPiece: InventoryTotem[],
                predictTotemId: string,

            }
            export interface Vision {
                value: number,
                isMax: boolean,
            }
            export interface Chaos {
                value: number,
                level: number,
                curMaxValue: number,
                chaosList: string[]
                predict: string
                deltaChaos: ChaosZoneDelta
                lastBattleGain: number
            }
            export interface ChaosZoneDelta {
                dValue: number,
                preLevel: number
                afterLevel: number
                dChaos: string[]
            }
            export interface Fragment {
                totalWeight: number,
                limitWeight: number,
                overWeight: number,
                fragments: { [key: string]: InventoryFragment }
                troopWeights: { [key: string]: number }
                troopCarry: string[]
                sellCount?: number
                currInspiration: InventoryInspiration | null
            }
            export interface InventoryFragment {
                id: string,
                index: string,
                used: boolean,
                ts: number
                weight: number
                value: number
                price?: number
                ei:number
            }
            export interface InventoryInspiration {
                instId: string,
                id: string
            }
            export interface Disaster {
                curDisaster: string|null,
                disperseStep: number
            }
            export interface NodeUpgrade {
                nodeTypeInfoMap: { [key: string]: NodeUpgradeInfo },
            }
            export interface NodeUpgradeInfo {
                tempUpgrade: string,
                upgradeList: string[]
                currUpgradeIndex:number
            }
        }

    }
    export interface OuterData {
        bp: OuterData.BattlePass
        buff: OuterData.Buff
        mission: OuterData.Mission
        collect: OuterData.Collection
        bank: OuterData.Bank
        record: OuterData.Record
        monthTeam: OuterData.MonthTeam
        challenge: OuterData.Challenge
    }
    export namespace OuterData {

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
            list: Mission.MissionSlot[]
        }
        export namespace Mission {
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
        }

        export interface TotemCollection {
            totem: { [key: string]: Collection.ItemUnlockInfo }
            affix: { [key: string]: Collection.ItemUnlockInfo }
        }
        export interface Collection {
            band: { [key: string]: Collection.ItemUnlockInfo }
            relic: { [key: string]: Collection.ItemUnlockInfo }
            capsule: { [key: string]: Collection.ItemUnlockInfo }
            activeTool: { [key: string]: Collection.ItemUnlockInfo }
            mode: { [key: string]: Collection.ItemUnlockInfo }
            modeGrade: { [key: string]: { [key: string]: Collection.DifficultyUnlockInfo } }
            recruitSet: { [key: string]: Collection.ItemUnlockInfo }
            bgm: { [key: string]: number }
            pic: { [key: string]: number }
            chat: { [key: string]: number }
            endbook: { [key: string]: Collection.ItemUnlockInfo }
            buff: { [key: string]: Collection.ItemUnlockInfo }
            totem: TotemCollection
            chaos: { [key: string]: Collection.ItemUnlockInfo }
            fragment: { [key: string]: Collection.ItemUnlockInfo }
            disaster: { [key: string]: Collection.ItemUnlockInfo }
            nodeUpgrade: { [key: string]: NodeUpgradeInfo }
        }
        export namespace Collection {
            export interface ItemUnlockInfo {
                state: number
                progress: number[]
            }
            export interface DifficultyUnlockInfo {
                state: number
            }
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

        export interface Buff {
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
            exploreTool: { [key: string]: Collection.ItemUnlockInfo }
        }
    }

}













export interface FriendAssistData {
    orig: OrigChar
    recruit: PlayerRoguelikeV2.CurrentData.RecruitChar
}





export interface RoguelikeNodePosition {
    x: number
    y: number
}


export interface PlayerRoguelikePendingEvent {
    index: string
    type: string//PlayerRoguelikePlayerEventType
    content: PlayerRoguelikePendingEvent.Content
}
export namespace PlayerRoguelikePendingEvent {
    export interface Content {
        scene?: SceneContent
        initRecruit?: InitRecruitContent
        battle?: BattleContent
        initRelic?: InitRelicContent
        initRecruitSet?: InitRecruitSetContent
        initModeRelic?: InitModeRelic
        initTeam?: InitTeam
        initSupport?: InitSupport
        initExploreTool?: InitExploreTool
        battleReward?: BattleRewardContent
        recruit?: Recruit
        dice?: Dice
        shop?: ShopContent
        result?: EndingResult
        battleShop?: ShopContent
        sacrifice?: SacrificeContent
        detailStr?: string
        popReport?: boolean
        alchemy?: AlchemyContent
        alchemyReward?: AlchemyRewardContent
        done?: boolean
    }
    export interface BattleRewardContent {
        rewards: RoguelikeReward[]
        earn: RoguelikeStageEarn
        show: string
        state: number
        isPerfect: number
    }
    export interface BattleContent {
        state: number
        chestCnt: number
        goldTrapCnt: number
        tmpChar: PlayerRoguelikeV2.CurrentData.Char
        unKeepBuff: RoguelikeBuff
        diceRoll: number
        sanity: number
        boxInfo: { [key: string]: number }
        isFailProtect: boolean
    }
    export interface InitRecruitContent {
        step: number[]
        tickets: string[]
        showChar: InitRecruitContent.ShowChar[]
        team: string|null
    }
    export namespace InitRecruitContent {
        export interface ShowChar {
            charId: string
            uniEquipIdOfChar: string
            type: string//RoguelikeCharState
        }
    }
    export interface InitRecruitSetContent {
        step: number[]
        option: string[]
    }
    export interface InitRelicContent {
        step: number[]
        items: {[key:string]:RoguelikeItemBundle}
    }
    

    export interface InitModeRelic {
        step: number[]
        items: string[]
    }
    export interface InitTeam {
        step: number[]
        chars: InitTeam.Char[]
        team: string
    }
    export namespace InitTeam {
        export interface Char {
            charId: string
            uniEquipIdOfChar: string
            type: string//RoguelikeCharState
        }
    }
    export interface InitSupport {
        step: number[]
        scene:SceneContent
    }
    export interface InitExploreTool {
        step: number[]
        items: {[key:string]:RoguelikeItemBundle}
    }
    
    export interface ChoiceAddition {
        rewards: ChoiceAddition.Reward[]
    }
    export namespace ChoiceAddition {
        export interface Reward {
            id: string
            type: string//PlayerRoguelikeChoiceRewardType
        }
    }
    export interface SceneContent {
        id: string
        choices: { [key: string]: number }
        choiceAdditional?: { [key: string]: ChoiceAddition }
    }
    export interface Recruit {
        ticket:string
    }
    export interface Dice {
        result:Dice.Result
        rerollCount:number
    }
    export namespace Dice {
        export interface Result {
            diceEventId: string
            diceRoll: number
            mutation:MutationResult
            virtue:string[]
        }
        export interface MutationResult {
            id:string
            chars:string[]
        }
    }
    export interface ShopContent{
        bank:ShopContent.Bank
        id:string
        goods:ShopContent.Goods[]
        canBattle:boolean
        hasBoss:boolean
        showRefresh:boolean
        refreshCnt:number
        recycleGoods:ShopContent.Goods[]
        recycleCount:number
    }
    export namespace ShopContent{
        export interface Bank{
            cost:number
            open:boolean
            canPut:boolean
            canWithdraw:boolean
            withdraw:number
            withdrawLimit:number
        }
        export interface Goods{
            index:string
            itemId:string
            count:number
            priceId:string
            priceCount:number
            origCost:number
            displayPriceChg:boolean
        }

    }
    export interface SacrificeContent {
        type:number //PlayerRoguelikeSacrificeType
    }
    export interface EndingResult {
        brief:EndingBrief
        record:EndingRecord
    }
    export interface EndingBrief {
        level:number
        success:number
        ending:string
        theme:string
        mode:string
        predefined:string
        band:string
        startTs:number
        endTs:number
        endZoneId:string
        modeGrade:number
    }
    export interface EndingRecord {
        cntZone:number
        relicList:string[]
        capsuleList:string[]
        activeToolList:string[]
        charBuff:string[]
        squadBuff:string[]
        totemList:string[]
        exploreToolList:string[]
        fragmentList:string[]
    }
    export interface AlchemyContent {
        canAlchemy:boolean
    }
    export interface AlchemyRewardContent {
        items:RoguelikeItemBundle[]
        isSSR:boolean
        isFail:boolean
    }
}
export interface RoguelikeBuff {
    key:string
    blackboard:Blackboard
}
export interface RoguelikeItemBundle {
    sub:number
    id: string
    count: number
}
export interface RoguelikeReward {
    index: string
    items: RoguelikeItemBundle[]
    done: boolean
    exDrop: boolean
    exDropSrc: string
}
export interface RoguelikeStageEarn {
    exp: number
    populationMax: number
    squadCapacity: number
    hp: number
    shield: number
    maxHpUp: number
}