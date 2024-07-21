import { EventEmitter } from "events";
import { PlayerDataModel, PlayerStatus } from "../model/playerdata";
import { InventoryManager } from "./InventoryManager";
import { TroopManager } from "./TroopManager";
import { DungeonManager } from "./DungeonManager";

export class PlayerDataManager {
    dungeon:DungeonManager
    inventory: InventoryManager
    troop: TroopManager
    status:PlayerStatus
    _trigger: EventEmitter
    _playerdata: PlayerDataModel;
    constructor(playerdata:PlayerDataModel) {
        this._playerdata = playerdata;
        this._trigger = new EventEmitter();

        this.status=playerdata.status

        this.inventory = new InventoryManager(playerdata.inventory, this._trigger);
        this.troop=new TroopManager(playerdata.troop, this._trigger)
        this.dungeon=new DungeonManager(playerdata.dungeon, this._trigger)

        this._trigger.on("status:refresh",this._refreshStatus.bind(this))
        this._trigger.on("status:refresh:time",this.refreshTime.bind(this))
    }
    refreshTime(){
        let ts=parseInt((new Date().getTime()/1000).toString())
        this.status.lastRefreshTs=ts
        this.status.lastApAddTime=ts
        this.status.lastOnlineTs=ts
    }
    _refreshStatus() {
        this.status.gold=this.inventory.items["4001"]
        this.status.diamondShard=this.inventory.items["4003"]
        this.status.exp=this.inventory.items["5001"]
        this.status.socialPoint=this.inventory.items["SOCIAL_PT"]
        this.status.gachaTicket=this.inventory.items["7003"]
        this.status.tenGachaTicket=this.inventory.items["7004"]
        this.status.instantFinishTicket=this.inventory.items["7002"]
        this.status.recruitLicense=this.inventory.items["7001"]
        this.status.ap=this.inventory.items["AP_GAMEPLAY"]
        this.status.iosDiamond=this.inventory.items["4002"]
        this.status.androidDiamond=this.inventory.items["4002"]
        this.status.practiceTicket=this.inventory.items["6001"]
        this.status.hggShard=this.inventory.items["4004"]
        this.status.lggShard=this.inventory.items["4005"]
        this.status.classicShard=this.inventory.items["classic_normal_ticket"]
        this.status.classicGachaTicket=this.inventory.items["classic_gacha"]
        this.status.classicTenGachaTicket=this.inventory.items["classic_gacha_10"]
    }
    toJSON() {
        return {
            status:this.status,
            inventory: this.inventory,
            troop:this.troop,
            dungeon:this.dungeon,
            activity:this._playerdata.activity,
            npcAudio:this._playerdata.npcAudio,
            pushFlags:this._playerdata.pushFlags,
            equipment:{},
            skin:this._playerdata.skin,
            shop:this._playerdata.shop,
            mission:this._playerdata.mission,
            social:this._playerdata.social,
            building:this._playerdata.building,
            dexNav:this._playerdata.dexNav,
            crisis:this._playerdata.crisis,
            crisisV2:this._playerdata.crisisV2,
            nameCardStyle:this._playerdata.nameCardStyle,
            tshop:this._playerdata.tshop,
            gacha:this._playerdata.gacha,
            backflow:this._playerdata.backflow,
            mainline:this._playerdata.mainline,
            avatar:this._playerdata.avatar,
            homeTheme:this._playerdata.homeTheme,
            rlv2:this._playerdata.rlv2,
            deepSea:this._playerdata.deepSea,
            tower:this._playerdata.tower,
            siracusaMap:this._playerdata.siracusaMap,
            sandboxPerm:this._playerdata.sandboxPerm,
            storyreview:this._playerdata.storyreview,
            medal:this._playerdata.medal,
            event:this._playerdata.event,
            retro:this._playerdata.retro,
            share:this._playerdata.share,
            roguelike:this._playerdata.roguelike,
            ticket:this._playerdata.ticket,
            aprilFool:this._playerdata.aprilFool,
            consumable:this._playerdata.consumable,
            charm:this._playerdata.charm,
            carousel:this._playerdata.carousel,
            openServer:this._playerdata.openServer,
            car:this._playerdata.car,
            recruit:this._playerdata.recruit,
            templateTrap:this._playerdata.templateTrap,
            checkIn:this._playerdata.checkIn,
            campaignsV2:this._playerdata.campaignsV2,
            setting:this._playerdata.setting,
            checkMeta:this._playerdata.checkMeta,
            limitedBuff:this._playerdata.limitedBuff,
            collectionReward:this._playerdata.collectionReward,
        }
    }
}