import { EventEmitter } from "events";
import { PlayerDataModel } from "../model/playerdata";
import { InventoryManager } from "./InventoryManager";
import { TroopManager } from "./TroopManager";
import { DungeonManager } from "./DungeonManager";
import { HomeManager } from "./HomeManager";
import { StatusManager } from "./StatusManager";
import { CheckInManager } from "./CheckInManager";
import { StoryreviewManager } from "./StoryreviewManager";

export class PlayerDataManager {
    dungeon:DungeonManager
    inventory: InventoryManager
    troop: TroopManager
    status:StatusManager
    home:HomeManager
    checkIn:CheckInManager
    storyreview:StoryreviewManager
    _trigger: EventEmitter
    _playerdata: PlayerDataModel;
    get delta(){
        return {
            playerDataDelta:{
                modified:this,
                deleted:{},
            }
        }
    }
    constructor(playerdata:PlayerDataModel) {
        this._playerdata = playerdata;
        this._trigger = new EventEmitter();

        this.status=new StatusManager(playerdata, this._trigger)
        this.inventory = new InventoryManager(playerdata.inventory,playerdata, this._trigger);
        this.troop=new TroopManager(playerdata.troop, this._trigger)
        this.dungeon=new DungeonManager(playerdata.dungeon, this._trigger)
        this.home=new HomeManager(playerdata, this._trigger)
        this.checkIn=new CheckInManager(playerdata, this._trigger)
        this.storyreview=new StoryreviewManager(playerdata.storyreview, this._trigger)
        
    }
    
    toJSON() {
        return {
            ...this.status.toJSON(),
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
            rlv2:this._playerdata.rlv2,
            deepSea:this._playerdata.deepSea,
            tower:this._playerdata.tower,
            siracusaMap:this._playerdata.siracusaMap,
            sandboxPerm:this._playerdata.sandboxPerm,
            storyreview:this.storyreview,
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
            car:this._playerdata.car,
            recruit:this._playerdata.recruit,
            templateTrap:this._playerdata.templateTrap,
            ...this.checkIn.toJSON(),
            campaignsV2:this._playerdata.campaignsV2,
            checkMeta:this._playerdata.checkMeta,
            limitedBuff:this._playerdata.limitedBuff,
            ...this.home.toJSON()
        }
    }
}