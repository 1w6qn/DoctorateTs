import { ItemBundle } from "app/excel/character_table";
import excel from "../../excel/excel";
import EventEmitter from "events";
import { PlayerConsumableItem, PlayerAvatar, PlayerSkins, PlayerStatus } from "../model/playerdata";
import { now } from "@utils/time";
import { PlayerDataManager } from "./PlayerDataManager";

export class InventoryManager {
    items: { [itemId: string]: number }
    skin: PlayerSkins
    consumable:{[key:string]:{[key:string]:PlayerConsumableItem}}
    
    _status:PlayerStatus
    _player: PlayerDataManager
    _trigger: EventEmitter
    constructor(player: PlayerDataManager, _trigger: EventEmitter) {
        this._player = player
        this.items = player._playerdata.inventory
        this.skin = player._playerdata.skin
        this.consumable=player._playerdata.consumable
        this._status=player._playerdata.status
        this._trigger = _trigger
        this._trigger.on("useItems", (items: ItemBundle[]) => items.forEach(item => this._useItem(item)))
        this._trigger.on("gainItems", (items: ItemBundle[]) => items.forEach(item => this._gainItem(item)))
    }
    _useItem(item: ItemBundle): void {
        if (!item.type) {
            item.type = excel.ItemTable.items[item.id].itemType as string
        }
        const funcs: { [key: string]: (item: ItemBundle) => void } = {
            "TKT_GACHA_PRSV": (item: ItemBundle) =>{},
        }
        if(funcs[item.type]){
            funcs[item.type](item)
        }else{
            this._trigger.emit("gainItems",[Object.assign({},item, { count: -item.count })])
        }

    }
    _gainItem(item: ItemBundle): void {
        const info=excel.ItemTable.items[item.id]
        console.log(`[InventoryManager] 获得物品 ${info.name} x ${item.count}`)
        if (!item.type) {
            item.type = excel.ItemTable.items[item.id].itemType as string
        }
        const funcs: { [key: string]: (item: ItemBundle) => void }={
            "NONE":(item:ItemBundle)=>{},
            "CHAR":(item:ItemBundle)=>this._trigger.emit("char:get", item.id),
            "CARD_EXP":(item:ItemBundle)=>this.items[item.id] = (this.items[item.id] || 0) + item.count,
            "MATERIAL":(item:ItemBundle)=>this.items[item.id] = (this.items[item.id] || 0) + item.count,
            "GOLD": (item: ItemBundle) => this._status.gold += item.count,
            "EXP_PLAYER": (item: ItemBundle) => {
                this._status.exp += item.count
                excel.GameDataConst.playerExpMap.slice(this._status.level-1).forEach(exp => {
                    if (this._status.exp >= exp) {
                        this._status.level += 1
                        this._status.exp -= exp
                        this._status.maxAp=excel.GameDataConst.playerApMap[this._status.level-1]
                        this._gainItem({ id: "", type: "AP_GAMEPLAY", count: this._status.maxAp })
                        this._trigger.emit("player:levelup")
                    }
                })
            },
            "TKT_TRY": (item: ItemBundle) => this._status.practiceTicket += item.count,
            "TKT_RECRUIT": (item: ItemBundle) => this._status.recruitLicense += item.count,
            "TKT_INST_FIN": (item: ItemBundle) => this._status.instantFinishTicket += item.count,
            "TKT_GACHA": (item: ItemBundle) => this._status.gachaTicket += item.count,
            "ACTIVITY_COIN":(item:ItemBundle)=>this.items[item.id] = (this.items[item.id] || 0) + item.count,
            "DIAMOND": (item: ItemBundle) => {
                this._status.iosDiamond += item.count
                this._status.androidDiamond += item.count
            },
            "DIAMOND_SHD": (item: ItemBundle) =>this._status.diamondShard += item.count,
            "HGG_SHD": (item: ItemBundle) => this._status.hggShard += item.count,
            "LGG_SHD": (item: ItemBundle) => this._status.lggShard += item.count,
            "FURN": (item: ItemBundle) => {},
            "AP_GAMEPLAY": (item: ItemBundle) => this._status.ap += item.count,
            "AP_BASE":(item:ItemBundle)=>{},
            "SOCIAL_PT":(item:ItemBundle)=>this._status.socialPoint+=item.count,
            "CHAR_SKIN":(item:ItemBundle)=>{
                this.skin.characterSkins[item.id]=1
                this.skin.skinTs[item.id]=now()
            },
            "TKT_GACHA_10": (item: ItemBundle) => this._status.tenGachaTicket += item.count,
            "TKT_GACHA_PRSV": (item: ItemBundle) => this.items[item.id] = (this.items[item.id] || 0) + item.count,
            "AP_ITEM":(item:ItemBundle)=>{},
            "AP_SUPPLY":(item:ItemBundle)=>{},
            "RENAMING_CARD":(item:ItemBundle)=>{},
            "RENAMING_CARD_2":(item:ItemBundle)=>{},
            "ET_STAGE":(item:ItemBundle)=>{},
            "ACTIVITY_ITEM":(item:ItemBundle)=>{},
            "VOUCHER_PICK":(item:ItemBundle)=>{},
            "VOUCHER_CGACHA":(item:ItemBundle)=>{},
            "VOUCHER_MGACHA":(item:ItemBundle)=>{},
            "CRS_SHOP_COIN":(item:ItemBundle)=>{},
            "CRS_RUNE_COIN":(item:ItemBundle)=>{},
            "LMTGS_COIN":(item:ItemBundle)=>{
                if(this.consumable[item.id]["999"]){
                    this.consumable[item.id]["999"].count+=item.count
                }
                else{
                    this.consumable[item.id]["999"]={count:item.count,ts:-1}
                }
            },
            "EPGS_COIN":(item:ItemBundle)=>{},
            "LIMITED_TKT_GACHA_10":(item:ItemBundle)=>{},
            "LIMITED_FREE_GACHA":(item:ItemBundle)=>{},
            "REP_COIN":(item:ItemBundle)=>{},
            "ROGUELIKE":(item:ItemBundle)=>{},
            "LINKAGE_TKT_GACHA_10":(item:ItemBundle)=>{},
            "VOUCHER_ELITE_II_4":(item:ItemBundle)=>{},
            "VOUCHER_ELITE_II_5":(item:ItemBundle)=>{},
            "VOUCHER_ELITE_II_6":(item:ItemBundle)=>{},
            "VOUCHER_SKIN":(item:ItemBundle)=>{},
            "RETRO_COIN":(item:ItemBundle)=>{},
            "PLAYER_AVATAR":(item:ItemBundle)=>{
                this._player.home.avatar.avatar_icon[item.id]={
                    ts:now(),
                    src:"other"
                }
            },
            "UNI_COLLECTION":(item:ItemBundle)=>{},
            "VOUCHER_FULL_POTENTIAL":(item:ItemBundle)=>{},
            "RL_COIN":(item:ItemBundle)=>{},
            "RETURN_CREDIT":(item:ItemBundle)=>{},
            "MEDAL":(item:ItemBundle)=>{},
            "CHARM":(item:ItemBundle)=>{},
            "HOME_BACKGROUND":(item:ItemBundle)=>{
                this._trigger.emit('background:get',item.id)
            },
            "EXTERMINATION_AGENT":(item:ItemBundle)=>{},
            "OPTIONAL_VOUCHER_PICK":(item:ItemBundle)=>{},
            "ACT_CART_COMPONENT":(item:ItemBundle)=>{},
            "VOUCHER_LEVELMAX_6":(item:ItemBundle)=>{},
            "VOUCHER_LEVELMAX_5":(item:ItemBundle)=>{},
            "VOUCHER_LEVELMAX_4":(item:ItemBundle)=>{},
            "VOUCHER_SKILL_SPECIALLEVELMAX_6":(item:ItemBundle)=>{},
            "VOUCHER_SKILL_SPECIALLEVELMAX_5":(item:ItemBundle)=>{},
            "VOUCHER_SKILL_SPECIALLEVELMAX_4":(item:ItemBundle)=>{},
            "ACTIVITY_POTENTIAL":(item:ItemBundle)=>{},
            "ITEM_PACK":(item:ItemBundle)=>{},
            "SANDBOX":(item:ItemBundle)=>{},
            "FAVOR_ADD_ITEM":(item:ItemBundle)=>{},
            "CLASSIC_SHD": (item: ItemBundle) => this._status.classicShard += item.count,
            "CLASSIC_TKT_GACHA": (item: ItemBundle) => this._status.classicGachaTicket += item.count,
            "CLASSIC_TKT_GACHA_10": (item: ItemBundle) => this._status.classicTenGachaTicket += item.count,
            "LIMITED_BUFF":(item:ItemBundle)=>{},
            "CLASSIC_FES_PICK_TIER_5":(item:ItemBundle)=>{},
            "CLASSIC_FES_PICK_TIER_6":(item:ItemBundle)=>{},
            "RETURN_PROGRESS":(item:ItemBundle)=>{},
            "NEW_PROGRESS":(item:ItemBundle)=>{},
            "MCARD_VOUCHER":(item:ItemBundle)=>{},
            "MATERIAL_ISSUE_VOUCHER":(item:ItemBundle)=>{},
            "CRS_SHOP_COIN_V2":(item:ItemBundle)=>{},
            "HOME_THEME":(item:ItemBundle)=>{
                this._trigger.emit('hometheme:get',item.id)
            },
            "SANDBOX_PERM":(item:ItemBundle)=>{},
            "SANDBOX_TOKEN":(item:ItemBundle)=>{},
            "TEMPLATE_TRAP":(item:ItemBundle)=>{},
            "NAME_CARD_SKIN":(item:ItemBundle)=>{},
            "EXCLUSIVE_TKT_GACHA":(item:ItemBundle)=>{},
            "EXCLUSIVE_TKT_GACHA_10":(item:ItemBundle)=>{},
        }
        funcs[item.type](item)
    }

    toJSON() {
        return { 
            inventory: this.items, 
            skin: this.skin,
            consumable:this.consumable,
        }
    }

}