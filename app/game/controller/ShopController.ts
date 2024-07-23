import EventEmitter from "events";
import { PlayerDataModel } from "../model/playerdata";
import { CashGoodList, HighGoodList, LowGoodList, SkinGoodList } from "../model/shop";
import { ItemBundle } from "../../excel/character_table";
export class ShopController {
    lowGoodList!:LowGoodList
    skinGoodList!:SkinGoodList
    cashGoodList!:CashGoodList
    highGoodList!:HighGoodList
    _playerdata:PlayerDataModel;
    _trigger:EventEmitter;
    constructor(_playerdata:PlayerDataModel,_trigger:EventEmitter) {
        this._playerdata = _playerdata;
        this._trigger = _trigger;
        this.initShop()
    }
    buyLowGood(goodId:string,count:number):ItemBundle {
        let good=this.lowGoodList.goodList.find(g=>g.goodId===goodId)
        let item={id:good!.item.id,count:good!.item.count*count}
        this._trigger.emit("useItems",[{id:"4005",count:good!.price*count}])
        this._trigger.emit("gainItems",[item])
        return item
    }
    buySkinGood(goodId:string,count:number):void {
        let good=this.skinGoodList.goodList.find(g=>g.goodId===goodId)
        let item={id:good!.skinId,count:1,type:"CHAR_SKIN"}
        this._trigger.emit("useItems",[{id:"4002",count:good!.price*count}])
        this._trigger.emit("gainItems",[item])
    }
    async initShop():Promise<void> {
        this.lowGoodList={
            groups:[],
            goodList:[],
            shopEndTime:-1,
            newFlag:[]
        }
        this.skinGoodList={
            goodList:[]
        }
        this.cashGoodList={
            goodList:[]
        }
        this.highGoodList={
            goodList:[],
            progressGoodList:{},
            newFlag:[]
        }
    }
    toJSON(){
        return {
            shop:this._playerdata.shop,
            
        }
    }
}
export default ShopController;