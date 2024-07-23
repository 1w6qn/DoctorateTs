import EventEmitter from "events";
import { PlayerDataModel, PlayerDataShop } from "../model/playerdata";
import { CashGoodList, HighGoodList, LowGoodList, SkinGoodList, REPGoodList, LMTGSGoodList, EPGSGoodList, ClassicGoodList, ExtraGoodList } from '../model/shop';
import { ItemBundle } from "../../excel/character_table";
export class ShopController {
    shop:PlayerDataShop
    lowGoodList!:LowGoodList
    skinGoodList!:SkinGoodList
    cashGoodList!:CashGoodList
    highGoodList!:HighGoodList
    REPGoodList!: REPGoodList;
    LMTGSGoodList!: LMTGSGoodList;
    EPGSGoodList!: EPGSGoodList;
    classicGoodList!: ClassicGoodList;
    extraGoodList!: ExtraGoodList;
    _playerdata:PlayerDataModel;
    _trigger:EventEmitter;
    constructor(_playerdata:PlayerDataModel,_trigger:EventEmitter) {
        this.shop = _playerdata.shop
        this._playerdata = _playerdata;
        this._trigger = _trigger;
        this._trigger.on("refresh:monthly",this.monthlyRefresh.bind(this))
        this._trigger.on("refresh:daily",this.dailyRefresh.bind(this))
        this.initShop()
    }
    dailyRefresh() {
        
    }
    monthlyRefresh() {
        //LS refresh
        let ts=new Date()
        let monthnum=ts.getMonth()-5+(ts.getFullYear()-2019)*12
        this.shop.LS.curShopId=`lggShdShopnumber${monthnum}`
        this.shop.LS.curGroupId=`lggShdGroupnumber${monthnum}_Group_1`
        this.shop.LS.info=[]
        //
    }
    buyLowGood(goodId:string,count:number):ItemBundle[] {
        let good=this.lowGoodList.goodList.find(g=>g.goodId===goodId)
        let item={id:good!.item.id,count:good!.item.count*count}
        if(this.shop.LS.info.some(i=>i.id===good!.goodId)){
            this.shop.LS.info.find(i=>i.id===good!.goodId)!.count+=count
        }else{
            this.shop.LS.info.push({id:good!.goodId,count:count})
        }
        this._trigger.emit("useItems",[{id:"4005",count:good!.price*count}])
        this._trigger.emit("gainItems",[item])
        return [item]
    }
    buyHighGood(goodId:string,count:number):ItemBundle {
        let good=this.lowGoodList.goodList.find(g=>g.goodId===goodId)
        let item={id:good!.item.id,count:good!.item.count*count}
        if(this.shop.LS.info.some(i=>i.id===good!.goodId)){
            this.shop.LS.info.find(i=>i.id===good!.goodId)!.count+=count
        }else{
            this.shop.LS.info.push({id:good!.goodId,count:count})
        }
        this._trigger.emit("useItems",[{id:"4005",count:good!.price*count}])
        this._trigger.emit("gainItems",[item])
        return item
    }
    buySkinGood(goodId:string):void {
        let good=this.skinGoodList.goodList.find(g=>g.goodId===goodId)
        let item={id:good!.skinId,count:1,type:"CHAR_SKIN"}
        this._trigger.emit("useItems",[{id:"4002",count:good!.price}])
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
        this.extraGoodList={
            goodList:[],
            lastClick:-1,
            newFlag:[]
        }
        this.REPGoodList={
            goodList:[],
            newFlag:[]
        }
        this.EPGSGoodList={
            goodList:[],
            newFlag:[]
        }
        this.LMTGSGoodList={
            goodList:[],
            newFlag:[]
        }
        this.classicGoodList={
            goodList:[],
            newFlag:[],
            progressGoodList:{}
        }
    }
    toJSON(){
        return {
            shop:this.shop,
            
        }
    }
}
export default ShopController;