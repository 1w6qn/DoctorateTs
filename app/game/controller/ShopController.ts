import EventEmitter from "events";
import { PlayerDataModel } from "../model/playerdata";
import { LowGoodList } from "../model/shop";
export class ShopController {
    lowGoodList!:LowGoodList
    _playerdata:PlayerDataModel;
    _trigger:EventEmitter;
    constructor(_playerdata:PlayerDataModel,_trigger:EventEmitter) {
        this._playerdata = _playerdata;
        this._trigger = _trigger;
        this.initShop()
    }
    async initShop():Promise<void> {
        this.lowGoodList={
            groups:[],
            goodList:[],
            shopEndTime:-1,
            newFlag:[]
        }
    }
}
export default ShopController;