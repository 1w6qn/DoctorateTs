import EventEmitter from "events";
import { PlayerDataModel } from "../model/playerdata";

export class ShopController {
    _playerdata:PlayerDataModel;
    _trigger:EventEmitter;
    get lowGoodList(){
        return
    }
    constructor(_playerdata:PlayerDataModel,_trigger:EventEmitter) {
        this._playerdata = _playerdata;
        this._trigger = _trigger;
    }
}
export default ShopController;