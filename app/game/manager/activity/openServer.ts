import EventEmitter from "events";
import { PlayerOpenServer, OpenServerChainLogin, OpenServerCheckIn } from '../../model/playerdata';
import excel from "@excel/excel";
import { ItemBundle } from "@excel/character_table";
import { now } from "@utils/time";
import { PlayerDataManager } from "../PlayerDataManager";
import moment from "moment";

export class CheckInManager implements PlayerOpenServer {

    checkIn: OpenServerCheckIn;
    chainLogin: OpenServerChainLogin;
    _player: PlayerDataManager;
    _trigger: EventEmitter;
    constructor(player: PlayerDataManager, _trigger: EventEmitter) {
        this.checkIn = player._playerdata.openServer.checkIn;
        this.chainLogin = player._playerdata.openServer.chainLogin;
        this._player = player;
        this._trigger = _trigger;
        this._trigger.on("refresh:daily", this.dailyRefresh.bind(this))

    }


    dailyRefresh(ts: number) {
        const diff=moment().diff(moment(ts), 'days')
        if(diff<=1&&this.chainLogin.isAvailable){
            this.chainLogin.history.push(1)
            this.chainLogin.nowIndex+=1
            
        }
        if(this.checkIn.isAvailable){
            this.checkIn.history.push(1)
            
        }
    }
    getChainLogInReward(index: number): ItemBundle[] {
        this.chainLogin.isAvailable=this.chainLogin.history.length==7
        return []
    }
    getCheckInReward(): ItemBundle[] {
        this.checkIn.isAvailable=this.checkIn.history.length==14
        return []
    }
    toJSON() {
        return {
            checkIn: this.checkIn,
            chainLogin: this.chainLogin
        }
    }
}