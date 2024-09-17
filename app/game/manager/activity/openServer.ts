import EventEmitter from "events";
import {
  OpenServerChainLogin,
  OpenServerCheckIn,
  PlayerOpenServer,
} from "../../model/playerdata";
import excel from "@excel/excel";
import { ItemBundle } from "@excel/character_table";
import { checkBetween, now } from "@utils/time";
import { PlayerDataManager } from "../PlayerDataManager";
import moment from "moment";

export class OpenServerManager implements PlayerOpenServer {
  checkIn: OpenServerCheckIn;
  chainLogin: OpenServerChainLogin;
  _player: PlayerDataManager;
  _trigger: EventEmitter;

  constructor(player: PlayerDataManager, _trigger: EventEmitter) {
    this.checkIn = player._playerdata.openServer.checkIn;
    this.chainLogin = player._playerdata.openServer.chainLogin;
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("refresh:daily", this.dailyRefresh.bind(this));
    this._trigger.on("openserver:chain:login", (ts) => {
      const diff = moment().diff(moment(ts), "days");
      this.chainLogin.nowIndex += 1;
      if (diff <= 1) {
        this.chainLogin.history[this.chainLogin.nowIndex] =
          this.chainLogin.history[this.chainLogin.nowIndex] || 1;
      } else {
        this.chainLogin.nowIndex = 0;
      }
    });
  }

  dailyRefresh(ts: number) {
    if (this.chainLogin.isAvailable) {
      this._trigger.emit("openserver:chain:login", ts);
    }
    if (this.checkIn.isAvailable) {
      this.checkIn.history.push(1);
    }
  }

  async getChainLogInReward(args: { index: number }): Promise<ItemBundle[]> {
    const schedule = excel.OpenServerTable.schedule.find((s) =>
      checkBetween(now(), s.startTs, s.endTs),
    )!.id;
    const item =
      excel.OpenServerTable.dataMap[schedule].chainLoginData[
        this.chainLogin.nowIndex
      ].item;
    const items = [{ id: item.itemId, count: item.count }];
    this.chainLogin.isAvailable = this.chainLogin.history.length == 7;
    return items;
  }

  async getCheckInReward(): Promise<ItemBundle[]> {
    const schedule = excel.OpenServerTable.schedule.find((s) =>
      checkBetween(now(), s.startTs, s.endTs),
    )!.id;
    const item =
      excel.OpenServerTable.dataMap[schedule].checkInData[
        this.checkIn.history.length - 1
      ].item;
    const items = [{ id: item.itemId, count: item.count }];
    this.checkIn.isAvailable = this.checkIn.history.length == 14;
    return items;
  }

  toJSON() {
    return {
      checkIn: this.checkIn,
      chainLogin: this.chainLogin,
    };
  }
}
