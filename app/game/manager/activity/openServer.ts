import EventEmitter from "events";
import excel from "@excel/excel";
import { ItemBundle } from "@excel/character_table";
import { checkBetween, now } from "@utils/time";
import { PlayerDataManager } from "../PlayerDataManager";
import moment from "moment";
import { OpenServerItemData } from "@excel/open_server_table";

export class OpenServerManager {
  _player: PlayerDataManager;
  _trigger: EventEmitter;
  constructor(player: PlayerDataManager, _trigger: EventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("refresh:daily", this.dailyRefresh.bind(this));
    this._trigger.on("openserver:chain:login", async (ts) => {
      const diff = moment().diff(moment(ts), "days");
      await this._player.update(async (draft) => {
        draft.openServer.chainLogin.nowIndex += 1;
        const { nowIndex } = draft.openServer.chainLogin;
        if (diff <= 1 && !draft.openServer.chainLogin.history[nowIndex]) {
          draft.openServer.chainLogin.history[nowIndex] = 1;
        } else {
          draft.openServer.chainLogin.nowIndex = 0;
        }
      });
    });
  }

  async dailyRefresh(ts: number) {
    await this._player.update(async (draft) => {
      if (draft.openServer.chainLogin.isAvailable) {
        this._trigger.emit("openserver:chain:login", ts);
      }
      if (draft.openServer.checkIn.isAvailable) {
        draft.openServer.checkIn.history.push(1);
      }
    });
  }

  async getChainLogInReward(args: { index: number }): Promise<ItemBundle[]> {
    const { index } = args;
    const schedule = excel.OpenServerTable.schedule.find((s) =>
      checkBetween(now(), s.startTs, s.endTs),
    )!.id;
    let item!: OpenServerItemData;
    await this._player.update(async (draft) => {
      item =
        excel.OpenServerTable.dataMap[schedule].chainLoginData[
          draft.openServer.chainLogin.nowIndex
        ].item;
      draft.openServer.chainLogin.isAvailable =
        draft.openServer.chainLogin.history.length == 7;
    });

    return [{ id: item.itemId, count: item.count }];
  }

  async getCheckInReward(): Promise<ItemBundle[]> {
    const schedule = excel.OpenServerTable.schedule.find((s) =>
      checkBetween(now(), s.startTs, s.endTs),
    )!.id;
    let item!: OpenServerItemData;
    await this._player.update(async (draft) => {
      item =
        excel.OpenServerTable.dataMap[schedule].checkInData[
          draft.openServer.checkIn.history.length - 1
        ].item;
      draft.openServer.checkIn.isAvailable =
        draft.openServer.checkIn.history.length == 14;
    });
    return [{ id: item.itemId, count: item.count }];
  }
}
