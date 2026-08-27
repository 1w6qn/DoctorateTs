import excel from "@excel/excel";
import { ItemBundle, ItemType } from "@excel/excel";
import { checkBetween, now } from "@utils/time";
import { PlayerDataManager } from "@game/service/PlayerDataManager";
import moment from "moment";
import { OpenServerItemData } from "@excel/excel";
import { TypedEventEmitter } from "@game/service/events";

export class OpenServerManager {
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("refresh:daily", this.dailyRefresh.bind(this));
    this._trigger.on("openserver:chain:login", async ([ts]: [number]) => {
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

  async dailyRefresh([ts]: [number]) {
    await this._player.update(async (draft) => {
      if (draft.openServer.chainLogin.isAvailable) {
        await this._trigger.emit("openserver:chain:login", [ts]);
      }
      if (draft.openServer.checkIn.isAvailable) {
        draft.openServer.checkIn.history.push(1);
      }
    });
  }

  async getChainLogInReward(args: { index: number }): Promise<ItemBundle[]> {
    const { index } = args;
    // 修复：schedule.find(...)! 在开服活动结束后（无匹配时间段）崩溃 → 防御返回空
    const schedule = excel.OpenServerTable.schedule.find((s) =>
      checkBetween(now(), s.startTs, s.endTs),
    );
    if (!schedule) return [];
    const item =
      excel.OpenServerTable.dataMap[schedule.id].chainLoginData[index]?.item;
    if (!item) return [];
    await this._player.update(async (draft) => {
      draft.openServer.chainLogin.history[index] = 0;
    });
    // 修复：奖励入账（原实现只回显不入账 → 领了但不到账，刷新即消失）
    const reward = [excel.makeItem(item.itemId, item.count)];
    await this._trigger.emit("items:get", [reward]);
    return reward;
  }

  async getChainLogInFinalRewards(): Promise<ItemBundle[]> {
    // 修复：同上 schedule 防御
    const schedule = excel.OpenServerTable.schedule.find((s) =>
      checkBetween(now(), s.startTs, s.endTs),
    );
    if (!schedule) return [];
    // 修复：chainLoginData[-1]（最终奖励）可能缺失（当前 schedule 未配置），
    // 直接访问 .item 会抛 TypeError → 500；缺失时返回空奖励。
    const chainData = excel.OpenServerTable.dataMap[schedule.id];
    const finalReward = chainData?.chainLoginData?.[-1];
    if (!finalReward) return [];
    let item!: OpenServerItemData;
    await this._player.update(async (draft) => {
      item = finalReward.item;
      draft.openServer.chainLogin.isAvailable = false;
    });

    if (!item) return [];
    // 修复：奖励入账
    const reward = [excel.makeItem(item.itemId, item.count)];
    await this._trigger.emit("items:get", [reward]);
    return reward;
  }

  async getCheckInReward(args: { index: number }): Promise<ItemBundle[]> {
    const { index } = args;
    // 修复：同上 schedule 防御
    const schedule = excel.OpenServerTable.schedule.find((s) =>
      checkBetween(now(), s.startTs, s.endTs),
    );
    if (!schedule) return [];
    let item!: OpenServerItemData;
    await this._player.update(async (draft) => {
      item = excel.OpenServerTable.dataMap[schedule.id].checkInData[index]?.item;
      draft.openServer.checkIn.history[index] = 0;
      if (
        draft.openServer.checkIn.history.length == 14 &&
        !draft.openServer.checkIn.history.some((n) => n == 1)
      ) {
        draft.openServer.checkIn.isAvailable = false;
      }
    });
    if (!item) return [];
    // 修复：奖励入账
    const reward = [excel.makeItem(item.itemId, item.count)];
    await this._trigger.emit("items:get", [reward]);
    return reward;
  }
}
