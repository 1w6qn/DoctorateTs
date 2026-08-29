import excel from "@excel/excel";
import { checkNew, now } from "@utils/time";
import moment from "moment";
import { AvatarInfo } from "../../kernel/model";
import { PlayerDataManager } from "../../kernel/PlayerDataManager";
import { TypedEventEmitter } from "../../kernel/events/runtime";
import { Draft } from "mutative";
import { PlayerDataModel } from "../../kernel/playerdata";
import { logger } from "@utils/logger";

export class StatusManager {
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("status:refresh:time", this.refreshTime.bind(this));
    this._trigger.on("refresh:daily", this.dailyRefresh.bind(this));
    this._trigger.on("refresh:weekly", this.weeklyRefresh.bind(this));
    this._trigger.on("refresh:monthly", this.monthlyRefresh.bind(this));
  }

  get uid(): string {
    return this._player._playerdata.status.uid;
  }
  async refreshTime() {
    // 先读取跨天判断所需的时间戳，再触发刷新事件
    // 注意：不能在 Immer recipe 内 emit（嵌套 update 会被外层 finishDraft 覆盖丢失）
    const ts = now();
    const lastRefreshTs = this._player._playerdata.status.lastRefreshTs;
    if (checkNew(lastRefreshTs, ts, "day")) {
      logger.info("StatusManager", "daily refresh");
      await this._trigger.emit("refresh:daily", [lastRefreshTs]);
    }
    if (moment().day() == 1 && checkNew(lastRefreshTs, ts, "week")) {
      logger.info("StatusManager", "weekly refresh");
      await this._trigger.emit("refresh:weekly", []);
    }
    if (moment().date() == 1 && checkNew(lastRefreshTs, ts, "month")) {
      logger.info("StatusManager", "monthly refresh");
      await this._trigger.emit("refresh:monthly", []);
    }
    await this._player.update(async (draft) => {
      draft.status.lastRefreshTs = ts;
      draft.status.lastOnlineTs = ts;
    });
  }

  /**
   * 每日刷新：恢复体力并重置每日购买次数
   */
  async dailyRefresh() {
    await this._player.update(async (draft) => {
      this._refreshAp(draft);
      draft.status.buyApRemainTimes = 10;
    });
  }

  /**
   * 每周刷新（委托 dailyRefresh：跨周必然跨日，执行体力恢复与购买次数重置）
   */
  async weeklyRefresh() {
    return this.dailyRefresh();
  }

  /**
   * 每月刷新（委托 dailyRefresh：跨月必然跨日，执行体力恢复与购买次数重置）
   */
  async monthlyRefresh() {
    return this.dailyRefresh();
  }

  /**
   * 内部方法：按时间恢复体力
   * 每 6 分钟恢复 1 点（与 inventory AP_GAMEPLAY 逻辑一致），上限 maxAp
   * @param draft - Immer 可写草稿
   */
  private _refreshAp(draft: Draft<PlayerDataModel>) {
    const addAp = Math.floor((now() - draft.status.lastApAddTime) / 360);
    if (draft.status.ap < draft.status.maxAp) {
      draft.status.ap = Math.min(
        draft.status.ap + Math.max(addAp, 0),
        draft.status.maxAp,
      );
    }
    draft.status.lastApAddTime = now();
  }

  async changeSecretary(args: { charInstId: number; skinId: string }) {
    const { charInstId, skinId } = args;
    await this._player.update(async (draft) => {
      // 修复：非法 charInstId（已删干员/乱传）不 500
      const char = draft.troop.chars[charInstId];
      if (!char) return;
      draft.status.secretary = char.charId;
      draft.status.secretarySkinId = skinId;
    });
  }

  async finishStory(args: { storyId: string }) {
    const { storyId } = args;
    await this._player.update(async (draft) => {
      draft.status.flags[storyId] = 1;
    });
  }

  async changeAvatar(args: { avatar: AvatarInfo }) {
    const { avatar } = args;
    await this._player.update(async (draft) => {
      draft.status.avatar = avatar;
    });
  }

  async changeResume(args: { resume: string }) {
    const { resume } = args;
    await this._player.update(async (draft) => {
      draft.status.resume = resume;
    });
  }

  async bindNickName(args: { nickname: string }) {
    const { nickname } = args;
    await this._player.update(async (draft) => {
      draft.status.nickName = nickname;
    });
  }

  /**
   * 购买理智
   * 每日次数（dailyRefresh 重置为 10）扣减；消耗 1 源石、发放 135 点理智（gainItem 管道）。
   * @returns 是否成功（false = 当日额度耗尽）
   */
  async buyAp(): Promise<boolean> {
    const allowed = await this._player.update(async (draft) => {
      // 旧存档缺失字段视为当日额度未用（dailyRefresh 每日重置为 10）
      if ((draft.status.buyApRemainTimes ?? 10) <= 0) return false;
      draft.status.buyApRemainTimes -= 1;
      return true;
    });
    if (!allowed) return false;
    await this._player.gainItem.setTarget("", "DIAMOND", 1).use();
    await this._player.gainItem.setTarget("", "AP_GAMEPLAY", 135).handle();
    return true;
  }

  /**
   * 兑换源石碎片（1 源石 → diamondToShdRate 碎片，gainItem 管道）
   * @param args.count - 兑换次数（路由层已校验正整数）
   */
  async exchangeDiamondShard(args: { count: number }) {
    const { count } = args;
    await this._player.gainItem
      .setTarget("", "DIAMOND_SHD", count * excel.GameDataConst.diamondToShdRate)
      .handle();
    await this._player.gainItem.setTarget("", "DIAMOND", count).use();
  }

  async receiveTeamCollectionReward(args: { rewardId: string }) {
    const { rewardId } = args;
    const teamMission = excel.HandbookInfoTable.teamMissionList[rewardId];
    // 防御：未知奖励 id 不 500
    if (!teamMission?.item) return;
    let claimed = false;
    await this._player.update(async (draft) => {
      // 修复：已领取过的不再发放（原实现无幂等 → 可无限刷该奖励）
      if (draft.collectionReward.team[rewardId]) {
        claimed = true;
        return;
      }
      draft.collectionReward.team[rewardId] = 1;
    });
    if (claimed) return;
    await this._trigger.emit("items:get", [[teamMission.item]]);
  }
}
