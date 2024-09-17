import EventEmitter from "events";
import {
  NameCardMisc,
  PlayerCollection,
  PlayerNameCardStyle,
  PlayerStatus,
} from "../model/playerdata";
import excel from "@excel/excel";
import { checkNewDay, checkNewMonth, checkNewWeek, now } from "@utils/time";
import moment from "moment";
import { AvatarInfo } from "@game/model/character";
import { PlayerDataManager } from "./PlayerDataManager";

export class StatusManager {
  status: PlayerStatus;
  collectionReward: PlayerCollection;
  nameCardStyle: PlayerNameCardStyle;
  _player: PlayerDataManager;
  _trigger: EventEmitter;

  constructor(player: PlayerDataManager, _trigger: EventEmitter) {
    this.status = player._playerdata.status;
    this.collectionReward = player._playerdata.collectionReward;
    this.nameCardStyle = player._playerdata.nameCardStyle;
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("status:refresh:time", this.refreshTime.bind(this));
    this._trigger.on("refresh:daily", this.dailyRefresh.bind(this));
    this._trigger.on("refresh:weekly", this.weeklyRefresh.bind(this));
    this._trigger.on("refresh:monthly", this.monthlyRefresh.bind(this));
  }

  get uid(): string {
    return this.status.uid;
  }

  refreshTime() {
    const ts = now();
    if (checkNewDay(this.status.lastRefreshTs, ts)) {
      this._trigger.emit("refresh:daily", this.status.lastRefreshTs);
    }
    if (moment().date() == 1 && checkNewMonth(this.status.lastRefreshTs, ts)) {
      this._trigger.emit("refresh:monthly");
    }
    if (moment().day() == 1 && checkNewWeek(this.status.lastRefreshTs, ts)) {
      this._trigger.emit("refresh:weekly");
    }
    this.status.lastRefreshTs = ts;
    this.status.lastOnlineTs = ts;
  }

  dailyRefresh() {}

  weeklyRefresh() {}

  monthlyRefresh() {}

  changeSecretary(args: { charInstId: number; skinId: string }) {
    this.status.secretary = this._player.troop.getCharacterByInstId(
      args.charInstId,
    ).charId;
    this.status.secretarySkinId = args.skinId;
  }

  finishStory(args: { storyId: string }) {
    this.status.flags[args.storyId] = 1;
  }

  changeAvatar(args: { avatar: AvatarInfo }) {
    this.status.avatar = args.avatar;
  }

  changeResume(args: { resume: string }) {
    this.status.resume = args.resume;
  }

  bindNickName(args: { nickname: string }) {
    this.status.nickName = args.nickname;
  }

  buyAp() {
    this._trigger.emit("gainItems", [
      { id: "", type: "AP_GAMEPLAY", count: this.status.maxAp },
    ]);
    this._trigger.emit("useItems", [{ id: "", type: "DIAMOND", count: 1 }]);
  }

  exchangeDiamondShard(args: { count: number }) {
    this._trigger.emit("useItems", [
      { id: "", type: "DIAMOND", count: args.count },
    ]);
    this._trigger.emit("gainItems", [
      {
        id: "",
        type: "DIAMOND_SHD",
        count: args.count * excel.GameDataConst.diamondToShdRate,
      },
    ]);
  }

  receiveTeamCollectionReward(args: { rewardId: string }) {
    this.collectionReward.team[args.rewardId] = 1;
    this._trigger.emit("gainItems", [
      excel.HandbookInfoTable.teamMissionList[args.rewardId].item,
    ]);
  }

  getOtherPlayerNameCard(args: { uid: string }) {
    //TODO
  }

  editNameCard(args: {
    flag: number;
    content: { skinId?: string; component?: string[]; misc?: NameCardMisc };
  }) {
    switch (args.flag) {
      case 1:
        this.nameCardStyle.componentOrder = args.content.component!;
        break;
      case 2:
        this.nameCardStyle.skin.selected = args.content.skinId!;
        break;
      case 4:
        this.nameCardStyle.misc = args.content.misc!;
        break;
      default:
        break;
    }
  }

  toJSON() {
    return {
      status: this.status,
      collectionReward: this.collectionReward,
      nameCardStyle: this.nameCardStyle,
    };
  }
}
