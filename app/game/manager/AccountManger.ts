import { PlayerDataModel } from "../model/playerdata";
import { PlayerDataManager } from "./PlayerDataManager";
import { readJson } from "@utils/file";
import { writeFile } from "fs/promises";
import { EventEmitter } from "events";
import { TypedEventEmitter } from "@game/model/events";

export class AccountManager {
  data!: { [key: string]: PlayerDataManager };
  configs!: { [key: string]: UserConfig };
  _trigger!: TypedEventEmitter;

  constructor() {}

  async init() {
    console.time("[AccountManager][loaded]");
    this.configs = await readJson(`./data/user/users.json`);
    this.data = {};
    this._trigger = new EventEmitter();
    this._trigger.on("save", async () => {
      await this.saveUserConfig();
    });
    for (const uid in this.configs) {
      this.data[uid] = new PlayerDataManager(
        await readJson<PlayerDataModel>(`./data/user/databases/${uid}.json`),
      );
      this.data[uid]._playerdata.status.uid = uid;
      this.data[uid]._trigger.on("save", async () => {
        await this.savePlayerData(uid);
        await this.saveUserConfig();
      });
    }
    console.timeEnd("[AccountManager][loaded]");
    console.log(
      `[AccountManager] ${Object.keys(this.configs).length} users loaded.`,
    );
  }

  getBattleReplay(uid: string, stageId: string): string {
    return this.configs[uid]?.battle.replays[stageId] || "";
  }

  saveBattleReplay(uid: string, stageId: string, replay: string): void {
    this.configs[uid]!.battle.replays[stageId] = replay;
    this._trigger.emit("save");
  }

  async getUserConfig(uid: string): Promise<UserConfig> {
    return this.configs[uid]!;
  }

  async saveUserConfig(): Promise<void> {
    await writeFile(
      `./data/user/users.json`,
      JSON.stringify(this.configs, null, 4),
    );
  }

  getBattleInfo(uid: string, battleId: string): BattleInfo | undefined {
    return this.configs[uid]?.battle.infos[battleId];
  }

  saveBattleInfo(uid: string, battleId: string, info: BattleInfo): void {
    this.configs[uid]!.battle.infos[battleId] = info;
    this._trigger.emit("save");
  }

  async getPlayerData(uid: string): Promise<PlayerDataManager> {
    return this.data[uid];
  }

  async getPlayerFriendInfo(uid: string) {
    return (await this.getPlayerData(uid)).socialInfo;
  }

  async savePlayerData(uid: string): Promise<void> {
    await writeFile(
      `./data/user/databases/${uid}.json`,
      JSON.stringify(this.data[uid], null, 4),
    );
  }

  getBeforeNonHitCnt(uid: string, gachaType: string): number {
    return this.configs[uid]!.gacha[gachaType].beforeNonHitCnt;
  }

  saveBeforeNonHitCnt(uid: string, gachaType: string, cnt: number): void {
    this.configs[uid]!.gacha[gachaType].beforeNonHitCnt = cnt;
    this._trigger.emit("save");
  }

  getSocial(uid: string): { friends: string[] } {
    return this.configs[uid]!.social;
  }

  deleteFriend(uid: string, friendUid: string): void {
    const social = this.configs[uid]!.social;
    social.friends.splice(social.friends.indexOf(friendUid), 1);
    this._trigger.emit("save");
  }

  addFriend(uid: string, friendUid: string): void {
    this.configs[uid]!.social.friends.push(friendUid);
    this._trigger.emit("save");
  }

  sendFriendRequest(from: string, to: string): void {
    this.configs[to]!.social.friendRequests.push(from);
    this._trigger.emit("save");
  }

  deleteFriendRequest(uid: string, friendId: string): void {
    const social = this.configs[uid]!.social;
    social.friendRequests.splice(social.friendRequests.indexOf(friendId), 1);
    this._trigger.emit("save");
  }

  async getFriendRequests(uid: string): Promise<string[]> {
    return this.configs[uid]!.social.friendRequests;
  }

  async searchPlayer(keyword: string): Promise<string[]> {
    return Object.entries(this.data)
      .filter(([uid, data]) => {
        return uid == keyword || data.socialInfo.nickName == keyword;
      })
      .map(([uid]) => uid);
  }

  async tokenByPhonePassword(phone: string, password: string): Promise<string> {
    const uid =
      Object.entries(this.configs).find(([, conf]) => {
        return conf.auth.phone == phone && conf.password == password;
      })?.[0] ?? "";
    return this.getTokenByUid(uid);
  }

  async getTokenByUid(uid: string): Promise<string> {
    return uid;
  }

  async getUidByToken(token: string): Promise<string> {
    return token;
  }

  async loginout() {}
}

export interface FriendSortViewModel {
  uid: string;
  level: number;
  infoShare?: number;
  infoShareVisited?: number;
  recentVisited?: number;
}
export interface UserConfig {
  uid: string;
  password: string;
  auth: {
    hgId: string;
    phone: string;
    email: string;
    identityNum: string;
    identityName: string;
    isMinor: false;
    isLatestUserAgreement: true;
  };
  social: {
    friends: string[];
    friendRequests: string[];
    visited: string[];
  };
  battle: {
    stageId: string;
    replays: { [key: string]: string };
    infos: { [key: string]: BattleInfo };
  };
  gacha: {
    [key: string]: {
      beforeNonHitCnt: number;
    };
  };
  rlv2: object;
}
export interface BattleInfo {
  stageId: string;
}
export const accountManager = new AccountManager();
