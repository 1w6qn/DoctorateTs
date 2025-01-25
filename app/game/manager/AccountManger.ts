import { PlayerDataModel } from "../model/playerdata";
import { PlayerDataManager } from "./PlayerDataManager";
import { readJson } from "@utils/file";
import { writeFile } from "fs/promises";
import { TypedEventEmitter } from "@game/model/events";
import Emittery from "emittery";

export class AccountManager {
  data!: { [key: string]: PlayerDataManager };
  configs!: { [key: string]: UserConfig };
  _trigger!: TypedEventEmitter;

  constructor() {}

  async init() {
    console.time("[AccountManager][loaded]");
    this.configs = await readJson(`./data/user/users.json`);
    this.data = {};
    this._trigger = new Emittery();
    this._trigger.on("save", async () => {
      await this.saveUserConfig();
    });
    for (const uid in this.configs) {
      this.data[uid] = new PlayerDataManager(
        await readJson<PlayerDataModel>(`./data/user/databases/${uid}.json`),
      );
      this.data[uid]._playerdata.status.uid = uid;
      this.data[uid]._trigger.on("save", async () => {
        console.log(`[AccountManager][save] ${uid}`);
        await this.savePlayerData(uid);
        await this.saveUserConfig();
      });
    }
    console.timeEnd("[AccountManager][loaded]");
    console.log(
      `[AccountManager] ${Object.keys(this.configs).length} users loaded.`,
    );
  }

  async getBattleReplay(uid: string, stageId: string): Promise<string> {
    return this.configs[uid]?.battle.replays[stageId] || "";
  }

  async saveBattleReplay(
    uid: string,
    stageId: string,
    replay: string,
  ): Promise<void> {
    this.configs[uid]!.battle.replays[stageId] = replay;
    await this._trigger.emit("save", []);
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

  async saveBattleInfo(
    uid: string,
    battleId: string,
    info: BattleInfo,
  ): Promise<void> {
    this.configs[uid]!.battle.infos[battleId] = info;
    await this._trigger.emit("save", []);
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

  async saveBeforeNonHitCnt(
    uid: string,
    gachaType: string,
    cnt: number,
  ): Promise<void> {
    this.configs[uid]!.gacha[gachaType].beforeNonHitCnt = cnt;
    await this._trigger.emit("save", []);
  }

  async getSocial(uid: string): Promise<{
    friends: { uid: string; alias: string }[];
    friendRequests: string[];
    visited: string[];
  }> {
    return this.configs[uid]!.social;
  }

  async deleteFriend(uid: string, friendUid: string): Promise<void> {
    const social = this.configs[uid]!.social;
    const friend = social.friends.find((f) => f.uid == friendUid)!;
    social.friends.splice(social.friends.indexOf(friend), 1);
    await this._trigger.emit("save", []);
  }

  async addFriend(uid: string, friendUid: string): Promise<void> {
    this.configs[uid]!.social.friends.push({ uid: friendUid, alias: "" });
    await this._trigger.emit("save", []);
  }

  async sendFriendRequest(from: string, to: string): Promise<void> {
    this.configs[to]!.social.friendRequests.push(from);
    const friendData = await this.getPlayerData(to);
    await friendData.update(async (draft) => {
      draft.pushFlags.hasFriendRequest = 1;
    });
    await this._trigger.emit("save", []);
  }

  async deleteFriendRequest(uid: string, friendId: string): Promise<void> {
    const social = this.configs[uid]!.social;
    social.friendRequests.splice(social.friendRequests.indexOf(friendId), 1);
    await this._trigger.emit("save", []);
  }

  async setFriendAlias(
    uid: string,
    friendId: string,
    alias: string,
  ): Promise<void> {
    const social = this.configs[uid]!.social;
    social.friends.find((f) => f.uid == friendId)!.alias = alias;
    await this._trigger.emit("save", []);
  }
  async getFriendRequests(uid: string): Promise<string[]> {
    return this.configs[uid]!.social.friendRequests;
  }

  async searchPlayer(keyword: string): Promise<string[]> {
    return Object.entries(this.data)
      .filter(([uid, data]) => {
        return (
          keyword.includes(uid) ||
          data.socialInfo.nickName == keyword ||
          data.socialInfo.nickName + "#" + data.socialInfo.nickNumber == keyword
        );
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
    friends: { uid: string; alias: string }[];
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
