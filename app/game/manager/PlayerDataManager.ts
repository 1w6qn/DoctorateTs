import { EventEmitter } from "events";
import { PlayerDataModel } from "../model/playerdata";
import { InventoryManager } from "./inventory";
import { TroopManager } from "./troop";
import { DungeonManager } from "./dungeon";
import { HomeManager } from "./home";
import { StatusManager } from "./status";
import { CheckInManager } from "./checkin";
import { StoryreviewManager } from "./storyreview";
import { MissionManager } from "./mission";
import ShopController from "../controller/shop";
import { RecruitManager } from "./recruit";
import { RoguelikeV2Controller } from "../controller/rlv2";
import { BattleManager } from "./battle";
import { GachaController } from "../controller/GachaController";
import { accountManager, BattleInfo } from "./AccountManger";
import { SocialManager } from "./social";
import { DexNavManager } from "./dexnav";
import { BuildingManager } from "./building";
import { FriendDataWithNameCard } from "@game/model/social";
import { OpenServerManager } from "@game/manager/activity/openServer";
import { createDraft, finishDraft, Patch } from "immer";
import { patchesToObject } from "@utils/delta";

export class PlayerDataManager {
  dungeon: DungeonManager;
  inventory: InventoryManager;
  troop: TroopManager;
  status: StatusManager;
  home: HomeManager;
  checkIn: CheckInManager;
  storyreview: StoryreviewManager;
  mission!: MissionManager;
  shop: ShopController;
  recruit: RecruitManager;
  rlv2: RoguelikeV2Controller;
  gacha: GachaController;
  social: SocialManager;
  dexNav: DexNavManager;
  building: BuildingManager;
  openServer: OpenServerManager;
  battle!: BattleManager;
  _trigger: EventEmitter;
  _playerdata: PlayerDataModel;
  _changes: Patch[][];
  _inverseChanges: Patch[][];
  constructor(playerdata: PlayerDataModel) {
    this._playerdata = playerdata;
    this._changes = [];
    this._inverseChanges = [];
    this._trigger = new EventEmitter();
    this._trigger.setMaxListeners(10000);
    this.status = new StatusManager(this, this._trigger);
    this.inventory = new InventoryManager(this, this._trigger);
    this.troop = new TroopManager(this, this._trigger);
    this.dungeon = new DungeonManager(this, this._trigger);
    this.home = new HomeManager(this, this._trigger);
    this.checkIn = new CheckInManager(this, this._trigger);
    this.storyreview = new StoryreviewManager(this, this._trigger);
    this.mission = new MissionManager(playerdata, this._trigger);
    this.shop = new ShopController(this, this._trigger);
    this.battle = new BattleManager(this._playerdata, this._trigger);
    this.recruit = new RecruitManager(this, this.troop, this._trigger);
    this.rlv2 = new RoguelikeV2Controller(this, this._trigger);
    this.social = new SocialManager(this, this._trigger);
    this.gacha = new GachaController(this, this._trigger);
    this.dexNav = new DexNavManager(this, this._trigger);
    this.building = new BuildingManager(this, this._trigger);
    this.openServer = new OpenServerManager(this, this._trigger);
    this._trigger.emit("game:fix");
    this._trigger.emit(
      "save:battle",
      async (battleId: string, info: BattleInfo) => {
        accountManager.saveBattleInfo(this.uid, battleId, info);
      },
    );
  }

  get delta() {
    const delta = patchesToObject(
      this._changes.reduce((pre, acc) => acc.concat(pre), []),
    );
    this._changes = [];
    return {
      playerDataDelta: delta,
    };
  }

  get uid() {
    return this._playerdata.status.uid;
  }

  get loginTime() {
    return this._playerdata.pushFlags.status;
  }

  get socialInfo(): FriendDataWithNameCard {
    return {
      nickName: this._playerdata.status.nickName,
      nickNumber: this._playerdata.status.nickNumber,
      uid: this.uid,
      serverName: this._playerdata.status.serverName,
      level: this._playerdata.status.level,
      avatar: this._playerdata.status.avatar,
      assistCharList: [],
      lastOnlineTime: this._playerdata.status.lastOnlineTs,
      board: this.building.boardInfo,
      infoShare: this.building.infoShare,
      recentVisited: 0,
      skin: this._playerdata.nameCardStyle.skin,
      registerTs: this._playerdata.status.registerTs,
      mainStageProgress: this._playerdata.status.mainStageProgress,
      charCnt: this.troop.curCharInstId - 1,
      furnCnt: this.building.furnCnt,
      skinCnt: this.inventory.skinCnt,
      secretary: this._playerdata.status.secretary,
      secretarySkinId: this._playerdata.status.secretarySkinId,
      resume: this._playerdata.status.resume,
      teamV2: this.dexNav.teamV2Info,
      medalBoard: { type: "", template: null, custom: null },
      nameCardStyle: this._playerdata.nameCardStyle,
    };
  }

  async update(recipe: (draft: PlayerDataModel) => Promise<void>) {
    const draft = createDraft(this._playerdata);
    await recipe(draft);
    finishDraft(draft, (patches, inversePatches) => {
      this._changes.push(patches);
      this._inverseChanges.push(inversePatches);
    });
  }
  getBattleInfo(battleId: string): BattleInfo {
    return accountManager.getBattleInfo(this.uid, battleId)!;
  }

  toJSON() {
    return {
      status: this._playerdata.status,
      collectionReward: this._playerdata.collectionReward,
      nameCardStyle: this._playerdata.nameCardStyle,
      inventory: this._playerdata.inventory,
      skin: this._playerdata.skin,
      consumable: this._playerdata.consumable,
      troop: this._playerdata.troop,
      dungeon: this._playerdata.dungeon,
      activity: this._playerdata.activity,
      pushFlags: this._playerdata.pushFlags,
      equipment: {},
      shop: this._playerdata.shop,
      mission: this.mission,
      social: this._playerdata.social,
      building: this._playerdata.building,
      dexNav: this._playerdata.dexNav,
      crisis: this._playerdata.crisis,
      crisisV2: this._playerdata.crisisV2,
      tshop: this._playerdata.tshop,
      gacha: this._playerdata.gacha,
      backflow: this._playerdata.backflow,
      mainline: this._playerdata.mainline,
      rlv2: this.rlv2,
      deepSea: this._playerdata.deepSea,
      tower: this._playerdata.tower,
      siracusaMap: this._playerdata.siracusaMap,
      sandboxPerm: this._playerdata.sandboxPerm,
      storyreview: this._playerdata.storyreview,
      medal: this._playerdata.medal,
      event: this._playerdata.event,
      retro: this._playerdata.retro,
      share: this._playerdata.share,
      roguelike: this._playerdata.roguelike,
      ticket: this._playerdata.ticket,
      aprilFool: this._playerdata.aprilFool,
      charm: this._playerdata.charm,
      carousel: this._playerdata.carousel,
      car: this._playerdata.car,
      recruit: this._playerdata.recruit,
      templateTrap: this._playerdata.templateTrap,
      checkIn: this._playerdata.checkIn,
      openServer: this._playerdata.openServer,
      campaignsV2: this._playerdata.campaignsV2,
      checkMeta: this._playerdata.checkMeta,
      limitedBuff: this._playerdata.limitedBuff,
      background: this._playerdata.background,
      homeTheme: this._playerdata.homeTheme,
      setting: this._playerdata.setting,
      npcAudio: this._playerdata.npcAudio,
      avatar: this._playerdata.avatar,
      trainingGround: this._playerdata.trainingGround,
    };
  }
}
