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
import { GachaController } from "../controller/gacha";
import { accountManager, BattleInfo } from "./AccountManger";
import { SocialManager } from "./social";
import { DexNavManager } from "./dexnav";
import { BuildingManager } from "./building";
import { FriendDataWithNameCard, FriendMedalBoard } from "@game/model/social";
import { OpenServerManager } from "@game/manager/activity/openServer";
import { createDraft, finishDraft, Patch, WritableDraft } from "immer";
import { patchesToObject } from "@utils/delta";
import { TypedEventEmitter } from "@game/model/events";
import { CharRotationManager } from "@game/manager/charRotation";
import { RetroManager } from "@game/manager/retro";
import { CharManager } from "@game/manager/char";

export class PlayerDataManager {
  dungeon: DungeonManager;
  inventory: InventoryManager;
  troop: TroopManager;
  status: StatusManager;
  home: HomeManager;
  charRotation: CharRotationManager;
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
  retro: RetroManager;
  char: CharManager;
  battle!: BattleManager;
  _trigger: TypedEventEmitter;
  _playerdata: PlayerDataModel;
  _changes: Patch[][];
  _inverseChanges: Patch[][];
  constructor(playerdata: PlayerDataModel) {
    this._playerdata = playerdata;
    this._changes = [];
    this._inverseChanges = [];
    this._trigger = new TypedEventEmitter();
    this._trigger.setMaxListeners(10000);
    this.status = new StatusManager(this, this._trigger);
    this.inventory = new InventoryManager(this, this._trigger);
    this.troop = new TroopManager(this, this._trigger);
    this.dungeon = new DungeonManager(this, this._trigger);
    this.home = new HomeManager(this, this._trigger);
    this.charRotation = new CharRotationManager(this, this._trigger);
    this.checkIn = new CheckInManager(this, this._trigger);
    this.storyreview = new StoryreviewManager(this, this._trigger);
    this.mission = new MissionManager(this, this._trigger);
    this.shop = new ShopController(this, this._trigger);
    this.battle = new BattleManager(this._playerdata, this._trigger);
    this.recruit = new RecruitManager(this, this._trigger);
    this.rlv2 = new RoguelikeV2Controller(this, this._trigger);
    this.social = new SocialManager(this, this._trigger);
    this.gacha = new GachaController(this, this._trigger);
    this.dexNav = new DexNavManager(this, this._trigger);
    this.building = new BuildingManager(this, this._trigger);
    this.openServer = new OpenServerManager(this, this._trigger);
    this.retro = new RetroManager(this, this._trigger);
    this.char = new CharManager(this, this._trigger);
    this._trigger.emit("game:fix");
    this._trigger.on(
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
    console.log(this._playerdata.status.androidDiamond);
    this._trigger.emit("save");
    console.log("delta", JSON.stringify(delta));
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
    let medalBoard: FriendMedalBoard;
    if (this._playerdata.social.medalBoard.custom) {
      medalBoard = {
        custom:
          this._playerdata.medal.custom.customs[
            this._playerdata.social.medalBoard.custom
          ],
        type: this._playerdata.social.medalBoard.type,
        template: null,
      };
    } else {
      medalBoard = {
        custom: null,
        type: this._playerdata.social.medalBoard.type,
        template: {
          groupId: this._playerdata.social.medalBoard.template!,
          medalList: this._playerdata.social.medalBoard.templateMedalList!,
        },
      };
    }
    const assistCharList = this._playerdata.social.assistCharList.map(
      (char) => {
        const charInfo = this._playerdata.troop.chars[char.charInstId];
        const res = {
          charId: charInfo.charId,
          skinId: charInfo.skin,
          skills: charInfo.skills,
          mainSkillLvl: charInfo.mainSkillLvl,
          skillIndex: char.skillIndex,
          evolvePhase: charInfo.evolvePhase,
          favorPoint: charInfo.favorPoint,
          potentialRank: charInfo.potentialRank,
          level: charInfo.level,
          crisisRecord: {},
          crisisV2Record: {},
          currentEquip: char.currentEquip,
          equip: charInfo.equip,
        };
        if (char?.currentTmpl) {
          return Object.assign({}, res, {
            currentTmpl: char.currentTmpl,
            tmpl: charInfo.tmpl!,
          });
        } else {
          return res;
        }
      },
    );
    return {
      nickName: this._playerdata.status.nickName,
      nickNumber: this._playerdata.status.nickNumber,
      uid: this.uid,
      registerTs: this._playerdata.status.registerTs,
      mainStageProgress: this._playerdata.status.mainStageProgress,
      charCnt: this._playerdata.troop.curCharInstId - 1,
      furnCnt: this.building.furnCnt,
      skinCnt: this.inventory.skinCnt,
      secretary: this._playerdata.status.secretary,
      secretarySkinId: this._playerdata.status.secretarySkinId,
      resume: this._playerdata.status.resume,
      teamV2: this.dexNav.teamV2Info,
      serverName: this._playerdata.status.serverName,
      level: this._playerdata.status.level,
      avatar: this._playerdata.status.avatar,
      assistCharList: assistCharList,
      lastOnlineTime: this._playerdata.status.lastOnlineTs,
      board: this.building.boardInfo,
      infoShare: this.building.infoShare,
      recentVisited: 0,
      skin: {
        selected: this._playerdata.nameCardStyle.skin.selected,
        state: {},
      },
      birthday: this._playerdata.status.birthday,
      medalBoard: medalBoard,
      nameCardStyle: this._playerdata.nameCardStyle,
    };
  }

  async init() {}

  async update(
    recipe: (draft: WritableDraft<PlayerDataModel>) => Promise<void>,
  ) {
    const draft = createDraft(this._playerdata);
    await recipe(draft);
    this._playerdata = finishDraft(draft, (patches, inversePatches) => {
      this._changes.push(patches);
      this._inverseChanges.push(inversePatches);
    });
    console.log(JSON.stringify(this._changes));
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
      charRotation: this._playerdata.charRotation,
    };
  }
}
