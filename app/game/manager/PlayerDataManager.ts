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
import { AprilFoolManager } from "@game/manager/aprilFool";

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
  aprilFool: AprilFoolManager;
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
    this.battle = new BattleManager(this, this._trigger);
    this.recruit = new RecruitManager(this, this._trigger);
    this.rlv2 = new RoguelikeV2Controller(this, this._trigger);
    this.social = new SocialManager(this, this._trigger);
    this.gacha = new GachaController(this, this._trigger);
    this.dexNav = new DexNavManager(this, this._trigger);
    this.building = new BuildingManager(this, this._trigger);
    this.openServer = new OpenServerManager(this, this._trigger);
    this.retro = new RetroManager(this, this._trigger);
    this.char = new CharManager(this, this._trigger);
    this.aprilFool = new AprilFoolManager(this, this._trigger);
    //this._trigger.emit("game:fix", []);
    this._trigger.on(
      "save:battle",
      async ([battleId, info]: [string, BattleInfo]) => {
        await accountManager.saveBattleInfo(this.uid, battleId, info);
      },
    );
  }

  get delta() {
    const delta = patchesToObject(
      this._changes.reduce((pre, acc) => acc.concat(pre), []),
      this._playerdata,
    );
    this._changes = [];
    this._trigger.emit("save", []);
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

  async update<T>(
    recipe: (draft: WritableDraft<PlayerDataModel>) => Promise<T>,
  ) {
    const draft = createDraft(this._playerdata);
    const result = await recipe(draft);
    this._playerdata = finishDraft(draft, (patches, inversePatches) => {
      this._changes.push(patches);
      console.log("patches", patches);
      this._inverseChanges.push(inversePatches);
    });
    return result;
  }

  async getBattleInfo(battleId: string): Promise<BattleInfo> {
    return (await accountManager.getBattleInfo(this.uid, battleId))!;
  }

  toJSON() {
    return this._playerdata;
  }
}
