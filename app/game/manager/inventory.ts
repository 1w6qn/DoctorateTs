import { ItemBundle } from "@excel/character_table";
import excel from "@excel/excel";
import { now } from "@utils/time";
import { PlayerDataModel } from "../model/playerdata";
import { PlayerDataManager } from "./PlayerDataManager";
import { WritableDraft } from "immer";
import { TypedEventEmitter } from "@game/model/events";

export class InventoryManager {
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("items:use", (items: ItemBundle[]) =>
      items.forEach((item) => this._useItem(item)),
    );
    this._trigger.on("items:get", (items: ItemBundle[]) =>
      items.forEach((item) => this.gainItem(item)),
    );
  }

  get items(): { [itemId: string]: number } {
    return this._player._playerdata.inventory;
  }

  get skinCnt(): number {
    return Object.keys(this._player._playerdata.skin.characterSkins).length;
  }

  async _useItem(item: ItemBundle): Promise<void> {
    if (!item.type) {
      item.type = excel.ItemTable.items[item.id].itemType as string;
    }
    const consumableFunc = (
      item: ItemBundle,
      draft: WritableDraft<PlayerDataModel>,
    ) => (draft.consumable[item.id][item.instId!].count -= item.count);
    const funcs: {
      [key: string]: (
        item: ItemBundle,
        draft: WritableDraft<PlayerDataModel>,
      ) => void;
    } = {
      TKT_GACHA_PRSV: consumableFunc,
      VOUCHER_ELITE_II_4: consumableFunc,
      VOUCHER_ELITE_II_5: consumableFunc,
      VOUCHER_ELITE_II_6: consumableFunc,
      VOUCHER_LEVELMAX_6: consumableFunc,
      VOUCHER_LEVELMAX_5: consumableFunc,
      VOUCHER_LEVELMAX_4: consumableFunc,
      VOUCHER_SKILL_SPECIALLEVELMAX_6: consumableFunc,
      VOUCHER_SKILL_SPECIALLEVELMAX_5: consumableFunc,
      VOUCHER_SKILL_SPECIALLEVELMAX_4: consumableFunc,
    };
    if (funcs[item.type]) {
      await this._player.update(async (draft) => {
        funcs[item.type!](item, draft);
      });
    } else {
      this._trigger.emit("items:get", [
        Object.assign({}, item, { count: -item.count }),
      ]);
    }
  }

  async gainItem(item: ItemBundle, callback?: () => void): Promise<void> {
    if (!item.type) {
      item.type = excel.ItemTable.items[item.id].itemType as string;
    }
    const funcs: {
      [key: string]: (
        item: ItemBundle,
        draft: WritableDraft<PlayerDataModel>,
      ) => void;
    } = {
      NONE: () => {},
      CHAR: (item) => this._trigger.emit("char:get", item.id),
      CARD_EXP: (item, draft) =>
        (draft.inventory[item.id] = (this.items[item.id] || 0) + item.count),
      MATERIAL: (item, draft) =>
        (draft.inventory[item.id] = (this.items[item.id] || 0) + item.count),
      GOLD: (item, draft) => (draft.status.gold += item.count),
      EXP_PLAYER: (item, draft) => {
        draft.status.exp += item.count;
        excel.GameDataConst.playerExpMap
          .slice(draft.status.level - 1)
          .forEach((exp) => {
            if (draft.status.exp >= exp) {
              draft.status.level += 1;
              draft.status.exp -= exp;
              draft.status.maxAp =
                excel.GameDataConst.playerApMap[draft.status.level - 1];
              this._trigger.emit("items:get", [
                {
                  id: "",
                  type: "AP_GAMEPLAY",
                  count: draft.status.maxAp,
                },
              ]);
              this._trigger.emit("player:levelUp");
            }
          });
      },
      TKT_TRY: (item, draft) => (draft.status.practiceTicket += item.count),
      TKT_RECRUIT: (item, draft) => (draft.status.recruitLicense += item.count),
      TKT_INST_FIN: (item, draft) =>
        (draft.status.instantFinishTicket += item.count),
      TKT_GACHA: (item, draft) => (draft.status.gachaTicket += item.count),
      ACTIVITY_COIN: (item, draft) =>
        (draft.inventory[item.id] = (this.items[item.id] || 0) + item.count),
      DIAMOND: (item, draft) => {
        draft.status.iosDiamond += item.count;
        draft.status.androidDiamond += item.count;
      },
      DIAMOND_SHD: (item, draft) => (draft.status.diamondShard += item.count),
      HGG_SHD: (item, draft) => (draft.status.hggShard += item.count),
      LGG_SHD: (item, draft) => (draft.status.lggShard += item.count),
      FURN: (item, draft) => {
        if (draft.building.furniture[item.id]) {
          draft.building.furniture[item.id].count += item.count;
        } else {
          draft.building.furniture[item.id] = {
            count: item.count,
            inUse: 0,
          };
        }
      },
      AP_GAMEPLAY: (item, draft) => (draft.status.ap += item.count),
      AP_BASE: () => {},
      SOCIAL_PT: (item, draft) => (draft.status.socialPoint += item.count),
      CHAR_SKIN: (item, draft) => {
        draft.skin.characterSkins[item.id] = 1;
        draft.skin.skinTs[item.id] = now();
      },
      TKT_GACHA_10: (item, draft) =>
        (draft.status.tenGachaTicket += item.count),
      TKT_GACHA_PRSV: (item, draft) =>
        (draft.inventory[item.id] = (this.items[item.id] || 0) + item.count),
      AP_ITEM: () => {},
      AP_SUPPLY: () => {},
      RENAMING_CARD: () => {},
      RENAMING_CARD_2: () => {},
      ET_STAGE: () => {},
      ACTIVITY_ITEM: () => {},
      VOUCHER_PICK: () => {},
      VOUCHER_CGACHA: () => {},
      VOUCHER_MGACHA: () => {},
      CRS_SHOP_COIN: () => {},
      CRS_RUNE_COIN: () => {},
      LMTGS_COIN: (item, draft) => {
        if (draft.consumable[item.id]["999"]) {
          draft.consumable[item.id]["999"].count += item.count;
        } else {
          draft.consumable[item.id]["999"] = { count: item.count, ts: -1 };
        }
      },
      EPGS_COIN: (item, draft) =>
        (draft.inventory[item.id] = (this.items[item.id] || 0) + item.count),
      LIMITED_TKT_GACHA_10: () => {},
      LIMITED_FREE_GACHA: () => {},
      REP_COIN: (item, draft) =>
        (draft.inventory[item.id] = (this.items[item.id] || 0) + item.count),
      ROGUELIKE: () => {},
      LINKAGE_TKT_GACHA_10: () => {},
      VOUCHER_ELITE_II_4: () => {},
      VOUCHER_ELITE_II_5: () => {},
      VOUCHER_ELITE_II_6: () => {},
      VOUCHER_SKIN: () => {},
      RETRO_COIN: () => {},
      PLAYER_AVATAR: (item, draft) => {
        draft.avatar.avatar_icon[item.id] = {
          ts: now(),
          src: "other",
        };
      },
      UNI_COLLECTION: () => {},
      VOUCHER_FULL_POTENTIAL: (item, draft) =>
        (draft.inventory[item.id] = (this.items[item.id] || 0) + item.count),
      RL_COIN: () => {},
      RETURN_CREDIT: () => {},
      MEDAL: () => {},
      CHARM: () => {},
      HOME_BACKGROUND: (item) => {
        this._trigger.emit("background:get", item.id);
      },
      EXTERMINATION_AGENT: () => {},
      OPTIONAL_VOUCHER_PICK: () => {},
      ACT_CART_COMPONENT: () => {},
      VOUCHER_LEVELMAX_6: () => {},
      VOUCHER_LEVELMAX_5: () => {},
      VOUCHER_LEVELMAX_4: () => {},
      VOUCHER_SKILL_SPECIALLEVELMAX_6: () => {},
      VOUCHER_SKILL_SPECIALLEVELMAX_5: () => {},
      VOUCHER_SKILL_SPECIALLEVELMAX_4: () => {},
      ACTIVITY_POTENTIAL: () => {},
      ITEM_PACK: () => {},
      SANDBOX: () => {},
      FAVOR_ADD_ITEM: () => {},
      CLASSIC_SHD: (item, draft) => (draft.status.classicShard += item.count),
      CLASSIC_TKT_GACHA: (item, draft) =>
        (draft.status.classicGachaTicket += item.count),
      CLASSIC_TKT_GACHA_10: (item, draft) =>
        (draft.status.classicTenGachaTicket += item.count),
      LIMITED_BUFF: () => {},
      CLASSIC_FES_PICK_TIER_5: () => {},
      CLASSIC_FES_PICK_TIER_6: () => {},
      RETURN_PROGRESS: () => {},
      NEW_PROGRESS: () => {},
      MCARD_VOUCHER: () => {},
      MATERIAL_ISSUE_VOUCHER: () => {},
      CRS_SHOP_COIN_V2: () => {},
      HOME_THEME: (item) => {
        this._trigger.emit("homeTheme:get", item.id);
      },
      SANDBOX_PERM: () => {},
      SANDBOX_TOKEN: () => {},
      TEMPLATE_TRAP: () => {},
      NAME_CARD_SKIN: (item, draft) => {
        draft.nameCardStyle.skin.state[item.id] = {
          unlock: true,
          progress: null,
        };
      },
      EXCLUSIVE_TKT_GACHA: () => {},
      EXCLUSIVE_TKT_GACHA_10: () => {},
    };
    callback?.();
    await this._player.update(async (draft) => {
      funcs[item.type!](item, draft);
    });
  }
}
