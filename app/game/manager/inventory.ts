import { ItemBundle } from "@excel/character_table";
import excel from "@excel/excel";
import { now } from "@utils/time";
import EventEmitter from "events";
import {
  PlayerConsumableItem,
  PlayerSkins,
  PlayerStatus,
} from "../model/playerdata";
import { PlayerDataManager } from "./PlayerDataManager";

export class InventoryManager {
  items: { [itemId: string]: number };
  skin: PlayerSkins;
  consumable: { [key: string]: { [key: string]: PlayerConsumableItem } };

  _status: PlayerStatus;
  _player: PlayerDataManager;
  _trigger: EventEmitter;

  constructor(player: PlayerDataManager, _trigger: EventEmitter) {
    this._player = player;
    this.items = player._playerdata.inventory;
    this.skin = player._playerdata.skin;
    this.consumable = player._playerdata.consumable;
    this._status = player._playerdata.status;
    this._trigger = _trigger;
    this._trigger.on("useItems", (items: ItemBundle[]) =>
      items.forEach((item) => this._useItem(item)),
    );
    this._trigger.on("gainItems", (items: ItemBundle[]) =>
      items.forEach((item) => this.gainItem(item)),
    );
  }

  get skinCnt(): number {
    return Object.keys(this.skin.characterSkins).length;
  }

  _useItem(item: ItemBundle): void {
    if (!item.type) {
      item.type = excel.ItemTable.items[item.id].itemType as string;
    }
    const consumableFunc = (item: ItemBundle) =>
      (this.consumable[item.id][item.instId!].count -= item.count);
    const funcs: { [key: string]: (item: ItemBundle) => void } = {
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
      funcs[item.type]?.(item);
    } else {
      this._trigger.emit("gainItems", [
        Object.assign({}, item, { count: -item.count }),
      ]);
    }
  }

  gainItem(item: ItemBundle, callback?: () => void): void {
    const info = excel.ItemTable.items[item.id];
    console.log(`[InventoryManager] 获得物品 ${info.name} x ${item.count}`);
    if (!item.type) {
      item.type = excel.ItemTable.items[item.id].itemType as string;
    }
    const funcs: { [key: string]: (item: ItemBundle) => void } = {
      NONE: () => {},
      CHAR: (item: ItemBundle) => this._trigger.emit("char:get", item.id),
      CARD_EXP: (item: ItemBundle) =>
        (this.items[item.id] = (this.items[item.id] || 0) + item.count),
      MATERIAL: (item: ItemBundle) =>
        (this.items[item.id] = (this.items[item.id] || 0) + item.count),
      GOLD: (item: ItemBundle) => (this._status.gold += item.count),
      EXP_PLAYER: (item: ItemBundle) => {
        this._status.exp += item.count;
        excel.GameDataConst.playerExpMap
          .slice(this._status.level - 1)
          .forEach((exp) => {
            if (this._status.exp >= exp) {
              this._status.level += 1;
              this._status.exp -= exp;
              this._status.maxAp =
                excel.GameDataConst.playerApMap[this._status.level - 1];
              this._trigger.emit("gainItems", [
                {
                  id: "",
                  type: "AP_GAMEPLAY",
                  count: this._status.maxAp,
                },
              ]);
              this._trigger.emit("player:levelup");
            }
          });
      },
      TKT_TRY: (item: ItemBundle) =>
        (this._status.practiceTicket += item.count),
      TKT_RECRUIT: (item: ItemBundle) =>
        (this._status.recruitLicense += item.count),
      TKT_INST_FIN: (item: ItemBundle) =>
        (this._status.instantFinishTicket += item.count),
      TKT_GACHA: (item: ItemBundle) => (this._status.gachaTicket += item.count),
      ACTIVITY_COIN: (item: ItemBundle) =>
        (this.items[item.id] = (this.items[item.id] || 0) + item.count),
      DIAMOND: (item: ItemBundle) => {
        this._status.iosDiamond += item.count;
        this._status.androidDiamond += item.count;
      },
      DIAMOND_SHD: (item: ItemBundle) =>
        (this._status.diamondShard += item.count),
      HGG_SHD: (item: ItemBundle) => (this._status.hggShard += item.count),
      LGG_SHD: (item: ItemBundle) => (this._status.lggShard += item.count),
      FURN: (item: ItemBundle) => {
        if (this._player.building.furniture[item.id]) {
          this._player.building.furniture[item.id].count += item.count;
        } else {
          this._player.building.furniture[item.id] = {
            count: item.count,
            inUse: 0,
          };
        }
      },
      AP_GAMEPLAY: (item: ItemBundle) => (this._status.ap += item.count),
      AP_BASE: () => {},
      SOCIAL_PT: (item: ItemBundle) => (this._status.socialPoint += item.count),
      CHAR_SKIN: (item: ItemBundle) => {
        this.skin.characterSkins[item.id] = 1;
        this.skin.skinTs[item.id] = now();
      },
      TKT_GACHA_10: (item: ItemBundle) =>
        (this._status.tenGachaTicket += item.count),
      TKT_GACHA_PRSV: (item: ItemBundle) =>
        (this.items[item.id] = (this.items[item.id] || 0) + item.count),
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
      LMTGS_COIN: (item: ItemBundle) => {
        if (this.consumable[item.id]["999"]) {
          this.consumable[item.id]["999"].count += item.count;
        } else {
          this.consumable[item.id]["999"] = { count: item.count, ts: -1 };
        }
      },
      EPGS_COIN: (item: ItemBundle) =>
        (this.items[item.id] = (this.items[item.id] || 0) + item.count),
      LIMITED_TKT_GACHA_10: () => {},
      LIMITED_FREE_GACHA: () => {},
      REP_COIN: (item: ItemBundle) =>
        (this.items[item.id] = (this.items[item.id] || 0) + item.count),
      ROGUELIKE: () => {},
      LINKAGE_TKT_GACHA_10: () => {},
      VOUCHER_ELITE_II_4: () => {},
      VOUCHER_ELITE_II_5: () => {},
      VOUCHER_ELITE_II_6: () => {},
      VOUCHER_SKIN: () => {},
      RETRO_COIN: () => {},
      PLAYER_AVATAR: (item: ItemBundle) => {
        this._player._playerdata.avatar.avatar_icon[item.id] = {
          ts: now(),
          src: "other",
        };
      },
      UNI_COLLECTION: () => {},
      VOUCHER_FULL_POTENTIAL: (item: ItemBundle) =>
        (this.items[item.id] = (this.items[item.id] || 0) + item.count),
      RL_COIN: () => {},
      RETURN_CREDIT: () => {},
      MEDAL: () => {},
      CHARM: () => {},
      HOME_BACKGROUND: (item: ItemBundle) => {
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
      CLASSIC_SHD: (item: ItemBundle) =>
        (this._status.classicShard += item.count),
      CLASSIC_TKT_GACHA: (item: ItemBundle) =>
        (this._status.classicGachaTicket += item.count),
      CLASSIC_TKT_GACHA_10: (item: ItemBundle) =>
        (this._status.classicTenGachaTicket += item.count),
      LIMITED_BUFF: () => {},
      CLASSIC_FES_PICK_TIER_5: () => {},
      CLASSIC_FES_PICK_TIER_6: () => {},
      RETURN_PROGRESS: () => {},
      NEW_PROGRESS: () => {},
      MCARD_VOUCHER: () => {},
      MATERIAL_ISSUE_VOUCHER: () => {},
      CRS_SHOP_COIN_V2: () => {},
      HOME_THEME: (item: ItemBundle) => {
        this._trigger.emit("homeTheme:get", item.id);
      },
      SANDBOX_PERM: () => {},
      SANDBOX_TOKEN: () => {},
      TEMPLATE_TRAP: () => {},
      NAME_CARD_SKIN: (item: ItemBundle) => {
        this._player._playerdata.nameCardStyle.skin.state[item.id] = {
          unlock: true,
          progress: null,
        };
      },
      EXCLUSIVE_TKT_GACHA: () => {},
      EXCLUSIVE_TKT_GACHA_10: () => {},
    };
    callback?.();
    funcs[item.type](item);
  }

  toJSON() {
    return {
      inventory: this.items,
      skin: this.skin,
      consumable: this.consumable,
    };
  }
}
