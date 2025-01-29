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
    this._trigger.on("items:use", async ([items]: [ItemBundle[]]) => {
      await Promise.all(items.map((item) => this._useItem(item)));
    });
    this._trigger.on("items:get", async ([items]: [ItemBundle[]]) => {
      await Promise.all(items.map((item) => this.gainItem(item)));
    });
  }

  get skinCnt(): number {
    return Object.keys(this._player._playerdata.skin.characterSkins).length;
  }

  async _useItem(item: ItemBundle): Promise<void> {
    if (!item.type) {
      item.type = excel.ItemTable.items[item.id].itemType;
    }
    const consumableFunc = async (
      item: ItemBundle,
      draft: WritableDraft<PlayerDataModel>,
    ) => {
      draft.consumable[item.id][item.instId!].count -= item.count;
    };
    const funcs: {
      [key: string]: (
        item: ItemBundle,
        draft: WritableDraft<PlayerDataModel>,
      ) => Promise<void>;
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
      AP_SUPPLY: async (item, draft) => {
        await consumableFunc(item, draft);
        await this._trigger.emit("items:get", [
          [{ id: "", type: "AP_GAMEPLAY", count: 120 * item.count }],
        ]);
      },
    };
    if (item.type in funcs) {
      await this._player.update(async (draft) => {
        await funcs[item.type!](item, draft);
      });
    } else {
      await this._trigger.emit("items:get", [
        [Object.assign({}, item, { count: -item.count })],
      ]);
    }
  }

  async gainItem(item: ItemBundle, callback?: () => void): Promise<void> {
    console.log("gainItem", item);
    if (!item.type) {
      item.type = excel.ItemTable.items[item.id].itemType as string;
    }
    const consumableFunc = async (
      item: ItemBundle,
      draft: WritableDraft<PlayerDataModel>,
    ) => {
      let consumableId = item?.instId;
      if (!consumableId) {
        const consumable_set = new Set<number>();
        for (const item of Object.values(draft.consumable)) {
          const keys = Object.keys(item);
          if (keys.length > 0) {
            consumable_set.add(parseInt(keys[0], 10));
          }
        }
        const maxConsumableId =
          consumable_set.size > 0 ? Math.max(...Array.from(consumable_set)) : 0;
        consumableId = maxConsumableId + 1;
      }

      if (!draft.consumable[item.id]) {
        draft.consumable[item.id] = {};
      }
      if (draft.consumable[item.id][consumableId]) {
        draft.consumable[item.id][consumableId].count += item.count;
      } else {
        draft.consumable[item.id][consumableId] = { count: item.count, ts: -1 };
      }
    };
    const funcs: {
      [key: string]: (
        item: ItemBundle,
        draft: WritableDraft<PlayerDataModel>,
      ) => Promise<void>;
    } = {
      NONE: async () => {},
      CHAR: async (item) => {
        await this._trigger.emit("char:get", [item.id]);
      },
      CARD_EXP: async (item, draft) => {
        draft.inventory[item.id] = (draft.inventory[item.id] || 0) + item.count;
      },
      MATERIAL: async (item, draft) => {
        draft.inventory[item.id] = (draft.inventory[item.id] || 0) + item.count;
      },
      GOLD: async (item, draft) => {
        draft.status.gold += item.count;
      },
      EXP_PLAYER: async (item, draft) => {
        draft.status.exp += item.count;
        for (
          let i = draft.status.level - 1;
          i < excel.GameDataConst.playerExpMap.length;
          i++
        ) {
          const exp = excel.GameDataConst.playerExpMap[i];
          if (draft.status.exp >= exp) {
            draft.status.level += 1;
            draft.status.exp -= exp;
            draft.status.maxAp =
              excel.GameDataConst.playerApMap[draft.status.level - 1];
            await this._trigger.emit("items:get", [
              [
                {
                  id: "",
                  type: "AP_GAMEPLAY",
                  count: draft.status.maxAp,
                },
              ],
            ]);
            await this._trigger.emit("player:levelUp", []);
          } else {
            break;
          }
        }
      },
      TKT_TRY: async (item, draft) => {
        draft.status.practiceTicket += item.count;
      },
      TKT_RECRUIT: async (item, draft) => {
        draft.status.recruitLicense += item.count;
      },
      TKT_INST_FIN: async (item, draft) => {
        draft.status.instantFinishTicket += item.count;
      },
      TKT_GACHA: async (item, draft) => {
        draft.status.gachaTicket += item.count;
      },
      ACTIVITY_COIN: async (item, draft) => {
        draft.inventory[item.id] = (draft.inventory[item.id] || 0) + item.count;
      },
      DIAMOND: async (item, draft) => {
        draft.status.androidDiamond += item.count;
      },
      DIAMOND_SHD: async (item, draft) => {
        draft.status.diamondShard += item.count;
      },
      HGG_SHD: async (item, draft) => {
        draft.status.hggShard += item.count;
      },
      LGG_SHD: async (item, draft) => {
        draft.status.lggShard += item.count;
      },
      FURN: async (item, draft) => {
        if (draft.building.furniture[item.id]) {
          draft.building.furniture[item.id].count += item.count;
        } else {
          draft.building.furniture[item.id] = {
            count: item.count,
            inUse: 0,
          };
        }
        draft.building.solution.furnitureTs[item.id] = now();
      },
      AP_GAMEPLAY: async (item, draft) => {
        const addAp = Math.floor((now() - draft.status.lastApAddTime) / 360);
        if (draft.status.ap < draft.status.maxAp) {
          if (draft.status.ap + addAp >= draft.status.maxAp) {
            draft.status.ap = draft.status.maxAp;
          } else if (addAp > 0) {
            draft.status.ap += addAp;
          }
        }
        console.log("AP_GAMEPLAY", item.count, addAp, draft.status.ap);
        draft.status.ap += item.count;
        draft.status.lastApAddTime = now();
      },
      AP_BASE: async () => {},
      SOCIAL_PT: async (item, draft) => {
        draft.status.socialPoint += item.count;
      },
      CHAR_SKIN: async (item, draft) => {
        draft.skin.characterSkins[item.id] = 1;
        draft.skin.skinTs[item.id] = now();
      },
      TKT_GACHA_10: async (item, draft) => {
        draft.status.tenGachaTicket += item.count;
      },
      TKT_GACHA_PRSV: async (item, draft) => {
        draft.inventory[item.id] = (draft.inventory[item.id] || 0) + item.count;
      },
      AP_ITEM: async () => {},
      AP_SUPPLY: consumableFunc,
      RENAMING_CARD: consumableFunc,
      RENAMING_CARD_2: consumableFunc,
      ET_STAGE: async () => {},
      ACTIVITY_ITEM: async () => {},
      VOUCHER_PICK: consumableFunc,
      VOUCHER_CGACHA: consumableFunc,
      VOUCHER_MGACHA: consumableFunc,
      CRS_SHOP_COIN: async () => {},
      CRS_RUNE_COIN: async () => {},
      LMTGS_COIN: consumableFunc,
      EPGS_COIN: async (item, draft) => {
        draft.inventory[item.id] = (draft.inventory[item.id] || 0) + item.count;
      },
      LIMITED_TKT_GACHA_10: consumableFunc,
      LIMITED_FREE_GACHA: async () => {},
      REP_COIN: async (item, draft) => {
        draft.inventory[item.id] = (draft.inventory[item.id] || 0) + item.count;
      },
      ROGUELIKE: async () => {},
      LINKAGE_TKT_GACHA_10: consumableFunc,
      VOUCHER_ELITE_II_4: consumableFunc,
      VOUCHER_ELITE_II_5: consumableFunc,
      VOUCHER_ELITE_II_6: consumableFunc,
      VOUCHER_SKIN: consumableFunc,
      RETRO_COIN: async () => {},
      PLAYER_AVATAR: async (item, draft) => {
        draft.avatar.avatar_icon[item.id] = {
          ts: now(),
          src: "other",
        };
      },
      UNI_COLLECTION: async () => {},
      VOUCHER_FULL_POTENTIAL: async (item, draft) => {
        draft.inventory[item.id] = (draft.inventory[item.id] || 0) + item.count;
      },
      RL_COIN: async () => {},
      RETURN_CREDIT: async () => {},
      MEDAL: async () => {},
      CHARM: async () => {},
      HOME_BACKGROUND: async (item) => {
        await this._trigger.emit("background:get", [item.id]);
      },
      EXTERMINATION_AGENT: consumableFunc,
      OPTIONAL_VOUCHER_PICK: consumableFunc,
      ACT_CART_COMPONENT: async () => {},
      VOUCHER_LEVELMAX_6: consumableFunc,
      VOUCHER_LEVELMAX_5: consumableFunc,
      VOUCHER_LEVELMAX_4: consumableFunc,
      VOUCHER_SKILL_SPECIALLEVELMAX_6: consumableFunc,
      VOUCHER_SKILL_SPECIALLEVELMAX_5: consumableFunc,
      VOUCHER_SKILL_SPECIALLEVELMAX_4: consumableFunc,
      ACTIVITY_POTENTIAL: consumableFunc,
      ITEM_PACK: consumableFunc,
      SANDBOX: async () => {},
      FAVOR_ADD_ITEM: async () => {},
      CLASSIC_SHD: async (item, draft) => {
        draft.status.classicShard += item.count;
      },
      CLASSIC_TKT_GACHA: async (item, draft) => {
        draft.status.classicGachaTicket += item.count;
      },
      CLASSIC_TKT_GACHA_10: async (item, draft) => {
        draft.status.classicTenGachaTicket += item.count;
      },
      LIMITED_BUFF: async () => {},
      CLASSIC_FES_PICK_TIER_5: async () => {},
      CLASSIC_FES_PICK_TIER_6: async () => {},
      RETURN_PROGRESS: async () => {},
      NEW_PROGRESS: async () => {},
      MCARD_VOUCHER: async () => {},
      MATERIAL_ISSUE_VOUCHER: consumableFunc,
      CRS_SHOP_COIN_V2: async () => {},
      HOME_THEME: async (item) => {
        await this._trigger.emit("homeTheme:get", [item.id]);
      },
      SANDBOX_PERM: async () => {},
      SANDBOX_TOKEN: async () => {},
      TEMPLATE_TRAP: async () => {},
      NAME_CARD_SKIN: async (item, draft) => {
        draft.nameCardStyle.skin.state[item.id] = {
          unlock: true,
          progress: null,
        };
      },
      EXCLUSIVE_TKT_GACHA: consumableFunc,
      EXCLUSIVE_TKT_GACHA_10: consumableFunc,
    };
    callback?.();
    await this._player.update(async (draft) => {
      await funcs[item.type!](item, draft);
    });
  }
}
