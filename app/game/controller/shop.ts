import EventEmitter from "events";
import {
  CashGoodList,
  ClassicGoodList,
  EPGSGoodList,
  ExtraGoodList,
  GPGoodList,
  HighGoodList,
  LMTGSGoodList,
  LowGoodList,
  REPGoodList,
  SkinGoodList,
  SocialGoodList,
} from "../model/shop";
import { ItemBundle } from "@excel/character_table";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";

export class ShopController {
  lowGoodList!: LowGoodList;
  skinGoodList!: SkinGoodList;
  cashGoodList!: CashGoodList;
  highGoodList!: HighGoodList;
  REPGoodList!: REPGoodList;
  LMTGSGoodList!: LMTGSGoodList;
  EPGSGoodList!: EPGSGoodList;
  classicGoodList!: ClassicGoodList;
  extraGoodList!: ExtraGoodList;
  GPGoodList!: GPGoodList;
  socialGoodList!: SocialGoodList;
  _player: PlayerDataManager;
  _trigger: EventEmitter;

  constructor(player: PlayerDataManager, _trigger: EventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("refresh:monthly", this.monthlyRefresh.bind(this));
    this._trigger.on("refresh:daily", this.dailyRefresh.bind(this));
    this.initShop();
  }

  async dailyRefresh() {}

  async monthlyRefresh() {
    //LS refresh
    const ts = new Date();
    const monthNum = ts.getMonth() - 5 + (ts.getFullYear() - 2019) * 12;
    await this._player.update(async (draft) => {
      draft.shop.LS.curShopId = `lggShdShopnumber${monthNum}`;
      draft.shop.LS.curGroupId = `lggShdGroupnumber${monthNum}_Group_1`;
      draft.shop.LS.info = [];
    });

    //
  }

  async buyLowGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    const good = this.lowGoodList.goodList.find((g) => g.goodId === goodId);
    const item = { id: good!.item.id, count: good!.item.count * count };
    await this._player.update(async (draft) => {
      if (draft.shop.LS.info.some((i) => i.id === good!.goodId)) {
        draft.shop.LS.info.find((i) => i.id === good!.goodId)!.count += count;
      } else {
        draft.shop.LS.info.push({ id: good!.goodId, count: count });
      }
    });
    this._trigger.emit("useItems", [
      { id: "4005", count: good!.price * count },
    ]);
    this._trigger.emit("gainItems", [item]);
    return [item];
  }

  async buyHighGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    const good = this.highGoodList.goodList.find((g) => g.goodId === goodId);
    let item!: ItemBundle;
    await this._player.update(async (draft) => {
      if (!good?.progressGoodId) {
        item = { id: good!.item.id, count: good!.item.count * count };
        if (draft.shop.HS.info.some((i) => i.id === good!.goodId)) {
          draft.shop.HS.info.find((i) => i.id === good!.goodId)!.count += count;
        } else {
          draft.shop.HS.info.push({ id: good!.goodId, count: count });
        }
      } else {
        const progressGood =
          this.highGoodList.progressGoodList[good!.progressGoodId];
        item =
          progressGood[
            draft.shop.HS.progressInfo[good!.progressGoodId].order - 1
          ].item;
        //TODO
        if (draft.shop.HS.progressInfo[good!.progressGoodId].order < 5) {
          draft.shop.HS.progressInfo[good!.progressGoodId].order += 1;
        } else {
          draft.shop.HS.progressInfo[good!.progressGoodId].count += 1;
        }
      }
    });

    this._trigger.emit("useItems", [
      { id: "4004", count: good!.price * count },
    ]);
    this._trigger.emit("gainItems", [item]);
    return [item];
  }

  async buyExtraGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    const good = this.extraGoodList.goodList.find((g) => g.goodId === goodId);
    const item = { id: good!.item.id, count: good!.item.count * count };
    await this._player.update(async (draft) => {
      if (draft.shop.ES.info.some((i) => i.id === good!.goodId)) {
        draft.shop.ES.info.find((i) => i.id === good!.goodId)!.count += count;
      } else {
        draft.shop.ES.info.push({ id: good!.goodId, count: count });
      }
    });
    this._trigger.emit("useItems", [
      { id: "4006", count: good!.price * count },
    ]);
    this._trigger.emit("gainItems", [item]);
    return [item];
  }

  async buySkinGood(args: { goodId: string }): Promise<void> {
    const { goodId } = args;
    const good = this.skinGoodList.goodList.find((g) => g.goodId === goodId);
    const item = { id: good!.skinId, count: 1, type: "CHAR_SKIN" };
    this._trigger.emit("useItems", [{ id: "4002", count: good!.price }]);
    this._trigger.emit("gainItems", [item]);
  }

  async buyCashGood(args: { goodId: string }): Promise<void> {
    const { goodId } = args;
  }

  async buyEPGSGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    const good = this.EPGSGoodList.goodList.find((g) => g.goodId === goodId);
    const item = { id: good!.item.id, count: good!.item.count * count };
    await this._player.update(async (draft) => {
      if (draft.shop.EPGS.info.some((i) => i.id === good!.goodId)) {
        draft.shop.EPGS.info.find((i) => i.id === good!.goodId)!.count += count;
      } else {
        draft.shop.EPGS.info.push({ id: good!.goodId, count: count });
      }
    });

    this._trigger.emit("useItems", [
      { id: "EPGS_COIN", count: good!.price * count },
    ]);
    this._trigger.emit("gainItems", [item]);
    return [item];
  }

  async buyREPGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    const good = this.REPGoodList.goodList.find((g) => g.goodId === goodId);
    const item = { id: good!.item.id, count: good!.item.count * count };
    await this._player.update(async (draft) => {
      if (draft.shop.REP.info.some((i) => i.id === good!.goodId)) {
        draft.shop.REP.info.find((i) => i.id === good!.goodId)!.count += count;
      } else {
        draft.shop.REP.info.push({ id: good!.goodId, count: count });
      }
    });

    this._trigger.emit("useItems", [
      { id: "REP_COIN", count: good!.price * count },
    ]);
    this._trigger.emit("gainItems", [item]);
    return [item];
  }

  async buyClassicGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    const good = this.classicGoodList.goodList.find((g) => g.goodId === goodId);
    let item!: ItemBundle;
    await this._player.update(async (draft) => {
      if (!good?.progressGoodId) {
        item = { id: good!.item.id, count: good!.item.count * count };
        if (draft.shop.CLASSIC.info.some((i) => i.id === good!.goodId)) {
          draft.shop.CLASSIC.info.find((i) => i.id === good!.goodId)!.count +=
            count;
        } else {
          draft.shop.CLASSIC.info.push({ id: good!.goodId, count: count });
        }
      } else {
        const { progressGoodId } = good;
        const progressGood =
          this.classicGoodList.progressGoodList[progressGoodId];
        item =
          progressGood[
            draft.shop.CLASSIC.progressInfo[progressGoodId].order - 1
          ].item;
        //TODO
        if (draft.shop.CLASSIC.progressInfo[progressGoodId].order < 5) {
          draft.shop.CLASSIC.progressInfo[progressGoodId].order += 1;
        } else {
          draft.shop.CLASSIC.progressInfo[progressGoodId].count += 1;
        }
      }
    });

    this._trigger.emit("useItems", [
      { id: "4004", count: good!.price * count },
    ]);
    this._trigger.emit("gainItems", [item]);
    return [item];
  }

  async buyLMTGSGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    const good = this.LMTGSGoodList.goodList.find((g) => g.goodId === goodId);
    const item = { id: good!.item.id, count: good!.item.count * count };
    this._trigger.emit("useItems", [
      { id: "LMTGS_COIN", count: good!.price.count * count },
    ]);
    //TODO
    this._trigger.emit("gainItems", [item]);
    return [item];
  }

  async initShop(): Promise<void> {
    this.lowGoodList = {
      groups: [],
      goodList: [],
      shopEndTime: -1,
      newFlag: [],
    };
    this.skinGoodList = {
      goodList: [],
    };
    this.cashGoodList = {
      goodList: [],
    };
    this.highGoodList = {
      goodList: [],
      progressGoodList: {},
      newFlag: [],
    };
    this.extraGoodList = {
      goodList: [],
      lastClick: -1,
      newFlag: [],
    };
    this.REPGoodList = {
      goodList: [],
      newFlag: [],
    };
    this.EPGSGoodList = {
      goodList: [],
      newFlag: [],
    };
    this.LMTGSGoodList = {
      goodList: [],
      newFlag: [],
    };
    this.classicGoodList = {
      goodList: [],
      newFlag: [],
      progressGoodList: {},
    };
    this.socialGoodList = {
      goodList: [],
      charPurchase: {},
    };
  }
}
export default ShopController;
