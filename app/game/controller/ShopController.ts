import EventEmitter from "events";
import { PlayerDataModel, PlayerDataShop } from "../model/playerdata";
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

export class ShopController {
  shop: PlayerDataShop;
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
  _playerdata: PlayerDataModel;
  _trigger: EventEmitter;

  constructor(_playerdata: PlayerDataModel, _trigger: EventEmitter) {
    this.shop = _playerdata.shop;
    this._playerdata = _playerdata;
    this._trigger = _trigger;
    this._trigger.on("refresh:monthly", this.monthlyRefresh.bind(this));
    this._trigger.on("refresh:daily", this.dailyRefresh.bind(this));
    this.initShop();
  }

  dailyRefresh() {}

  monthlyRefresh() {
    //LS refresh
    const ts = new Date();
    const monthnum = ts.getMonth() - 5 + (ts.getFullYear() - 2019) * 12;
    this.shop.LS.curShopId = `lggShdShopnumber${monthnum}`;
    this.shop.LS.curGroupId = `lggShdGroupnumber${monthnum}_Group_1`;
    this.shop.LS.info = [];
    //
  }

  buyLowGood(goodId: string, count: number): ItemBundle[] {
    const good = this.lowGoodList.goodList.find((g) => g.goodId === goodId);
    const item = { id: good!.item.id, count: good!.item.count * count };
    if (this.shop.LS.info.some((i) => i.id === good!.goodId)) {
      this.shop.LS.info.find((i) => i.id === good!.goodId)!.count += count;
    } else {
      this.shop.LS.info.push({ id: good!.goodId, count: count });
    }
    this._trigger.emit("useItems", [
      { id: "4005", count: good!.price * count },
    ]);
    this._trigger.emit("gainItems", [item]);
    return [item];
  }

  buyHighGood(goodId: string, count: number): ItemBundle[] {
    const good = this.highGoodList.goodList.find((g) => g.goodId === goodId);
    let item: ItemBundle;
    if (!good?.progressGoodId) {
      item = { id: good!.item.id, count: good!.item.count * count };
      if (this.shop.HS.info.some((i) => i.id === good!.goodId)) {
        this.shop.HS.info.find((i) => i.id === good!.goodId)!.count += count;
      } else {
        this.shop.HS.info.push({ id: good!.goodId, count: count });
      }
    } else {
      const progressGood =
        this.highGoodList.progressGoodList[good!.progressGoodId];
      item =
        progressGood[this.shop.HS.progressInfo[good!.progressGoodId].order - 1]
          .item;
      //TODO
      if (this.shop.HS.progressInfo[good!.progressGoodId].order < 5) {
        this.shop.HS.progressInfo[good!.progressGoodId].order += 1;
      } else {
        this.shop.HS.progressInfo[good!.progressGoodId].count += 1;
      }
    }

    this._trigger.emit("useItems", [
      { id: "4004", count: good!.price * count },
    ]);
    this._trigger.emit("gainItems", [item]);
    return [item];
  }

  buyExtraGood(goodId: string, count: number): ItemBundle[] {
    const good = this.extraGoodList.goodList.find((g) => g.goodId === goodId);
    const item = { id: good!.item.id, count: good!.item.count * count };
    if (this.shop.ES.info.some((i) => i.id === good!.goodId)) {
      this.shop.ES.info.find((i) => i.id === good!.goodId)!.count += count;
    } else {
      this.shop.ES.info.push({ id: good!.goodId, count: count });
    }
    this._trigger.emit("useItems", [
      { id: "4006", count: good!.price * count },
    ]);
    this._trigger.emit("gainItems", [item]);
    return [item];
  }

  buySkinGood(goodId: string): void {
    const good = this.skinGoodList.goodList.find((g) => g.goodId === goodId);
    const item = { id: good!.skinId, count: 1, type: "CHAR_SKIN" };
    this._trigger.emit("useItems", [{ id: "4002", count: good!.price }]);
    this._trigger.emit("gainItems", [item]);
  }

  buyCashGood(goodId: string): void {
    //
  }

  buyEPGSGood(goodId: string, count: number): ItemBundle[] {
    const good = this.EPGSGoodList.goodList.find((g) => g.goodId === goodId);
    const item = { id: good!.item.id, count: good!.item.count * count };
    if (this.shop.EPGS.info.some((i) => i.id === good!.goodId)) {
      this.shop.EPGS.info.find((i) => i.id === good!.goodId)!.count += count;
    } else {
      this.shop.EPGS.info.push({ id: good!.goodId, count: count });
    }
    this._trigger.emit("useItems", [
      { id: "EPGS_COIN", count: good!.price * count },
    ]);
    this._trigger.emit("gainItems", [item]);
    return [item];
  }

  buyREPGood(goodId: string, count: number): ItemBundle[] {
    const good = this.REPGoodList.goodList.find((g) => g.goodId === goodId);
    const item = { id: good!.item.id, count: good!.item.count * count };
    if (this.shop.REP.info.some((i) => i.id === good!.goodId)) {
      this.shop.REP.info.find((i) => i.id === good!.goodId)!.count += count;
    } else {
      this.shop.REP.info.push({ id: good!.goodId, count: count });
    }
    this._trigger.emit("useItems", [
      { id: "REP_COIN", count: good!.price * count },
    ]);
    this._trigger.emit("gainItems", [item]);
    return [item];
  }

  buyClassicGood(goodId: string, count: number): ItemBundle[] {
    const good = this.classicGoodList.goodList.find((g) => g.goodId === goodId);
    let item: ItemBundle;
    if (!good?.progressGoodId) {
      item = { id: good!.item.id, count: good!.item.count * count };
      if (this.shop.CLASSIC.info.some((i) => i.id === good!.goodId)) {
        this.shop.CLASSIC.info.find((i) => i.id === good!.goodId)!.count +=
          count;
      } else {
        this.shop.CLASSIC.info.push({ id: good!.goodId, count: count });
      }
    } else {
      const progressGood =
        this.classicGoodList.progressGoodList[good!.progressGoodId];
      item =
        progressGood[
          this.shop.CLASSIC.progressInfo[good!.progressGoodId].order - 1
        ].item;
      //TODO
      if (this.shop.CLASSIC.progressInfo[good!.progressGoodId].order < 5) {
        this.shop.CLASSIC.progressInfo[good!.progressGoodId].order += 1;
      } else {
        this.shop.CLASSIC.progressInfo[good!.progressGoodId].count += 1;
      }
    }

    this._trigger.emit("useItems", [
      { id: "4004", count: good!.price * count },
    ]);
    this._trigger.emit("gainItems", [item]);
    return [item];
  }

  buyLMTGSGood(goodId: string, count: number): ItemBundle[] {
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
    //this.GPGoodList = await import('../../../data/shop/GPGoodList.json')
  }

  toJSON() {
    return {
      shop: this.shop,
    };
  }
}
export default ShopController;
