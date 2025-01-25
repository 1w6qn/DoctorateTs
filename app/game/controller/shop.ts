import { ItemBundle } from "@excel/character_table";
import { PlayerDataManager } from "@game/manager/PlayerDataManager";
import { SocialGoodList } from "@excel/shop";
import excel from "@excel/excel";
import { TypedEventEmitter } from "@game/model/events";

export class ShopController {
  socialGoodList!: SocialGoodList;
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("refresh:monthly", this.monthlyRefresh.bind(this));
    this._trigger.on("refresh:daily", this.dailyRefresh.bind(this));
    this.socialGoodList = {
      goodList: [],
      charPurchase: {},
    };
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

  /*
  async _buyGood(shop,label:string,args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    const good = shop.goodList.find(
      (g) => g.goodId === goodId,
    );
    let item=good!.item
    item.count*=count
    await this._player.update(async (draft) => {
      const existingItem = draft.shop.LS.info.find((i) => i.id === goodId);
      if (existingItem) {
        existingItem.count += count;
      } else {
        draft.shop.LS.info.push({ id: goodId, count });
      }
    });
    this._trigger.emit("useItems", [
      { id: "4005", count: good!.price * count },
    ]);
    this._trigger.emit("gainItems", [item]);
    return [item];
  }
  
   */
  async buyLowGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    const good = excel.ShopTable.lowGoodList.goodList.find(
      (g) => g.goodId === goodId,
    );
    const item = { id: good!.item.id, count: good!.item.count * count };
    await this._player.update(async (draft) => {
      const existingItem = draft.shop.LS.info.find((i) => i.id === goodId);
      if (existingItem) {
        existingItem.count += count;
      } else {
        draft.shop.LS.info.push({ id: goodId, count });
      }
    });
    await this._trigger.emit("items:use", [
      [{ id: "4005", count: good!.price * count }],
    ]);
    await this._trigger.emit("items:get", [[item]]);
    return [item];
  }

  async buyHighGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    const good = excel.ShopTable.highGoodList.goodList.find(
      (g) => g.goodId === goodId,
    );
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
          excel.ShopTable.highGoodList.progressGoodList[good!.progressGoodId];
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

    await this._trigger.emit("items:use", [
      [{ id: "4004", count: good!.price * count }],
    ]);
    await this._trigger.emit("items:get", [[item]]);
    return [item];
  }

  async buyExtraGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    const good = excel.ShopTable.extraGoodList.goodList.find(
      (g) => g.goodId === goodId,
    );
    const item = { id: good!.item.id, count: good!.item.count * count };
    await this._player.update(async (draft) => {
      if (draft.shop.ES.info.some((i) => i.id === good!.goodId)) {
        draft.shop.ES.info.find((i) => i.id === good!.goodId)!.count += count;
      } else {
        draft.shop.ES.info.push({ id: good!.goodId, count: count });
      }
    });
    await this._trigger.emit("items:use", [
      [{ id: "4006", count: good!.price * count }],
    ]);
    await this._trigger.emit("items:get", [[item]]);
    return [item];
  }

  async buySkinGood(args: { goodId: string }): Promise<void> {
    const { goodId } = args;
    const good = excel.ShopTable.skinGoodList.goodList.find(
      (g) => g.goodId === goodId,
    );
    const item = { id: good!.skinId, count: 1, type: "CHAR_SKIN" };
    await this._trigger.emit("items:use", [
      [{ id: "4002", count: good!.price }],
    ]);
    await this._trigger.emit("items:get", [[item]]);
  }

  async buyCashGood(args: { goodId: string }): Promise<void> {
    const { goodId } = args;
    console.log(goodId);
  }

  async buyEPGSGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    const good = excel.ShopTable.EPGSGoodList.goodList.find(
      (g) => g.goodId === goodId,
    );
    const item = { id: good!.item.id, count: good!.item.count * count };
    await this._player.update(async (draft) => {
      if (draft.shop.EPGS.info.some((i) => i.id === good!.goodId)) {
        draft.shop.EPGS.info.find((i) => i.id === good!.goodId)!.count += count;
      } else {
        draft.shop.EPGS.info.push({ id: good!.goodId, count: count });
      }
    });

    await this._trigger.emit("items:use", [
      [{ id: "EPGS_COIN", count: good!.price * count }],
    ]);
    await this._trigger.emit("items:get", [[item]]);
    return [item];
  }

  async buyREPGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    const good = excel.ShopTable.REPGoodList.goodList.find(
      (g) => g.goodId === goodId,
    );
    const item = { id: good!.item.id, count: good!.item.count * count };
    await this._player.update(async (draft) => {
      if (draft.shop.REP.info.some((i) => i.id === good!.goodId)) {
        draft.shop.REP.info.find((i) => i.id === good!.goodId)!.count += count;
      } else {
        draft.shop.REP.info.push({ id: good!.goodId, count: count });
      }
    });

    await this._trigger.emit("items:use", [
      [{ id: "REP_COIN", count: good!.price * count }],
    ]);
    await this._trigger.emit("items:get", [[item]]);
    return [item];
  }

  async buyClassicGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    const good = excel.ShopTable.classicGoodList.goodList.find(
      (g) => g.goodId === goodId,
    );
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
          excel.ShopTable.classicGoodList.progressGoodList[progressGoodId];
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

    await this._trigger.emit("items:use", [
      [{ id: "4004", count: good!.price * count }],
    ]);
    await this._trigger.emit("items:get", [[item]]);
    return [item];
  }

  async buyLMTGSGood(args: {
    goodId: string;
    count: number;
  }): Promise<ItemBundle[]> {
    const { goodId, count } = args;
    const good = excel.ShopTable.LMTGSGoodList.goodList.find(
      (g) => g.goodId === goodId,
    );
    const item = { id: good!.item.id, count: good!.item.count * count };
    await this._trigger.emit("items:use", [
      [{ id: "LMTGS_COIN", count: good!.price.count * count }],
    ]);
    //TODO
    await this._trigger.emit("items:get", [[item]]);
    return [item];
  }

  async buyFurniGood(args: {
    goodId: string;
    buyCount: number;
    costType: string;
  }): Promise<ItemBundle[]> {
    const { goodId, buyCount, costType } = args;
    const good = excel.ShopTable.furniGoodList.goods.find(
      (g) => g.goodId === goodId,
    )!;
    if (costType === "COIN_FURN") {
      await this._trigger.emit("items:use", [
        [{ id: "3401", count: good.priceCoin * buyCount }],
      ]);
    } else {
      await this._trigger.emit("items:use", [
        [{ id: "", type: "DIAMOND", count: good.priceDia * buyCount }],
      ]);
    }
    await this._player.update(async (draft) => {
      const existingItem = draft.shop.FURNI.info.find((i) => i.id === goodId);
      existingItem!.count += buyCount;
    });
    const item = { id: good.furniId, type: "FURN", count: buyCount };
    await this._trigger.emit("items:get", [[item]]);
    return [item];
  }
}
export default ShopController;
