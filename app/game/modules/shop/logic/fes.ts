/**
 * 基建分区逻辑：限定与复刻（限定/经典/EPGS/REP 商品、自选票）
 *
 * 由 ShopManager 拆分而来：函数首参 mgr 为管理器实例，
 * 类侧保留同名薄委派（见 logic.ts）。
 */
import type { ShopManager } from "../logic";
import excel from "@excel/excel";
import { ItemBundle, ItemType } from "@excel/excel";
import { GachaPerChar } from "@excel/excel";
import { now } from "@utils/time";
import { LMTGSGood, QCObject, REPGoodList } from "@excel/excel";

  /**
   * 每月刷新处理
   *
   * 更新月度商店的ID和分组信息，重置购买记录。
   */
export async function monthlyRefresh(mgr: ShopManager) {
    await mgr._player.update(async (draft) => {
      // 修复：兜底 shop.LS 缺失（同 dailyRefresh）
      const ls = mgr._shopDraft(draft, "LS");
      ls.curShopId = mgr.todayLowShopId();
      ls.curGroupId = `${mgr.todayLowShopId()}_Group_1`;
      ls.info = [];
    });
}

  /**
   * 购买联合行动商店商品
   * @param args - 购买参数
   * @param args.goodId - 商品ID
   * @param args.count - 购买数量
   * @returns 获取的物品列表
   */
export async function buyEPGSGood(mgr: ShopManager, args: {
    goodId: string;
    count: number;
  }) : Promise<ItemBundle[]> {
    const { goodId, count } = args;
    // 修复：负数 count → 免费刷 EPGS 币；正整数校验
    mgr._assertBuyCount(count);
    const good = excel.ShopTable.EPGSGoodList.goodList.find(
      (g) => g.goodId === goodId,
    );
    // 防御：未知商品不 500
    if (!good) return [];
    // 修复：余额不足拒绝（寻访参数模型 EPGS_COIN）
    mgr._assertAffordable("EPGS_COIN", good.price * count);
    // 修复：限购检查
    mgr._assertAvail("EPGS", goodId, count, good.availCount);
    const item = { id: good.item.id, count: good.item.count * count, type: good.item.type as ItemType };
    await mgr._player.update(async (draft) => {
      const epgs = mgr._shopDraft(draft, "EPGS");
      const existingItem = epgs.info.find((i: any) => i.id === goodId);
      if (existingItem) {
        existingItem.count += count;
      } else {
        epgs.info.push({ id: goodId, count } as unknown as ItemBundle);
      }
    });
    await mgr._trigger.emit("items:use", [
      [excel.makeItem("EPGS_COIN", good!.price * count)],
    ]);
    // 修复：干员（CHAR）走 char:get 入账并返回 instId；其余走 items:get
    const granted = await mgr._issueCharItem(item);
    return [granted];
}

  /**
   * 购买声望商店商品
   * @param args - 购买参数
   * @param args.goodId - 商品ID
   * @param args.count - 购买数量
   * @returns 获取的物品列表
   */
export async function buyREPGood(mgr: ShopManager, args: {
    goodId: string;
    count: number;
  }) : Promise<ItemBundle[]> {
    const { goodId, count } = args;
    // 修复：负数 count → 免费刷声望币；正整数校验
    mgr._assertBuyCount(count);
    const good = excel.ShopTable.REPGoodList.goodList.find(
      (g) => g.goodId === goodId,
    );
    // 防御：未知商品不 500
    if (!good) return [];
    // 修复：余额不足拒绝（情报凭证 REP_COIN）
    mgr._assertAffordable("REP_COIN", good.price * count);
    // 修复：限购检查
    mgr._assertAvail("REP", goodId, count, good.availCount);
    const item = excel.makeItem(good.item.id, good.item.count * count);
    await mgr._player.update(async (draft) => {
      const rep = mgr._shopDraft(draft, "REP");
      const existingItem = rep.info.find((i: any) => i.id === goodId);
      if (existingItem) {
        existingItem.count += count;
      } else {
        rep.info.push({ id: goodId, count } as unknown as ItemBundle);
      }
    });
    await mgr._trigger.emit("items:use", [
      [excel.makeItem("REP_COIN", good.price * count)],
    ]);
    await mgr._trigger.emit("items:get", [[item]]);
    return [item];
}

  /**
   * 购买经典商店商品
   * @param args - 购买参数
   * @param args.goodId - 商品ID
   * @param args.count - 购买数量
   * @returns 获取的物品列表
   */
export async function buyClassicGood(mgr: ShopManager, args: {
    goodId: string;
    count: number;
  }) : Promise<ItemBundle[]> {
    const { goodId, count } = args;
    // 修复：负数 count → 免费刷经典票/凭证；正整数校验
    mgr._assertBuyCount(count);
    const good =
      excel.ShopTable.classicGoodList.goodList.find((g) => g.goodId === goodId) ??
      // 动态商品（根据当前中坚池自动生成的干员区）
      mgr.buildClassicCharGoods().find((g) => g.goodId === goodId) ??
      // 中坚甄选券（CLASSIC_FES_PICK_TIER_*/5，随中坚甄选池）
      mgr.buildFesPickGoods("KS").find((g) => g.goodId === goodId);
    // 防御：未知商品不 500
    if (!good) return [];
    let item!: ItemBundle;
    let price = good.price;
    if (!good?.progressGoodId) {
      // 修复：余额不足拒绝（高级凭证 4004）
      mgr._assertAffordable("4004", good.price * count);
      // 修复：限购检查
      mgr._assertAvail("CLASSIC", good.goodId, count, good.availCount);
    } else {
      // 进度商品：按档位定价，一次购买推进一档（count 按 1 档处理）
      const progressGood =
        excel.ShopTable.classicGoodList.progressGoodList[good.progressGoodId];
      const order =
        (mgr._player._playerdata.shop as any)?.CLASSIC?.progressInfo?.[
          good.progressGoodId
        ]?.order ?? 1;
      mgr._assertAffordable("4004", progressGood[order - 1]?.price ?? 0);
    }
    await mgr._player.update(async (draft) => {
      const classic = mgr._shopDraft(draft, "CLASSIC");
      if (!good?.progressGoodId) {
        item = { id: good.item.id, count: good.item.count * count, type: good.item.type as ItemType };
        const existingItem = classic.info.find(
          (i: any) => i.id === good.goodId,
        );
        if (existingItem) {
          existingItem.count += count;
        } else {
          classic.info.push(excel.makeItem(good.goodId, count));
        }
      } else {
        const { progressGoodId } = good;
        const progressGood =
          excel.ShopTable.classicGoodList.progressGoodList[progressGoodId];
        // 修复：先判空再解引用——原实现先取 progressInfo.order 后判空，
        // 首次购买（progressInfo 为 undefined）直接 TypeError 500
        let progressInfo = classic.progressInfo[progressGoodId];
        if (!progressInfo) {
          progressInfo = {
            order: 1,
            count: 0,
          };
          classic.progressInfo[progressGoodId] = progressInfo;
        }
        price = progressGood[progressInfo.order - 1].price;
        item = progressGood[progressInfo.order - 1].item;
        // 修复：档位数取配置长度（原硬编码 5）
        if (progressInfo.order < progressGood.length) {
          progressInfo.order += 1;
        } else {
          progressInfo.count += 1;
        }
      }
    });

    await mgr._trigger.emit("items:use", [
      [excel.makeItem("4004", price * count)],
    ]);
    // 修复：干员（CHAR）走 char:get 入账并返回带 instId（获得干员效果）；其余走 items:get
    const granted = await mgr._issueCharItem(item);
    await mgr._trigger.emit("BuyShopItem", [{ type: "CLASSIC" as ItemType, socialPoint: 0 }]);
    return [granted];
}

  /**
   * 购买限定商店商品
   * @param args - 购买参数
   * @param args.goodId - 商品ID
   * @param args.count - 购买数量
   * @returns 获取的物品列表
   */
export async function buyLMTGSGood(mgr: ShopManager, args: {
    goodId: string;
    count: number;
  }) : Promise<ItemBundle[]> {
    const { goodId, count } = args;
    // 修复：查找范围含自动生成商品（当前池商品不在静态 LMTGSGoodList.json）
    const good =
      excel.ShopTable.LMTGSGoodList?.goodList.find(
        (g) => g.goodId === goodId,
      ) ?? mgr.buildLMTGSGoodList().find((g) => g.goodId === goodId);
    // 防御：未知商品不 500
    if (!good) return [];
    // 修复：扣对应池的寻访数据契约（price.id = LMTGS_COIN_<poolId>；原硬编码
    // "LMTGS_COIN" 通用 id 扣不到玩家手里的具体凭证）——先校验余额，不足拒绝
    mgr._assertAffordable(good.price.id, good.price.count * count);
    // 修复：限购检查（静态表 availCount；自动生成商品为 -1 不限）
    mgr._assertAvail("LMTGS", goodId, count, good.availCount);
    // 修复：记录购买（原不写任何记录 → 客户端 getGoodPurchaseState 永远可买）
    await mgr._player.update(async (draft) => {
      const shop = draft.shop as any;
      shop.LMTGS = shop.LMTGS ?? { info: [] };
      const existing = shop.LMTGS.info.find((i: any) => i.id === goodId);
      if (existing) {
        existing.count += count;
      } else {
        shop.LMTGS.info.push({ id: goodId, count } as unknown as ItemBundle);
      }
    });
    await mgr._trigger.emit("items:use", [
      [{ id: good.price.id, count: good.price.count * count, type: good.price.type as ItemType }],
    ]);
    // 带 type 发放（CHAR → char:get 入账干员并返回 instId，客户端"获得干员"效果）
    const item: ItemBundle = {
      id: good.item.id,
      count: good.item.count * count,
      type: good.item.type,
    };
    const granted = await mgr._issueCharItem(item);
    return [granted];
}

  /**
   * 当前限定池（LMTGS 商店按当期池代币过滤）
   *
   * 优先当前活跃 LIMITED 池（openTime<=now<=endTime），无活跃池回退最近一期
   *（数据版本落后/卡池空窗期商店仍有内容）。客户端限定商店只展示当期池商品，
   * 商品代币 = 当期池 lMTGSID（LMTGS_COIN_<poolId>）。
   * @returns 当前限定池，无则 null
   */
export function currentLimitedPool(mgr: ShopManager) : (typeof excel.GachaTable.gachaPoolClient)[number] | null {
    const ts = now();
    const pools = excel.GachaTable.gachaPoolClient
      .filter((p) => p.gachaRuleType === "LIMITED")
      .sort((a, b) => b.openTime - a.openTime);
    if (!pools.length) return null;
    return (
      pools.find((p) => p.openTime <= ts && ts <= p.endTime) ??
      pools[0]
    );
}

  /**
   * 自动生成限定商店商品（运行时——新限定池无需手动补 LMTGSGoodList.json）
   *
   * 修复：按当期卡池过滤——只生成当前限定池（currentLimitedPool）商品，
   * 商品代币为当期池 lMTGSID；不再跨池返回全部 LIMITED 池商品（原实现客户端需按
   * LMTGSID 自行过滤，且非当期池商品用旧池代币无法购买）。
   * 每池生成：本池 UP 六星（300 凭证）+ 本池新五星（75 凭证）+
   * 历史限定六星（300 凭证，最多 4 个，排除本池已含）。goodId = `${poolId}_${seq}`
   * 稳定（客户端按 getLMTGSGoodList 拿到的 goodId 回传 buyLMTGSGood）。
   * 与静态 LMTGSGoodList.json 合并（静态保留当期池特殊商品，按 goodId 去重、自动优先）。
   *
   * @returns 自动生成的当期限定商品（客户端按当前池 LMTGSID 过滤）
   */
export function buildLMTGSGoodList(mgr: ShopManager) : LMTGSGood[] {
    if (mgr._autoLMTGSGoods) return mgr._autoLMTGSGoods;
    const pool = mgr.currentLimitedPool();
    const goods: LMTGSGood[] = [];
    if (pool) {
      // 历史限定六星：全部 LIMITED 池的 UP 六星（去重、按池序收集），供当期池"历史限定"区
      const historical: string[] = [];
      const allPools = excel.GachaTable.gachaPoolClient
        .filter((p) => p.gachaRuleType === "LIMITED")
        .sort((a, b) => a.openTime - b.openTime);
      for (const p of allPools) {
        const detail = excel.GachaDetailTable.details[p.gachaPoolId];
        const up6 =
          (detail?.upCharInfo?.perCharList ?? []).filter(
            (c: GachaPerChar) => c.rarityRank === 5,
          );
        for (const c of up6) {
          for (const id of c.charIdList) {
            if (!historical.includes(id)) historical.push(id);
          }
        }
      }
      const detail = excel.GachaDetailTable.details[pool.gachaPoolId];
      const up = detail?.upCharInfo?.perCharList ?? [];
      const up6 = up.filter((c: GachaPerChar) => c.rarityRank === 5);
      const up4 = up.find((c: GachaPerChar) => c.rarityRank === 4);
      // 寻访数据契约按池（JSON 键 lMTGSID，如 LMTGS_COIN_7601）
      const token = (pool as any).lMTGSID || "LMTGS_COIN";
      let seq = 0;
      const push = (
        item: ItemBundle,
        price: number,
      ): void => {
        goods.push({
          goodId: `${pool.gachaPoolId}_${++seq}`,
          startTime: pool.openTime,
          endTime: pool.endTime,
          availCount: -1,
          item,
          price: { id: token, count: price, type: "LMTGS_COIN" as ItemType },
          sortId: seq,
        });
      };
      // 本池 UP 六星（含限定干员）→ 300 凭证
      for (const c of up6) {
        for (const id of c.charIdList) push({ id, count: 1, type: "CHAR" as ItemType }, 300);
      }
      // 本池新五星 → 75 凭证
      if (up4) {
        for (const id of up4.charIdList) push({ id, count: 1, type: "CHAR" as ItemType }, 75);
      }
      // 历史限定六星（最多 4 个，排除本池已含）→ 300 凭证
      let added = 0;
      for (const id of historical) {
        if (added >= 4) break;
        if (up6.some((c: GachaPerChar) => c.charIdList.includes(id))) continue;
        push({ id, count: 1, type: "CHAR" as ItemType }, 300);
        added++;
      }
    }
    mgr._autoLMTGSGoods = goods;
    return goods;
}

  /**
   * 按当期中坚甄选（FESCLASSIC）池生成"中坚甄选 6/5★ 干员"甄选券商品
   *
   * 参考官方抓包 /shop/getClassicGoodList、/shop/getHighGoodList：两处都售卖两张甄选券
   *（CLASSIC_FES_PICK_TIER_6 / CLASSIC_FES_PICK_TIER_5），玩家购买后可在 FESCLASSIC 池
   * 通过 /gacha/choosePoolUp 自选 UP 干员并抽取（复用既有 gacha 自选抽卡逻辑）。
   * 价格对齐抓包——高级凭证区（HS）6★180/5★45，通用凭证区（KS）6★1800/5★450。
   * 无 FESCLASSIC 池时返回空数组（商店不展现甄选券）。
   * @param prefix - 商店前缀（HS=高级凭证区 / KS=通用凭证区），决定 goodId 与价格档位
   * @returns 甄选券商品列表（NORMAL；可空）
   */
export function buildFesPickGoods(mgr: ShopManager, prefix: "HS" | "KS") : QCObject[] {
    if (mgr._autoFesPickGoods) return mgr._autoFesPickGoods[prefix];
    let resolved: { HS: QCObject[]; KS: QCObject[] } = { HS: [], KS: [] };
    const pool = mgr._currentFesClassicPool();
    if (pool) {
      // 两商店售卖的券物品一致（同一 FESCLASSIC 池、同一券），仅 goodId/价格档位不同
      const tier6 = mgr._pickTicketId(6, pool.gachaPoolId);
      const tier5 = mgr._pickTicketId(5, pool.gachaPoolId);
      resolved = {
        HS: [
          mgr._buildFesPickGood("HS", "6", tier6, pool, 180, "CLASSIC_FES_PICK_TIER_6"),
          mgr._buildFesPickGood("HS", "5", tier5, pool, 45, "CLASSIC_FES_PICK_TIER_5"),
        ].filter(Boolean) as QCObject[],
        KS: [
          mgr._buildFesPickGood("KS", "6", tier6, pool, 1800, "CLASSIC_FES_PICK_TIER_6"),
          mgr._buildFesPickGood("KS", "5", tier5, pool, 450, "CLASSIC_FES_PICK_TIER_5"),
        ].filter(Boolean) as QCObject[],
      };
    }
    mgr._autoFesPickGoods = resolved;
    return resolved[prefix];
}

  /**
   * 构造单张甄选券商品（NORMAL）
   *
   * @param prefix - 商店前缀（HS/KS，用于 goodId 前缀与排序号）
   * @param tier - 稀有度档位标签（"6"/"5"）
   * @param ticketId - 甄选券物品 id
   * @param pool - 关联的 FESCLASSIC 池（提供时间窗）
   * @param price - 价格（按商店币种档位传入）
   * @param itemType - 物品类型（CLASSIC_FES_PICK_TIER_6 / _5）
   * @returns 单条甄选券商品
   */
export function _buildFesPickGood(mgr: ShopManager, prefix: "HS" | "KS",
    tier: string,
    ticketId: string,
    pool: (typeof excel.GachaTable.gachaPoolClient)[number],
    price: number,
    itemType: string,) : QCObject {
    const goodId = `${prefix}_FESPICK${tier}_${pool.gachaPoolId}`;
    return {
      goodId,
      displayName: tier === "6" ? "中坚甄选6星干员" : "中坚甄选5星干员",
      priority: 1,
      number: tier === "6" ? 1 : 2,
      goodType: "NORMAL",
      item: { id: ticketId, count: 1, type: itemType as ItemType },
      progressGoodId: "",
      price,
      originPrice: price,
      discount: 0,
      availCount: 1,
      slotId: 0,
      groupId: "",
      goodStartTime: pool.openTime,
      goodEndTime: pool.endTime,
    };
}

  /**
   * 声望商店（REP）商品列表
   *
   * 修复：剩余数量显示为负——客户端 RemainCount = availCount - 已购 count
   *（QCShopREPGood.RemainCount），限购修复前可无限购买的老存档 count 已超过静态
   * availCount → 显示负数。此处对每个商品按已购数量抬升 availCount 至 max(静态, 已购)，
   * 保证剩余 ≥ 0；已购达上限的商品显示售罄（isSoldOut），且 buyREPGood 的限购检查
   *（静态 availCount）继续拦截新购买，语义一致。
   * @returns 修正后的 REP 商品列表
   */
export function buildREPGoodList(mgr: ShopManager) : REPGoodList {
    const staticList = excel.ShopTable.REPGoodList;
    return {
      ...staticList,
      goodList: staticList.goodList.map((g) => ({
        ...g,
        availCount: Math.max(g.availCount, mgr._boughtCount("REP", g.goodId)),
      })),
    };
}
