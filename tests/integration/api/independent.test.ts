/**
 * 游戏 API「独立端点」集成测试（真实 Input → Output）
 *
 * 通过真实 HTTP 请求打游戏路由，验证单个游戏 API 在给定请求体下是否返回正确业务输出
 * （真实 excel + 真实 PlayerDataManager，SQLite 内存隔离）。每个用例独立验证一个端点。
 */
import { describe, beforeAll, afterAll, it, expect } from "vitest";
import { startApiFixture, type ApiFixture } from "../../helpers/apiServer";
import excel from "../../../app/excel/excel";

describe("游戏 API 独立端点：输入 → 输出", () => {
  let fx: ApiFixture;
  /** 测试账号 id */
  let uid: string;
  /** 测试账号 secret（认证头） */
  let secret: string;

  beforeAll(async () => {
    fx = await startApiFixture();
    const acc = await fx.register("independent_test", "Ab12cd34");
    uid = acc.uid;
    secret = acc.secret;
    // 注入通用货币/可签到状态（等价于账号已通过签到/充值/任务获得资源）
    // status 子树未被冻结，直接经 manager.update 配方写入（真实生效路径）
    await fx.getPlayerData(uid).update((draft: any) => {
      draft.checkIn.canCheckIn = 1;
      const groups: any = excel.CheckinTable?.groups ?? {};
      draft.checkIn.checkInGroupId = Object.keys(groups)[0];
      draft.checkIn.checkInRewardIndex = 0;
      draft.status.gachaTicket = 100;
      draft.status.gold = 100000;
      draft.status.lggShard = 100000;
    });
  });

  afterAll(async () => {
    await fx.close();
  });

  it("签到 /user/checkIn：注入可签到状态后应发放签到奖励与增量", async () => {
    const res = await fx.post("/user/checkIn", {}, secret);
    expect(res.status).toBe(200);
    expect(res.body.signInRewards).toEqual([
      expect.objectContaining({ id: expect.any(String), count: expect.any(Number), type: "GOLD" }),
    ]);
    // 签到必然产生玩家增量（gold 入账等）
    expect(res.body.playerDataDelta.modified).toBeDefined();
  });

  it("商店列表 /shop/getLowGoodList：应返回分组与商品明细", async () => {
    const res = await fx.post("/shop/getLowGoodList", {}, secret);
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.groups)).toBe(true);
    // 商品需包含唯一 goodId 与价格等可购买要素
    expect(res.body.goodList[0]).toEqual(
      expect.objectContaining({ goodId: expect.any(String), price: expect.any(Number) }),
    );
  });

  it("商店购买 /shop/buyLowGood：合法商品应返回命中物品与增量", async () => {
    const res = await fx.post(
      "/shop/buyLowGood",
      { goodId: "LS_lggShdShopnumber19_1", count: 1 }, // 寻访凭证
      secret,
    );
    expect(res.status).toBe(200);
    expect(res.body.result).toBe(0);
    // 购买的物品项含 id / count / type
    expect(res.body.items[0]).toEqual(
      expect.objectContaining({ id: "7003", count: 1, type: "TKT_GACHA" }),
    );
    // 购买产生增量（货币扣减、商店限购记录）
    expect(res.body.playerDataDelta.modified).toBeDefined();
  });

  it("抽卡单抽 /gacha/advancedGacha：给定寻访凭证应抽到干员并扣费", async () => {
    const before = await fx.getPlayerData(uid)._playerdata.status.gachaTicket;
    const res = await fx.post(
      "/gacha/advancedGacha",
      { poolId: "NORM_0_1_1", useTkt: 1, itemId: null },
      secret,
    );
    expect(res.status).toBe(200);
    expect(res.body.result).toBe(0);
    // 返回抽到的干员 ID
    expect(res.body.charGet.charId).toMatch(/^char_/);
    // 抽卡凭证被消耗（100 → 99）
    expect(res.body.playerDataDelta.modified.status.gachaTicket).toBeLessThan(before);
  });

  it("邮件列表 /mail/listMailBox：应返回邮件数组与增量", async () => {
    const res = await fx.post(
      "/mail/listMailBox",
      { mailIdList: [], sysMailIdList: [], surveyMailIdList: [] },
      secret,
    );
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.mailList)).toBe(true);
  });

  it("rlv2 /rlv2/createGame：缺失必填参数返回 HTTP 422（zod 格式校验，非 500）", async () => {
    const res = await fx.post("/rlv2/createGame", {}, secret);
    expect(res.status).toBe(422);
    expect(res.body.result).toBe(-1);
    expect(res.body.message).toBeTruthy();
  });
});