/**
 * 游戏 API「核心业务流程」集成测试
 *
 * 以全新账号走一条完整业务闭环：
 *   注册 → 登录 → 注入可签到状态 → 签到得钱 → 商城买入寻访凭证 → 抽卡消耗凭证 → 干员入账
 * 逐段断言跨多端点的状态累计，验证真实输入请求能驱动正确输出。
 */
import { describe, beforeAll, afterAll, it, expect } from "vitest";
import { startApiFixture, type ApiFixture } from "../../helpers/apiServer";
import excel from "@game/excel/excel";

describe("游戏 API 核心业务流程（注册→登录→签到→商城→抽卡）", () => {
  let fx: ApiFixture;
  let uid: string;
  let secret: string;

  beforeAll(async () => {
    fx = await startApiFixture();
  });

  afterAll(async () => {
    await fx.close();
  });

  it("注册账号并通过真实登录接口换取 secret token", async () => {
    const acc = await fx.register("flow_core_test", "Ab12cd34");
    uid = acc.uid;
    secret = acc.secret;
    // 用账号密码走官方登录链路，确认返回 token 与注册 secret 一致
    const login = await fx.post("/user/auth/v1/login", {
      account: "flow_core_test",
      password: "Ab12cd34",
    });
    expect(login.status).toBe(200);
    expect(login.body.result).toBe(0);
    expect(login.body.uid).toBe(uid);
    expect(login.body.token).toBe(secret);
  });

  it("签到发放金币 → 商城购得寻访凭证 → 抽卡消耗凭证并新增干员", async () => {
    // 注入可签到状态与启动货币（等价账号日常刷新+充值）；status 子树可经配方写入
    const player = fx.getPlayerData(uid);
    await player.update((draft: any) => {
      draft.checkIn.canCheckIn = 1;
      const groups: any = excel.CheckinTable?.groups ?? {};
      draft.checkIn.checkInGroupId = Object.keys(groups)[0];
      draft.checkIn.checkInRewardIndex = 0;
      draft.status.gachaTicket = 0;
      draft.status.gold = 100000;
      // 商店低级凭证区商品以资质凭证（4005）计价，需一并注入才能购得寻访凭证
      draft.status.lggShard = 100000;
    });

    // 1) 签到 → 发放金币（不含寻访凭证）
    const checkIn = await fx.post("/user/checkIn", {}, secret);
    expect(checkIn.body.signInRewards[0].type).toBe("GOLD");

    // 2) 商城购买 1 张寻访凭证（id 7003 / TKT_GACHA）
    const buy = await fx.post(
      "/shop/buyLowGood",
      { goodId: "LS_lggShdShopnumber19_1", count: 1 },
      secret,
    );
    expect(buy.body.result).toBe(0);
    expect(buy.body.items[0]).toEqual(
      expect.objectContaining({ id: "7003", type: "TKT_GACHA" }),
    );
    // 凭证到手 → 可抽卡（gachaTicket > 0）
    const afterBuy = await fx.getPlayerData(uid)._playerdata.status.gachaTicket;
    expect(afterBuy).toBeGreaterThan(0);

    // 3) 单抽消耗 1 凭证 → 返回干员且凭证 -1
    const gacha = await fx.post(
      "/gacha/advancedGacha",
      { poolId: "NORM_0_1_1", useTkt: 1, itemId: null },
      secret,
    );
    expect(gacha.body.result).toBe(0);
    expect(gacha.body.charGet.charId).toMatch(/^char_/);
    // 凭证被真实消耗 1 张
    expect(await fx.getPlayerData(uid)._playerdata.status.gachaTicket).toBeLessThan(afterBuy);
    // 增量中记录了该池抽卡计数累计
    expect(gacha.body.playerDataDelta.modified.gacha.normal.NORM_0_1_1.cnt).toBe(1);
  });
});