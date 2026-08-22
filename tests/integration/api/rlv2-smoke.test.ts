/**
 * 游戏 API「Roguelike(rlv2)」集成冒烟测试
 *
 * 覆盖 rlv2 入口建局（createGame）：合法入参建局成功进入 INIT 状态，
 * 缺失必填参数时返回受控业务错误，验证真实输入→输出契约。
 * （rlv2 深层玩法已有 app 层大量单测覆盖，此处聚焦 HTTP 端到端契约。）
 */
import { describe, beforeAll, afterAll, it, expect } from "vitest";
import { startApiFixture, type ApiFixture } from "../../helpers/apiServer";

describe("游戏 API rlv2 建局冒烟", () => {
  let fx: ApiFixture;
  let secret: string;

  beforeAll(async () => {
    fx = await startApiFixture();
    const acc = await fx.register("rlv2_smoke_test", "Ab12cd34");
    secret = acc.secret;
  });

  afterAll(async () => {
    await fx.close();
  });

  it("createGame 缺失必填参数 → HTTP 422（zod 格式校验，非 500）", async () => {
    const res = await fx.post("/rlv2/createGame", {}, secret);
    expect(res.status).toBe(422);
    expect(res.body.result).toBe(-1);
    // 校验失败由 validateBody 中间件返回，不再进入控制器/playerDataDelta 分支
    expect(res.body.message).toBeTruthy();
  });

  it("createGame 合法入参 → 建局成功进入 INIT 状态", async () => {
    const res = await fx.post(
      "/rlv2/createGame",
      { theme: "rogue_6", mode: "NORMAL", modeGrade: 15 },
      secret,
    );
    expect(res.status).toBe(200);
    // 建局成功：current.player.state 进入 INIT，并带建局推送事件
    expect(res.body.playerDataDelta.modified.rlv2.current.player.state).toBe("INIT");
    expect(Array.isArray(res.body.pushMessage)).toBe(true);
  });
});