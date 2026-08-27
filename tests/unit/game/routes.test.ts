import { describe, it, expect, vi } from "vitest";
import {
  routes,
  crisisV2Rewrite,
  sandboxPermRewrite,
} from "../../../app/game/routes";

/**
 * 集中路由注册表（RE-4）
 *
 * 断言声明式路由表把每个客户端关键前缀解析到意图 router 模块、根级 rootRouter 挂载、
 * 以及内联 URL 重写函数（crisisV2 / sandboxPerm）的重写行为。
 */

/** 客户端关键单前缀 → 意图 router 模块（默认导出） */
const expectedPrefixes: Array<[string, string]> = [
  ["/businessCard", "./domain/router/businessCard"],
  ["/account", "./domain/router/account"],
  ["/charBuild", "./domain/router/charBuild"],
  ["/building", "./domain/building/handler"],
  ["/quest", "./domain/router/quest"],
  ["/user", "./domain/router/user"],
  ["/activity", "./domain/activity"],
  ["/storyreview", "./domain/router/storyreview"],
  ["/mission", "./domain/mission/handler"],
  ["/shop", "./domain/shop/handler"],
  ["/rlv2", "./domain/rlv2/handler"],
  ["/gacha", "./domain/gacha/handler"],
  ["/mail", "./domain/router/mail"],
  ["/social", "./domain/router/social"],
  ["/retro", "./domain/router/retro"],
  ["/aprilFool", "./domain/router/aprilFool"],
  ["/crisis", "./domain/router/crisis"],
  ["/deepsea", "./domain/router/deepsea"],
  ["/siracusaMap", "./domain/router/siracusaMap"],
  ["/explore", "./domain/router/explore"],
  ["/tower", "./domain/router/tower"],
  ["/charm", "./domain/router/charm"],
  ["/charRotation", "./domain/router/charRotation"],
  ["/depot", "./domain/router/depot"],
  ["/sandbox", "./domain/router/sandbox"],
  ["/templateShop", "./domain/router/templateShop"],
  ["/mailCollection", "./domain/router/mailCollection"],
  ["/multiplayer", "./domain/router/multiplayer"],
  ["/roguelike", "./domain/router/roguelike"],
  ["/campaignV2", "./domain/router/campaignV2"],
  ["/vecbreak", "./domain/router/vecbreak"],
  ["/interlock", "./domain/router/interlock"],
  ["/autochess", "./domain/router/autochess"],
  ["/pay", "./domain/router/pay"],
  ["/plugin", "./domain/router/plugin-heartbeat"],
  ["/rune", "./domain/router/rune"],
  ["/audit", "./domain/router/audit"],
  ["/arkodc", "./domain/router/arkodc"],
  ["/", "./domain/router/home"],
  ["/", "./domain/router/misc-alignment"],
];

describe("集中路由注册表 routes", () => {
  it("每个客户端关键前缀解析到意图 router 模块", () => {
    for (const [prefix, module] of expectedPrefixes) {
      expect(
        routes.some((r) => r.prefix === prefix && r.module === module),
        `${prefix} 应注册到 ${module}`,
      ).toBe(true);
    }
  });

  it("user/activity 根级路由通过 rootRouter 挂载到根路径", () => {
    expect(
      routes.some(
        (r) => r.prefix === "/" && r.module === "./domain/router/user" && r.exportName === "rootRouter",
      ),
    ).toBe(true);
    expect(
      routes.some(
        (r) =>
          r.prefix === "/" && r.module === "./domain/activity" && r.exportName === "rootRouter",
      ),
    ).toBe(true);
  });

  it("/activity 前缀别名覆盖 roguelike/interlock/vecbreak/multiplayer", () => {
    for (const module of [
      "./domain/router/roguelike",
      "./domain/router/interlock",
      "./domain/router/vecbreak",
      "./domain/router/multiplayer",
    ]) {
      expect(
        routes.some((r) => r.prefix === "/activity" && r.module === module),
        `/activity 别名应包含 ${module}`,
      ).toBe(true);
    }
  });

  it("根挂载别名（multiplayer/campaignV2/retro/vecbreak）对齐客户端单前缀", () => {
    for (const module of [
      "./domain/router/multiplayer",
      "./domain/router/campaignV2",
      "./domain/router/retro",
      "./domain/router/vecbreak",
    ]) {
      expect(
        routes.some((r) => r.prefix === "/" && r.module === module),
        `根路径应包含 ${module}`,
      ).toBe(true);
    }
  });

  it("crisisV2 挂载带重写函数且指向 crisis router", () => {
    expect(
      routes.some(
        (r) =>
          r.prefix === "/crisisV2" &&
          r.module === "./domain/router/crisis" &&
          r.rewrite === crisisV2Rewrite,
      ),
    ).toBe(true);
  });

  it("sandboxPerm 挂载带重写函数且指向 sandbox router", () => {
    expect(
      routes.some(
        (r) =>
          r.prefix === "/sandboxPerm" &&
          r.module === "./domain/router/sandbox" &&
          r.rewrite === sandboxPermRewrite,
      ),
    ).toBe(true);
  });

  it("crisisV2Rewrite 将去前缀后的 url 前补 /v2", () => {
    const req: any = { url: "/battleStart" };
    const next = vi.fn();
    crisisV2Rewrite(req, {} as any, next);
    expect(req.url).toBe("/v2/battleStart");
    expect(next).toHaveBeenCalledTimes(1);
  });

  it("sandboxPermRewrite 映射 /sandboxV2|V3 段并保留其余路径", () => {
    const v2: any = { url: "/sandboxV2/foo/bar" };
    const n2 = vi.fn();
    sandboxPermRewrite(v2, {} as any, n2);
    expect(v2.url).toBe("/v2/foo/bar");
    expect(n2).toHaveBeenCalledTimes(1);

    const v3: any = { url: "/sandboxV3/baz" };
    const n3 = vi.fn();
    sandboxPermRewrite(v3, {} as any, n3);
    expect(v3.url).toBe("/v3/baz");
    expect(n3).toHaveBeenCalledTimes(1);

    const other: any = { url: "/changeTopic" };
    const no = vi.fn();
    sandboxPermRewrite(other, {} as any, no);
    expect(other.url).toBe("/changeTopic");
    expect(no).toHaveBeenCalledTimes(1);
  });

  it("路由表顺序保持：根级挂载与别名别名的匹配优先级（misc-alignment 根级对齐位于末尾）", () => {
    const rootEntries = routes
      .map((r, i) => ({ ...r, index: i }))
      .filter((r) => r.prefix === "/");
    // 首个根级挂载为 home 兜底
    expect(rootEntries[0].module).toBe("./domain/router/home");
    // 末个根级挂载为 misc-alignment 全量对齐
    expect(rootEntries[rootEntries.length - 1].module).toBe("./domain/router/misc-alignment");
  });
});