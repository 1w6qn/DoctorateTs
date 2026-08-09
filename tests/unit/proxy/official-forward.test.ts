import { describe, it, expect } from "vitest";
import {
  resolveForwardTarget,
  OFFICIAL_AS_HOST,
  OFFICIAL_GS_HOST,
} from "../../../app/proxy/official-forward";

/**
 * capture 模式转发目标解析测试
 *
 * 只测纯函数 resolveForwardTarget（不依赖 config/网络），覆盖：
 *   Host 优先分发（as.* / ak-gs-* / 其余官方子域保持本地）
 *   路径级兜底（as 前缀、/game 剥前缀、gs 根路径 POST 兜底 + 本地挂载点排除）
 *   主机覆写（opts.asHost/gsHost）
 */
describe("resolveForwardTarget（官服转发目标解析）", () => {
  describe("Host 优先分发（客户端 hosts 指向私服、保留官服子域名）", () => {
    it("as.hypergryph.com → as 域，路径原样", () => {
      const t = resolveForwardTarget("POST", "/user/auth/v1/token_by_phone_password", "as.hypergryph.com");
      expect(t).toEqual({ baseUrl: OFFICIAL_AS_HOST, path: "/user/auth/v1/token_by_phone_password" });
    });

    it("as.hypergryph.com 的 GET 用户信息 → as 域", () => {
      const t = resolveForwardTarget("GET", "/user/info/v1/basic", "as.hypergryph.com");
      expect(t?.baseUrl).toBe(OFFICIAL_AS_HOST);
    });

    it("ak-gs-gf.hypergryph.com → gs 域，路径原样（官服游戏路径无 /game 基址）", () => {
      const t = resolveForwardTarget("POST", "/account/login", "ak-gs-gf.hypergryph.com");
      expect(t).toEqual({ baseUrl: OFFICIAL_GS_HOST, path: "/account/login" });
    });

    it("ak-gs-* 带 /game 基址前缀 → 剥前缀到 gs 域", () => {
      const t = resolveForwardTarget("POST", "/game/account/login", "ak-gs-gf.hypergryph.com");
      expect(t).toEqual({ baseUrl: OFFICIAL_GS_HOST, path: "/account/login" });
    });

    it("ak-conf.hypergryph.com（配置域）→ 不转发（保持本地引导）", () => {
      const t = resolveForwardTarget("GET", "/config/prod/official/network_config", "ak-conf.hypergryph.com");
      expect(t).toBeNull();
    });

    it("game-config.hypergryph.com（新版配置域）→ 不转发", () => {
      const t = resolveForwardTarget("GET", "/api/remote_config/1/prod/default/Windows/network_config", "game-config.hypergryph.com");
      expect(t).toBeNull();
    });

    it("其余官方子域（ak.hypergryph.com）→ 不转发", () => {
      const t = resolveForwardTarget("GET", "/protocol/service", "ak.hypergryph.com");
      expect(t).toBeNull();
    });
  });

  describe("路径级兜底（Host 非官服：127.0.0.1 直连 / mitmweb 重写）", () => {
    it("/user/auth/* → as 域", () => {
      const t = resolveForwardTarget("POST", "/user/auth/v1/token_by_phone_password", "127.0.0.1:8443");
      expect(t).toEqual({ baseUrl: OFFICIAL_AS_HOST, path: "/user/auth/v1/token_by_phone_password" });
    });

    it("/user/info/*、/user/online/*、/user/oauth2/* → as 域", () => {
      expect(resolveForwardTarget("GET", "/user/info/v1/basic", "127.0.0.1:8443")?.baseUrl).toBe(OFFICIAL_AS_HOST);
      expect(resolveForwardTarget("POST", "/user/online/v1/loginout", "127.0.0.1:8443")?.baseUrl).toBe(OFFICIAL_AS_HOST);
      expect(resolveForwardTarget("POST", "/user/oauth2/v2/grant", "127.0.0.1:8443")?.baseUrl).toBe(OFFICIAL_AS_HOST);
    });

    it("/u8/* → as 域 /u8 基址", () => {
      const t = resolveForwardTarget("POST", "/u8/user/v1/getToken", "127.0.0.1:8443");
      expect(t).toEqual({ baseUrl: `${OFFICIAL_AS_HOST}/u8`, path: "/u8/user/v1/getToken" });
    });

    it("/app/*、/general/* → as 域", () => {
      expect(resolveForwardTarget("GET", "/app/v1/config", "127.0.0.1:8443")?.baseUrl).toBe(OFFICIAL_AS_HOST);
      expect(resolveForwardTarget("GET", "/general/v1/server_time", "127.0.0.1:8443")?.baseUrl).toBe(OFFICIAL_AS_HOST);
    });

    it("/as/* 路径化前缀 → 剥 /as 到 as 域", () => {
      const t = resolveForwardTarget("POST", "/as/user/auth/v1/register", "127.0.0.1:8443");
      expect(t).toEqual({ baseUrl: OFFICIAL_AS_HOST, path: "/user/auth/v1/register" });
    });

    it("/game/* → 剥 /game 到 gs 域（POST/GET 均转发）", () => {
      expect(resolveForwardTarget("POST", "/game/account/login", "127.0.0.1:8443")).toEqual({
        baseUrl: OFFICIAL_GS_HOST,
        path: "/account/login",
      });
      expect(resolveForwardTarget("GET", "/game/activity/getActivityList", "127.0.0.1:8443")).toEqual({
        baseUrl: OFFICIAL_GS_HOST,
        path: "/activity/getActivityList",
      });
    });

    it("根路径游戏域 POST 兜底：/account、/user/checkIn、/batch_event 等 → gs 域", () => {
      expect(resolveForwardTarget("POST", "/account/login", "127.0.0.1:8443")?.baseUrl).toBe(OFFICIAL_GS_HOST);
      expect(resolveForwardTarget("POST", "/user/checkIn", "127.0.0.1:8443")?.baseUrl).toBe(OFFICIAL_GS_HOST);
      expect(resolveForwardTarget("POST", "/shop/getSkinGoodList", "127.0.0.1:8443")?.baseUrl).toBe(OFFICIAL_GS_HOST);
      expect(resolveForwardTarget("POST", "/batch_event", "127.0.0.1:8443")?.baseUrl).toBe(OFFICIAL_GS_HOST);
      // 裸根路径 POST 也兜底（对齐 test.ts 的 app.post("/*endpoint")）
      expect(resolveForwardTarget("POST", "/", "127.0.0.1:8443")?.baseUrl).toBe(OFFICIAL_GS_HOST);
    });

    it("本地挂载点 POST 不转发（/admin、/config、/api、/pcSdk、/assetbundle、/audit、/arkodc）", () => {
      expect(resolveForwardTarget("POST", "/admin/users", "127.0.0.1:8443")).toBeNull();
      expect(resolveForwardTarget("POST", "/config/foo", "127.0.0.1:8443")).toBeNull();
      expect(resolveForwardTarget("POST", "/api/game/get_latest", "127.0.0.1:8443")).toBeNull();
      expect(resolveForwardTarget("POST", "/pcSdk/whatever", "127.0.0.1:8443")).toBeNull();
      expect(resolveForwardTarget("POST", "/assetbundle/upload", "127.0.0.1:8443")).toBeNull();
      expect(resolveForwardTarget("POST", "/audit/official/x", "127.0.0.1:8443")).toBeNull();
      expect(resolveForwardTarget("POST", "/arkodc/odp", "127.0.0.1:8443")).toBeNull();
    });

    it("GET 非 as 路径不转发（/pcSdk、游戏 GET 保持本地响应）", () => {
      expect(resolveForwardTarget("GET", "/pcSdk/userInfo", "127.0.0.1:8443")).toBeNull();
      expect(resolveForwardTarget("GET", "/shop/getSkinGoodList", "127.0.0.1:8443")).toBeNull();
      expect(resolveForwardTarget("GET", "/config/prod/official/network_config", "127.0.0.1:8443")).toBeNull();
    });

    it("/asset 等相近前缀不被 /as 误判（startsWith 边界）", () => {
      const t = resolveForwardTarget("POST", "/assetbundle/download", "127.0.0.1:8443");
      expect(t).toBeNull();
    });
  });

  describe("主机覆写（opts.asHost/gsHost）", () => {
    it("自定义 as/gs 主机生效", () => {
      const opts = { asHost: "https://as.example.com", gsHost: "https://gs.example.com" };
      expect(resolveForwardTarget("POST", "/user/auth/v1/login", "127.0.0.1", opts)).toEqual({
        baseUrl: "https://as.example.com",
        path: "/user/auth/v1/login",
      });
      expect(resolveForwardTarget("POST", "/account/login", "127.0.0.1", opts)).toEqual({
        baseUrl: "https://gs.example.com",
        path: "/account/login",
      });
    });
  });

  describe("边界：query 与多斜杠归一化", () => {
    it("query 不参与路径匹配", () => {
      const t = resolveForwardTarget("POST", "/account/login?foo=1", "127.0.0.1");
      expect(t?.path).toBe("/account/login");
    });

    it("前导多斜杠归一化为单斜杠（防官服 // 404）", () => {
      const t = resolveForwardTarget("POST", "//shop/getSkinGoodList", "127.0.0.1");
      expect(t?.path).toBe("/shop/getSkinGoodList");
    });
  });
});
