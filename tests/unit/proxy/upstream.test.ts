/**
 * 上游解析与注册表测试（upstream.ts）
 *
 * 语义基线：从 official-forward.test.ts 的 resolveForwardTarget 全量迁移——
 * Host 优先分发 / 路径级兜底 / 本地挂载点排除 / 主机覆写 / query 与多斜杠归一化。
 * 新增：自定义上游优先于官方兜底、注册表 API（register/unregister/list/reset）、
 *       host 通配匹配、每规则独立 stripPrefix。
 */
import { describe, it, expect, beforeEach } from "vitest";

import {
  resolveProxyTarget,
  buildOfficialUpstreams,
  registerUpstream,
  registerUpstreams,
  unregisterUpstream,
  listUpstreams,
  resolveAllUpstreams,
  resetUpstreams,
  OFFICIAL_AS_HOST,
  OFFICIAL_GS_HOST,
  type ProxyUpstream,
} from "@ops/proxy/upstream";

const official = () => buildOfficialUpstreams({});

/** 便捷：官方上游表 + 自定义上游（模拟 resolveAllUpstreams 的求值序：自定义在前） */
function withCustom(custom: ProxyUpstream[]) {
  return [...custom, ...official()];
}

describe("resolveProxyTarget（官方内置上游语义迁移）", () => {
  describe("Host 优先分发（客户端 hosts 指向私服、保留官服子域名）", () => {
    it("as.hypergryph.com → as 域，路径原样", () => {
      const t = resolveProxyTarget("POST", "/user/auth/v1/token_by_phone_password", "as.hypergryph.com", official());
      expect(t).toMatchObject({ baseUrl: OFFICIAL_AS_HOST, path: "/user/auth/v1/token_by_phone_password" });
    });

    it("as.hypergryph.com 的 GET 用户信息 → as 域", () => {
      const t = resolveProxyTarget("GET", "/user/info/v1/basic", "as.hypergryph.com", official());
      expect(t?.baseUrl).toBe(OFFICIAL_AS_HOST);
    });

    it("as.*.hypergryph.com 通配子域（mitmweb 等）→ as 域", () => {
      const t = resolveProxyTarget("POST", "/user/auth/v1/login", "as.jp.hypergryph.com", official());
      expect(t?.baseUrl).toBe(OFFICIAL_AS_HOST);
    });

    it("ak-gs-gf.hypergryph.com → gs 域，路径原样（官服游戏路径无 /game 基址）", () => {
      const t = resolveProxyTarget("POST", "/account/login", "ak-gs-gf.hypergryph.com", official());
      expect(t).toMatchObject({ baseUrl: OFFICIAL_GS_HOST, path: "/account/login" });
    });

    it("ak-gs-* 带 /game 基址前缀 → 剥前缀到 gs 域", () => {
      const t = resolveProxyTarget("POST", "/game/account/login", "ak-gs-gf.hypergryph.com", official());
      expect(t).toMatchObject({ baseUrl: OFFICIAL_GS_HOST, path: "/account/login" });
    });

    it("ak-conf.hypergryph.com（配置域）→ 不转发（保持本地引导）", () => {
      const t = resolveProxyTarget("GET", "/config/prod/official/network_config", "ak-conf.hypergryph.com", official());
      expect(t).toBeNull();
    });

    it("game-config.hypergryph.com（新版配置域）→ 不转发", () => {
      const t = resolveProxyTarget("GET", "/api/remote_config/1/prod/default/Windows/network_config", "game-config.hypergryph.com", official());
      expect(t).toBeNull();
    });

    it("其余官方子域（ak.hypergryph.com）→ 不转发", () => {
      const t = resolveProxyTarget("GET", "/protocol/service", "ak.hypergryph.com", official());
      expect(t).toBeNull();
    });
  });

  describe("路径级兜底（Host 非官服：127.0.0.1 直连 / mitmweb 重写）", () => {
    it("/user/auth/* → as 域", () => {
      const t = resolveProxyTarget("POST", "/user/auth/v1/token_by_phone_password", "127.0.0.1:8443", official());
      expect(t).toMatchObject({ baseUrl: OFFICIAL_AS_HOST, path: "/user/auth/v1/token_by_phone_password" });
    });

    it("/user/info/*、/user/online/*、/user/oauth2/* → as 域", () => {
      expect(resolveProxyTarget("GET", "/user/info/v1/basic", "127.0.0.1:8443", official())?.baseUrl).toBe(OFFICIAL_AS_HOST);
      expect(resolveProxyTarget("POST", "/user/online/v1/loginout", "127.0.0.1:8443", official())?.baseUrl).toBe(OFFICIAL_AS_HOST);
      expect(resolveProxyTarget("POST", "/user/oauth2/v2/grant", "127.0.0.1:8443", official())?.baseUrl).toBe(OFFICIAL_AS_HOST);
    });

    it("/u8/* → as 域，路径含 /u8 原样（baseUrl 不拼 /u8，避免双写）", () => {
      const t = resolveProxyTarget("POST", "/u8/user/v1/getToken", "127.0.0.1:8443", official());
      expect(t).toMatchObject({ baseUrl: OFFICIAL_AS_HOST, path: "/u8/user/v1/getToken" });
      // 中间件最终转发 URL = baseUrl + "/" + path（去前导斜杠），验证不出现 //u8//u8 双写
      const endpoint = (t?.path ?? "").replace(/^\/+/, "");
      expect(`${t?.baseUrl}/${endpoint}`).toBe(`${OFFICIAL_AS_HOST}/u8/user/v1/getToken`);
    });

    it("/app/*、/general/* → as 域（GET 也转发）", () => {
      expect(resolveProxyTarget("GET", "/app/v1/config", "127.0.0.1:8443", official())?.baseUrl).toBe(OFFICIAL_AS_HOST);
      expect(resolveProxyTarget("GET", "/general/v1/server_time", "127.0.0.1:8443", official())?.baseUrl).toBe(OFFICIAL_AS_HOST);
    });

    it("/as/* 路径化前缀 → 剥 /as 到 as 域", () => {
      const t = resolveProxyTarget("POST", "/as/user/auth/v1/register", "127.0.0.1:8443", official());
      expect(t).toMatchObject({ baseUrl: OFFICIAL_AS_HOST, path: "/user/auth/v1/register" });
    });

    it("/game/* → 剥 /game 到 gs 域（POST/GET 均转发）", () => {
      expect(resolveProxyTarget("POST", "/game/account/login", "127.0.0.1:8443", official())).toMatchObject({
        baseUrl: OFFICIAL_GS_HOST,
        path: "/account/login",
      });
      expect(resolveProxyTarget("GET", "/game/activity/getActivityList", "127.0.0.1:8443", official())).toMatchObject({
        baseUrl: OFFICIAL_GS_HOST,
        path: "/activity/getActivityList",
      });
    });

    it("根路径游戏域 POST 兜底：/account、/user/checkIn、/shop 等 → gs 域", () => {
      expect(resolveProxyTarget("POST", "/account/login", "127.0.0.1:8443", official())?.baseUrl).toBe(OFFICIAL_GS_HOST);
      expect(resolveProxyTarget("POST", "/user/checkIn", "127.0.0.1:8443", official())?.baseUrl).toBe(OFFICIAL_GS_HOST);
      expect(resolveProxyTarget("POST", "/shop/getSkinGoodList", "127.0.0.1:8443", official())?.baseUrl).toBe(OFFICIAL_GS_HOST);
      // 裸根路径 POST 也兜底（对齐 test.ts 的 app.post("/*endpoint")）
      expect(resolveProxyTarget("POST", "/", "127.0.0.1:8443", official())?.baseUrl).toBe(OFFICIAL_GS_HOST);
    });

    it("/batch_event 不转发（事件上报由私服 home.ts 返回 {} 即可），路径与 Host 两种模式都保持本地", () => {
      // 全局守卫：LOCAL_ONLY_PREFIXES 命中即 null（路径级与 Host 级统一）
      expect(resolveProxyTarget("POST", "/batch_event", "127.0.0.1:8443", official())).toBeNull();
      expect(resolveProxyTarget("POST", "/batch_event", "ak-gs-gf.hypergryph.com", official())).toBeNull();
      expect(resolveProxyTarget("POST", "/admin/users", "ak-gs-gf.hypergryph.com", official())).toBeNull();
      expect(resolveProxyTarget("POST", "/pcSdk/userInfo", "ak-gs-gf.hypergryph.com", official())).toBeNull();
    });

    it("本地挂载点 POST 不转发（/admin、/config、/api、/pcSdk、/assetbundle、/audit）", () => {
      expect(resolveProxyTarget("POST", "/admin/users", "127.0.0.1:8443", official())).toBeNull();
      expect(resolveProxyTarget("POST", "/config/foo", "127.0.0.1:8443", official())).toBeNull();
      expect(resolveProxyTarget("POST", "/api/game/get_latest", "127.0.0.1:8443", official())).toBeNull();
      expect(resolveProxyTarget("POST", "/pcSdk/whatever", "127.0.0.1:8443", official())).toBeNull();
      expect(resolveProxyTarget("POST", "/assetbundle/upload", "127.0.0.1:8443", official())).toBeNull();
      expect(resolveProxyTarget("POST", "/audit/official/x", "127.0.0.1:8443", official())).toBeNull();
    });

    it("/arkodc（act53side ODC 小游戏路由）转发官服 gs——OBS 路由即从官服逆向，须抓真实响应", () => {
      expect(resolveProxyTarget("POST", "/arkodc/odp", "127.0.0.1:8443", official())?.baseUrl).toBe(OFFICIAL_GS_HOST);
      expect(resolveProxyTarget("POST", "/arkodc/battleStart", "127.0.0.1:8443", official())?.baseUrl).toBe(OFFICIAL_GS_HOST);
    });

    it("GET 非 as 路径不转发（/pcSdk、游戏 GET 保持本地响应）", () => {
      expect(resolveProxyTarget("GET", "/pcSdk/userInfo", "127.0.0.1:8443", official())).toBeNull();
      expect(resolveProxyTarget("GET", "/shop/getSkinGoodList", "127.0.0.1:8443", official())).toBeNull();
      expect(resolveProxyTarget("GET", "/config/prod/official/network_config", "127.0.0.1:8443", official())).toBeNull();
    });

    it("/asset 等相近前缀不被 /as 误判（startsWith 边界）", () => {
      const t = resolveProxyTarget("POST", "/assetbundle/download", "127.0.0.1:8443", official());
      expect(t).toBeNull();
    });
  });

  describe("主机覆写（buildOfficialUpstreams opts）", () => {
    it("自定义 as/gs 主机生效", () => {
      const opts = { asHost: "https://as.example.com", gsHost: "https://gs.example.com" };
      expect(resolveProxyTarget("POST", "/user/auth/v1/login", "127.0.0.1", buildOfficialUpstreams(opts))).toMatchObject({
        baseUrl: "https://as.example.com",
        path: "/user/auth/v1/login",
      });
      expect(resolveProxyTarget("POST", "/account/login", "127.0.0.1", buildOfficialUpstreams(opts))).toMatchObject({
        baseUrl: "https://gs.example.com",
        path: "/account/login",
      });
    });

    it("opts.asPathPrefixes 额外前缀 → as 域（yostar 登录链路）", () => {
      const opts = {
        asHost: "https://as.example.jp",
        gsHost: "https://gs.example.jp",
        asPathPrefixes: ["/account/yostar_auth_request", "/user/yostar_createlogin", "/yostar/get-auth"],
      };
      expect(resolveProxyTarget("POST", "/account/yostar_auth_request", "127.0.0.1", buildOfficialUpstreams(opts))).toMatchObject({
        baseUrl: "https://as.example.jp",
        path: "/account/yostar_auth_request",
      });
      expect(resolveProxyTarget("POST", "/yostar/get-auth", "127.0.0.1", buildOfficialUpstreams(opts))).toMatchObject({
        baseUrl: "https://as.example.jp",
        path: "/yostar/get-auth",
      });
    });

    it("未传 asPathPrefixes → 默认列表行为不变（/account/login 仍走 gs 兜底）", () => {
      const opts = { asHost: "https://as.example.jp", gsHost: "https://gs.example.jp" };
      expect(resolveProxyTarget("POST", "/account/login", "127.0.0.1", buildOfficialUpstreams(opts))).toMatchObject({
        baseUrl: "https://gs.example.jp",
        path: "/account/login",
      });
    });
  });

  describe("边界：query 与多斜杠归一化", () => {
    it("query 不参与路径匹配", () => {
      const t = resolveProxyTarget("POST", "/account/login?foo=1", "127.0.0.1", official());
      expect(t?.path).toBe("/account/login");
    });

    it("前导多斜杠归一化为单斜杠（防官服 // 404）", () => {
      const t = resolveProxyTarget("POST", "//shop/getSkinGoodList", "127.0.0.1", official());
      expect(t?.path).toBe("/shop/getSkinGoodList");
    });
  });
});

describe("自定义上游（config/API 注册）", () => {
  it("自定义上游命中优先于官方 gs POST 兜底（/arkodc → 自建 OBS）", () => {
    const custom: ProxyUpstream = {
      id: "obs-arkodc",
      baseUrl: "https://obs.example.com",
      rules: [{ paths: ["/arkodc"] }],
    };
    const t = resolveProxyTarget("POST", "/arkodc/odp", "127.0.0.1", withCustom([custom]));
    expect(t?.baseUrl).toBe("https://obs.example.com");
    expect(t?.upstream.id).toBe("obs-arkodc");
  });

  it("自定义上游不命中时回落到官方兜底", () => {
    const custom: ProxyUpstream = {
      id: "obs-arkodc",
      baseUrl: "https://obs.example.com",
      rules: [{ paths: ["/arkodc"] }],
    };
    expect(resolveProxyTarget("POST", "/account/login", "127.0.0.1", withCustom([custom]))?.baseUrl).toBe(OFFICIAL_GS_HOST);
    expect(resolveProxyTarget("POST", "/user/auth/v1/login", "127.0.0.1", withCustom([custom]))?.baseUrl).toBe(OFFICIAL_AS_HOST);
  });

  it("自定义 host 通配匹配（my-*.example.com），非命中保持官方行为", () => {
    const custom: ProxyUpstream = {
      id: "my",
      baseUrl: "https://my.example.com",
      rules: [{ hosts: ["my-*.example.com"] }],
    };
    expect(resolveProxyTarget("POST", "/account/login", "my-gs.example.com", withCustom([custom]))?.baseUrl).toBe("https://my.example.com");
    expect(resolveProxyTarget("POST", "/account/login", "other.example.com", withCustom([custom]))?.baseUrl).toBe(OFFICIAL_GS_HOST);
  });

  it("自定义 host 规则优先于官方 host 规则（同 host 族覆写为目标）", () => {
    const custom: ProxyUpstream = {
      id: "as-mirror",
      baseUrl: "https://mirror.example.com",
      rules: [{ hosts: ["as.*.hypergryph.com"] }],
    };
    // 自定义在前 → 通配 as.* 命中 mirror；官方 official-as 规则不参与求值
    const t = resolveProxyTarget("POST", "/user/auth/v1/login", "as.mirror.hypergryph.com", withCustom([custom]));
    expect(t?.baseUrl).toBe("https://mirror.example.com");
    // 自定义未覆盖的裸 as 主机 → 官方 official-as 字面规则
    const t2 = resolveProxyTarget("POST", "/user/auth/v1/login", "as.hypergryph.com", withCustom([custom]));
    expect(t2?.baseUrl).toBe(OFFICIAL_AS_HOST);
  });

  it("同上游多规则各自独立 stripPrefix", () => {
    const custom: ProxyUpstream = {
      id: "dual",
      baseUrl: "https://dual.example.com",
      rules: [
        { paths: ["/game"], stripPrefix: "/game" },
        { paths: ["/cdn"], stripPrefix: "/cdn" },
      ],
    };
    expect(resolveProxyTarget("POST", "/game/foo", "127.0.0.1", withCustom([custom]))?.path).toBe("/foo");
    expect(resolveProxyTarget("POST", "/cdn/bar", "127.0.0.1", withCustom([custom]))?.path).toBe("/bar");
  });

  it("methods 过滤：自定义规则仅 GET 命中时 POST 回落官方兜底", () => {
    const custom: ProxyUpstream = {
      id: "get-only",
      baseUrl: "https://get.example.com",
      rules: [{ paths: ["/stats"], methods: ["GET"] }],
    };
    expect(resolveProxyTarget("GET", "/stats", "127.0.0.1", withCustom([custom]))?.baseUrl).toBe("https://get.example.com");
    // 自定义拒绝 POST → 不转发到自定义，回落官方 gs POST 兜底
    expect(resolveProxyTarget("POST", "/stats", "127.0.0.1", withCustom([custom]))?.baseUrl).toBe(OFFICIAL_GS_HOST);
  });

  it("自定义 catchAll 可接管所有未命中 POST（覆盖官方 gs 兜底）", () => {
    const custom: ProxyUpstream = {
      id: "everything",
      baseUrl: "https://all.example.com",
      rules: [{ catchAll: true, methods: ["POST"] }],
    };
    expect(resolveProxyTarget("POST", "/whatever/path", "127.0.0.1", withCustom([custom]))?.baseUrl).toBe("https://all.example.com");
    // GET 仍不转发（官方 GET 非 as 保持本地）
    expect(resolveProxyTarget("GET", "/whatever/path", "127.0.0.1", withCustom([custom]))).toBeNull();
  });
});

describe("注册表 API（registerUpstream / registerUpstreams / unregister / list / reset）", () => {
  beforeEach(() => {
    resetUpstreams();
  });

  it("registerUpstream 单条注册 → listUpstreams 可见且自定义在前", () => {
    registerUpstream({ id: "x", baseUrl: "https://x.example.com", rules: [{ paths: ["/x"] }] });
    const all = listUpstreams();
    expect(all[0].id).toBe("x");
    expect(resolveAllUpstreams()[0].id).toBe("x");
  });

  it("registerUpstreams 批量注册 + 同名 id 幂等覆盖（不重复）", () => {
    registerUpstreams([
      { id: "x", baseUrl: "https://a.example.com", rules: [{ paths: ["/x"] }] },
      { id: "y", baseUrl: "https://b.example.com", rules: [{ paths: ["/y"] }] },
    ]);
    registerUpstreams([{ id: "x", baseUrl: "https://a2.example.com", rules: [{ paths: ["/x"] }] }]);
    const xs = listUpstreams().filter((u) => u.id === "x");
    expect(xs).toHaveLength(1);
    expect(xs[0].baseUrl).toBe("https://a2.example.com");
  });

  it("unregisterUpstream 命中返回 true，未命中返回 false", () => {
    registerUpstream({ id: "x", baseUrl: "https://x.example.com", rules: [] });
    expect(unregisterUpstream("x")).toBe(true);
    expect(unregisterUpstream("x")).toBe(false);
    expect(listUpstreams().some((u) => u.id === "x")).toBe(false);
  });

  it("resetUpstreams 清空自定义（官方内置不受影响）", () => {
    registerUpstream({ id: "x", baseUrl: "https://x.example.com", rules: [] });
    resetUpstreams();
    expect(listUpstreams()).toHaveLength(0);
    // 官方内置经 buildOfficialUpstreams 独立构建，不受注册表影响
    expect(official().map((u) => u.id)).toEqual(["official-as", "official-gs"]);
  });

  it("buildOfficialUpstreams 输出官方两条内置上游", () => {
    const list = official();
    expect(list.map((u) => u.id)).toEqual(["official-as", "official-gs"]);
    expect(list[0].baseUrl).toBe(OFFICIAL_AS_HOST);
    expect(list[1].baseUrl).toBe(OFFICIAL_GS_HOST);
  });
});
