/**
 * 变换器管线测试（transform.ts）
 *
 * 覆盖：链式注册序执行、upstreamId 过滤、path 前缀/正则匹配、request/response 双向修改、
 * 内置 arkhub enterHall 响应变换器（改写 endpoint/port + 跟随网关目标）、reset 保留内置。
 */
import { describe, it, expect, beforeEach } from "vitest";

import {
  registerRequestTransform,
  registerResponseTransform,
  applyRequestTransforms,
  applyResponseTransforms,
  resetTransforms,
  setArkhubGatewayInfo,
  type ProxyTransformContext,
} from "@ops/proxy/transform";
import { getGatewayTarget } from "@game/modules/activities/arkhub/public";

/** 构造最小变换上下文（path/upstream 等可覆写） */
function makeCtx(partial: Partial<ProxyTransformContext> = {}): ProxyTransformContext {
  return {
    method: "POST",
    originalUrl: "/shop/getSkinGoodList",
    path: "/shop/getSkinGoodList",
    upstream: { id: "official-gs", baseUrl: "https://ak-gs-gf.hypergryph.com", rules: [] },
    headers: { "content-type": "application/json" },
    body: { itemId: 1 },
    status: 200,
    responseBody: { ok: true },
    ...partial,
  };
}

describe("变换器管线（transform.ts）", () => {
  beforeEach(() => {
    resetTransforms();
    setArkhubGatewayInfo(null);
  });

  it("链式按注册序执行，前一规则输出喂给后一规则输入", async () => {
    const order: string[] = [];
    registerRequestTransform({
      path: "/shop",
      fn: (ctx) => {
        order.push("1");
        ctx.headers = { ...ctx.headers, "x-step": "1" };
        return ctx;
      },
    });
    registerRequestTransform({
      path: "/shop",
      fn: (ctx) => {
        order.push("2");
        // 读取上一规则写入的头
        ctx.headers = { ...ctx.headers, "x-chained": ctx.headers["x-step"] };
        return ctx;
      },
    });
    const ctx = makeCtx();
    await applyRequestTransforms(ctx);
    expect(order).toEqual(["1", "2"]);
    expect(ctx.headers["x-chained"]).toBe("1");
  });

  it("upstreamId 过滤：仅命中指定上游，其它上游不执行", async () => {
    const hits: string[] = [];
    registerRequestTransform({
      upstreamId: "official-as",
      path: "/shop",
      fn: (ctx) => {
        hits.push("hit");
        return ctx;
      },
    });
    // gs 上游 → 不命中
    await applyRequestTransforms(makeCtx());
    expect(hits).toEqual([]);
    // as 上游 → 命中
    await applyRequestTransforms(makeCtx({ upstream: { id: "official-as", baseUrl: "https://as.hypergryph.com", rules: [] } }));
    expect(hits).toEqual(["hit"]);
  });

  it("upstreamId 缺省 = 任意上游", async () => {
    const hits: string[] = [];
    registerResponseTransform({
      path: "/shop",
      fn: (ctx) => {
        hits.push(ctx.upstream.id);
        return ctx;
      },
    });
    await applyResponseTransforms(makeCtx());
    await applyResponseTransforms(makeCtx({ upstream: { id: "custom-x", baseUrl: "https://x", rules: [] } }));
    expect(hits).toEqual(["official-gs", "custom-x"]);
  });

  it("path 字符串前缀匹配（/activity 命中 /activity/arkhub/enterHall）", async () => {
    const hits: string[] = [];
    registerRequestTransform({
      path: "/activity",
      fn: (ctx) => {
        hits.push(ctx.path);
        return ctx;
      },
    });
    await applyRequestTransforms(makeCtx({ path: "/activity/arkhub/enterHall" }));
    await applyRequestTransforms(makeCtx({ path: "/shop/getSkinGoodList" }));
    expect(hits).toEqual(["/activity/arkhub/enterHall"]);
  });

  it("path 正则匹配（/^\\/shop\\/v\\d+/ 命中 /shop/v2/foo，不命中 /shop/plain）", async () => {
    const hits: string[] = [];
    registerResponseTransform({
      path: /^\/shop\/v\d+/,
      fn: (ctx) => {
        hits.push(ctx.path);
        return ctx;
      },
    });
    await applyResponseTransforms(makeCtx({ path: "/shop/v2/foo" }));
    await applyResponseTransforms(makeCtx({ path: "/shop/plain" }));
    expect(hits).toEqual(["/shop/v2/foo"]);
  });

  it("request 变换器可修改 headers 与 body（影响后续转发）", async () => {
    registerRequestTransform({
      fn: (ctx) => {
        ctx.headers = { ...ctx.headers, "x-custom": "1" };
        ctx.body = { itemId: 2, injected: true };
        return ctx;
      },
    });
    const ctx = makeCtx();
    await applyRequestTransforms(ctx);
    expect(ctx.headers["x-custom"]).toBe("1");
    expect(ctx.body).toEqual({ itemId: 2, injected: true });
  });

  it("response 变换器可修改 status 与 responseBody（影响回写）", async () => {
    registerResponseTransform({
      path: "/shop",
      fn: (ctx) => {
        ctx.status = 201;
        ctx.responseBody = { patched: true };
        return ctx;
      },
    });
    const ctx = makeCtx();
    await applyResponseTransforms(ctx);
    expect(ctx.status).toBe(201);
    expect(ctx.responseBody).toEqual({ patched: true });
  });

  it("变换器异常向上抛出（转发流程终止，由 forwarder 兜底）", async () => {
    registerRequestTransform({
      fn: () => {
        throw new Error("transform boom");
      },
    });
    await expect(applyRequestTransforms(makeCtx())).rejects.toThrow("transform boom");
  });

  describe("内置 enterHall 响应变换器", () => {
    it("有 arkhubGatewayInfo → 改写 endpoint/port 指向代理 + 跟随官服网关目标", async () => {
      setArkhubGatewayInfo({ endpoint: "127.0.0.1", port: 30000 });
      const ctx = makeCtx({
        path: "/activity/arkhub/enterHall",
        responseBody: {
          result: 0,
          endpoint: "arkhub-gateway-canary.hypergryph.com",
          port: 30000,
          playerDataDelta: { modified: {}, deleted: {} },
        },
      });
      await applyResponseTransforms(ctx);
      // 改写为代理地址
      expect(ctx.responseBody).toEqual({
        result: 0,
        endpoint: "127.0.0.1",
        port: 30000,
        playerDataDelta: { modified: {}, deleted: {} },
      });
      // 同时动态更新 TCP 转发器目标（跟随官服 canary 域名）
      expect(getGatewayTarget()).toEqual({ host: "arkhub-gateway-canary.hypergryph.com", port: 30000 });
    });

    it("无 arkhubGatewayInfo → 不改写 body 但仍更新网关目标", async () => {
      const body = {
        result: 0,
        endpoint: "arkhub-gateway-canary.hypergryph.com",
        port: 30000,
        playerDataDelta: {},
      };
      const ctx = makeCtx({ path: "/activity/arkhub/enterHall", responseBody: body });
      await applyResponseTransforms(ctx);
      expect(ctx.responseBody).toBe(body); // 原样（同一对象引用）
      expect(getGatewayTarget().host).toBe("arkhub-gateway-canary.hypergryph.com");
    });

    it("非 enterHall 路径不改写（syncInfo 保持原样）", async () => {
      const body = { playerDataDelta: {} };
      const ctx = makeCtx({ path: "/activity/arkhub/syncInfo", responseBody: body });
      await applyResponseTransforms(ctx);
      expect(ctx.responseBody).toBe(body);
    });
  });

  it("resetTransforms 清除自定义变换器但保留内置 enterHall", async () => {
    const hits: string[] = [];
    registerResponseTransform({
      path: "/custom",
      fn: (ctx) => {
        hits.push("custom");
        return ctx;
      },
    });
    await applyResponseTransforms(makeCtx({ path: "/custom" }));
    expect(hits).toEqual(["custom"]);
    resetTransforms();
    // 自定义已被清除
    await applyResponseTransforms(makeCtx({ path: "/custom" }));
    expect(hits).toEqual(["custom"]);
    // 内置 enterHall 仍在
    const ctx = makeCtx({ path: "/activity/arkhub/enterHall", responseBody: { endpoint: "e.example.com", port: 30000 } });
    await applyResponseTransforms(ctx);
    expect(getGatewayTarget().host).toBe("e.example.com");
  });
});
