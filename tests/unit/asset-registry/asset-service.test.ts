import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as path from "path";
import * as os from "os";
import * as fs from "fs";
import { assetRegistry } from "@asset/asset-service";

/** 测试专用独立临时目录——绝不碰真实 tmp/asset/ */
const TEST_ROOT = path.join(os.tmpdir(), "asset-registry-test");

beforeEach(() => {
  assetRegistry.reset();
  assetRegistry.configure({ root: TEST_ROOT });
});

afterEach(() => {
  assetRegistry.reset();
  if (fs.existsSync(TEST_ROOT)) fs.rmSync(TEST_ROOT, { recursive: true, force: true });
});

describe("assetRegistry（一体化资产注册表）", () => {
  it("register 幂等：同 key 重复注册只保留一条资产", async () => {
    await assetRegistry.init();
    const input = {
      name: "hot_update_list.json",
      category: "manifest" as const,
      source: "https://ak.hycdn.cn/hul",
      version: "v1",
      hash: "abc",
      size: 10,
    };
    await assetRegistry.register(input);
    await assetRegistry.register({ ...input, hash: "def", size: 20 });
    const { items, total } = await assetRegistry.listAssets();
    expect(total).toBe(1);
    expect(items[0].hash).toBe("def");
    expect(items[0].size).toBe(20);
  });

  it("register 不同 version 视为不同资产", async () => {
    await assetRegistry.init();
    await assetRegistry.register({ name: "x", category: "excel", version: "v1" });
    await assetRegistry.register({ name: "x", category: "excel", version: "v2" });
    const { total } = await assetRegistry.listAssets({ category: "excel" });
    expect(total).toBe(2);
  });

  it("recordEvent 写入资产 + 事件，并广播给订阅者", async () => {
    await assetRegistry.init();
    const seen: string[] = [];
    const unsub = assetRegistry.subscribe((e) => seen.push(e.action));

    await assetRegistry.recordEvent({
      asset: { name: "hot_update_list.json", category: "manifest", version: "v1" },
      action: "acquire",
      actor: "asset-router",
      source: "https://ak.hycdn.cn/hul",
      version: "v1",
    });
    await assetRegistry.recordEvent({
      asset: { name: "hot_update_list.json", category: "manifest", version: "v1" },
      action: "deliver",
      actor: "asset-router",
      source: "mod-inject",
      detail: { abInfos: 14983 },
    });

    expect(seen).toEqual(["acquire", "deliver"]);

    const { asset, events } = await assetRegistry.getAssetLineage("hot_update_list.json");
    expect(asset?.name).toBe("hot_update_list.json");
    expect(events.map((e) => e.action)).toEqual(["acquire", "deliver"]);
    expect(events[0].actor).toBe("asset-router");
    expect(JSON.parse(events[1].detail!)).toEqual({ abInfos: 14983 });
    unsub();
  });

  it("recordEvent 缺失资产时自动注册", async () => {
    await assetRegistry.init();
    await assetRegistry.recordEvent({
      asset: { name: "config.version", category: "version", version: "26-08-07-10-51-39" },
      action: "modify",
      actor: "update-data",
      hashBefore: "a",
      hashAfter: "b",
    });
    const { asset } = await assetRegistry.getAssetLineage("config.version");
    expect(asset).not.toBeNull();
    const { items } = await assetRegistry.listEvents({ action: "modify" });
    expect(items.length).toBe(1);
    expect(items[0].hashBefore).toBe("a");
    expect(items[0].hashAfter).toBe("b");
  });

  it("listAssets 支持分类与名称模糊过滤", async () => {
    await assetRegistry.init();
    await assetRegistry.register({ name: "hot_update_list.json", category: "manifest" });
    await assetRegistry.register({ name: "char_table.json", category: "excel" });
    await assetRegistry.register({ name: "foo.dat", category: "mod" });

    const { total } = await assetRegistry.listAssets({ category: "excel" });
    expect(total).toBe(1);
    const named = await assetRegistry.listAssets({ name: "hot" });
    expect(named.total).toBe(1);
  });

  it("写入失败静默降级：坏 dbPath 时 recordEvent 不抛错、不阻断", async () => {
    // dbPath 指向一个已存在的目录 → 打开失败，校验 no-throw 契约
    const badDir = path.join(os.tmpdir(), "asset-baddb-" + Date.now());
    fs.mkdirSync(badDir, { recursive: true });
    try {
      assetRegistry.reset();
      assetRegistry.configure({ root: TEST_ROOT, dbPath: badDir });
      await expect(
        assetRegistry.recordEvent({
          asset: { name: "x", category: "file", version: "v1" },
          action: "acquire",
        }),
      ).resolves.toBeUndefined();
      // 查询在坏库下也返回空而不抛
      const r = await assetRegistry.listAssets();
      expect(r.total).toBe(0);
    } finally {
      fs.rmSync(badDir, { recursive: true, force: true });
    }
  });
});