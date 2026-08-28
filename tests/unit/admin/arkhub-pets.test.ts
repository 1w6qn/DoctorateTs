/**
 * 官服枢纽宠物还原（arkhub-pets.ts）：官服场景帧户籍提取 + 存档合并
 *
 * 背景：官服 playerdata 不含枢纽宠物（仅网关户籍持有）——导入官服账号时宠物
 * 从官服网关抓包的 EnterSceneNotify（PlayerSyncData.f5/f6）还原。
 */
import { describe, it, expect, afterEach, vi } from "vitest";
import { EventBus } from "@game/kernel/events/runtime";
import { mockPlayerData } from "../../helpers";
import {
  encodeFieldBytes as fb,
  encodeFieldVarint as fv,
} from "@ops/proxy/arkhub-gateway-codec";
import { parseGatewayStream } from "@ops/proxy/arkhub-gateway-protocol";
import {
  extractArkhubDocsFromSceneFrame,
  applyArkhubDocs,
  type ArkhubImportedDocs,
} from "@ops/admin/arkhub-pets";

afterEach(() => vi.clearAllMocks());

/** 合成官服 EnterSceneNotify 帧（f2.f5 CreatureData + f2.f6 ArkhubItemData） */
function buildSceneFrame(): Buffer {
  // creatures：19006（普通）×1 个体 + 19002（奥术绒绒=19001 亚种）×1 个体
  const creature1 = fb(1, Buffer.concat([fv(1, 53), fv(2, 19006), fv(3, 4), fv(5, BigInt(1786193736043))]));
  const creature2 = fb(1, Buffer.concat([fv(1, 7), fv(2, 19002), fv(3, 1), fv(5, BigInt(1786184316345))]));
  // collections：19001（星术绒绒，仅图鉴收录无个体）
  const collection1 = fb(2, Buffer.concat([fv(1, 19001), fv(3, 1)]));
  const creatureData = Buffer.concat([creature1, creature2, collection1]);
  // ArkhubItemData：coin=120 + 道具 5006×1
  const itemData = Buffer.concat([fv(1, 120), fb(2, Buffer.concat([fv(1, 5006), fv(2, 1)]))]);
  const sync = Buffer.concat([fb(5, creatureData), fb(6, itemData)]);
  const hall = Buffer.concat([fv(1, 110793), fv(3, 200)]);
  const payload = Buffer.concat([fb(1, hall), fb(2, sync)]);
  const header = Buffer.alloc(16);
  header.writeUInt32BE(payload.length + 16, 0);
  header.writeUInt32BE(8, 4);
  header.writeBigUInt64BE((BigInt("0x2c89b3") << BigInt(32)) | BigInt(0x38b37d3d), 8);
  return Buffer.concat([header, payload]);
}

function hubPlayer(overrides: Record<string, any> = {}) {
  const bus = new EventBus();
  const player = mockPlayerData({
    status: { uid: 1, nickName: "T", nickNumber: 0, level: 1, exp: 0 } as any,
    activity: { ARK_HUB: { act1arkhub: { coin: 0, ...overrides } } },
    tshop: { shop_act1arkhub: { coin: 0 } },
  });
  (player as any)._trigger = bus;
  return player;
}

describe("官服枢纽宠物还原（arkhub-pets）", () => {
  it("extractArkhubDocsFromSceneFrame：官服场景帧 → 图鉴/个体/道具/券（含亚种识别）", () => {
    const frames = parseGatewayStream(buildSceneFrame(), "down").frames;
    expect(frames.length).toBe(1);
    const docs = extractArkhubDocsFromSceneFrame(frames[0]);
    expect(docs).not.toBeNull();
    const d = docs as ArkhubImportedDocs;
    // 图鉴：个体种类 + 仅收录种类（19001），亚种标记正确（19002 是 19001 的亚种）
    expect(Object.keys(d.dex).sort()).toEqual(["19001", "19002", "19006"]);
    expect(d.dex["19002"].isAlter).toBe(true);
    expect(d.dex["19002"].alterOf).toBe(19001);
    expect(d.dex["19006"].isAlter).toBe(false);
    // 扫描仪个体：unique_id/template_id/persona 保留
    expect(d.scanBag).toHaveLength(2);
    expect(d.scanBag).toContainEqual(
      expect.objectContaining({ id: 53, numId: 19006, persona: 4 }),
    );
    // 道具箱与券
    expect(d.coin).toBe(120);
    expect(d.props["5006"]).toEqual({ count: 1, uses: 1 });
  });

  it("applyArkhubDocs：合并进存档（计数刷新 + sourceUid 标记）；幂等二次合并零新增", async () => {
    const frames = parseGatewayStream(buildSceneFrame(), "down").frames;
    const docs = extractArkhubDocsFromSceneFrame(frames[0])!;
    const player = hubPlayer();
    const first = await applyArkhubDocs(player as any, docs);
    expect(first).toEqual({ dexAdded: 3, bagAdded: 2 });
    const hub = (player._playerdata as any).activity.ARK_HUB.act1arkhub;
    expect(hub.creatureCollected).toBe(3);
    expect(hub.alterCollected).toBe(1); // 19002 亚种
    expect(hub.coin).toBe(120); // 券继承（官服 120 > 本地 0）
    expect(hub.scanBag.every((b: any) => b.sourceUid === "official")).toBe(true);
    // 二次合并：全部去重，零新增
    const second = await applyArkhubDocs(player as any, docs);
    expect(second).toEqual({ dexAdded: 0, bagAdded: 0 });
    expect((player._playerdata as any).activity.ARK_HUB.act1arkhub.scanBag).toHaveLength(2);
  });

  it("applyArkhubDocs：券取较大值不减少本地已有；道具数量取较大值", async () => {
    const frames = parseGatewayStream(buildSceneFrame(), "down").frames;
    const docs = extractArkhubDocsFromSceneFrame(frames[0])!;
    const player = hubPlayer({ coin: 500, props: { "5006": { count: 3, uses: 2 } } });
    await applyArkhubDocs(player as any, docs);
    const hub = (player._playerdata as any).activity.ARK_HUB.act1arkhub;
    expect(hub.coin).toBe(500); // 本地 500 > 官服 120，不减少
    expect(hub.props["5006"]).toEqual({ count: 3, uses: 2 }); // 本地更多，不覆盖
  });
});
