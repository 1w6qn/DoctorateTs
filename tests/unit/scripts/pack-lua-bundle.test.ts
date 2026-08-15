/**
 * pack-lua-bundle 重打包器单测：打包 → 现有解包器回读，验证往返一致。
 */
import { describe, expect, it } from "vitest";
import {
  buildSerializedFile,
  buildUnityFS,
  packLuaBundle,
  buildDat,
  type LuaAsset,
} from "../../../scripts/pack-lua-bundle";
import { extractTextAsset } from "../../../scripts/vendor/unityfs";
import JSZip from "jszip";

/** 构造受控 Lua 资产列表 */
function sampleAssets(): LuaAsset[] {
  return [
    { name: "gamedata/[uc]lua/entry.lua", script: Buffer.from("EntryTable = {}\n") },
    { name: "gamedata/[uc]lua/GlobalConfig.lua", script: Buffer.from("GlobalConfig = { CUR_FUNC_VER = \"V075\" }\n") },
    { name: "gamedata/[uc]lua/feature/TestHotfixer.lua", script: Buffer.from("local M = {}\nreturn M\n") },
  ];
}

describe("pack-lua-bundle 重打包器", () => {
  it("单 asset：SerializedFile → UnityFS → 解包回读一致", () => {
    const asset = { name: "gamedata/[uc]lua/entry.lua", script: Buffer.from("EntryTable = {}\n") };
    const sf = buildSerializedFile([asset]);
    const uf = buildUnityFS(sf);
    // UnityFS 头可识别
    expect(Buffer.from(uf.subarray(0, 8)).toString("utf8")).toContain("UnityFS");
    // 解包回读
    const ta = extractTextAsset(uf);
    expect(ta).not.toBeNull();
    expect(ta!.name).toBe(asset.name);
    expect(Buffer.from(ta!.script)).toEqual(asset.script);
  });

  it("多 asset：packLuaBundle 整体可被解包器解析（非 null）", () => {
    const uf = packLuaBundle(sampleAssets());
    const ta = extractTextAsset(uf);
    expect(ta).not.toBeNull();
  });

  it("buildDat 产出官方 .dat（zip 单条目，条目名=bundle 路径）", async () => {
    const assets = sampleAssets();
    const uf = packLuaBundle(assets);
    const bundlePath = "anon/7d91430e114d86fef7d3b3511151e12d.bin";
    const dat = await buildDat(uf, bundlePath);
    // .dat 是 zip，可被 JSZip 解出单条目
    const zip = await JSZip.loadAsync(Buffer.from(dat));
    const entries = Object.keys(zip.files);
    expect(entries).toHaveLength(1);
    expect(entries[0]).toBe(bundlePath);
    // 条目内为可解析的 UnityFS
    const inner = await zip.files[bundlePath].async("uint8array");
    const ta = extractTextAsset(inner);
    expect(ta).not.toBeNull();
  });

  it("空资产列表抛错", () => {
    expect(() => buildSerializedFile([])).toThrow("至少需要 1 条 Lua 资产");
  });
});