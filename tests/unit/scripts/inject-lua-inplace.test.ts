/**
 * inject-lua-inplace 在位注入器单测。
 *
 * 校验两处重量级不变量（决定注入成败）：
 *   1. `padTo` 把明文补到目标长度后，`encryptLuaScript` 输出密文长度与原内容长度一致
 *      （AES-CBC + PKCS7，100% 保证结构零改动所需的字节级长度保持）。
 *   2. `buildUnityFSUncompressed`（mode0 无压缩 wrapper）可被 `unityfsToSF` 完整回读，
 *      且 SerializedFile 内容字节不变 —— 证明 wrapper 自洽、无损坏。
 * 官方 bundle 为 gitignored 的运行期依赖（reference/），故不依赖真实文件，仅测纯函数。
 */
import { describe, expect, it } from "vitest";
import { encryptLuaScript, decryptLuaScript } from "../../../scripts/vendor/lua-crypt";
import {
  padTo,
  plainBudget,
  buildUnityFSCompressed,
  unityfsToSF,
} from "../../../scripts/inject-lua-inplace";

/** 原内容密文长度（取官方 TestStubHotfixer 密文长度） */
const ORIG_ENC_LEN = 496;

describe("inject-lua-inplace 长度保持不变量", () => {
  it("padTo 产出的明文加密后密文长度 == 原内容长度", () => {
    // 构造一段真实的引导明文（足以包含 return，模拟注入产物）
    const base =
      'local T=Class("T",HotfixBase)\n' +
      "function T:OnInit()\n" +
      '  local p=CS.UnityEngine.Application.persistentDataPath.."/plugin_boot_trace.txt"\n' +
      '  CS.Torappu.FileUtil.WriteToFile("i",p,true)\n' +
      "end\n" +
      "return T\n";
    const budget = plainBudget(ORIG_ENC_LEN);
    expect(budget).toBe(ORIG_ENC_LEN - 145);
    // 明文按预算补足
    const padded = padTo(base, budget);
    expect(Buffer.byteLength(padded, "utf8")).toBe(budget);
    // 加密后长度必须与原长度精确一致（核心不变量）
    const enc = Buffer.from(encryptLuaScript(Buffer.from(padded, "utf8")));
    expect(enc.length).toBe(ORIG_ENC_LEN);
    // 回解得到原明文（含注入内容）
    const dec = Buffer.from(decryptLuaScript(enc)).toString("utf8");
    expect(dec).toContain("plugin_boot_trace.txt");
    expect(dec).toContain("return T");
  });

  it("padTo 对过长内容抛错，绝不静默截断", () => {
    const base = "return T // " + "x".repeat(500);
    expect(() => padTo(base, 200)).toThrow();
  });
});

describe("inject-lua-inplace UnityFS wrapper 往返", () => {
  it("buildUnityFSCompressed → unityfsToSF 完整回读同一 SerializedFile", () => {
    // 模拟一个最小的 SerializedFile（仅需是任意字节，wrapper 往返不解析 SF 内部）
    const sf = new Uint8Array([0x55, 0x6e, 0x69, 0x74, 0x79, 0x46, 0x53, 0x00, 1, 2, 3, 4, 5]);
    const cabName = "CAB-testhash";
    const uf = buildUnityFSCompressed(sf, cabName);
    // UnityFS 魔数
    expect(Buffer.from(uf.subarray(0, 7)).toString("utf8")).toBe("UnityFS");
    const back = unityfsToSF(uf);
    expect(back.cabNodeName).toBe(cabName);
    expect(Buffer.from(back.sf)).toEqual(Buffer.from(sf));
  });
});