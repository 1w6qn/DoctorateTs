import * as fs from "fs";
import * as path from "path";
import JSZip from "jszip";
import { extractTextAssets } from "./vendor/unityfs";

// 校验插件模块 require 依赖图：所有 require "Plugin/xxx" 路径都能在 bundle 资产中解析到对应 asset。

async function main(): Promise<void> {
  const datPath = path.join(__dirname, "..", "mods", "anon_7d91430e114d86fef7d3b3511151e12d.dat");
  const zip = await JSZip.loadAsync(fs.readFileSync(datPath));
  const names = Object.keys(zip.files).filter((n) => !zip.files[n].dir);
  const unity = await zip.files[names[0]].async("uint8array");
  const assets = extractTextAssets(new Uint8Array(unity));

  // 资产名集合（标准化：小写、去 gamedata/[uc]lua/ 前缀）
  const assetNames = new Set<string>();
  for (const a of assets) {
    const lower = a.name.toLowerCase();
    if (lower.startsWith("gamedata/[uc]lua/")) {
      assetNames.add(lower.slice("gamedata/[uc]lua/".length));
    }
  }

  // 收集所有插件 Lua 源码中的 require "X" 调用
  const pluginAssets = assets.filter((a) => a.name.toLowerCase().includes("/plugin/"));
  const missing: string[] = [];
  // require 解析辅助：xLua 自动补 .lua 后缀，且大小写不敏感（官方 require "Hotfixes/DefinedFix" 匹配 hotfixes/definedfix.lua）
  const resolve = (dep: string): boolean => {
    const candidates = [dep, dep + ".lua"];
    return candidates.some((c) => assetNames.has(c.toLowerCase()));
  };
  for (const a of pluginAssets) {
    const src = new TextDecoder().decode(a.script);
    const re = /require\s*["']([^"']+)["']/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(src)) !== null) {
      const dep = m[1].trim();
      if (!dep.startsWith("Plugin/") && !dep.toLowerCase().startsWith("plugin/")) continue;
      if (!resolve(dep)) missing.push(`${a.name} -> require ${m[1]}`);
    }
  }

  console.log("bundle 资产数:", assets.length);
  console.log("插件资产数:", pluginAssets.length);
  if (missing.length === 0) {
    console.log("✓ 所有 Plugin require 依赖均能解析到 bundle 资产");
  } else {
    console.log("✗ 以下 require 无法解析:");
    for (const m of missing) console.log("  " + m);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});