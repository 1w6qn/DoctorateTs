import * as fs from "fs";
import * as path from "path";
import JSZip from "jszip";
import { extractTextAssets } from "./vendor/unityfs";

// 从 mod dat 解出 DefinedFix.lua 明文，打印注入后的内容，验证格式与路径。
// 可指定 dat 路径（默认取当前插件 bundle）。
export async function main(argv: string[] = []): Promise<void> {
  const datPath = path.resolve(argv[0] ?? path.join(__dirname, "..", "mods", "anon_6edf14bbd79243eb61e288ff28e446c3.dat"));
  const zip = await JSZip.loadAsync(fs.readFileSync(datPath));
  const names = Object.keys(zip.files).filter((n) => !zip.files[n].dir);
  const unity = await zip.files[names[0]].async("uint8array");
  const assets = extractTextAssets(new Uint8Array(unity));
  const df = assets.find((a) => a.name.toLowerCase().endsWith("definedfix.lua"));
  if (!df) {
    console.log("DefinedFix.lua NOT FOUND");
    return;
  }
  console.log("asset name:", df.name);
  console.log("---- content ----");
  console.log(new TextDecoder().decode(df.script));
}

// 直连执行入口（被 admin-cli tools 导入时不自动运行）
if (typeof require !== "undefined" && require.main === module) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}