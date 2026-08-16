import * as fs from "fs";
import * as path from "path";
import JSZip from "jszip";
import { extractTextAssets } from "./vendor/unityfs";

// 从 mod dat 解出 DefinedFix.lua 明文，打印注入后的前 20 行，验证格式与路径

async function main(): Promise<void> {
  const datPath = path.join(__dirname, "..", "mods", "anon_7d91430e114d86fef7d3b3511151e12d.dat");
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

main().catch((e) => {
  console.error(e);
  process.exit(1);
});