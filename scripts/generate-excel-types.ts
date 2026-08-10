import * as fs from "fs";
import * as path from "path";
import { buildExcelTypes } from "./excel-types-builder";

const INPUT_FILE = path.join(__dirname, "../reference/com.hypergryph.arknights_2.7.61.cs");
const OUTPUT_FILE = path.join(__dirname, "../app/excel/types_excel_gen.ts");

function main(): void {
  console.log("读取 C# 反编译文件...");
  if (!fs.existsSync(INPUT_FILE)) {
    console.error(`输入文件不存在: ${INPUT_FILE}`);
    process.exit(1);
  }
  const content = fs.readFileSync(INPUT_FILE, "utf-8");
  console.log(`文件大小: ${(content.length / 1024 / 1024).toFixed(2)} MB`);

  console.log("构建 excel 表类型闭包...");
  const result = buildExcelTypes(content);
  console.log(`闭包: ${result.classes.length} 个类，${result.enums.length} 个枚举`);

  fs.writeFileSync(OUTPUT_FILE, result.output);
  console.log(`生成完成: ${OUTPUT_FILE}`);
  console.log(`文件大小: ${(result.output.length / 1024).toFixed(2)} KB`);
}

main();
