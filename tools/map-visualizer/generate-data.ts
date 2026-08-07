/**
 * 生成脚本：从官方 excel 提取各主题关卡数据，供地图可视化页面使用
 * 输出：tools/map-visualizer/game-data.js（window.MAPVIZ_DATA）
 * 运行：npx tsx tools/map-visualizer/generate-data.ts
 */
import * as fs from "fs";

const DATA = "D:/develop/DoctorateTs/data";
const topic = JSON.parse(fs.readFileSync(`${DATA}/excel/roguelike_topic_table.json`, "utf8"));
const nodesInfo = JSON.parse(fs.readFileSync(`${DATA}/rlv2/nodesInfo.json`, "utf8"));

const THEMES = ["rogue_1", "rogue_2", "rogue_3", "rogue_4", "rogue_5", "rogue_6"];

const themes: any = {};
for (const theme of THEMES) {
  const roNum = parseInt(theme.split("_")[1]);
  const stages = Object.keys(topic.details[theme].stages || {});
  // 关卡按前缀分组（与 map.ts 动态过滤一致）
  const normal = stages.filter((s) => s.startsWith(`ro${roNum}_n_`));
  const elite = stages.filter((s) => s.startsWith(`ro${roNum}_e_`));
  const boss = stages.filter((s) => /^ro\d+_b_[1-9]$/.test(s));
  // nodesInfo 数据（map.ts 优先读取）
  const zones = nodesInfo.themes?.[theme]?.zones || {};
  themes[theme] = {
    normal,
    elite,
    boss,
    zones,
  };
}

const out = `/* 自动生成：地图可视化数据（从官方 excel + nodesInfo 提取，勿手改） */
window.MAPVIZ_DATA = ${JSON.stringify(themes)};
`;
fs.mkdirSync("D:/develop/DoctorateTs/tools/map-visualizer", { recursive: true });
fs.writeFileSync("D:/develop/DoctorateTs/tools/map-visualizer/game-data.js", out);
console.log("written tools/map-visualizer/game-data.js");
for (const th of THEMES) {
  const t = themes[th];
  console.log(th, `n:${t.normal.length} e:${t.elite.length} b:${t.boss.length} zones:${Object.keys(t.zones).length}`);
}
