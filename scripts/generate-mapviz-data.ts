/**
 * 生成脚本：从官方 excel 提取各主题关卡数据，供 Dashboard「地图」Tab 使用
 * 输出：data/mapviz/game-data.js（window.MAPVIZ_DATA）
 * 运行：pnpm exec tsx scripts/generate-mapviz-data.ts（或 pnpm run generate:mapviz）
 */
import * as fs from "fs";
import * as path from "path";

const ROOT = process.cwd();
const DATA = path.join(ROOT, "data");
const OUT_DIR = path.join(DATA, "mapviz");
const OUT_FILE = path.join(OUT_DIR, "game-data.js");
const topic = JSON.parse(fs.readFileSync(path.join(DATA, "excel/roguelike_topic_table.json"), "utf8"));
const nodesInfo = JSON.parse(fs.readFileSync(path.join(DATA, "rlv2/nodesInfo.json"), "utf8"));

const THEMES = ["rogue_1", "rogue_2", "rogue_3", "rogue_4", "rogue_5", "rogue_6"];

/** 单个分区（nodesInfo.themes.<theme>.zones.<zoneId>）的关卡分组；额外键按原样透传 */
interface MapvizZone {
  Normal?: string[];
  Emergency?: string[];
  Boss?: string[];
}

/** 单个主题输出的关卡数据（zone 字典按键排序无关，仅原样 JSON 序列化） */
interface MapvizTheme {
  normal: string[];
  elite: string[];
  boss: string[];
  zones: Record<string, MapvizZone>;
}

const themes: Record<string, MapvizTheme> = {};
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
fs.mkdirSync(OUT_DIR, { recursive: true });
fs.writeFileSync(OUT_FILE, out);
console.log(`written ${OUT_FILE}`);
for (const th of THEMES) {
  const t = themes[th];
  console.log(th, `n:${t.normal.length} e:${t.elite.length} b:${t.boss.length} zones:${Object.keys(t.zones).length}`);
}
