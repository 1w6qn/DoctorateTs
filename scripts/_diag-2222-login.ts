/* 临时诊断：复现 2222 登录加载失败点（用完删除） */
import { DatabaseSync } from "node:sqlite";
import { gunzipSync } from "zlib";

async function main() {
  const excel = (await import("@excel/excel")).default;
  await excel.init();
  const { PlayerDataManager } = await import("../app/game/manager/PlayerDataManager");
  const { checkAndRepairSave } = await import("../app/game/util/save-health");

  const db = new DatabaseSync("./data/user/social.db");
  const row = db.prepare("SELECT data FROM player_data WHERE uid = ?").get("2222");
  db.close();
  let raw = gunzipSync(Buffer.from(row.data)).toString("utf-8");
  let data: any;
  try { data = JSON.parse(raw); } catch (e) { console.log("JSON.parse 失败:", (e as Error).message); return; }
  console.log("JSON.parse ok, root keys:", Object.keys(data).length);

  try { const issues = checkAndRepairSave(data); console.log("checkAndRepairSave ok, issues:", issues.filter(i=>i.fixed).length); }
  catch (e) { console.log("checkAndRepairSave 抛错:", (e as Error).message, (e as Error).stack?.split("\n")[1]); }

  let player: any;
  try {
    player = new PlayerDataManager(data as any);
    console.log("PlayerDataManager 构造 ok, live rlv2 state:", player.rlv2?._status?.state);
  } catch (e) { console.log("PlayerDataManager 构造抛错:", (e as Error).message); console.log((e as Error).stack); }

  if (player) {
    try { await player.mission?.initPromise; console.log("mission.initPromise ok"); }
    catch (e) { console.log("mission.initPromise 抛错:", (e as Error).message); }
    const { unlockActivity } = await import("../app/game/manager/activity/unlockActivity");
    try { await unlockActivity(player); console.log("unlockActivity ok"); }
    catch (e) { console.log("unlockActivity 抛错:", (e as Error).message, (e as Error).stack?.split("\n")[1]); }
    try { const j = player.toJSONString(); console.log("toJSONString ok, len:", j.length); }
    catch (e) { console.log("toJSONString 抛错:", (e as Error).message, (e as Error).stack?.split("\n")[1]); }
    try { player.delta; console.log("player.delta ok"); }
    catch (e) { console.log("player.delta 抛错:", (e as Error).message, (e as Error).stack?.split("\n")[1]); }
  }
  console.log("done");
}
main();