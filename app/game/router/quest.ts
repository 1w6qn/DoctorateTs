import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

/**
 *    SQUAD_FORMATION = "/quest/squadFormation";
 *    SQUAD_RENAME = "/quest/changeSquadName";
 *    SQUAD_GET_ASSIST_LIST = "/quest/getAssistList";
 *    DEFAULT_BATTLE_START = "/quest/battleStart";
 *    DEFAULT_BATTLE_FINISH = "/quest/battleFinish";
 *    DEFAULT_BATTLE_CONTINUE = "/quest/battleContinue";
 *    SAVE_BATTLE_REPLAY = "/quest/saveBattleReplay";
 *    LOAD_BATTLE_REPLAY = "/quest/getBattleReplay";
 *    FINISH_STORY_STAGE = "/quest/finishStoryStage";
 *    UNLOCK_STAGE_FOG = "/quest/unlockStageFog";
 *    UNLOCK_HIDDEN_STAGE = "/quest/unlockHideStage";
 *    GET_SPECIAL_STAGE_REWARD = "/quest/getCowLevelReward";
 *    GET_ZONE_RECORD_REWARD = "/quest/getMainlineRecordRewards";
 *    GET_MAINLINE_CACHE = "/quest/getMainlineCache";
 *    **/
const router = Router();
router.post("/squadFormation", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.troop.squadFormation(req.body);
  res.send(player.delta);
});
router.post("/changeSquadName", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.troop.changeSquadName(req.body);
  res.send(player.delta);
});
router.post("/getAssistList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    list: await player.social.getAssistList(req.body),
    ...player.delta,
  });
});
router.post("/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...(await player.battle.start(req.body)),
    ...player.delta,
  });
});
router.post("/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...(await player.battle.finish(req.body)),
    ...player.delta,
  });
});
router.post("/getBattleReplay", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    battleReplay:await player.battle.loadReplay(req.body),
    ...player.delta,
  });
});
router.post("/saveBattleReplay", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.battle.saveReplay(req.body);
  res.send(player.delta);
});
router.post("/battleContinue", async (req, res) => {
  // 继续战斗：参考 OBS bp_quest.battleContinue，仅返回固定 stub（战斗数据由 battleFinish 结算）
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    result: 1,
    battleId: "00000000-0000-0000-0000-000000000000",
    apFailReturn: 0,
    ...player.delta,
  });
});
router.post("/finishStoryStage", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ...(await player.battle.finishStoryStage(req.body)),
    ...player.delta,
  });
});
router.post("/editStageSixStarTag", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { stageId, selected } = req.body;
  // 手写 PlayerDataModel 未声明 dungeon.sixStar（生成参考类型 types-playerdata.ts 有），用 (draft as any) 访问
  await player.update(async (draft) => {
    (draft as any).dungeon.sixStar.stages[stageId].tagSelected = selected;
  });
  res.send(player.delta);
});
export default router;
