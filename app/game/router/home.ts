import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { decryptBattleData } from "@utils/crypt";

const router = Router();
router.post("/homeTheme/change", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.home.setHomeTheme(req.body);
  res.send(player.delta);
});
router.post("/background/setBackground", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.home.setBackground(req.body);
  res.send(player.delta);
});
router.post("/charRotation/setCurrent", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.charRotation.setCurrent(req.body);
  res.send(player.delta);
});
router.post("/charRotation/createPreset", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.charRotation.createPreset();
  res.send(player.delta);
});
router.post("/charRotation/updatePreset", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.charRotation.updatePreset(req.body);
  res.send(player.delta);
});
router.post("/charRotation/deletePreset", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.charRotation.deletePreset(req.body);
  res.send(player.delta);
});
router.post("/char/changeMarkStar", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.char.changeMarkStar(req.body);
  res.send(player.delta);
});
router.post("/setting/perf/setLowPower", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.home.setLowPower(req.body);
  res.send(player.delta);
});
router.post("/npcAudio/changeLan", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.home.npcAudioChangeLan(req.body);
  res.send(player.delta);
});
router.post("/story/finishStory", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.status.finishStory(req.body);
  res.send({
    items: [],
    ...player.delta,
  });
});
router.post("/aprilFool/act5fun/battleStart", async (req, res) => {
  res.send({
    "apFailReturn": 0,
    'battleId': 'abcdefgh-1234-5678-a1b2c3d4e5f6',
    "inApProtectPeriod": false,
    "isApProtect": 0,
    "notifyPowerScoreNotEnoughIfFailed": false,
    'playerDataDelta': {
        'modified': {},
        'deleted': {}
    },
    'result': 0
});
});
router.post("/aprilFool/act5fun/battleFinish", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  let score=0
  const battledata=decryptBattleData(req.body.battleData, player._playerdata.pushFlags.status)
  battledata["battleData"]["stats"]["extraBattleInfo"].forEach((info:string) => {
    if(info.startsWith("SIMPLE,money,")){
      score = parseInt(info.split(",")[-1])
    }
  })
  res.send({
    "result": 0,
    "score": score,
    "isHighScore": false,
    "npcResult": {},
    "playerResult": {"totalWin": 0, "streak": 0, "totalRound": 10},
    "reward": [],
    "playerDataDelta": {"modified": {}, "deleted": {}},
  });
});
export default router;
