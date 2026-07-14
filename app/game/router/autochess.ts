import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();

router.post("/autochessSeason/syncInfo", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    info: {},
  });
});

router.post("/autochessSeason/setChessPoolDeploy", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/autochessSeason/finishGuideBattle", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/autochessSeason/getFriendCharAssistList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    charList: [],
  });
});

router.post("/autochessSeason/joinTeam", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/autochessSeason/multiBattleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/autochessSeason/multiBattleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    battleId: "abcdefgh-1234-5678-a1b2c3d4e5f6",
    result: 0,
  });
});

router.post("/autochessSeason/queryMatch", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    matchInfo: null,
    result: 1,
  });
});

router.post("/autochessSeason/quitSingleGame", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/autochessSeason/removeChessPoolChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/autochessSeason/report", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/autochessSeason/setChessPoolAssist", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/autochessSeason/setChessPoolDiyChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/autochessSeason/settleGame", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    result: 0,
  });
});

router.post("/autochessSeason/settleLike", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/autochessSeason/startMatch", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/autochessSeason/createTeam", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    teamId: "team_" + Math.random().toString(36).substr(2, 9),
  });
});

router.post("/autochessSeason/startGuideBattle", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    battleId: "abcdefgh-1234-5678-a1b2c3d4e5f6",
    result: 0,
  });
});

export default router;