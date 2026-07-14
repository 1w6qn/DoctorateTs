import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();

router.post("/multiplayerV3/getInfo", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    info: {
      teamId: "",
      teamName: "",
      captainUid: "",
      members: [],
      buffList: [],
      squadList: [],
      album: {},
      title: "",
      photo: "",
    },
  });
});

router.post("/multiplayerV3/changeTitle", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/multiplayerV3/setBuff", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/multiplayerV3/setSquads", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/multiplayerV3/guideBattleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    battleId: "abcdefgh-1234-5678-a1b2c3d4e5f6",
    result: 0,
  });
});

router.post("/multiplayerV3/guideBattleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/multiplayerV3/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    battleId: "abcdefgh-1234-5678-a1b2c3d4e5f6",
    result: 0,
  });
});

router.post("/multiplayerV3/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/multiplayerV3/changePhoto", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/multiplayerV3/commitAlbum", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/multiplayerV3/createTeam", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    teamId: "team_" + Math.random().toString(36).substr(2, 9),
  });
});

router.post("/multiplayerV3/joinTeam", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/multiplayerV3/queryMatch", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    matchInfo: null,
    result: 1,
  });
});

router.post("/multiplayerV3/report", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/multiplayerV3/settleLike", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/multiplayerV3/startMatch", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/multiplayerV3/unlockBuff", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/invite/refreshInviteList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    inviteList: [],
  });
});

router.post("/invite/switchInviteAccept", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/invite/sendInvite", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/invite/processInvite", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

export default router;