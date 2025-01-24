import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import { ItemBundle } from "@excel/character_table";

const router = Router();
router.post("/changeSecretary", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.status.changeSecretary(req.body);
  res.send(player.delta);
});
router.post("/changeAvatar", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.status.changeAvatar(req.body);
  res.send(player.delta);
});
router.post("/changeResume", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  if ((req.body!.resume as string).slice(0) == "@") {
    player._trigger.emit(req.body!.resume.slice(1, req.body!.resume.length));
  } else {
    await player.status.changeResume(req.body);
  }
  res.send(player.delta);
});
router.post("/bindNickName", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  const nickName = req.body!.nickName;
  let result = 0;
  const specialChars = "~!@#$%^&*()_+{}|:\"<>?[]\\;',./";
  if (nickName.length > 16) {
    result = 1;
  }

  if (Array.from(specialChars).some((char) => nickName.includes(char))) {
    result = 2;
  }

  const sensitiveWords = ["admin", "ban", "banned", "forbidden", "root"];
  if (sensitiveWords.includes(nickName.toLowerCase())) {
    result = 3;
  }

  if (nickName.toLowerCase().includes("doctoratepy")) {
    result = 4;
  }
  if (result !== 0) res.send({ result });
  else {
    await player.status.bindNickName(req.body);
    res.send(player.delta);
  }
});
router.post("/useRenameCard", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.status.bindNickName(req.body);
  player._trigger.emit("items:use", [
    { id: req.body!.itemId, count: 1, instId: req.body!.instId } as ItemBundle,
  ]);
  res.send(player.delta);
});
router.post("/receiveTeamCollectionReward", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.status.receiveTeamCollectionReward(req.body);
  res.send(player.delta);
});
router.post("/buyAp", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  await player.status.buyAp();
  res.send(player.delta);
});
router.post("/exchangeDiamondShard", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  if (player._playerdata.status.androidDiamond < req.body!.count) {
    res.send({
      result: 1,
      errMsg: "至纯源石不足，是否前往商店购买至纯源石？",
    });
  } else {
    await player.status.exchangeDiamondShard(req.body);
    res.send(player.delta);
  }
});
router.post("/useItem", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  const item = {
    id: req.body!.itemId,
    count: req.body!.count,
    instId: req.body!.instId,
  } as ItemBundle;
  player._trigger.emit("items:use", [item]);

  res.send(player.delta);
});
router.post("/useItems", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  console.log(req.body!.items);
  const items: {
    itemId: string;
    cnt: number;
    instId: number;
  }[] = req.body!.items;
  player._trigger.emit(
    "items:use",
    items.map((item) => {
      return {
        id: item.itemId,
        count: item.cnt,
        instId: item.instId,
      };
    }),
  );
  console.log("useItems finish");
  console.log(player.delta);
  res.send(player.delta);
});
router.post("/checkIn", async (req, res) => {
  const player = httpContext.get("playerData") as PlayerDataManager;
  res.send({
    ...(await player.checkIn.checkIn()),
    ...player.delta,
  });
});
export default router;
