import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();
router.post("/homeTheme/change", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.home.setHomeTheme(req.body);
  res.send(player.delta);
});
router.post("/background/setBackground", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.home.setBackground(req.body);
  res.send(player.delta);
});
router.post("/charRotation/setCurrent", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.charRotation.setCurrent(req.body);
  res.send(player.delta);
});
router.post("/charRotation/createPreset", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    instId: await player.charRotation.createPreset(),
    ...player.delta,
  });
});
router.post("/charRotation/updatePreset", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.charRotation.updatePreset(req.body);
  res.send(player.delta);
});
router.post("/charRotation/deletePreset", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.charRotation.deletePreset(req.body);
  res.send(player.delta);
});
router.post("/char/changeMarkStar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.char.changeMarkStar(req.body);
  res.send(player.delta);
});
router.post("/setting/perf/setLowPower", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.home.setLowPower(req.body);
  res.send(player.delta);
});
router.post("/npcAudio/changeLan", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.home.npcAudioChangeLan(req.body);
  res.send(player.delta);
});
router.post("/story/finishStory", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.status.finishStory(req.body);
  res.send({
    items: [],
    ...player.delta,
  });
});
/**
 * 客户端事件批量上报（统计/BI 类接口）
 *
 * 客户端定期批量上报行为事件（关卡、抽卡、UI 等），私服无需处理业务逻辑，
 * 返回空响应即可（客户端只认状态码）。
 *
 * 路径：POST /batch_event（游戏域 ak-gs-* 根级接口，mitmweb 重定向后 Host 为 127.0.0.1）
 */
router.post("/batch_event", async (_req, res) => {
  res.send({});
});
router.post("/charm/setSquad", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.update(async (draft) => {
    draft.charm.squad = req.body.squad;
  });
  res.send(player.delta);
});
router.post("/firework/savePlateSlots", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  // 参考 OBS misc_bp.firework_savePlateSlots：firework.plate.slots = slots
  await player.update(async (draft) => {
    (draft as any).firework.plate.slots = req.body.slots;
  });
  res.send(player.delta);
});
router.post("/firework/changeAnimal", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  // 参考 OBS misc_bp.firework_changeAnimal：firework.animal.select = animal
  await player.update(async (draft) => {
    (draft as any).firework.animal.select = req.body.animal;
  });
  res.send({ animal: req.body.animal, ...player.delta });
});
router.post("/car/confirmBattleCar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  // 参考 OBS misc_bp.car_confirmBattleCar：car.battleCar = car
  await player.update(async (draft) => {
    draft.car.battleCar = req.body.car;
  });
  res.send(player.delta);
});
router.post("/templateTrap/setTrapSquad", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  // 参考 OBS misc_bp.templateTrap_setTrapSquad：templateTrap.domains[id].squad = trapSquad
  await player.update(async (draft) => {
    draft.templateTrap.domains[req.body.trapDomainId].squad = req.body.trapSquad;
  });
  res.send({
    trapDomainId: req.body.trapDomainId,
    trapSquad: req.body.trapSquad,
    ...player.delta,
  });
});
router.post("/troop/pinSpecialOperator", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  // 参考 OBS misc_bp.troop_pinSpecialOperator：mission.pinnedSpecialOperator = troop.chars[instId].charId
  await player.update(async (draft) => {
    const charId = draft.troop.chars[req.body.instId].charId;
    (draft as any).mission.pinnedSpecialOperator = charId;
  });
  res.send(player.delta);
});
export default router;
