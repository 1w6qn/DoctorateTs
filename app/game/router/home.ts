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
export default router;
