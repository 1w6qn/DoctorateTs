import { Router } from "express";
import { getPlayer, getPlayerOptional } from "../../request-context";
import { PlayerDataManager } from "@game/service/PlayerDataManager";
import {
  BatchEventRequest,
  BatchEventResponse,
  ChangeMarkStarRequest,
  ChangeMarkStarResponse,
  CharmSetSquadRequest,
  CharmSetSquadResponse,
  ConfirmBattleCarRequest,
  ConfirmBattleCarResponse,
  FireworkChangeAnimalRequest,
  FireworkChangeAnimalResponse,
  FireworkSavePlateSlotsRequest,
  FireworkSavePlateSlotsResponse,
  FinishStoryRequest,
  FinishStoryResponse,
  NpcAudioChangeLanRequest,
  NpcAudioChangeLanResponse,
  PinSpecialOperatorRequest,
  PinSpecialOperatorResponse,
  SetBackgroundRequest,
  SetBackgroundResponse,
  SetHomeThemeRequest,
  SetHomeThemeResponse,
  SetLowPowerRequest,
  SetLowPowerResponse,
  SetTrapSquadRequest,
  SetTrapSquadResponse,
} from "../../domain/home/home";
import {
  CharRotationCreatePresetRequest,
  CharRotationCreatePresetResponse,
  CharRotationDeletePresetRequest,
  CharRotationDeletePresetResponse,
  CharRotationSetCurrentPresetRequest,
  CharRotationSetCurrentPresetResponse,
  CharRotationUpdatePresetRequest,
  CharRotationUpdatePresetResponse,
} from "../../domain/character/charRotation";
import { validateBody } from "../../domain/contracts/validate-body";
import {
  batchEventSchema,
  changeMarkStarSchema,
  charmSetSquadSchema,
  charRotationCreatePresetSchema,
  charRotationDeletePresetSchema,
  charRotationSetCurrentSchema,
  charRotationUpdatePresetSchema,
  confirmBattleCarSchema,
  finishStorySchema,
  fireworkChangeAnimalSchema,
  fireworkSavePlateSlotsSchema,
  npcAudioChangeLanSchema,
  pinSpecialOperatorSchema,
  setBackgroundSchema,
  setHomeThemeSchema,
  setLowPowerSchema,
  setTrapSquadSchema,
} from "../../domain/home/home.schema";

const router = Router();
router.post("/homeTheme/change", validateBody(setHomeThemeSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as SetHomeThemeRequest;
  await player.home.setHomeTheme(body);
  res.send(player.delta satisfies SetHomeThemeResponse);
});
router.post("/background/setBackground", validateBody(setBackgroundSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as SetBackgroundRequest;
  await player.home.setBackground(body);
  res.send(player.delta satisfies SetBackgroundResponse);
});
router.post("/charRotation/setCurrent", validateBody(charRotationSetCurrentSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as CharRotationSetCurrentPresetRequest;
  await player.charRotation.setCurrent(body);
  res.send(player.delta satisfies CharRotationSetCurrentPresetResponse);
});
router.post("/charRotation/createPreset", validateBody(charRotationCreatePresetSchema), async (req, res) => {
  const player = getPlayer();
  req.body as CharRotationCreatePresetRequest;
  res.send({
    instId: await player.charRotation.createPreset(),
    ...player.delta,
  } satisfies CharRotationCreatePresetResponse);
});
router.post("/charRotation/updatePreset", validateBody(charRotationUpdatePresetSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as CharRotationUpdatePresetRequest;
  await player.charRotation.updatePreset(body);
  res.send(player.delta satisfies CharRotationUpdatePresetResponse);
});
router.post("/charRotation/deletePreset", validateBody(charRotationDeletePresetSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as CharRotationDeletePresetRequest;
  await player.charRotation.deletePreset(body);
  res.send(player.delta satisfies CharRotationDeletePresetResponse);
});
router.post("/char/changeMarkStar", validateBody(changeMarkStarSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as ChangeMarkStarRequest;
  await player.char.changeMarkStar(body);
  res.send(player.delta satisfies ChangeMarkStarResponse);
});
router.post("/setting/perf/setLowPower", validateBody(setLowPowerSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as SetLowPowerRequest;
  await player.home.setLowPower(body);
  res.send(player.delta satisfies SetLowPowerResponse);
});
router.post("/npcAudio/changeLan", validateBody(npcAudioChangeLanSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as NpcAudioChangeLanRequest;
  // 修复：缺 id/voiceLan 必填参数时返回业务错误，而非 500
  if (typeof body?.id !== "string" || typeof body?.voiceLan !== "string") {
    return res.send({ result: 1, ...player.delta });
  }
  await player.home.npcAudioChangeLan(body);
  res.send(player.delta satisfies NpcAudioChangeLanResponse);
});
router.post("/story/finishStory", validateBody(finishStorySchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as FinishStoryRequest;
  await player.status.finishStory(body);
  // ODC：教程剧情提交后同步主题 varSeq bool_end_guide_done=1——
  // 否则 logic_game_end_p1（q003_prog==4 && bool_end_guide_done==0 &&
  // q003_banner_showed==1）每次进图 AUTO_ONCE 重放新手教程（无限教程）
  const { finishArkOdcGuideStory } = await import("./arkodc");
  await finishArkOdcGuideStory(player, body.storyId);
  res.send({
    items: [],
    ...player.delta,
  } satisfies FinishStoryResponse);
});
/**
 * 客户端事件批量上报（统计/BI 类接口）
 *
 * 客户端定期批量上报行为事件（关卡、抽卡、UI 等），私服无需处理业务逻辑，
 * 返回空响应即可（客户端只认状态码）。
 *
 * 路径：POST /batch_event（游戏域 ak-gs-* 根级接口，mitmweb 重定向后 Host 为 127.0.0.1）
 */
router.post("/batch_event", validateBody(batchEventSchema), async (req, res) => {
  req.body as BatchEventRequest;
  res.send({} satisfies BatchEventResponse);
});
router.post("/charm/setSquad", validateBody(charmSetSquadSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as CharmSetSquadRequest;
  await player.update(async (draft) => {
    draft.charm.squad = body.squad;
  });
  res.send(player.delta satisfies CharmSetSquadResponse);
});
router.post("/firework/savePlateSlots", validateBody(fireworkSavePlateSlotsSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as FireworkSavePlateSlotsRequest;
  // 参考 OBS misc_bp.firework_savePlateSlots：firework.plate.slots = slots
  await player.update(async (draft) => {
    // 修复：firework 数据未初始化时兜底，避免 .plate.slots 抛「reading 'plate'」500
    const fw = (draft as any).firework ??= {};
    fw.plate ??= {};
    fw.plate.slots = body.slots;
  });
  res.send(player.delta satisfies FireworkSavePlateSlotsResponse);
});
router.post("/firework/changeAnimal", validateBody(fireworkChangeAnimalSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as FireworkChangeAnimalRequest;
  // 参考 OBS misc_bp.firework_changeAnimal：firework.animal.select = animal
  await player.update(async (draft) => {
    // 修复：firework 数据未初始化时兜底，避免 .animal.select 抛「reading 'animal'」500
    const fw = (draft as any).firework ??= {};
    fw.animal ??= {};
    fw.animal.select = body.animal;
  });
  res.send({ animal: body.animal, ...player.delta } satisfies FireworkChangeAnimalResponse);
});
router.post("/car/confirmBattleCar", validateBody(confirmBattleCarSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as ConfirmBattleCarRequest;
  // 参考 OBS misc_bp.car_confirmBattleCar：car.battleCar = car
  await player.update(async (draft) => {
    draft.car.battleCar = body.car;
  });
  res.send(player.delta satisfies ConfirmBattleCarResponse);
});
router.post("/templateTrap/setTrapSquad", validateBody(setTrapSquadSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as SetTrapSquadRequest;
  // 修复：缺 trapDomainId/trapSquad 必填参数时返回业务错误，而非 500
  if (typeof body?.trapDomainId !== "string" || !Array.isArray(body?.trapSquad)) {
    return res.send({ result: 1, ...player.delta });
  }
  // 参考 OBS misc_bp.templateTrap_setTrapSquad：templateTrap.domains[id].squad = trapSquad
  await player.update(async (draft) => {
    draft.templateTrap.domains[body.trapDomainId].squad = body.trapSquad;
  });
  res.send({
    trapDomainId: body.trapDomainId,
    trapSquad: body.trapSquad,
    ...player.delta,
  } satisfies SetTrapSquadResponse);
});
router.post("/troop/pinSpecialOperator", validateBody(pinSpecialOperatorSchema), async (req, res) => {
  const player = getPlayer();
  const body = req.body as PinSpecialOperatorRequest;
  // 参考 OBS misc_bp.troop_pinSpecialOperator：mission.pinnedSpecialOperator = troop.chars[instId].charId
  await player.update(async (draft) => {
    // 修复：非法 instId（已删干员/乱传）不 500
    const char = draft.troop.chars[body.instId];
    if (!char) return;
    (draft as any).mission.pinnedSpecialOperator = char.charId;
  });
  res.send(player.delta satisfies PinSpecialOperatorResponse);
});
export default router;
