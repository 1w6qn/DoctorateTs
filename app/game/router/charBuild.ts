import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";
import {
  AddonStageBattleFinishRequest,
  AddonStageBattleFinishResponse,
  AddonStageBattleStartRequest,
  AddonStageBattleStartResponse,
  AddonStoryUnlockRequest,
  AddonStoryUnlockResponse,
  BatchSetCharVoiceLanRequest,
  BatchSetCharVoiceLanResponse,
  BoostPotentialRequest,
  BoostPotentialResponse,
  ChangeCharSkinRequest,
  ChangeCharSkinResponse,
  ChangeCharSkinSpStateRequest,
  ChangeCharSkinSpStateResponse,
  ChangeCharTemplateRequest,
  ChangeCharTemplateResponse,
  CompleteUpgradeSpecializationRequest,
  CompleteUpgradeSpecializationResponse,
  EvolveCharRequest,
  EvolveCharResponse,
  EvolveCharUseItemRequest,
  EvolveCharUseItemResponse,
  GetSpCharMissionRewardRequest,
  GetSpCharMissionRewardResponse,
  LockCharRequest,
  LockCharResponse,
  SellCharRequest,
  SellCharResponse,
  SetCharVoiceLanRequest,
  SetCharVoiceLanResponse,
  SetDefaultSkillRequest,
  SetDefaultSkillResponse,
  SetEquipmentRequest,
  SetEquipmentResponse,
  UpgradeCharLevelMaxUseItemRequest,
  UpgradeCharLevelMaxUseItemResponse,
  UpgradeCharRequest,
  UpgradeCharResponse,
  UpgradeEquipmentRequest,
  UpgradeEquipmentResponse,
  UpgradeSkillRequest,
  UpgradeSkillResponse,
  UpgradeSpecializationRequest,
  UpgradeSpecializationResponse,
  UpgradeSpecializedSkillUseItemRequest,
  UpgradeSpecializedSkillUseItemResponse,
  UnlockEquipmentRequest,
  UnlockEquipmentResponse,
} from "../model/protocol/charBuild";

const router = Router();
router.post("/setDefaultSkill", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as SetDefaultSkillRequest;
  await player.char.setDefaultSkill(body);
  res.send(player.delta satisfies SetDefaultSkillResponse);
});
router.post("/upgradeChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as UpgradeCharRequest;
  await player.char.upgradeChar(body);
  res.send(player.delta satisfies UpgradeCharResponse);
});
router.post("/evolveChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as EvolveCharRequest;
  await player.char.evolveChar(body);
  res.send(player.delta satisfies EvolveCharResponse);
});
router.post("/lockChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as LockCharRequest;
  await player.char.lockChar(body);
  res.send(player.delta satisfies LockCharResponse);
});
router.post("/sellChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as SellCharRequest;
  await player.char.sellChar(body);
  res.send(player.delta satisfies SellCharResponse);
});
router.post("/boostPotential", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BoostPotentialRequest;
  await player.char.boostPotential(body);
  res.send({
    result: 1,
    ...player.delta,
  } satisfies BoostPotentialResponse);
});

router.post("/upgradeSkill", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as UpgradeSkillRequest;
  await player.char.upgradeSkill(body);
  res.send(player.delta satisfies UpgradeSkillResponse);
});
router.post("/upgradeSpecialization", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as UpgradeSpecializationRequest;
  await player.char.upgradeSpecialization(body);
  res.send(player.delta satisfies UpgradeSpecializationResponse);
});
router.post("/completeUpgradeSpecialization", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as CompleteUpgradeSpecializationRequest;
  await player.char.completeUpgradeSpecialization(body);
  res.send(player.delta satisfies CompleteUpgradeSpecializationResponse);
});
router.post("/changeCharSkin", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ChangeCharSkinRequest;
  await player.char.changeCharSkin(body);
  res.send(player.delta satisfies ChangeCharSkinResponse);
});
router.post("/changeCharTemplate", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as ChangeCharTemplateRequest;
  await player.char.changeCharTemplate(body);
  res.send(player.delta satisfies ChangeCharTemplateResponse);
});
router.post("/getSpCharMissionReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as GetSpCharMissionRewardRequest;
  await player.char.getSpCharMissionReward(body);
  res.send(player.delta satisfies GetSpCharMissionRewardResponse);
});
router.post("/evolveCharUseItem", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as EvolveCharUseItemRequest;
  // 修复：CS 字段为 charInsId/itemInsId——客户端按 CS 发，服务端读 charInstId/instId
  //（原实现读不到 → undefined 干员 → 500）
  await player.char.evolveCharUseItem({
    charInstId: (body as any).charInstId ?? (body as any).charInsId,
    itemId: body.itemId,
    instId: (body as any).instId ?? (body as any).itemInsId,
  });
  res.send(player.delta satisfies EvolveCharUseItemResponse);
});
router.post("/upgradeCharLevelMaxUseItem", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as UpgradeCharLevelMaxUseItemRequest;
  // 修复：同上 CS 字段名归一化
  await player.char.upgradeCharLevelMaxUseItem({
    charInstId: (body as any).charInstId ?? (body as any).charInsId,
    itemId: body.itemId,
    instId: (body as any).instId ?? (body as any).itemInsId,
  });
  res.send(player.delta satisfies UpgradeCharLevelMaxUseItemResponse);
});
router.post("/upgradeSpecializedSkillUseItem", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as UpgradeSpecializedSkillUseItemRequest;
  // 修复：同上 CS 字段名归一化
  await player.char.upgradeSpecializedSkillUseItem({
    charInstId: (body as any).charInstId ?? (body as any).charInsId,
    skillIndex: body.skillIndex,
    itemId: body.itemId,
    instId: (body as any).instId ?? (body as any).itemInsId,
  });
  res.send(player.delta satisfies UpgradeSpecializedSkillUseItemResponse);
});

router.post("/addonStory/unlock", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as AddonStoryUnlockRequest;
  const medalId = await player.troop.addonStoryUnlock(body);
  res.send({
    rewards: null,
    // 对齐官服响应：解锁密录发放勋章时推送 medalFinish（无勋章配置则省略）
    ...(medalId
      ? { pushMessage: [{ path: "medalFinish", payload: { idList: [medalId] } }] }
      : {}),
    ...player.delta,
  } satisfies AddonStoryUnlockResponse);
});
router.post("/addonStage/battleStart", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as AddonStageBattleStartRequest;
  await player.troop.addonStageBattleStart(body);
  res.send(player.delta satisfies AddonStageBattleStartResponse);
});
router.post("/addonStage/battleFinish", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as AddonStageBattleFinishRequest;
  const result = await player.troop.addonStageBattleFinish(body);
  res.send({ ...(result as object), ...player.delta } satisfies AddonStageBattleFinishResponse);
});
router.post("/unlockEquipment", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as UnlockEquipmentRequest;
  await player.char.unlockEquipment(body);
  res.send(player.delta satisfies UnlockEquipmentResponse);
});
router.post("/upgradeEquipment", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as UpgradeEquipmentRequest;
  await player.char.upgradeEquipment(body);
  res.send(player.delta satisfies UpgradeEquipmentResponse);
});
router.post("/setEquipment", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as SetEquipmentRequest;
  await player.char.setEquipment(body);
  res.send(player.delta satisfies SetEquipmentResponse);
});

router.post("/batchSetCharVoiceLan", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as BatchSetCharVoiceLanRequest;
  await player.char.batchSetCharVoiceLan(body);
  res.send(player.delta satisfies BatchSetCharVoiceLanResponse);
});
router.post("/setCharVoiceLan", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as SetCharVoiceLanRequest;
  await player.char.setCharVoiceLan(body);
  res.send(player.delta satisfies SetCharVoiceLanResponse);
});
router.post("/changeSkinSpState", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { skinId, isSpecial } = req.body as ChangeCharSkinSpStateRequest;
  // 参考 OBS bp_charBuild.changeSkinSpState：skin.skinSp[skinId] = isSpecial
  await player.update(async (draft) => {
    const skin = draft.skin as any;
    // 修复：skin.skinSp 从未初始化（新存档/模板均无此字段）→ 原实现直接写 undefined 500
    if (!skin.skinSp) skin.skinSp = {};
    skin.skinSp[skinId] = isSpecial;
  });
  res.send(player.delta satisfies ChangeCharSkinSpStateResponse);
});
export default router;
