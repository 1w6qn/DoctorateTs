import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();

/**
 * 基建系统路由模块
 *
 * 提供基建系统的所有 HTTP 接口，包括房间管理、干员分配、订单生产、
 * 线索系统、预设队列以及其他基建相关功能。
 * 所有路由处理函数委托给 BuildingManager 进行业务处理。
 */

// ==================== 同步与基础设置 ====================

/** 同步基建数据 */
router.post("/sync", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    ts: await player.building.sync(),
    ...player.delta,
  });
});

/** 切换基建背景音乐 */
router.post("/changeBGM", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.changeBGM(req.body);
  res.send({
    ...player.delta,
  });
});

/** 设置私人宿舍归属 */
router.post("/setPrivateDormOwner", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.setPrivateDormOwner(req.body);
  res.send({
    ...player.delta,
  });
});

/** 设置基建助战干员 */
router.post("/setBuildingAssist", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.setBuildingAssist(req.body);
  res.send({
    ...player.delta,
  });
});

// ==================== 房间管理 ====================

/** 建造房间 */
router.post("/buildRoom", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.buildRoom(req.body);
  res.send(player.delta);
});

/** 升级房间等级 */
router.post("/upgradeRoom", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.upgradeRoom(req.body);
  res.send(player.delta);
});

/** 完成房间升级 */
router.post("/completeUpgradeRoom", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.completeUpgradeRoom();
  res.status(202).send(player.delta);
});

/** 降级房间 */
router.post("/degradeRoom", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.degradeRoom(req.body);
  res.send(player.delta);
});

/** 专精升级（简化实现） */
router.post("/upgradeSpecialization", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.upgradeSpecialization(req.body);
  res.send(player.delta);
});

/** 完成专精升级（简化实现） */
router.post("/completeUpgradeSpecialization", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.completeUpgradeSpecialization(req.body);
  res.send(player.delta);
});

/** 升级自定义等级（简化实现） */
router.post("/upgradeDiyLevel", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.upgradeDiyLevel();
  res.status(202).send(player.delta);
});

// ==================== 干员分配 ====================

/** 分配干员到房间 */
router.post("/assignChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.assignChar(req.body);
  res.send(player.delta);
});

/** 批量更换工作干员（简化实现） */
router.post("/batchChangeWorkChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.batchChangeWorkChar(req.body);
  res.status(202).send(player.delta);
});

/** 批量休息干员（简化实现） */
router.post("/batchRestChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.batchRestChar(req.body);
  res.send(player.delta);
});

/** 获得信赖（简化实现） */
router.post("/gainIntimacy", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.gainIntimacy(req.body);
  res.status(202).send(player.delta);
});

/** 获得全部信赖（简化实现） */
router.post("/gainAllIntimacy", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.gainAllIntimacy(req.body);
  res.status(202).send(player.delta);
});

/** 获得助战信赖（简化实现） */
router.post("/gainAssistIntimacy", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.gainAssistIntimacy(req.body);
  res.status(202).send(player.delta);
});

/** 确认私人宿舍信赖 */
router.post("/confirmPrivateDormIntimacy", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.confirmPrivateDormIntimacy(req.body);
  res.send(player.delta);
});

// ==================== 订单/生产 ====================

/** 加速订单（简化实现） */
router.post("/accelerateOrder", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.accelerateOrder(req.body);
  res.status(202).send(player.delta);
});

/** 加速方案（简化实现） */
router.post("/accelerateSolution", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.accelerateSolution(req.body);
  res.status(202).send(player.delta);
});

/** 完成订单（贸易站交付） */
router.post("/deliveryOrder", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.deliveryOrder(req.body);
  res.send(player.delta);
});

/** 批量完成订单 */
router.post("/deliveryBatchOrder", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.deliveryBatchOrder(req.body);
  res.send(player.delta);
});

/** 删除订单（简化实现） */
router.post("/deleteOrder", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.deleteOrder(req.body);
  res.status(202).send(player.delta);
});

/** 制造站结算 */
router.post("/settleManufacture", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.settleManufacture(req.body);
  res.send(player.delta);
});

/** 贸易站结算（简化实现） */
router.post("/settleSale", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.settleSale(req.body);
  res.status(202).send(player.delta);
});

/** 更换制造方案 */
router.post("/changeManufactureSolution", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.changeManufactureSolution(req.body);
  res.send(player.delta);
});

/** 更换贸易方案（简化实现） */
router.post("/changeSaleSolution", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.changeSaleSolution(req.body);
  res.status(202).send(player.delta);
});

/** 更换自定义方案 */
router.post("/changeDiySolution", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.changeDiySolution(req.body);
  res.send(player.delta);
});

/** 加工站合成 */
router.post("/workshopSynthesis", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const result = await player.building.workshopSynthesis(req.body);
  res.send({
    results: result,
    ...player.delta,
  });
});

/** 加工站分解（简化实现） */
router.post("/workshopDecomposition", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.workshopDecomposition(req.body);
  res.status(202).send(player.delta);
});

// ==================== 线索系统 ====================

/** 获取每日线索（简化实现） */
router.post("/getDailyClue", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.getDailyClue(req.body);
  res.status(202).send(player.delta);
});

/** 发送线索（简化实现） */
router.post("/sendClue", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.sendClue(req.body);
  res.status(202).send(player.delta);
});

/** 自动发送线索（简化实现） */
router.post("/sendClueAuto", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.sendClueAuto(req.body);
  res.status(202).send(player.delta);
});

/** 接收线索到库存（简化实现） */
router.post("/receiveClueToStock", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.receiveClueToStock(req.body);
  res.status(202).send(player.delta);
});

/** 放置线索到留言板（简化实现） */
router.post("/putClueToTheBoard", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.putClueToTheBoard(req.body);
  res.status(202).send(player.delta);
});

/** 自动放置线索到留言板（简化实现） */
router.post("/putClueToTheBoardAuto", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.putClueToTheBoardAuto(req.body);
  res.status(202).send(player.delta);
});

/** 删除自己持有的线索（简化实现） */
router.post("/deleteOwnClue", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.deleteOwnClue(req.body);
  res.status(202).send(player.delta);
});

/** 删除接收到的线索（简化实现） */
router.post("/deleteReceiveClue", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.deleteReceiveClue(req.body);
  res.status(202).send(player.delta);
});

/** 获取线索盒 */
router.post("/getClueBox", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const result = await player.building.getClueBox();
  res.send({
    ...result,
    ...player.delta,
  });
});

/** 获取线索好友列表 */
router.post("/getClueFriendList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const result = await player.building.getClueFriendList();
  res.send({
    ...result,
    ...player.delta,
  });
});

/** 获取会议室奖励 */
router.post("/getMeetingroomReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const result = await player.building.getMeetingroomReward();
  res.send({
    ...result,
    ...player.delta,
  });
});

// ==================== 预设队列 ====================

/** 添加预设队列（简化实现） */
router.post("/addPresetQueue", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.addPresetQueue(req.body);
  res.send(player.delta);
});

/** 删除预设队列（简化实现） */
router.post("/deletePresetQueue", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.deletePresetQueue(req.body);
  res.send(player.delta);
});

/** 编辑预设队列（简化实现） */
router.post("/editPresetQueue", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.editPresetQueue(req.body);
  res.send(player.delta);
});

/** 使用预设队列（简化实现） */
router.post("/usePresetQueue", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.usePresetQueue(req.body);
  res.send(player.delta);
});

/** 使用单个预设队列（简化实现） */
router.post("/useOnePresetQueue", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.useOnePresetQueue(req.body);
  res.status(202).send(player.delta);
});

/** 修改预设名称（简化实现） */
router.post("/changePresetName", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.changePresetName(req.body);
  res.status(202).send(player.delta);
});

/** 保存自定义预设方案（简化实现） */
router.post("/saveDiyPresetSolution", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.saveDiyPresetSolution(req.body);
  res.status(202).send(player.delta);
});

/** 编辑锁定队列（简化实现） */
router.post("/editLockQueue", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.editLockQueue(req.body);
  res.send(player.delta);
});

// ==================== 其他功能 ====================

/** 更改贸易站策略 */
router.post("/changeStrategy", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.changeStrategy(req.body);
  res.send(player.delta);
});

/** 购买劳动力（简化实现） */
router.post("/buyLabor", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.buyLabor(req.body);
  res.status(202).send(player.delta);
});

/** 清理房间槽位（简化实现） */
router.post("/cleanRoomSlot", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.cleanRoomSlot(req.body);
  res.send(player.delta);
});

/** 确认留言板奖励（简化实现） */
router.post("/confirmMessageBoardReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.confirmMessageBoardReward(req.body);
  res.status(202).send(player.delta);
});

/** 获取协助报告 */
router.post("/getAssistReport", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const result = await player.building.getAssistReport();
  res.send({
    ...result,
    ...player.delta,
  });
});

/** 获取信息共享访客数 */
router.post("/getInfoShareVisitorsNum", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const result = await player.building.getInfoShareVisitorsNum();
  res.send({
    ...result,
    ...player.delta,
  });
});

/** 获取最近访客 */
router.post("/getRecentVisitors", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const result = await player.building.getRecentVisitors();
  res.send({
    ...result,
    ...player.delta,
  });
});

/** 获取他人留言板内容（简化实现） */
router.post("/getOthersMessageBoardContent", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.getOthersMessageBoardContent(req.body);
  res.status(202).send(player.delta);
});

/** 获取缩略图 URL（简化实现） */
router.post("/getThumbnailUrl", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.getThumbnailUrl(req.body);
  res.status(202).send(player.delta);
});

/** 发送表情（简化实现） */
router.post("/sendEmoji", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.sendEmoji(req.body);
  res.status(202).send(player.delta);
});

/** 开始信息共享（简化实现） */
router.post("/startInfoShare", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.startInfoShare(req.body);
  res.status(202).send(player.delta);
});

/** 访问基建（简化实现） */
router.post("/visitBuilding", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  await player.building.visitBuilding(req.body);
  res.status(202).send(player.delta);
});

export default router;