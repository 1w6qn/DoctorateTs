/**
 * 仓库路由模块
 * 
 * 处理仓库相关的 HTTP 请求，包括凭证详情获取等功能。
 */

import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();

/**
 * 获取凭证详情
 * @route POST /depot/getVoucherDetail
 * @param req.body.itemId - 物品ID
 * @param req.body.instId - 实例ID
 * @returns 凭证详情
 */
router.post("/getVoucherDetail", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const { itemId } = req.body;

  res.send({});
});

/**
 * 凭证抽卡
 * @route POST /depot/voucherGacha
 * @returns 空响应（202）
 */
router.post("/voucherGacha", async (req, res) => {
  res.sendStatus(202);
});

/**
 * 获取干员抽卡凭证详情
 * @route POST /depot/getCharGachaVoucherDetail
 * @returns 空响应（202）
 */
router.post("/getCharGachaVoucherDetail", async (req, res) => {
  res.sendStatus(202);
});

/**
 * 获取材料凭证详情
 * @route POST /depot/getMaterialVoucherDetail
 * @returns 空响应（202）
 */
router.post("/getMaterialVoucherDetail", async (req, res) => {
  res.sendStatus(202);
});

/**
 * 使用干员抽卡凭证
 * @route POST /depot/useCharGachaVoucher
 * @returns 空响应（202）
 */
router.post("/useCharGachaVoucher", async (req, res) => {
  res.sendStatus(202);
});

/**
 * 使用材料凭证
 * @route POST /depot/useMaterialVoucher
 * @returns 空响应（202）
 */
router.post("/useMaterialVoucher", async (req, res) => {
  res.sendStatus(202);
});

/**
 * 使用满潜能物品
 * @route POST /depot/useFullPotentialItem
 * @returns 空响应（202）
 */
router.post("/useFullPotentialItem", async (req, res) => {
  res.sendStatus(202);
});

/**
 * 使用选项凭证
 * @route POST /depot/useOptionVoucher
 * @returns 空响应（202）
 */
router.post("/useOptionVoucher", async (req, res) => {
  res.sendStatus(202);
});

export default router;