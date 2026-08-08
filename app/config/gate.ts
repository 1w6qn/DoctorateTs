/**
 * 网关路由（/api/gate/*）
 *
 * 客户端启动时请求网关元数据/信息：
 * - /api/gate/meta/:platform —— 网关元数据（版本/公告等）
 * - /api/gate/info/:platform —— 网关信息（启动链路早期请求，私服简化返回 code:0）
 */
import { Router } from "express";
import { now } from "@utils/time";

const router = Router();

/** 网关元数据（平台参数——Android/Windows/iOS） */
router.get("/meta/:platform", async (req, res) => {
  res.send({
    code: 0,
    data: {
      platform: req.params.platform,
      serverTime: now(),
      notice: null,
    },
  });
});

/** 网关信息（启动链路早期请求，无官服抓包参考——返回 code:0 保证客户端不阻塞） */
router.get("/info/:platform", async (req, res) => {
  res.send({
    code: 0,
    data: {
      platform: req.params.platform,
      serverTime: now(),
    },
  });
});

export default router;
