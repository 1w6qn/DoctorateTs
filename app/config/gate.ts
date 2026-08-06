/**
 * 网关 meta 路由（/api/gate/meta/:platform）
 *
 * 客户端启动时请求网关元数据（版本/公告等）——私服简化返回空数据（200 即可）
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

export default router;
