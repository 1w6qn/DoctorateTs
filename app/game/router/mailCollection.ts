/**
 * 邮件收藏路由模块
 *
 * 处理邮件收藏（mailCollection）相关请求。
 * 参考实现：reference/OpenBachelorS-master/src/openbachelors/bp/bp_mail.py mailCollection_getList
 */

import { Router } from "express";
import excel from "@excel/excel";

const router = Router();

/**
 * 获取邮件收藏列表
 * @route POST /mailCollection/getList
 * @returns collections（display_meta_table.mailArchiveData 的收藏 ID 列表）与 extra
 */
router.post("/getList", async (_req, res) => {
  const collectionLst = Object.keys(
    excel.DisplayMetaTable.mailArchiveData.mailArchiveInfoDict,
  );
  res.send({ collections: collectionLst, extra: [] });
});

export default router;
