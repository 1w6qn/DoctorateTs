/**
 * 管理 REST API 路由
 *
 * API 前缀 /admin/api，需通过 adminAuth 认证。
 * Dashboard 页面 /admin/dashboard 免认证（登录在页面内完成）。
 */
import { Router, Request, Response } from "express";
import path from "path";
import { adminService } from "./AdminService";
import { adminAuth } from "./admin-auth";
import { ADMIN_ENDPOINTS } from "./api-spec";
import config from "../config";

const router = Router();

/** Dashboard 静态页面（免认证，页面内输入令牌后访问 API） */
router.get("/dashboard", (_req: Request, res: Response) => {
  // 用 process.cwd() 而非 __dirname，兼容 ts-node 与 tsc build 产物
  res.sendFile(path.join(process.cwd(), "app", "admin", "dashboard", "index.html"));
});

/** API 全部需要认证 */
router.use("/api", adminAuth);

/** 服务器状态 */
router.get("/api/status", async (_req: Request, res: Response) => {
  res.json(await adminService.status());
});

/** 用户列表 */
router.get("/api/users", async (_req: Request, res: Response) => {
  res.json(await adminService.listUsers());
});

/** 用户详情 */
router.get("/api/users/:uid", async (req: Request, res: Response) => {
  const info = await adminService.getUserInfo(String(req.params.uid));
  if (!info) {
    res.status(404).json({ error: `用户不存在: ${req.params.uid}` });
    return;
  }
  res.json(info);
});

/** 创建用户 */
router.post("/api/users", async (req: Request, res: Response) => {
  try {
    const { phone, password } = req.body ?? {};
    const uid = await adminService.createUser(String(phone), String(password));
    await adminService.reloadUser(uid);
    res.status(201).json({ uid });
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 发放物品 */
router.post("/api/users/:uid/grant", async (req: Request, res: Response) => {
  try {
    const { itemId, count } = req.body ?? {};
    await adminService.grantItem(
      String(req.params.uid),
      String(itemId),
      Number(count),
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 发放干员 */
router.post("/api/users/:uid/grantchar", async (req: Request, res: Response) => {
  try {
    const { charId } = req.body ?? {};
    const result = await adminService.grantChar(String(req.params.uid), String(charId));
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 解锁皮肤 */
router.post("/api/users/:uid/grantskin", async (req: Request, res: Response) => {
  try {
    const { skinId } = req.body ?? {};
    await adminService.grantSkin(String(req.params.uid), String(skinId));
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 干员列表 */
router.get("/api/users/:uid/chars", async (req: Request, res: Response) => {
  try {
    res.json(await adminService.listChars(String(req.params.uid)));
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 修改干员属性 */
router.post("/api/users/:uid/chars", async (req: Request, res: Response) => {
  try {
    const { instId, ...attrs } = req.body ?? {};
    const result = await adminService.setCharAttrs(
      String(req.params.uid),
      Number(instId),
      attrs,
    );
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 一键满配 */
router.post("/api/users/:uid/maxout", async (req: Request, res: Response) => {
  try {
    res.json(await adminService.maxOutAccount(String(req.params.uid)));
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 基建满级 */
router.post("/api/users/:uid/building-max", async (req: Request, res: Response) => {
  try {
    res.json(await adminService.buildingMax(String(req.params.uid)));
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 创建备份 */
router.post("/api/users/:uid/backup", async (req: Request, res: Response) => {
  try {
    res.json(await adminService.backup(String(req.params.uid)));
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 备份列表 */
router.get("/api/users/:uid/backups", async (req: Request, res: Response) => {
  try {
    res.json(await adminService.listBackups(String(req.params.uid)));
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 从备份恢复 */
router.post("/api/users/:uid/restore", async (req: Request, res: Response) => {
  try {
    const { backup } = req.body ?? {};
    await adminService.restore(String(req.params.uid), String(backup));
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 原始玩家数据（完整 JSON） */
router.get("/api/users/:uid/raw", async (req: Request, res: Response) => {
  try {
    res.json(await adminService.getRawJson(String(req.params.uid)));
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 用户邮件列表 */
router.get("/api/users/:uid/mails", async (req: Request, res: Response) => {
  try {
    res.json(await adminService.listMails(String(req.params.uid)));
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 删除单封邮件 */
router.delete(
  "/api/users/:uid/mails/:mailId",
  async (req: Request, res: Response) => {
    try {
      const ok = await adminService.deleteMail(
        String(req.params.uid),
        Number(req.params.mailId),
      );
      if (!ok) {
        res.status(404).json({ error: `邮件不存在: ${req.params.mailId}` });
        return;
      }
      res.json({ ok: true });
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
    }
  },
);

/** 发送邮件 */
router.post("/api/mail", async (req: Request, res: Response) => {
  try {
    const { uid, subject, content, items } = req.body ?? {};
    const mail = await adminService.sendMail(String(uid), {
      subject: String(subject),
      content: String(content ?? ""),
      items: Array.isArray(items) ? items : [],
    });
    res.status(201).json({ mailId: mail.mailId });
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 群发邮件（全部用户） */
router.post("/api/mail/all", async (req: Request, res: Response) => {
  try {
    const { subject, content, items } = req.body ?? {};
    const result = await adminService.sendMailAll({
      subject: String(subject),
      content: String(content ?? ""),
      items: Array.isArray(items) ? items : [],
    });
    res.status(201).json(result);
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 每日/每周刷新 */
router.post("/api/users/:uid/refresh", async (req: Request, res: Response) => {
  try {
    await adminService.refreshUser(String(req.params.uid));
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 立即保存 */
router.post("/api/users/:uid/save", async (req: Request, res: Response) => {
  try {
    await adminService.saveUser(String(req.params.uid));
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 统计聚合 */
router.get("/api/stats", async (_req: Request, res: Response) => {
  res.json(await adminService.stats());
});

/** 审计日志 */
router.get("/api/logs", async (req: Request, res: Response) => {
  const q = (req.query ?? {}) as { limit?: string };
  const limit = Number(q.limit ?? 50);
  res.json(await adminService.logs(Number.isFinite(limit) ? limit : 50));
});

/** 常用物品别名（前端提示用） */
router.get("/api/common-items", (_req: Request, res: Response) => {
  res.json(adminService.getCommonItems());
});

/** 管理 API 端点规范（Dashboard「接口」控制台数据源） */
router.get("/api/spec", (_req: Request, res: Response) => {
  res.json({ endpoints: ADMIN_ENDPOINTS });
});

/** 游戏协议代理（带玩家 secret 调用游戏端点） */
router.post("/api/game-proxy", async (req: Request, res: Response) => {
  try {
    const { uid, path: gamePath, method, body } = req.body ?? {};
    const result = await adminService.gameProxy(
      String(uid),
      String(gamePath),
      (String(method ?? "GET").toUpperCase() as "GET" | "POST" | "DELETE"),
      body,
    );
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 卡池清单 */
router.get("/api/pools", (_req: Request, res: Response) => {
  res.json(adminService.listPools());
});

/** 卡池详情（UP/可用干员 + 概率） */
router.get("/api/pools/:poolId", (req: Request, res: Response) => {
  const detail = adminService.poolDetail(String(req.params.poolId));
  if (!detail) {
    res.status(404).json({ error: `卡池不存在: ${req.params.poolId}` });
    return;
  }
  res.json(detail);
});

/** 玩家卡池状态（UP 选择 + 保底计数） */
router.get("/api/users/:uid/pools/:poolId", async (req: Request, res: Response) => {
  try {
    res.json(
      await adminService.getPlayerPoolState(
        String(req.params.uid),
        String(req.params.poolId),
      ),
    );
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 设置玩家卡池 UP 选择（charIds 空数组清除） */
router.post("/api/users/:uid/pools/:poolId/up", async (req: Request, res: Response) => {
  try {
    const { charIds } = req.body ?? {};
    res.json(
      await adminService.setPlayerPoolUp(
        String(req.params.uid),
        String(req.params.poolId),
        Array.isArray(charIds) ? charIds : [],
      ),
    );
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 设置玩家保底计数 */
router.post("/api/users/:uid/pity", async (req: Request, res: Response) => {
  try {
    const { ruleType, count } = req.body ?? {};
    res.json(
      await adminService.setPlayerPity(
        String(req.params.uid),
        String(ruleType),
        Number(count),
      ),
    );
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

/** 配置（只读） */
router.get("/api/config", (_req: Request, res: Response) => {
  res.json(config);
});

export default router;
