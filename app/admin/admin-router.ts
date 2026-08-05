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

/** 配置（只读） */
router.get("/api/config", (_req: Request, res: Response) => {
  res.json(config);
});

export default router;
