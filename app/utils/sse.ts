/**
 * SSE（Server-Sent Events）工具
 *
 * Dashboard「日志」实时尾随与「抓包」实时列表共用：
 * - createSse：设置 text/event-stream 响应头 + 15s 心跳保活 + 客户端断开自动清理
 * - sseSend：推送一条事件（event + JSON data）
 *
 * 注意：index.ts 的 compression 中间件已排除 /stream 路径（zlib 缓冲会破坏逐事件推送）。
 */
import { Request, Response } from "express";

/** 心跳间隔（毫秒）——代理/浏览器 keep-alive 保活 */
const HEARTBEAT_MS = 15000;

/**
 * 初始化 SSE 响应
 *
 * @param req - 请求（监听 close 清理心跳）
 * @param res - 响应
 * @returns 清理函数（关闭时调用，幂等）
 */
export function createSse(req: Request, res: Response): () => void {
  res.set({
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  res.flushHeaders();
  res.write(": connected\n\n");
  const heartbeat = setInterval(() => {
    try {
      res.write(": ping\n\n");
    } catch {
      clearInterval(heartbeat);
    }
  }, HEARTBEAT_MS);
  const cleanup = () => clearInterval(heartbeat);
  req.on("close", cleanup);
  return cleanup;
}

/**
 * 推送一条 SSE 事件
 *
 * @param res - SSE 响应
 * @param event - 事件名（客户端 addEventListener(event) 接收）
 * @param data - 事件数据（JSON 序列化）
 */
export function sseSend(res: Response, event: string, data: unknown): void {
  try {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    // compression 中间件存在时 res.flush 可强制冲刷（SSE 路径已排除压缩，此处仅防御性调用）
    const flushable = res as Response & { flush?: () => void };
    flushable.flush?.();
  } catch {
    /* 客户端已断开，写入失败忽略（由 close 清理心跳） */
  }
}
