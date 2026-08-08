import { describe, it, expect, vi } from "vitest";
import { gameErrorHandler } from "../../../app/game/app";

/**
 * 游戏路由统一错误处理（S5 相关）
 *
 * 无此中间件时 Express 默认返回 HTML 500（客户端 JSON 解析失败）——
 * 例：single 模式社交自请求（不能加自己为好友）抛错走此路径。
 * 中间件返回 JSON { status, msg, code }。
 */
describe("gameErrorHandler 统一错误处理", () => {
  it("async 抛错应返回 JSON 500 而非 HTML", () => {
    const res = { status: vi.fn().mockReturnThis(), json: vi.fn() };
    const next = vi.fn();
    gameErrorHandler(new Error("不能向自己发送好友请求"), {} as any, res as any, next as any);
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({
      status: 1,
      msg: "服务器内部错误",
      code: "INTERNAL_ERROR",
    });
    expect(next).not.toHaveBeenCalled();
  });
});
