import { describe, it, expect, vi } from "vitest";
import type { Request, Response } from "express";
import { gameErrorHandler } from "../../../app/game/app";

/** 错误处理中间件响应视图：只声明被测分支读到的两个方法 */
interface MockRes {
  status: Response["status"];
  json: Response["json"];
}

/**
 * 游戏路由统一错误处理（S5 相关）
 *
 * 无此中间件时 Express 默认返回 HTML 500（客户端 JSON 解析失败）——
 * 例：single 模式社交自请求（不能加自己为好友）抛错走此路径。
 * 中间件返回 JSON { status, msg, code }。
 */
describe("gameErrorHandler 统一错误处理", () => {
  it("async 抛错应返回 JSON 500 而非 HTML", () => {
    const res: MockRes = {
      status: vi.fn<Response["status"]>().mockReturnThis(),
      json: vi.fn<Response["json"]>(),
    };
    const next = vi.fn();
    // 请求替身只满足中间件签名（错误处理分支不读 req）
    gameErrorHandler(new Error("不能向自己发送好友请求"), {} as Request, res as Response, next);
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json).toHaveBeenCalledWith({
      status: 1,
      msg: "服务器内部错误",
      code: "INTERNAL_ERROR",
    });
    expect(next).not.toHaveBeenCalled();
  });
});
