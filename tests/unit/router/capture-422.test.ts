/**
 * 抓包 422 修复回归测试
 *
 * 覆盖真实客户端抓包中被 zod 校验拦成 422、现已修复放行的请求形态，
 * 防止后续收紧 schema 再次误伤正常客户端请求。
 */
import { describe, it, expect, vi } from "vitest";
import * as Building from "../../../app/game/modules/building/schemas";
import * as BusinessCard from "../../../app/game/model/protocol/businessCard.schema";
import { validateBody } from "../../../app/game/model/protocol/validate-body";

function makeRes() {
  const json = vi.fn();
  const status = vi.fn().mockReturnThis();
  return { json, status };
}

/** 断言合法 body 通过（next 被调用且未返回 4xx） */
function expectPass(schema: any, body: unknown): void {
  const res = makeRes();
  const next = vi.fn();
  validateBody(schema)({ body } as any, res as any, next);
  expect(next).toHaveBeenCalledTimes(1);
  expect(res.status).not.toHaveBeenCalled();
}

describe("抓包 422 修复（真实客户端形态放行）", () => {
  it("/building/batchRestChar 发空体 {} 应通过（handler 空列表不改分配）", () => {
    expectPass(Building.batchRestCharSchema, {});
  });

  it("/building/batchChangeWorkChar 发空体 {} 应通过（换班走预设队列轮换）", () => {
    expectPass(Building.batchChangeWorkCharSchema, {});
  });

  it("/businessCard/editNameCard content.skinId/component 为 null、misc 为 0/1 数字应通过", () => {
    expectPass(BusinessCard.editNameCardSchema, {
      flag: 4,
      content: {
        skinId: null,
        component: null,
        misc: { showDetail: 1, showBirthday: 0 },
        skinTmpl: 0,
      },
    });
  });

  it("/businessCard/editNameCard 非杂项模式 flag=1 时 misc 显式传 null 应通过", () => {
    expectPass(BusinessCard.editNameCardSchema, {
      flag: 1,
      content: {
        skinId: null,
        component: ["module_medal", "module_equip"],
        misc: null,
        skinTmpl: 0,
      },
    });
  });
});