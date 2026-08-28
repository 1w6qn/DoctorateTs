/* 上帝视角实时修改：applyRlv2Patch 路径补丁（set/del/inc，含数组下标）单测 */
import { describe, it, expect } from "vitest";
import { applyRlv2Patch } from "@ops/admin/AdminService";

describe("applyRlv2Patch（上帝视角实时修改补丁）", () => {
  it("set 赋值标量并自动创建中间路径", () => {
    const root: Record<string, unknown> = {
      player: { property: { hp: {} } },
    };
    applyRlv2Patch(root, "set", ["player", "property", "hp", "current"], 999);
    expect((root.player as any).property.hp.current).toBe(999);
  });

  it("set 不存在时自动创建中间对象路径", () => {
    const root: Record<string, unknown> = {};
    applyRlv2Patch(root, "set", ["a", "b", "c"], 42);
    expect((root as any).a.b.c).toBe(42);
  });

  it("set 数组下标按数字键写入（inventory.char 下标场景）", () => {
    const root: Record<string, unknown> = { list: [{ id: 1 }] };
    applyRlv2Patch(root, "set", ["list", "1", "id"], 2);
    expect((root.list as any[])[1].id).toBe(2);
  });

  it("inc 数值累加（缺省从 0 起步 / 显式增量）", () => {
    const root: Record<string, unknown> = { n: 5, blank: {} };
    applyRlv2Patch(root, "inc", ["n"], 3);
    applyRlv2Patch(root, "inc", ["blank", "x"], 7);
    expect((root as any).n).toBe(8);
    expect((root as any).blank.x).toBe(7);
  });

  it("del 删除对象键 / 数组元素", () => {
    const root: Record<string, unknown> = {
      obj: { a: 1, b: 2 },
      arr: [10, 20, 30],
    };
    applyRlv2Patch(root, "del", ["obj", "a"]);
    applyRlv2Patch(root, "del", ["arr", "1"]);
    expect((root as any).obj).toEqual({ b: 2 });
    expect((root as any).arr).toEqual([10, 30]);
  });

  it("set 传 undefined 语义为删除键", () => {
    const root: Record<string, unknown> = { keep: 1, gone: 2 };
    applyRlv2Patch(root, "set", ["gone"], undefined);
    expect(root).toEqual({ keep: 1 });
  });
});