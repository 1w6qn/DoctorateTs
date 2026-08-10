import type { ClassDef } from "./playerdata-parser";

/**
 * 类型适配共用操作（playerdata / excel 两个域共用）
 *
 * 适配操作按序应用：rename → add → override（整接口/字段级）→ 字段类型覆盖。
 * 各域只维护数据表（scripts/playerdata-server-adapt.ts、excel-server-adapt.ts），
 * 应用逻辑统一在本模块。
 */

export interface AdaptOps {
  /** 字段改名：接口名 → { 客户端字段名: 目标 key } */
  rename?: Record<string, Record<string, string>>;
  /** 服务端独有字段补充：接口名 → { 字段名: TS 类型 } */
  add?: Record<string, Record<string, string>>;
  /** 结构差异覆盖：接口名 → { "[server]": 整接口类型别名 } 或 { 字段名: 类型 } */
  override?: Record<string, Record<string, string>>;
  /** 可选字段：接口名 → 字段名数组（生成 name?: type） */
  optional?: Record<string, string[]>;
  /** 字段类型覆盖（最高优先级）："Iface.field" → TS 类型 */
  fieldTypeOverrides?: Record<string, string>;
}

/** 应用整接口覆盖（"[server]" 键）：返回覆盖后的类型别名；无覆盖返回 null */
function applyWholeOverride(override: Record<string, string> | undefined): string | null {
  if (!override) return null;
  const whole = override["[server]"];
  return whole === undefined ? null : whole;
}

/**
 * 应用适配操作：rename → add → override → 字段类型覆盖（按序）
 * @param classes - 客户端闭包类定义
 * @param ops - 适配数据表
 * @returns 适配后的类定义列表（不修改入参）
 */
export function applyAdaptOps(classes: ClassDef[], ops: AdaptOps): ClassDef[] {
  const rename = ops.rename ?? {};
  const add = ops.add ?? {};
  const override = ops.override ?? {};
  const optional = ops.optional ?? {};
  const fieldOverrides = ops.fieldTypeOverrides ?? {};

  return classes.map(iface => {
    const ifaceRename = rename[iface.name] ?? {};
    const ifaceAdd = add[iface.name] ?? {};
    const ifaceOptional = optional[iface.name] ?? [];

    // 1. rename
    let fields = iface.fields.map(f => {
      const target = ifaceRename[f.name];
      return target ? { ...f, name: target } : { ...f };
    });

    // 2. add（不重复）
    for (const [name, type] of Object.entries(ifaceAdd)) {
      if (!fields.some(f => f.name === name)) {
        fields.push({ name, rawType: type, type });
      }
    }

    // 3. override（整接口覆盖优先：转为类型别名；字段级覆盖：替换类型）
    const aliasType = applyWholeOverride(override[iface.name]);
    if (aliasType !== null) {
      return { ...iface, fields: [], aliasType, optionalFields: ifaceOptional };
    }
    const ifaceOverride = override[iface.name];
    if (ifaceOverride) {
      fields = fields.map(f => {
        const target = ifaceOverride[f.name];
        return target ? { ...f, rawType: target, type: target } : f;
      });
    }

    // 4. 字段类型覆盖（最高优先级）
    fields = fields.map(f => {
      const target = fieldOverrides[`${iface.name}.${f.name}`];
      return target ? { ...f, rawType: target, type: target } : f;
    });

    return { ...iface, fields, optionalFields: ifaceOptional };
  });
}
