/**
 * 基建 Buff 模板基类（BaseBuffTpl）
 *
 * 对齐 OBS BuildingManager.BaseBuffTpl 体系：每个基建技能一个模板类，
 * 参数属性化（param 下标语义） + 效果钩子（value），类 JSDoc 内嵌官方效果原文。
 *
 * 本项目定位：buff 计算核心仍是 buff-parse.ts 的纯函数引擎（数值/单位已按真实存档
 * 校准），模板类是**声明式注册层**——为每个 buff 类别提供可扩展的类文件与文档入口，
 * 新技能只需在 buffs/ 新增一个类并注册（见 buffs/index.ts），无需改引擎。
 * 模板 value() 内部委托 buff-parse 解析函数，保证与引擎结果一致
 * （一致性由 tests/unit/modules/building/buff-tpl.test.ts 守护）。
 */
import type { BuildingBuffLike } from "./buff-parse";
import type { SpecialSkillContext } from "./special";

export abstract class BaseBuffTpl {
  /** 原始 buff 对象（excel.BuildingData.buffs[buffId]） */
  constructor(public readonly raw: BuildingBuffLike) {}

  /** 效果类别标识（子类覆盖：CONTROL_GLOBAL / ROOM_SPEED / DORM_RECOVER / MOOD_COST） */
  abstract readonly kind: string;

  /** 官方参数（raw.param，缺失给空数组；语义由各模板 JSDoc 标注） */
  get param(): string[] {
    return Array.isArray(this.raw?.param) ? this.raw.param : [];
  }

  /** 官方效果描述（类 JSDoc 内嵌原文的运行时入口） */
  get description(): string {
    return this.raw?.description ?? "";
  }

  /** buffId（去 [] 后缀） */
  get groupKey(): string {
    return this.raw?.buffId ?? "";
  }

  /** 匹配判定：buffId/结构是否属于本模板（子类覆盖） */
  static matches(_buff: BuildingBuffLike): boolean {
    return false;
  }

  /**
   * 效果数值（乘法系数/点值，子类覆盖；未实现返回 0）
   * @param ctx - 特殊技能上下文（fraction/token 条件判定用，可选）
   */
  value(_ctx?: SpecialSkillContext): number {
    return 0;
  }

  /**
   * 对指定目标房间的效果数值（控制中枢全局类覆盖；其余默认等于 value()）
   * @param targetRoom - 目标房间类型（如 DORMITORY 无 % 时取心情恢复原值）
   */
  valueForTarget(_targetRoom: string): number {
    return this.value();
  }
}
