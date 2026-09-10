/**
 * act44side（「墟」）活动族对外出口（public.ts）
 *
 * 跨模块引用约定（AGENTS.md「落位规则」）：模块间只允许 import 对方 public.ts 或走事件总线。
 * 情报屋（informant）状态机被 activities/milestone 与 activities/shared 共用，经此门面导出，
 * 不再让兄弟活动族直接触达 `act44side/informant` 内部实现（守卫 R3，见
 * tests/unit/architecture/module-boundary.test.ts）。
 */
export {
  resolveAct44Data,
  defaultAct44State,
  syncAct44SideEntry,
  informantStartGame,
  informantNextState,
  informantSelectChoice,
  informantUseInsight,
} from "./informant";
