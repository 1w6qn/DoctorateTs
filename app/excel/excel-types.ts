/**
 * Excel 防腐层（业务层类型入口）
 *
 * 职责：作为业务层接触「由官方热更管线重新生成的权威类型」的唯一入口，
 * 业务代码不得直接 `import ... from "@excel/types_excel_gen"`（由架构守卫强制）。
 *
 * 收益：生成文件若发生类型改名/移动，只需在此处同步 re-export，业务层零感知，
 * 把「生成 schema 变更 → 波及全部业务文件」收敛为「仅波及本 seam」。
 * 采用 `export type` 保持与生成类型完全一致（不引入形状漂移）。
 *
 * 官方生成文件见 `scripts/generate-types.ts`（AGENTS.md 标注「never hand-edit」，
 * 本 seam 是对其的业务侧唯一可编辑入口）。
 */
export type { GachaPoolClientData } from "./types_excel_gen";
export type { UniEquipData } from "./types_excel_gen";
export type { MailArchiveItemData } from "./types_excel_gen";
export type { MissionData } from "./types_excel_gen";
export type { Act44SideData } from "./types_excel_gen";
export type {
  ActivityBossRushData,
  ActivityBossRushData_RelicLevelInfo,
} from "./types_excel_gen";