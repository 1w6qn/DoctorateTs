/**
 * 任务模板注册表组装
 *
 * 按域分组的模板文件在此汇总为完整注册表（键序按分组固定，
 * 模板按事件名查找，顺序无语义影响）。
 */
import type { MissionTemplateGroup } from "./types";
import { stageTemplates } from "./stage";
import { charTemplates } from "./char";
import { buildingTemplates } from "./building";
import { economyTemplates } from "./economy";
import { arkhubTemplates } from "./arkhub";
import { rlv2Templates } from "./rlv2";

export const MissionTemplates: MissionTemplateGroup = {
  ...stageTemplates,
  ...charTemplates,
  ...buildingTemplates,
  ...economyTemplates,
  ...arkhubTemplates,
  ...rlv2Templates,
};
