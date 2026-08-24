/**
 * 活动领域事件映射（Activity）
 *
 * 集中定义限时活动（活动任务 + 活动勋章）的领域事件：
 * - 奇象巡展（ARK_HUB）任务模板事件
 * - 奇象巡展勋章模板事件
 *
 * 事件名 = ActivityTable.missionData.template / medal_table.template 一致，
 * 各事件参数与模板 param 语义对齐。
 */
export type EventMapActivity = {
  // ============ 奇象巡展（ARK_HUB）任务模板事件 ============
  /** ArkhubMissionCompleted：引导任务（param[2]=引导 flag，本服引导为完成态 → 播种即完成） */
  ArkhubMissionCompleted: [{ activityId: string; flag: string }];
  /** ArkhubDailyMissionCompleted：每日物资领取天数（param[2..3]=日期区间，param[4]=目标天数） */
  ArkhubDailyMissionCompleted: [{ activityId: string; days: number }];
  /** ArkhubCreatureCollection：收录生物种类数（param[2]=目标 N，param[3]=collectionKey：1=全部/2=活动频繁） */
  ArkhubCreatureCollection: [
    { activityId: string; count: number; collectionKey: string },
  ];
  /** ArkhubCreatureCaptured：信息素诱引生物扫描（param[2]=目标次数） */
  ArkhubCreatureCaptured: [{ activityId: string }];
  /** ArkhubCreatureExchange：发起生物数据交换（param[2]=目标次数） */
  ArkhubCreatureExchange: [{ activityId: string }];
  /** ArkhubPassDexBattle：奇象拟合对战完成次数（param[2]=目标 N；count=累计完成数） */
  ArkhubPassDexBattle: [{ activityId: string; count: number }];
  /** ArkhubPublishPixelArt：发布画像数（param[2]=目标 N） */
  ArkhubPublishPixelArt: [{ activityId: string; count: number }];
  /** ArkhubCollectPixelArt：收集画像数（param[2]=目标 N） */
  ArkhubCollectPixelArt: [{ activityId: string; count: number }];

  // ============ 奇象巡展勋章模板事件 ============
  /** ActivityArkhubPixelCollect：收集画像（unlockParam=[act1arkhub,0,4] → target=param[2]） */
  ActivityArkhubPixelCollect: [{ activityId: string; count: number }];
  /** ActivityArkhubCreatureCollect：收录生物种类（unlockParam=[act1arkhub,arkhubMissionCollection1,10]） */
  ActivityArkhubCreatureCollect: [
    { activityId: string; count: number; collectionKey: string },
  ];
  /** ActivityArkhubAlterCollect：镀层（unlockParam=[act1arkhub,arkhubMissionCollection1,10,1]：10 种 + 1 亚种） */
  ActivityArkhubAlterCollect: [
    { activityId: string; count: number; alterCount: number },
  ];
};