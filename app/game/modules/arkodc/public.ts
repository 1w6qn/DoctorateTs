/**
 * arkodc 对外门面（模块间仅可 import public.ts）
 *
 * 跨模块引用的业务函数在此收敛导出（home /story/finishStory → finishArkOdcGuideStory）。
 */
export { ARK_ODC_GUIDE_STORY_ID, finishArkOdcGuideStory } from "./guide";
