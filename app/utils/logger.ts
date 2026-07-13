/**
 * 日志工具模块
 * 
 * 提供日志记录功能和颜色映射配置。
 */

/**
 * 日志记录器
 * 
 * 直接使用 console 对象作为日志记录器，支持 console.log、console.error 等方法。
 */
export const logger = console;

/**
 * 角色稀有度颜色映射
 * 
 * 根据角色稀有度等级返回对应的颜色值，用于日志输出或 UI 显示。
 */
export const text2color = {
    "TIER_6": "#FF0000",  // 六星角色 - 红色
    "TIER_5": "#FFFF00",  // 五星角色 - 黄色
    "TIER_4": "#FF00FF",  // 四星角色 - 紫色
    "TIER_3": "#0000FF",  // 三星角色 - 蓝色
    "TIER_2": "#FFFFFF",  // 二星角色 - 白色
    "TIER_1": "#FFFFFF",  // 一星角色 - 白色
}