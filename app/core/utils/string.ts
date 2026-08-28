/**
 * 字符串工具模块
 * 
 * 提供字符串处理相关的工具函数。
 */

/**
 * 将下划线命名转换为驼峰命名
 * 
 * @param str - 下划线命名的字符串
 * @returns 驼峰命名的字符串
 */
export function toCamelCase(str: string): string {
    return str.toLowerCase().replace(/(_[a-z])/g, (group) => group.toUpperCase().replace('_', ''));
}