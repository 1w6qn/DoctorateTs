/**
 * 网络工具模块
 * 
 * 提供网络相关的工具函数，如获取本机 IP 地址。
 */

import os from "os";

/**
 * 获取本机 IP 地址
 * 
 * 遍历网络接口，返回第一个非本地的 IP 地址。
 * 
 * @param isIPV4 - 是否获取 IPv4 地址，默认为 true
 * @returns IP 地址字符串，未找到返回 undefined
 */
export function getIPAddress(isIPV4: boolean = true) {
  const interfaces = os.networkInterfaces();
  for (const devName in interfaces) {
    const ifs = interfaces[devName]!;
    for (let i = 0; i < ifs.length; i++) {
      const alias = ifs[i];
      if (isIPV4) {
        if (
          alias.family === "IPv4" &&
          alias.address !== "127.0.0.1" &&
          !alias.internal
        ) {
          return alias.address;
        }
      } else if (alias.address !== "127.0.0.1" && !alias.internal) {
        if (alias.family === "IPv6") {
          return alias.address;
        }
      }
    }
  }
}