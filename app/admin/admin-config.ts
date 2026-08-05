/**
 * 管理后台配置模块
 *
 * 从 data/config.json 读取 admin 配置段（enable / token）。
 */
import config from "../config";

/** 管理后台配置接口 */
export interface AdminConfig {
  /** 是否开启 /admin HTTP 管理接口（CLI 不受影响） */
  enable: boolean;
  /** 管理 API Bearer Token */
  token: string;
}

/** 默认管理配置（安全默认：接口关闭） */
const DEFAULT_ADMIN_CONFIG: AdminConfig = {
  enable: false,
  token: "doctorate-admin",
};

/** 读取管理配置（缺失 admin 段时回退默认值） */
export function getAdminConfig(): AdminConfig {
  const admin = (config as any).admin;
  return {
    enable: admin?.enable ?? DEFAULT_ADMIN_CONFIG.enable,
    token: admin?.token ?? DEFAULT_ADMIN_CONFIG.token,
  };
}
