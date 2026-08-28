/**
 * region 抽象层（RegionProvider）
 *
 * 多服维度配置解析：capture 模式下按 region 提供伪装版本、资源通道（CDN/版本）、
 * 转发目标与 as 域路径前缀。字段级回退保证零迁移——region 未配置/字段缺失时
 * 全部回退现状（config.version / 国服 CDN / 现有转发主机）。
 *
 * 作用域：region 特性仅在 capture 模式生效（config.capture.enabled）；非 capture
 * 的私服游玩场景保持现状，避免伪装版本破坏正常更新链路。
 */
import config from "../config";
import { logger } from "@utils/logger";

/** region 版本伪装（字段级可选，缺省回退 config.version 对应字段） */
export interface RegionVersion {
  clientVersion?: string;
  resVersion?: string;
  windows?: { clientVersion?: string; resVersion?: string };
}

/** 单 region 配置（对齐《多服支持》方案 A 字段：as/gs/cdn/version） */
export interface RegionConfig {
  /** 版本伪装（version 端点响应字段级回退 config.version） */
  version?: RegionVersion;
  /** 资源 CDN 基址（缺省国服 CDN DEFAULT_CDN） */
  cdn?: string;
  /** CDN 下载用资源版本（缺省 version.resVersion；「指定资源版本」） */
  cdnVersion?: string;
  /** capture 转发 as 目标（缺省 OFFICIAL_AS_HOST / capture.asHost） */
  as?: string;
  /** capture 转发 gs 目标（缺省 OFFICIAL_GS_HOST / capture.gsHost） */
  gs?: string;
  /** 额外 as 域路径前缀（yostar 登录链路等，可选；与默认 AS_PATH_PREFIXES 合并） */
  asPathPrefixes?: string[];
}

/** 国服资源 CDN 基址（region 未配置时的缺省值） */
export const DEFAULT_CDN = "https://ak.hycdn.cn";

/** 解析后版本（字段已回退，非可选） */
export interface ResolvedVersion {
  clientVersion: string;
  resVersion: string;
  windows?: { clientVersion: string; resVersion: string };
}

/**
 * 当前生效 region id（capture 模式专用）
 *
 * capture.region ?? config.region ?? "cn"；capture 未启用或 region 名不在
 * regions 表中（cn 缺条目属正常——回退 config.version 现状）→ null。
 */
export function resolveRegionId(): string | null {
  if (!config.capture?.enabled) return null;
  const id = config.capture.region ?? config.region ?? "cn";
  // cn 为内建缺省 region：regions 表无条目时由 resolveRegion 层回退现状（config.version 等）
  if (id !== "cn" && !config.regions?.[id]) {
    logger.warn("region", `region "${id}" 未在 regions 表配置，回退现状`);
    return null;
  }
  return id;
}

/** 当前生效的 region 配置（null = 现状行为） */
export function resolveRegion(): RegionConfig | null {
  const id = resolveRegionId();
  if (!id) return null;
  return config.regions?.[id] ?? null;
}

/** 伪装版本：region.version 字段级回退 fallback（config.version） */
export function resolveRegionVersion(
  region: RegionConfig | null,
  fallback: ResolvedVersion,
): ResolvedVersion {
  if (!region?.version) return fallback;
  return {
    clientVersion: region.version.clientVersion ?? fallback.clientVersion,
    resVersion: region.version.resVersion ?? fallback.resVersion,
    windows: region.version.windows
      ? {
          clientVersion:
            region.version.windows.clientVersion ??
            region.version.clientVersion ??
            fallback.windows?.clientVersion ??
            fallback.clientVersion,
          resVersion:
            region.version.windows.resVersion ??
            region.version.resVersion ??
            fallback.windows?.resVersion ??
            fallback.resVersion,
        }
      : fallback.windows,
  };
}

/** 资源 CDN 基址：region.cdn 优先，缺省 fallbackCdn（DEFAULT_CDN） */
export function resolveRegionCdn(
  region: RegionConfig | null,
  fallbackCdn: string = DEFAULT_CDN,
): string {
  return region?.cdn ?? fallbackCdn;
}

/** CDN 下载用资源版本：region.cdnVersion 优先，缺省解析后版本的 resVersion */
export function resolveRegionCdnVersion(region: RegionConfig | null, resolved: ResolvedVersion): string {
  return region?.cdnVersion ?? resolved.resVersion;
}

/** 转发目标：region.as/gs 优先，缺省回退 fallback */
export function resolveRegionHosts(
  region: RegionConfig | null,
  fallbackAs: string,
  fallbackGs: string,
): { as: string; gs: string } {
  return { as: region?.as ?? fallbackAs, gs: region?.gs ?? fallbackGs };
}

/** as 域路径前缀：默认列表 + region.asPathPrefixes 扩展 */
export function resolveRegionAsPrefixes(
  region: RegionConfig | null,
  defaults: readonly string[],
): string[] {
  return [...defaults, ...(region?.asPathPrefixes ?? [])];
}
