/**
 * 本地数据版本一致性校验
 *
 * 官服热更管线同时在 `data/excel/` 落下两份版本信息：
 * - `data_version.txt` —— 官服热更描述符（`Stream: //torappu-data/v076/rel76.0` /
 *   `Change: 120163 on 2026/08/06` / `VersionControl: 76.2.0`）
 * - `gamedata_const.json → dataVersion` —— excel 数据内嵌版本（实测同为 76.2.0）
 *
 * 修复（2026-09-09，S10）：此前全仓仅有类型声明引用 `dataVersion`，两份版本号不一致时**无任何告警**
 * ——更新中断/只转换了部分表时静默带着新旧混合数据启动。现提供解析与比对，供启动期与离线校验使用。
 */
import fs from "node:fs";
import path from "node:path";

import { logger } from "@utils/logger";
import { excelFilePath } from "./excel-data-dir";

/** data_version.txt 解析结果 */
export interface DataVersionDescriptor {
  /** `Stream:` 行（热更流地址） */
  stream?: string;
  /** `Change:` 行（变更号与日期） */
  change?: string;
  /** `VersionControl:` 行（版本号，如 76.2.0） */
  versionControl?: string;
}

/** 版本一致性校验结果 */
export interface DataVersionCheck {
  /** 两份版本是否一致（任一侧缺失时视为不可判定 → ok: true 但 ok=false 不适用，见 message） */
  ok: boolean;
  /** data_version.txt 中的版本号 */
  fileVersion?: string;
  /** gamedata_const.json 中的 dataVersion */
  dataVersion?: string;
  /** 人类可读结论 */
  message: string;
}

/**
 * 解析 `data_version.txt`（逐行 `Key: Value`）
 * @param text - 文件内容
 * @returns 解析出的描述符（缺行则为 undefined）
 */
export function parseDataVersionFile(text: string): DataVersionDescriptor {
  const out: DataVersionDescriptor = {};
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line) continue;
    const idx = line.indexOf(":");
    if (idx < 0) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (key === "stream") out.stream = value;
    else if (key === "change") out.change = value;
    else if (key === "versioncontrol") out.versionControl = value;
  }
  return out;
}

/**
 * 比对两份版本号
 * @param fileVersion - `data_version.txt` 的 `VersionControl`（可缺失）
 * @param dataVersion - `gamedata_const.json` 的 `dataVersion`（可缺失）
 * @returns 校验结果（任一侧缺失时判为不可判定，ok 为 true，message 说明原因）
 */
export function checkDataVersion(
  fileVersion: string | undefined,
  dataVersion: string | undefined,
): DataVersionCheck {
  if (!fileVersion || !dataVersion) {
    return {
      ok: true,
      fileVersion,
      dataVersion,
      message: `数据版本不可判定（data_version.txt=${fileVersion ?? "缺失"}，gamedata_const=${dataVersion ?? "缺失"}）`,
    };
  }
  const ok = fileVersion === dataVersion;
  return {
    ok,
    fileVersion,
    dataVersion,
    message: ok
      ? `数据版本一致（${dataVersion}）`
      : `数据版本不一致：data_version.txt=${fileVersion} 而 gamedata_const.dataVersion=${dataVersion}（更新可能中断或仅转换了部分表）`,
  };
}

/**
 * 读取磁盘上的两份版本信息并比对（纯文件系统操作，无网络）
 * @param baseDir - 项目根目录（默认 cwd）
 * @returns 校验结果；文件不存在时按不可判定返回
 */
export function verifyLocalDataVersion(baseDir: string = process.cwd()): DataVersionCheck {
  let fileVersion: string | undefined;
  let dataVersion: string | undefined;
  try {
    const txt = fs.readFileSync(
      path.join(baseDir, "data/excel/data_version.txt"),
      "utf8",
    );
    fileVersion = parseDataVersionFile(txt).versionControl;
  } catch {
    /* 文件缺失 → 不可判定 */
  }
  try {
    const constTable = JSON.parse(
      fs.readFileSync(path.join(baseDir, "data/excel/gamedata_const.json"), "utf8"),
    ) as { dataVersion?: string };
    dataVersion = constTable?.dataVersion;
  } catch {
    /* 文件缺失 → 不可判定 */
  }
  return checkDataVersion(fileVersion, dataVersion);
}

/**
 * 启动期校验已加载的 excel 数据版本（不阻断启动，仅告警）
 *
 * 与调用方传入的 `GameDataConst.dataVersion` 比对磁盘 `data_version.txt`；
 * 不一致时打 WARN，便于发现「更新中断 / 只转换了部分表」的混合数据状态。
 * 注：刻意不 import excel 单例（excel.ts 反向 import 本模块，避免循环依赖）。
 * @param dataVersion - 已加载的 `GameDataConst.dataVersion`
 * @returns 校验结果
 */
export function verifyLoadedDataVersion(dataVersion?: string): DataVersionCheck {
  const fileVersion = (() => {
    try {
      return parseDataVersionFile(
        fs.readFileSync(
          excelFilePath("./data/excel/data_version.txt"),
          "utf8",
        ),
      ).versionControl;
    } catch {
      return undefined;
    }
  })();
  const result = checkDataVersion(fileVersion, dataVersion);
  if (!result.ok) logger.warn("Excel", result.message);
  return result;
}
