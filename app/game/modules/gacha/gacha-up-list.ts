/**
 * 抽卡共享工具（domain/util 公共件）
 *
 * GACHA_RULE_TYPE（gachaRuleType → 玩家数据子结构名）与 resolveEffectiveUpPerCharList
 * （生效 UP 干员列表纯函数）原属 gacha 模块；ShopManager 等跨模块消费——
 * 上移公共工具层，gacha/shop 统一从本层取用，消除 shop → gacha 值级耦合。
 */
import type {
  GachaDetailData,
  GachaDetailTable,
  GachaPerChar,
  GachaPoolClientData,
} from "@excel/excel";
import type { PlayerGacha } from "../../kernel/playerdata";
import { getIn } from "../../kernel/util/json-path";

export const GACHA_RULE_TYPE: { [rule: string]: string } = {
    NORMAL: "normal",
    ATTAIN: "attain",
    LIMITED: "limit",
    SINGLE: "single",
    CLASSIC: "classic",
    CLASSIC_ATTAIN: "classic",
    CLASSIC_DOUBLE: "doubleGacha",
    FESCLASSIC: "fesClassic",
    SPECIAL: "special",
    BACKFLOW: "backflow",
    DOUBLE: "double",
    NEWBEE: "newbee",
    LINKAGE: "linkage",
};


/**
 * 生效 UP 干员列表（纯函数版，供 ShopManager 等跨模块直接调用）
 *
 * 内联 GachaManager.effectiveUpPerCharList/_selfSelectedUpDict 的实现：
 * 静态 upCharInfo.perCharList 为基座，按稀有度用玩家自选 charIdList 覆盖。
 * 详情缺失时回退首个结构完整卡池（upCharInfo 置空走通用池）。返回克隆，不改共享详情。
 *
 * @param table - 抽卡详情表（excel.GachaDetailTable）
 * @param poolConfigs - 卡池客户端配置列表（excel.GachaTable.gachaPoolClient）
 * @param gacha - 玩家抽卡数据（含自选 UP 字典）
 * @param poolId - 抽卡池ID
 * @returns 合并玩家自选后的 perCharList（克隆）
 */
export function resolveEffectiveUpPerCharList(
  table: GachaDetailTable,
  poolConfigs: GachaPoolClientData[],
  gacha: PlayerGacha | undefined,
  poolId: string,
): GachaPerChar[] {
  // _poolDetail 内联：缺详情回退首个结构完整卡池（无缓存，每次重建）
  let d = table.details[poolId];
  if (!d) {
    const first = Object.values(table.details).find(
      (x) => x?.availCharInfo?.perAvailList?.length,
    );
    d = first
      ? ({
          ...first,
          upCharInfo: { perCharList: [] },
          limitedChar: [],
          weightUpCharInfoList: [],
          gachaObjGroups: null,
        } as GachaDetailData)
      : ({
          upCharInfo: { perCharList: [] },
          availCharInfo: { perAvailList: [] },
          gachaObjGroups: null,
        } as unknown as GachaDetailData);
  }
  // 格式归一：CS GachaDetailData.gachaObjGroups 为客户端解析必需字段，缺失时补 null
  // （用 hasOwnProperty 而非 `in`：TS 已知该属性为必填，`in` 反查会收窄成 never）
  if (d && !Object.prototype.hasOwnProperty.call(d, "gachaObjGroups")) {
    d.gachaObjGroups = null;
  }
  const base: GachaPerChar[] = (d.upCharInfo?.perCharList ?? []).map(
    (c) => ({ ...c, charIdList: [...c.charIdList] }),
  );
  // _selfSelectedUpDict 内联：字典形态（{稀有度: 干员列表}）才合并
  const cfg = poolConfigs.find((g) => g.gachaPoolId === poolId);
  const gachaType = GACHA_RULE_TYPE[cfg?.gachaRuleType ?? ""] ?? "single";
  // gachaType 为运行时字符串（服务端按规则类型动态建键）→ 经 json-path 下钻，返回 JSON 域值
  const upChar = getIn(gacha, [gachaType, poolId, "upChar"]);
  if (!upChar || typeof upChar !== "object" || Array.isArray(upChar)) {
    return base;
  }
  const result = base.map((c) => ({ ...c, charIdList: [...c.charIdList] }));
  for (const [rankKey, charIds] of Object.entries(upChar)) {
    const rank = Number(rankKey);
    if (!Number.isInteger(rank) || !Array.isArray(charIds) || !charIds.length) {
      continue;
    }
    const charIdList = charIds as string[];
    const ex = result.find((c) => c.rarityRank === rank);
    if (ex) {
      ex.charIdList = [...charIdList];
      ex.count = 1;
    } else {
      result.push({
        rarityRank: rank,
        charIdList: [...charIdList],
        percent: 0.35,
        count: 1,
      });
    }
  }
  return result;
}
