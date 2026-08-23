import { RoguelikeV2Controller } from "../rlv2";
import { BattleData } from "@game/model/battle";
import { decryptBattleData } from "@utils/crypt";
import { TypedEventEmitter } from "@game/model/events";
import { generateBattleId } from "@utils/random";
import type { BattleRecord } from "@game/manager/BattleInfoStore";
import { logger } from "@utils/logger";
import excel from "@excel/excel";

/** 各账号最近一次 rlv2 战斗上下文（start 生成写入，finish 读取结算与记录留存用） */
const battleSessionByUid = new Map<
  string,
  { battleId: string; stageId: string }
>();

/**
 * 组装 rlv2 战斗结束记录（battle_records 表留存，供未来分析）
 *
 * @param controller - RoguelikeV2Controller（提供 _player.data 访问底层 PlayerDataManager）
 * @param battleId - 战斗 id
 * @param stageId - 关卡 id
 * @param decryptResult - 解密后的战斗数据（win 路径；可为 null）
 * @param rewards - 结算奖励（扁平化为 ItemBundle 摘要）
 * @returns 战斗结束记录对象
 */
function buildRlv2Record(
  controller: RoguelikeV2Controller,
  battleId: string,
  stageId: string,
  decryptResult: any,
  rewards: { type: string; id: string; count: number }[],
): BattleRecord {
  // controller 内置 _player 字段即底层 PlayerDataManager（提供 uid 与记录存储）
  const player = controller._player;
  const stats = decryptResult?.battleData?.stats;
  const completeState =
    decryptResult?.completeState === 1 ? 1 : (decryptResult?.completeState ?? 0);
  return {
    battleId,
    uid: player.uid,
    stageId,
    isPractice: 0,
    source: "rlv2",
    completeState,
    beginTs: stats?.beginTs ?? Math.floor(Date.now() / 1000),
    endTs: stats?.endTs ?? Math.floor(Date.now() / 1000),
    killCnt: stats?.checkKilledCnt ?? 0,
    totalDamage: stats?.totalDamage ?? 0,
    leftHp: stats?.leftHp ?? 0,
    totalHeal: stats?.totalHeal ?? 0,
    fixedPlayTime: stats?.fixedPlayTime ?? 0,
    squadInstIds: [],
    rewards,
    stats,
    createdTs: Math.floor(Date.now() / 1000),
  };
}

/** 黑流树海基础职业招募券列表（官服 battleFinish 奖励为职业券而非通用 _all） */
const ROGUE6_CLASS_TICKETS = [
  "rogue_6_recruit_ticket_pioneer",
  "rogue_6_recruit_ticket_warrior",
  "rogue_6_recruit_ticket_tank",
  "rogue_6_recruit_ticket_sniper",
  "rogue_6_recruit_ticket_caster",
  "rogue_6_recruit_ticket_support",
  "rogue_6_recruit_ticket_medic",
  "rogue_6_recruit_ticket_special",
] as const;

/**
 * 随机抽取一张黑流树海职业招募券（8 职业等概率）
 * @returns 一个职业招募券 id
 */
function pickRogue6ClassTicket(): string {
  return ROGUE6_CLASS_TICKETS[
    Math.floor(Math.random() * ROGUE6_CLASS_TICKETS.length)
  ];
}

export class RoguelikeBattleManager {
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("rlv2:battle:start", this.start.bind(this));
    this._trigger.on("rlv2:battle:finish", this.finish.bind(this));
  }

  /**
   * 留存 rlv2 战斗结束记录（失败不阻断结算）
   *
   * @param record - 战斗结束记录
   */
  private async persistRecord(record: BattleRecord): Promise<void> {
    try {
      await this._player._player.saveBattleRecord(record);
    } catch (e) {
      // 留存失败不影响战斗结算/状态机（分析数据偶发丢失可接受）
      logger.warn("rlv2", `战斗记录留存失败: ${(e as Error).message}`);
    }
  }

  async start([stageId]: [string]) {
    // 唯一 battleId：crypto.randomUUID 随机生成，替换固定 "1"，支持多场战斗区分/历史检索
    const battleId = generateBattleId();
    // 记录当前 battleId 与关卡，finish 据此读取本次战斗（覆盖最近一场）
    battleSessionByUid.set(this._player._player.uid, { battleId, stageId });
    let sanity = 0;
    const diceRoll = [];
    if ("SANCHECK" in this._player._module._modules) {
      sanity = this._player._module.toJSON().san?.sanity || sanity;
    }
    if ("DICE" in this._player._module._modules) {
      let diceUpgradeCount = 0;
      const relics = Object.values(this._player.inventory!.relic || {});
      const firstRelic = relics[0] as any;
      const band = firstRelic?.id || "";
      if (band === "rogue_2_band_16" || band === "rogue_2_band_17" || band === "rogue_2_band_18") {
        diceUpgradeCount += 1;
      }
      for (const relic of relics) {
        if ((relic as any).id === "rogue_2_relic_grace_63") {
          diceUpgradeCount += 1;
          break;
        }
      }
      let diceFaceCount: number;
      let diceId: string;
      if (diceUpgradeCount === 0) {
        diceFaceCount = 6;
        diceId = "trap_067_dice";
      } else if (diceUpgradeCount === 1) {
        diceFaceCount = 8;
        diceId = "trap_088_dice2";
      } else {
        diceFaceCount = 12;
        diceId = "trap_089_dice3";
      }
      for (let i = 0; i < 100; i++) {
        diceRoll.push(Math.floor(Math.random() * diceFaceCount) + 1);
      }
    }
    await this._trigger.emit("rlv2:event:create", [
      "BATTLE",
      {
        state: 1,
        chestCnt: 2,
        goldTrapCnt: 1,
        diceRoll: diceRoll,
        boxInfo: {},
        tmpChar: [],
        sanity: sanity,
        unKeepBuff: this._player._buff._buffs,
      },
    ]);
    await this._trigger.emit("save:battle", [
      battleId,
      { stageId: stageId, isPractice: 0 },
    ]);
  }

  async finish([args]: [
    {
      battleLog: string;
      data: string;
      battleData: BattleData;
    },
  ]) {
    const { battleId, stageId } =
      battleSessionByUid.get(this._player._player.uid) ?? {
        battleId: "",
        stageId: "",
      };
    const loginTime = this._player._player.loginTime;
    let decryptResult: any = null;
    try {
      decryptResult = await decryptBattleData(args.data, loginTime);
    } catch {
      // 无效/空战斗数据（模拟器/异常结算）：按战斗失败路径处理（WAIT_MOVE + 清空 pending）
    }
    const event = this._player._status.pending.shift();
    const theme = this._player.current.game!.theme;
    const detail = excel.RoguelikeTopicTable.details[theme];
    const ticket = `${theme}_recruit_ticket_all`;

    for (const buff of this._player._buff.filterBuffs("battle_extra_reward")) {
      await this._trigger.emit("rlv2:get:items", [
        [
          {
            id: buff.blackboard[0].valueStr!,
            count: buff.blackboard[1].value!,
          },
        ],
      ]);
    }

    const earn = {
      damage: 0,
      hp: 0,
      shield: 0,
      exp: 0,
      populationMax: 0,
      squadCapacity: 0,
      maxHpUp: 0,
    };

    // 战斗胜利判定：completeState 语义与标准战斗一致（1=失败 / 2=通关 / 3=三星）。
    // 修复：原实现用 `=== 1` 当胜利——真实胜利（2/3）被误判为失败 → 清空 pending、
    // 直接进 WAIT_MOVE（表现为"进入 zone 而不弹 BATTLE_REWARD"），而真实失败（1）反而误发奖励。
    if ((decryptResult as any)?.completeState >= 2) {
      // 战斗胜利：rogue_3 CHAOS 模块累积坍缩值（每次胜利 +1，达到上限升层）
      const chaosMgr = this._player._module._modules["CHAOS"];
      chaosMgr?.gainChaos(1);
      const finalHp = (decryptResult as any).finalHp || 0;
      const maxHp = this._player._status.property.hp.max;
      earn.damage = maxHp - finalHp;
      earn.hp = Math.floor(earn.damage * 0.3);

      if (earn.hp > 0) {
        this._player._status.property.hp.current += earn.hp;
        if (this._player._status.property.hp.current > maxHp) {
          this._player._status.property.hp.current = maxHp;
        }
      }

      earn.exp =
        detail.detailConst.playerLevelTable[this._player._status.property.level + 1]?.exp || 10;
      // earn.populationMax：本场胜利升级带来的希望上限增加——从下一级等级表读 (
      // 官服黑流树海 battleFinish 抓包 populationMax=4 = lv2.populationUp，
      // 实际升级在 finishBattleReward 发放 exp 后进行，earn 仅为回报口径)
      earn.populationMax =
        detail.detailConst.playerLevelTable[this._player._status.property.level + 1]?.populationUp ?? 0;

      // —— 战斗奖励组构建：奖励组"序 + 内容"对齐官服黑流树海 battleFinish（金/废品/招募券）——
      const rewards: any[] = [];

      // 节点/阶段判定（boss 战必掉多件——废品/收藏品数量加成）
      // 兼容黑流树海（map.zones 键为区域索引 1000+）与标准主题（层号键）
      const pos = this._player._status.cursor.position;
      const mapZones = this._player._map.zones;
      const zoneKey = mapZones[this._player._status.cursor.zone]
        ? this._player._status.cursor.zone
        : String(1000 + this._player._status.cursor.zone - 1);
      const node = pos
        ? mapZones[zoneKey]?.nodes[pos.x * 100 + pos.y]
        : undefined;
      const curStageId = (node as any)?.stage || "";
      const isBoss = curStageId.includes("_b_");

      // 黄金奖励（官服 index 0）
      const goldReward = Math.floor(Math.random() * 10) + 5;
      rewards.push({
        index: 0,
        items: [{ sub: 0, id: `${theme}_gold`, count: goldReward }],
        done: 0,
      });

      // 黑流树海（rogue_6）专属：零件（废品）组（官服 index 1）——官方抓包 battleFinish
      // rewards 含 rogue_6_scrap_P_01/P_02 等。从主题 scrapItemToType 池随机 1-2 件
      // （boss 必 2 件）。
      if (theme === "rogue_6") {
        const scrapPool = Object.keys(
          excel.RoguelikeTopicTable.modules[theme]?.scrap?.scrapItemToType || {},
        );
        const scrapRewards: any[] = [];
        const scrapCount = isBoss ? 2 : Math.random() < 0.5 ? 1 : 0;
        for (let i = 0; i < scrapCount && scrapPool.length > 0; i++) {
          const pick =
            scrapPool[Math.floor(Math.random() * scrapPool.length)];
          scrapRewards.push({ sub: i, id: pick, count: 1 });
        }
        if (scrapRewards.length > 0) {
          rewards.push({ index: rewards.length, items: scrapRewards, done: 0 });
        }
      }

      // 招募券奖励（官服 index 2）：黑流树海发职业券（官服 rogue_6_recruit_ticket_sniper），
      // 其余主题沿用通用券（`${theme}_recruit_ticket_all`）。
      const rewardTicket =
        theme === "rogue_6" ? pickRogue6ClassTicket() : ticket;
      rewards.push({
        index: rewards.length,
        items: [{ sub: 0, id: rewardTicket, count: 1 }],
        done: 0,
      });

      // 通用主题（非黑流树海）追加碎片 + 随机收藏品掉落——黑流树海收藏品不随战斗掉落
      // （官服 battleFinish 无该组，收藏品经分队/事件/贸易获取），故仅非 rogue_6 生成。
      if (theme !== "rogue_6") {
        const fragmentPool = detail.items
          ? Object.keys(detail.items).filter((k) => k.includes("fragment"))
          : [];
        if (fragmentPool.length > 0) {
          const fragmentId =
            fragmentPool[Math.floor(Math.random() * fragmentPool.length)];
          rewards.push({
            index: rewards.length,
            items: [{ sub: 0, id: fragmentId, count: 1 }],
            done: 0,
          });
        }

        // 随机收藏品掉落（参考 Dorothinights generateBaseBattleRewards：
        // 收藏品池过滤已拥有，boss 战必掉 2 个）
        const relicChance = isBoss ? 1 : 0.4; // 简化概率：普通/紧急 40%，boss 100%
        const hasRelic = Object.values(this._player.inventory!.relic || {}).map(
          (r) => (r as any).id,
        );
        const relicCount = isBoss ? 2 : 1;
        if (Math.random() < relicChance) {
          const relicItems: any[] = [];
          for (let i = 0; i < relicCount; i++) {
            const relicId = this._player._pool.getRelic(
              "pool_relic_all",
              hasRelic,
            );
            if (!relicId) break;
            relicItems.push({ sub: i, id: relicId, count: 1 });
            hasRelic.push(relicId);
          }
          if (relicItems.length > 0) {
            rewards.push({ index: rewards.length, items: relicItems, done: 0 });
          }
        }
      }

      await this._trigger.emit("rlv2:event:create", [
        "BATTLE_REWARD",
        {
          earn: earn,
          rewards: rewards,
          show: "2",
          state: 0,
          isPerfect: (decryptResult as any).isPerfect || 0,
        },
      ]);

      // —— 自然物（GOODS）估价动态：每次作战胜利 → G_02 +2；完美作战 → G_06 +4；
      // 非完美作战 → G_06 自身损坏（移除）。
      const perfect = (decryptResult as any).isPerfect || 0;
      const scrap = this._player._module?.scrap;
      scrap?.applyGoodsEffect("battle_win");
      scrap?.applyGoodsEffect(perfect ? "battle_perfect" : "battle_nonperfect");

      // —— 战斗结束记录留存（win 路径）：扁平化奖励摘要 + 统计入库 ——
      const flatRewards: { type: string; id: string; count: number }[] = [];
      for (const block of rewards as {
        items?: { sub: number; id: string; count: number }[];
      }[]) {
        for (const it of block.items ?? []) {
          flatRewards.push({ type: "", id: it.id, count: it.count });
        }
      }
      await this.persistRecord(
        buildRlv2Record(
          this._player,
          battleId,
          stageId,
          decryptResult,
          flatRewards,
        ),
      );

      // 特勤干员任务：战斗简单事件计数（Rlv2StageSimpleEventMore，如"使用电弧及其召唤物击杀'易'"）。
      // 事件携带本关 extraBattleInfo（键如 "radian_kill_enemy_dylbhm"），模板按任务 param 的键匹配。
      const extraInfo =
        (decryptResult as any)?.battleData?.stats?.extraBattleInfo;
      if (extraInfo && typeof extraInfo === "object") {
        await this._trigger.emit("Rlv2StageSimpleEventMore", [
          {
            theme: this._player.current.game?.theme || "",
            mode: this._player.current.game?.mode || "NORMAL",
            grade: this._player.current.game?.modeGrade ?? 0,
            stageId,
            events: extraInfo,
          },
        ]);
      }
    } else {
      // 自然物估价动态：非完美作战（含失败）→ G_06 自身损坏（移除）
      this._player._module?.scrap?.applyGoodsEffect("battle_fail");

      // —— 战斗结束记录留存（loss 路径）：仅统计入库，无奖励 ——
      await this.persistRecord(
        buildRlv2Record(this._player, battleId, stageId, decryptResult, []),
      );

      if ((decryptResult as any)?.completeState === 1) {
        // 战斗战败（completeState 语义 1=失败）：直接结算结束本局——官服肉鸽战败即终止。
        // runResult 置 "fail"（非 "success"）→ gameSettle 的 success=0，展示失败结算页；
        // fire-and-forget 防未捕获拒绝终止进程（同 checkZoneEnd 通关路径的 void gameSettle 约定）。
        this._player._status.runResult = "fail";
        void this._player.gameSettle().catch((e: Error) =>
          logger.error("rlv2", `battle-fail gameSettle failed: ${e.message}`),
        );
      } else {
        // 解密失败/无效数据（模拟器/异常报文）：软失败——不清空整局，仅回退一步并进入
        // WAIT_MOVE（不下发结算，避免一次异常请求终止整局）。
        this._player._status.state = "WAIT_MOVE";
        while (this._player._status.pending.length > 0) {
          this._player._status.pending.shift();
        }
        this._player._status.trace.pop();
      }
    }
  }
}
