import { RoguelikeV2Controller } from "../rlv2";
import { BattleData } from "@game/model/battle";
import { decryptBattleData } from "@utils/crypt";
import { TypedEventEmitter } from "@game/model/events";
import excel from "@excel/excel";

export class RoguelikeBattleManager {
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("rlv2:battle:start", this.start.bind(this));
    this._trigger.on("rlv2:battle:finish", this.finish.bind(this));
  }

  async start([stageId]: [string]) {
    const battleId = "1";
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
    const battleId = "1";
    const loginTime = this._player._player.loginTime;
    const decryptResult = await decryptBattleData(args.data, loginTime);
    const info = this._player._player.getBattleInfo(battleId);
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

    if ((decryptResult as any).completeState === 1) {
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

      earn.exp = detail.detailConst.playerLevelTable[this._player._status.property.level + 1]?.exp || 10;

      const rewards: any[] = [
        {
          index: 0,
          items: [{ sub: 0, id: ticket, count: 1 }],
          done: 0,
        },
      ];

      const goldReward = Math.floor(Math.random() * 10) + 5;
      rewards.push({
        index: 1,
        items: [{ sub: 0, id: `${theme}_gold`, count: goldReward }],
        done: 0,
      });

      const fragmentPool = detail.items ? Object.keys(detail.items).filter((k) => k.includes("fragment")) : [];
      if (fragmentPool.length > 0) {
        const fragmentId = fragmentPool[Math.floor(Math.random() * fragmentPool.length)];
        rewards.push({
          index: 2,
          items: [{ sub: 0, id: fragmentId, count: 1 }],
          done: 0,
        });
      }

      await this._trigger.emit("rlv2:event:create", [
        "BATTLE_REWARD",
        {
          earn: earn,
          rewards: rewards,
          show: "1",
          state: 0,
          isPerfect: (decryptResult as any).isPerfect || 0,
        },
      ]);
    } else {
      this._player._status.state = "WAIT_MOVE";
      while (this._player._status.pending.length > 0) {
        this._player._status.pending.shift();
      }
      this._player._status.trace.pop();
    }
  }
}
