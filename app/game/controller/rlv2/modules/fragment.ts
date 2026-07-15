import excel from "@excel/excel";
import { PlayerRoguelikeV2, RoguelikeBuff } from "@game/model/rlv2";
import { RoguelikeV2Controller } from "../../rlv2";
import { now } from "@utils/time";
import { TypedEventEmitter } from "@game/model/events";

export class RoguelikeFragmentManager {
  index: number;
  limitWeight: number;
  _fragments: {
    [key: string]: PlayerRoguelikeV2.CurrentData.Module.InventoryFragment;
  };
  _troopCarry: string[];
  _currInspiration: PlayerRoguelikeV2.CurrentData.Module.InventoryInspiration | null;
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this.index = 0;
    this.limitWeight = 0;
    this._fragments = player.current.module?.fragment?.fragments || {};
    this._troopCarry = player.current.module?.fragment?.troopCarry || [];
    this._currInspiration =
      player.current.module?.fragment?.currInspiration || null;
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("rlv2:module:init", this.init.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
    this._trigger.on("rlv2:fragment:gain", this.gain.bind(this));
    this._trigger.on("rlv2:fragment:max_weight:add", ([count]) => {
      this.limitWeight += count;
    });
    this._trigger.on("rlv2:fragment:use", this.use.bind(this));
    this._trigger.on("rlv2:fragment:lose", this.lose.bind(this));
    this._trigger.on(
      "rlv2:fragment:use_inspiration",
      this.useInspiration.bind(this),
    );
    this._trigger.on(
      "rlv2:fragment:set_troop_carry",
      ([troopCarry]: [string[]]) => {
        const weights = this._troopWeights;
        this.limitWeight -= this._troopCarry.reduce(
          (acc, cur) => acc + weights[cur],
          0,
        );
        this.limitWeight += troopCarry.reduce(
          (acc, cur) => acc + weights[cur],
          0,
        );
        this._troopCarry = troopCarry;
      },
    );
    this._trigger.on(
      "rlv2:fragment:change_type_weight",
      ([b]: [RoguelikeBuff]) => {
        const theme = player.current.game!.theme;
        Object.values(this._fragments).forEach((f) => {
          const info =
            excel.RoguelikeTopicTable.modules[theme].fragment?.fragmentData[
              f.id
            ];
          if (b.blackboard[1].valueStr == info?.type) {
            f.weight += b.blackboard[0].value!;
          }
        });
      },
    );
    this._trigger.on("rlv2:levelUp", ([targetLevel]) => {
      const theme = this._player.current.game!.theme;
      this.limitWeight += excel.RoguelikeTopicTable.modules[theme].fragment
        ?.fragmentLevelData[targetLevel].weightUp as number;
    });
  }

  get _totalWeight(): number {
    return Object.values(this._fragments)
      .filter((f) => !f.used)
      .reduce((acc, cur) => acc + cur.weight, 0);
  }

  get _troopWeights(): { [key: string]: number } {
    const chars = this._player.troop.chars;
    return Object.fromEntries(
      Object.entries(chars).map(([k, v]) => {
        const data = excel.CharacterTable[v.charId];
        const rarity = data.rarity;
        let weight = [
          [2, 2, 2, 2, 3, 4],
          [-1, -1, -1, 4, 5, 6],
        ][v.evolvePhase == 2 ? 1 : 0][rarity - 1];
        this._player._buff.filterBuffs("char_weight_rarity").forEach((b) => {
          if (b.blackboard[0].value == rarity - 1) {
            weight += b.blackboard[1].value!;
          }
        });
        if (v.charId == "char_4151_tinman") {
          weight += 0;
          if (v.evolvePhase > 0) {
            weight += v.evolvePhase == 1 ? 3 : 9;
            if (v.potentialRank == 2) {
              weight += 1;
            }
          }
        }
        return [k, weight];
      }),
    );
  }

  alchemy(fragmentIndex: [string, string]) {
    const [f1, f2] = fragmentIndex;
    const theme = this._player.current.game!.theme;
    const fragmentData = excel.RoguelikeTopicTable.modules[theme].fragment;
    const alchemyData = fragmentData?.alchemyData || {};

    const fragment1 = this._fragments[f1];
    const fragment2 = this._fragments[f2];
    if (!fragment1 || !fragment2 || fragment1.used || fragment2.used) {
      return;
    }

    const type1 = fragmentData?.fragmentData[fragment1.id]?.type || "";
    const type2 = fragmentData?.fragmentData[fragment2.id]?.type || "";
    const value1 = fragment1.value;
    const value2 = fragment2.value;
    const squareSum = value1 * value1 + value2 * value2;

    let matchedRecipe: any = null;
    for (const recipe of Object.values(alchemyData)) {
      const types = (recipe as any).fragmentTypeList;
      const expectedSum = (recipe as any).fragmentSquareSum;
      if (
        expectedSum === squareSum &&
        ((types[0] === type1 && types[1] === type2) ||
          (types[0] === type2 && types[1] === type1))
      ) {
        matchedRecipe = recipe;
        break;
      }
    }

    if (matchedRecipe) {
      fragment1.used = true;
      fragment2.used = true;

      const rand = Math.random();
      if (rand < (matchedRecipe as any).relicProp) {
        this._trigger.emit("rlv2:get:items", [[{ id: `${theme}_relic_`, count: 1 }]]);
      } else if (rand < (matchedRecipe as any).relicProp + (matchedRecipe as any).shieldProp) {
        this._player._status.property.shield += 1000;
      } else if (rand < (matchedRecipe as any).relicProp + (matchedRecipe as any).shieldProp + (matchedRecipe as any).populationProp) {
        this._player._status.property.population.max += 1;
      }
    }
  }

  alchemyReward(fragmentIndex: [string, string]) {
    const [f1, f2] = fragmentIndex;
    const theme = this._player.current.game!.theme;
    const fragmentData = excel.RoguelikeTopicTable.modules[theme].fragment;

    const fragment1 = this._fragments[f1];
    const fragment2 = this._fragments[f2];
    if (!fragment1 || !fragment2) {
      return;
    }

    const value1 = fragment1.value;
    const value2 = fragment2.value;
    const totalValue = value1 + value2;

    const goldReward = totalValue * 50;
    this._player._status.property.gold += goldReward;

    const expReward = totalValue * 10;
    this._player._status.property.exp += expReward;
  }

  useInspiration([fragmentIndex]: [string]): void {
    this._fragments[fragmentIndex].used = true;
    this._currInspiration = {
      instId: fragmentIndex,
      id: this._fragments[fragmentIndex].id,
      ei: -1,
    };
  }

  use([id, count]: [string, number]) {
    for (let i = 0; i < count; i++) {
      const f = Object.values(this._fragments).filter(
        (f) => f.id == id && !f.used,
      )[i]!;
      f.used = true;
    }
  }

  lose([fragmentIndex]: [string]): void {
    this._fragments[fragmentIndex].used = true;
  }

  gain([id]: [string]): void {
    const theme = this._player.current.game!.theme;
    const data =
      excel.RoguelikeTopicTable.modules[theme].fragment?.fragmentData[id];
    this._fragments[id] = {
      index: `f_${this.index}`,
      id: id,
      used: false,
      ts: now(),
      weight: data!.weight,
      value: data!.value,
      ei: -1,
    };
    this.index += 1;
  }

  init() {
    this.index = 0;
    this.limitWeight = 3;
    this._currInspiration = null;
    this._fragments = {};
    this._troopCarry = [];
  }

  continue() {}

  toJSON(): PlayerRoguelikeV2.CurrentData.Module.Fragment {
    return {
      totalWeight: this._totalWeight,
      limitWeight: this.limitWeight,
      overWeight: Math.floor(this.limitWeight * 1.5),
      fragments: this._fragments,
      troopWeights: this._troopWeights,
      troopCarry: this._troopCarry,
      currInspiration: this._currInspiration,
    };
  }
}
