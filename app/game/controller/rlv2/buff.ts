import { Blackboard } from "@excel/character_table";
import excel from "@excel/excel";
import { RoguelikeBuff, RoguelikeItemBundle } from "../../model/rlv2";
import { RoguelikeV2Controller } from "../rlv2";
import { RoguelikePlayerStatusManager } from "./status";
import { TypedEventEmitter } from "@game/model/events";

export class RoguelikeBuffManager {
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;
  _buffs!: RoguelikeBuff[];
  _status: RoguelikePlayerStatusManager;
  /** 难度效果：进入下一区域损失源石锭百分比（difficulty zone_gold_loss_percent） */
  _zoneGoldLossPercent: number;

  constructor(player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._player = player;
    this._status = this._player._status;
    this._buffs = [];
    this._zoneGoldLossPercent = 0;
    this._trigger = _trigger;
    this._trigger.on("rlv2:buff:apply", this.applyBuffs.bind(this));
    this._trigger.on("rlv2:init", this.init.bind(this));
    this._trigger.on("rlv2:create", this.create.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
  }

  async init() {
    this._buffs = [];
    this._zoneGoldLossPercent = 0;
  }

  async continue() {
    const theme = this._player.current.game!.theme;
    Object.values(this._player.inventory!.relic).reduce((acc, relic) => {
      const buffs =
        excel.RoguelikeTopicTable.details[theme].relics[relic.id].buffs;
      this._buffs.push(...buffs);
      return [...acc, ...buffs];
    }, [] as RoguelikeBuff[]);
  }

  async create() {
    const theme = this._player.current.game!.theme;
    const modeGrade = this._player.current.game!.modeGrade;
    // 存档可能没有该主题的 outer 数据（从未玩过）→ 容错
    const unlocked = this._player.outer?.[theme]?.buff?.unlocked ?? {};
    Object.keys(unlocked).forEach((id) => {
      const buffs = excel.RoguelikeConsts[theme]?.outbuff?.[id];
      if (!buffs) return;
      this.applyBuffs([[...buffs]]);
    });
    const modebuff = excel.RoguelikeConsts?.[theme]?.modebuff?.[modeGrade];
    if (modebuff) {
      await this.applyBuffs([[...modebuff]]);
    }
    // 难度 buff：data/rlv2.json modebuff 多数主题缺失（rogue_6 为空）→ 按官方难度描述
    // （difficulties[].ruleDesc/addDesc）解析生成，官方无结构化难度 buff 数据
    await this.applyBuffs([this.difficultyBuffs(theme, modeGrade)]);
  }

  /**
   * 根据难度描述（ruleDesc/addDesc 文本）生成难度 buff。
   * 官服 difficulty 仅带人类可读描述，无结构化数据；此处解析出服务端可生效的条目：
   * - 初始目标生命上限-N → level_life_point_add -N（生命上限/当前）
   * - 可同时部署人数-N → deploy_limit_add -N（可部署干员上限）
   * - 招募N星及以上干员希望消耗+N → recruit_hop_cost +N（星级阈值）
   * - 进入下一区域损失N%源石锭 → zone_gold_loss_percent N
   * - 零件箱初始容量-N → scrap_limit_add -N（rogue_6 零件/废品库存上限）
   * - 初始灯火-N → light_add -N（rogue_2 灯火）
   * 敌人属性类描述（生命/攻击+%）由客户端在战斗内应用，服务端不重复处理。
   */
  difficultyBuffs(theme: string, modeGrade: number): RoguelikeBuff[] {
    const game = this._player.current.game;
    if (!game) return [];
    const detail = excel.RoguelikeTopicTable.details[theme];
    const difficulty = (detail.difficulties || []).find(
      (d: any) =>
        (d.modeDifficulty ?? "NORMAL") === (game.mode ?? "NORMAL") &&
        (d.grade ?? 0) === (modeGrade ?? 0),
    );
    if (!difficulty) return [];
    const texts = [difficulty.ruleDesc, difficulty.addDesc]
      .filter(Boolean)
      .join(" ");
    const buffs: RoguelikeBuff[] = [];
    const bb = (key: string, value: number) => ({
      key,
      blackboard: [{ key: "value", value }] as Blackboard,
    });

    // 初始目标生命上限-N（描述自带符号：上限-2 → -2）
    const hp = texts.match(/目标生命上限\s*([+-]?\d+)/);
    if (hp) buffs.push(bb("level_life_point_add", parseInt(hp[1], 10)));

    // 可同时部署人数-N（描述自带符号：人数-1 → -1）
    const deploy = texts.match(/可同时部署人数\s*([+-]?\d+)/);
    if (deploy) buffs.push(bb("deploy_limit_add", parseInt(deploy[1], 10)));

    // 招募N星及以上干员希望消耗+N（星级阈值：3/4/5/6；描述用数字或中文数字，
    // 措辞有"希望+1"与"希望消耗+1"两种）
    const CN_NUM: { [k: string]: number } = { 三: 3, 四: 4, 五: 5, 六: 6, 七: 7 };
    const hop =
      texts.match(/招募\s*([3-6三四五六])星(?:及以上)?干员[^，。]*?希望消耗?\s*\+\s*(\d+)/) ||
      texts.match(/非初始招募\s*([三四五六])星干员[^，。]*?希望\s*\+\s*(\d+)/);
    if (hop) {
      const starRaw = hop[1];
      const minStar = /^\d$/.test(starRaw) ? parseInt(starRaw, 10) : CN_NUM[starRaw] || 3;
      const cost = parseInt(hop[2], 10);
      buffs.push({
        key: "recruit_hop_cost",
        blackboard: [
          { key: "min_star", value: minStar },
          { key: "cost", value: cost },
        ] as Blackboard,
      });
    }

    // 进入下一区域损失N%源石锭
    const gold = texts.match(/损失\s*(\d+)%\s*的源石锭|源石锭损失\s*(\d+)%/);
    if (gold) {
      const pct = parseInt(gold[1] || gold[2], 10);
      buffs.push(bb("zone_gold_loss_percent", pct));
    }

    // 零件箱初始容量-N（rogue_6 零件库存上限；描述自带符号）
    const scrap = texts.match(/零件箱[^]*?容量\s*([+-]?\d+)/);
    if (scrap) buffs.push(bb("scrap_limit_add", parseInt(scrap[1], 10)));

    // 初始灯火-N（rogue_2；描述自带符号）
    const light = texts.match(/初始灯火\s*([+-]?\d+)/);
    if (light) buffs.push(bb("light_add", parseInt(light[1], 10)));

    return buffs;
  }

  async applyBuffs([[...args]]: [RoguelikeBuff[]]) {
    for (const arg of args) {
      if (arg.key == "immediate_reward") {
        await this.immediate_reward(arg.blackboard);
      } else if (arg.key == "item_cover_set") {
        await this.item_cover_set(arg.blackboard);
      } else if (arg.key == "change_fragment_type_weight") {
        await this._trigger.emit("rlv2:fragment:change_type_weight", [arg]);
      } else if (arg.key == "level_life_point_add") {
        // 分队效果：生命上限/当前 +value（指挥分队等）
        const value = arg.blackboard[0]?.value ?? 0;
        this._status.property.hp.max += value;
        this._status.property.hp.current += value;
      } else if (arg.key == "level_char_limit_add") {
        // 分队效果：可部署人数上限 +value（集群分队等）
        const value = arg.blackboard[0]?.value ?? 0;
        this._status.property.population.max += value;
      } else if (arg.key == "immediate_recruit") {
        // 分队效果：初始额外干员（immediate_recruit char_list）
        const list = (arg.blackboard[0]?.valueStr || "").split(",").filter(Boolean);
        for (const charId of list) {
          await this._trigger.emit("rlv2:recruit:initial_char", [charId]);
        }
      } else if (arg.key == "deploy_limit_add") {
        // 难度效果：可同时部署人数（干员部署上限）+value
        const value = arg.blackboard[0]?.value ?? 0;
        this._status.property.capacity += value;
      } else if (arg.key == "scrap_limit_add") {
        // 难度效果：零件箱/废品库存容量 +value（rogue_6 SCRAP 模块）
        const value = arg.blackboard[0]?.value ?? 0;
        const scrap = this._player._module?.scrap;
        if (scrap) {
          scrap.limit = Math.max(0, (scrap.limit || 6) + value);
        }
      } else if (arg.key == "light_add") {
        // 难度效果：初始灯火 +value（rogue_2 灯火模块 sanity）
        const value = arg.blackboard[0]?.value ?? 0;
        const san = this._player._module?._modules?.["SANCHECK"];
        if (san && typeof san.sanity === "number") {
          san.sanity += value;
        }
      } else if (arg.key == "zone_gold_loss_percent") {
        // 难度效果：进入下一区域时损失 N% 源石锭（record 记录，由 checkZoneEnd 应用）
        this._zoneGoldLossPercent = arg.blackboard[0]?.value ?? 0;
      }
    }
    this._buffs.push(...args);
  }

  filterBuffs(key: string): RoguelikeBuff[] {
    return this._buffs.filter((buff) => buff.key == key);
  }

  generateBuff(key: string, id: string, value: number): RoguelikeBuff {
    let blackboard: Blackboard = [];
    const funcs: { [key: string]: (id: string, value: number) => Blackboard } =
      {
        immediate_reward: (id: string, value: number) => {
          return [
            { key: "id", value: 0.0, valueStr: id },
            { key: "count", value: value, valueStr: null },
          ];
        },
      };
    if (funcs[key]) {
      blackboard = funcs[key](id, value);
    }
    return { key: key, blackboard: blackboard };
  }

  async immediate_reward(blackboard: Blackboard) {
    const item: RoguelikeItemBundle = {
      id: blackboard[0].valueStr!,
      count: blackboard[1].value!,
      sub: 0,
    };
    await this._trigger.emit("rlv2:get:items", [[item]]);
  }

  async item_cover_set(blackboard: Blackboard) {
    const item: RoguelikeItemBundle = {
      id: blackboard[0].valueStr!,
      count: blackboard[1].value!,
      sub: 0,
    };
    const theme = this._player.current.game!.theme;
    const type =
      item.type || excel.RoguelikeTopicTable.details[theme].items[item.id].type;
    switch (type) {
      case "HP":
        this._status.property.hp.current = item.count;
        break;
    }
  }
}
