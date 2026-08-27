import { Blackboard } from "@excel/excel";
import excel from "@excel/excel";
import { RoguelikeBuff, RoguelikeItemBundle } from "../../domain/rlv2/rlv2";
import { RoguelikeV2Manager } from "./logic";
import { RoguelikePlayerStatusManager } from "./status";
import { TypedEventEmitter } from "@game/service/events";

export class RoguelikeBuffManager {
  _player: RoguelikeV2Manager;
  _trigger: TypedEventEmitter;
  _buffs!: RoguelikeBuff[];
  _status: RoguelikePlayerStatusManager;
  /** 难度效果：进入下一区域损失源石锭百分比（difficulty zone_gold_loss_percent） */
  _zoneGoldLossPercent: number;

  constructor(player: RoguelikeV2Manager, _trigger: TypedEventEmitter) {
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
    // 重置防残留：续局重建控制器时重复执行 continue 会重复 push 藏品 buff；
    // 上一局的难度/分队 buff 也不应带入新局（招募希望受上一把分队影响的根因之一）
    this._buffs = [];
    this._zoneGoldLossPercent = 0;
    const theme = this._player.current.game!.theme;
    Object.values(this._player.inventory!.relic).reduce((acc, relic) => {
      const buffs =
        excel.RoguelikeTopicTable.details[theme].relics[relic.id].buffs;
      this._buffs.push(...buffs);
      return [...acc, ...buffs];
    }, [] as RoguelikeBuff[]);
  }

  async create() {
    // 重置防残留：控制器为玩家持久实例，上一局的分队/难度/藏品 buff 存于 _buffs；
    // 新局 createGame 只发 rlv2:create 不再发 rlv2:init（init 仅登录构造时），
    // 若不重置，上把分队的 recruit_cost 等 buff 污染新局招募希望消耗。
    this._buffs = [];
    this._zoneGoldLossPercent = 0;
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
    // 难度 buff 由 createGame 在 rlv2:create（模块初始化完成）之后统一应用：
    // scrap_limit_add 等需要 SCRAP 模块实例已创建（此处模块可能尚未就绪）
  }

  /**
   * 根据难度描述（ruleDesc/addDesc 文本）生成难度 buff（进阶式累积：选 N 难度时 1..N 全部生效）。
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
    // 进阶式难度：选 N 难度时 grade 1..N 全部生效（每个难度的 ruleDesc/addDesc 独立解析，
    // 累积叠加——如 N15 含难度7的"零件箱容量-2"、难度10的"部署-1/生命-2"）
    const difficulties = ((detail.difficulties || []) as any[]).filter(
      (d) =>
        (d.modeDifficulty ?? "NORMAL") === (game.mode ?? "NORMAL") &&
        (d.grade ?? 0) >= 1 &&
        (d.grade ?? 0) <= (modeGrade ?? 0),
    );
    const buffs: RoguelikeBuff[] = [];
    for (const difficulty of difficulties) {
      const texts = [difficulty.ruleDesc, difficulty.addDesc]
        .filter(Boolean)
        .join(" ");
      this.parseDifficultyText(theme, texts, buffs);
    }
    return buffs;
  }

  /** 解析单个难度描述文本 → 追加到 buffs */
  private parseDifficultyText(theme: string, texts: string, buffs: RoguelikeBuff[]): void {
    const bb = (key: string, value: number) => ({
      key,
      blackboard: [{ key: "value", value }] as Blackboard,
    });

    // 初始目标生命上限-N：**不解析**——init 表已按 modeGrade 预扣血量
    // （rogue_6：grade 0=8 / 1-9=6 / 10+=4；rogue_4/5 同理）。再解析并应用
    // level_life_point_add 会双重扣血（N15 4-2-2=0，开局血 0/0 客户端崩溃）。

    // 可同时部署人数-N（描述自带符号：人数-1 → -1）
    const deploy = texts.match(/可同时部署人数\s*([+-]?\d+)/);
    if (deploy) buffs.push(bb("deploy_limit_add", parseInt(deploy[1], 10)));

    // 招募N星[及以上]干员希望消耗+N（星级：3/4/5/6；措辞"希望+1"与"希望消耗+1"）。
    // 语义分两种：含"及以上"（rogue_2/3）→ 星级阈值 gte；精确星级（rogue_1/4/5/6）→ 精确匹配
    const CN_NUM: { [k: string]: number } = { 三: 3, 四: 4, 五: 5, 六: 6, 七: 7 };
    const hop1 = texts.match(
      /招募\s*([3-6三四五六])星(及以上)?干员[^，。]*?希望消耗?\s*\+\s*(\d+)/,
    );
    const hop2 = texts.match(
      /非初始招募\s*([三四五六])星干员[^，。]*?希望\s*\+\s*(\d+)/,
    );
    if (hop1 || hop2) {
      const m = (hop1 || hop2)!;
      const starRaw = m[1];
      const minStar = /^\d$/.test(starRaw) ? parseInt(starRaw, 10) : CN_NUM[starRaw] || 3;
      // hop1 捕获组：[全, 星, 及以上?, cost]；hop2：[全, 星, cost]
      const cost = parseInt(hop1 ? m[3] : m[2], 10);
      const gte = hop1 && m[2] === "及以上" ? 1 : 0;
      buffs.push({
        key: "recruit_hop_cost",
        blackboard: [
          { key: "min_star", value: minStar },
          { key: "cost", value: cost },
          { key: "gte", value: gte },
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
        // 可部署人数+value（outbuff_50"信息素"等）——**开局 property 不生效**：
        // 官服 createGame 初始 population.max=init 值（6），该加成是战斗内部署上限，
        // 应用到 population.max 会把开局希望上限改错（8-11 官服抓包对照确认）。
        // 仅记录 buff（filterBuffs 可读），不修改 property。
      } else if (arg.key == "immediate_recruit") {
        // 分队效果：初始额外干员（immediate_recruit char_list）
        const list = (arg.blackboard[0]?.valueStr || "").split(",").filter(Boolean);
        for (const charId of list) {
          await this._trigger.emit("rlv2:recruit:initial_char", [charId]);
        }
      } else if (arg.key == "deploy_limit_add") {
        // 可同时部署人数+value（难度10"可部署人数-1"）——**开局 property 不生效**：
        // 官服 createGame 初始 capacity=7（init 6 + outbuff_22 可携带+1），
        // 难度部署限制是战斗内生效；原实现改 capacity 导致 7→6（8-11 官服抓包对照）。
        // 仅记录 buff，不修改 property。
      } else if (arg.key == "scrap_limit_add") {
        // 难度效果：零件箱/废品库存容量 +value（rogue_6 SCRAP 模块）
        const value = arg.blackboard[0]?.value ?? 0;
        const scrap = this._player._module?.scrap;
        if (scrap) {
          scrap.setLimit((scrap.limit || 6) + value);
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

  /**
   * 全部生效 buff 只读快照（battle 存档序列化用，不直接读 _buffs）
   * @returns 当前全部 buff 数组（引用，调用方不得修改）
   */
  getBuffs(): RoguelikeBuff[] {
    return this._buffs;
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
