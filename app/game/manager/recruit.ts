import excel from "@excel/excel";
import { GachaResult } from "../model/gacha";
import {
  randomChoice,
  randomChoices,
  randomInt,
  randomSample,
} from "@utils/random";
import { now } from "@utils/time";
import { PlayerDataManager } from "./PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";

export class RecruitManager {
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
    this._trigger.on("recruit:refresh:tags", async ([args]) => {
      await this.refreshTags(args);
    });
  }

  async refreshTags(args: { slotId: number }): Promise<void> {
    const { slotId } = args;
    await this._player.update(async (draft) => {
      //TODO
      draft.recruit.normal.slots[slotId].tags =
        await RecruitTools.refreshTagList();
    });
  }

  async sync() {}

  async cancel(args: { slotId: number }) {
    const { slotId } = args;
    await this._player.update(async (draft) => {
      const slot = draft.recruit.normal.slots[slotId];
      slot.state = 1;
      slot.selectTags = [];
      slot.startTs = -1;
      slot.maxFinishTs = -1;
      slot.realFinishTs = -1;
      slot.durationInSec = -1;
      slot.tags = await RecruitTools.refreshTagList();
    });
  }

  async buyRecruitSlot(args: { slotId: number }) {
    const { slotId } = args;
    await this._player.update(async (draft) => {
      draft.recruit.normal.slots[slotId].state = 1;
    });
  }

  async normalGacha(args: {
    slotId: number;
    tagList: number[];
    specialTagId: number;
    duration: number;
  }) {
    const { slotId, tagList, duration } = args;
    await this._player.update(async (draft) => {
      draft.recruit.normal.slots[slotId] = {
        state: 2,
        selectTags: tagList.map((tag) => ({ tagId: tag, pick: 1 })),
        startTs: now(),
        maxFinishTs: now() + duration,
        realFinishTs: now() + duration,
        durationInSec: duration,
        tags: await RecruitTools.refreshTagList(),
      };
    });
    await this._trigger.emit("items:use", [
      [{ id: "7001", count: 1, type: "TKT_RECRUIT" }],
    ]);
    await this._trigger.emit("NormalGacha", []);
  }

  async finish(args: { slotId: number }): Promise<GachaResult> {
    const { slotId } = args;
    const { durationInSec, selectTags } =
      this._player._playerdata.recruit.normal.slots[slotId];
    //TODO seperate
    const [char_id, filtered] = await RecruitTools.generateValidTags(
      durationInSec,
      selectTags.map((v) => v.tagId),
    );
    await this._player.update(async (draft) => {
      draft.recruit.normal.slots[slotId].selectTags = selectTags.map((tag) => ({
        tagId: tag.tagId,
        pick: filtered.includes(tag.tagId) ? 1 : 0,
      }));
    });
    await this.cancel(args);
    let result!: GachaResult;
    await this._trigger.emit("char:get", [
      char_id,
      { from: "NORMAL" },
      (res: GachaResult) => {
        result = res;
      },
    ]);
    return result;
  }

  async boost(args: { slotId: number; buy: number }) {
    const { slotId } = args;
    //TODO:
    await this._player.update(async (draft) => {
      draft.recruit.normal.slots[slotId].state = 2;
      draft.recruit.normal.slots[args.slotId].realFinishTs = now();
    });
    await this._trigger.emit("BoostNormalGacha", []);
  }
}
interface CharData {
  [charId: string]: {
    name: string;
    rarity: number;
    tags: number[];
  };
}
export class RecruitTools {
  static async refreshTagList(): Promise<number[]> {
    const rankWeights = {
      "6star": 0.210417,
      "5star": 0.523127,
      "4star": 14.988323,
      "3star": 79.11354,
      "2star": 3.51041,
      "1star": 0.554183,
    };
    let tagsSet: number[] = [];

    const [charsList, charData] = await this.generateRecruitableData();
    const ranks = Object.keys(rankWeights);
    const probs = Object.values(rankWeights);

    while (tagsSet.length < 5) {
      const randomGroup = randomChoices(ranks, probs, 10);
      const charPool = randomGroup.map((group) =>
        randomChoice(charsList[parseInt(group[0]) - 1]),
      );
      tagsSet = [
        ...new Set(charPool.flatMap((char) => charData[char].tags)),
      ] as number[];
    }
    return randomSample(tagsSet, 5).sort((a, b) => a - b);
  }

  static async generateValidTags(
    duration: number,
    tagList: number[],
  ): Promise<[string, number[]]> {
    const [charList, charData] = await this.generateRecruitableData();
    const selectedTags = randomSample(tagList, randomInt(0, 3));
    let charRange: [number, number];
    if (duration <= 13800) {
      charRange = [0, 3];
    } else if (duration <= 27000) {
      charRange = [1, 4];
    } else {
      if (selectedTags.includes(11)) {
        charRange = [5, 5];
      } else if (selectedTags.includes(14)) {
        charRange = [4, 4];
      } else {
        charRange = [2, 4];
      }
    }

    const alternateList: string[] = [];
    for (const [charId, value] of Object.entries(charData)) {
      if (charRange[0] <= value.rarity && value.rarity <= charRange[1]) {
        alternateList.push(charId);
      }
    }

    const alternateCharData = Object.fromEntries(
      Object.entries(charData).filter(([k]) => alternateList.includes(k)),
    );
    const matchingChars = Object.fromEntries(
      Object.entries(alternateCharData).filter(([char]) => {
        return selectedTags.some((tag) =>
          alternateCharData[char].tags.includes(tag),
        );
      }),
    );
    const sortedMatchingChars = Object.entries(matchingChars).sort((a, b) => {
      return (
        b[1].tags.filter((tag) => selectedTags.includes(tag)).length -
        a[1].tags.filter((tag) => selectedTags.includes(tag)).length
      );
    });

    if (selectedTags.length === 1 && !selectedTags.includes(11)) {
      const compensation = 6.3 - (duration / 600) * 0.05;
      const crossTag = randomChoices(
        [0, 1],
        [100 - compensation, compensation],
        1,
      )[0];
      console.log(crossTag);
    }

    let randomCharId: string;
    if (sortedMatchingChars.length === 0) {
      charRange[1] += 1;
      const groupWeights = [5, 15, 77, 2, 1].slice(
        charRange[0],
        charRange[1] + 1,
      );
      const group = randomChoices(
        Array.from(
          { length: charRange[1] - charRange[0] + 1 },
          (_, i) => i + charRange[0],
        ),
        groupWeights,
        1,
      )[0];
      const allChars = charList[group];
      randomCharId = randomChoice(allChars);
    } else {
      randomCharId = randomChoice(sortedMatchingChars.map((x) => x[0]));
    }

    const filterTags = selectedTags.filter(
      (x) => !charData[randomCharId].tags.includes(x),
    );

    return [randomCharId, filterTags];
  }

  private static parseRecruitableChars(s: string): Set<string> {
    const ret = new Set<string>();
    let minPos = s.indexOf("★" + "\\n");
    for (let rarity = 1; rarity <= 6; rarity++) {
      const startS = "★".repeat(rarity) + "\\n";
      const startPos = s.indexOf(startS, minPos) + startS.length;
      const endPos = s.indexOf("\n-", startPos);
      let s2: string;
      if (endPos === -1) {
        s2 = s.substring(startPos);
      } else {
        s2 = s.substring(startPos, endPos);
      }
      minPos = endPos;
      s2 = s2.replace(/<.*?>/g, "");
      const sl = s2.split("/");
      for (const v of sl) {
        ret.add(v.trim());
      }
    }
    return ret;
  }

  private static async generateRecruitableData(): Promise<
    [Record<number, string[]>, CharData]
  > {
    const tag2name = excel.GachaTable.gachaTags.slice(0, -2).reduce(
      (acc, v) => {
        acc[v.tagId] = v.tagName;
        return acc;
      },
      {} as Record<number, string>,
    );
    const name2tag = Object.fromEntries(
      Object.entries(tag2name).map(([k, v]) => [v, parseInt(k)]),
    );
    const profession2tag: Record<string, number> = {
      MEDIC: 4,
      WARRIOR: 1,
      PIONEER: 8,
      TANK: 3,
      SNIPER: 2,
      CASTER: 6,
      SUPPORT: 5,
      SPECIAL: 7,
    };
    const charsList: Record<number, string[]> = {};
    const charData: CharData = {};

    const recruitable = this.parseRecruitableChars(
      excel.GachaTable.recruitDetail,
    );

    for (const [charId, value] of Object.entries(excel.CharacterTable)) {
      if (value.tagList === null || !recruitable.has(value.name)) {
        continue;
      }
      const data = {
        name: value.name,
        rarity: value.rarity,
        tags: [] as number[],
      };

      const tags = value.tagList.map((tag_name) => name2tag[tag_name]);
      if (data.rarity === 5) tags.push(11);
      else if (data.rarity === 4) tags.push(14);
      if (value.position === "MELEE") tags.push(9);
      else if (value.position === "RANGED") tags.push(10);
      tags.push(profession2tag[value.profession]);

      data.tags = tags;
      charData[charId] = data;
    }

    for (const char of Object.keys(charData)) {
      if (char.startsWith("char_")) {
        if (!charsList[charData[char].rarity]) {
          charsList[charData[char].rarity] = [];
        }
        charsList[charData[char].rarity].push(char);
      }
    }

    return [charsList, charData];
  }
}
