import EventEmitter from "events";
import { PlayerRecruit } from "../model/playerdata";
import * as fs from 'fs';
import { CharacterTable } from "../../excel/character_table";
import { GachaData } from "../../excel/gacha_table";
import excel from "../../excel/excel";


export class RecruitManager {
    recruit: PlayerRecruit
    _trigger: EventEmitter
    constructor(recruit: PlayerRecruit, _trigger: EventEmitter) {
        this.recruit = recruit
        this._trigger = _trigger
    }
    async refreshTags(slotId: number): Promise<void> {
        this.recruit.normal.slots[slotId.toString()].tags = await RecruitTools.refreshTagList()
    }
    sync() {

    }
    cancle(slotId: number) {
        this.recruit.normal.slots[slotId.toString()].state = 1
        this.recruit.normal.slots[slotId.toString()].selectTags = []
        this.recruit.normal.slots[slotId.toString()].startTs = -1
        this.recruit.normal.slots[slotId.toString()].maxFinishTs = -1
        this.recruit.normal.slots[slotId.toString()].realFinishTs = -1
        this.recruit.normal.slots[slotId.toString()].durationInSec = -1

    }
    buyRecruitSlot(slotId: number) {
        this.recruit.normal.slots[slotId.toString()].state = 1
    }
    async normalGacha(slotId: number, tagList: number[], specialTagId: number, duration: number) {
        this.recruit.normal.slots[slotId.toString()].state = 2
        this.recruit.normal.slots[slotId.toString()].selectTags = tagList.map(tag => ({ tagId: tag, pick: 1 }))
        this.recruit.normal.slots[slotId.toString()].startTs = parseInt((new Date().getTime() / 1000).toString())
        this.recruit.normal.slots[slotId.toString()].maxFinishTs = parseInt((new Date().getTime() / 1000).toString()) + duration
        this.recruit.normal.slots[slotId.toString()].realFinishTs = -1
        this.recruit.normal.slots[slotId.toString()].durationInSec = duration
        await this.refreshTags(slotId)
        this._trigger.emit("NormalGacha", {})
    }
    finish(slotId: number) {
        let selected = this.recruit.normal.slots[slotId.toString()].selectTags
        let chars = Object.values(excel.CharacterTable).filter((char) => {
            for (let tag of selected) {
                let tagName = excel.GachaTable.gachaTags.find(t => t.tagId == tag.tagId)!.tagName
                if (char.tagList?.includes(tagName)) {
                    return true
                }
            }
            return false
        }).sort((a, b) => {
            return parseInt(a.rarity.slice(-1)) - parseInt(b.rarity.slice(-1))
        })
        let char_id = chars[0]
        this.cancle(slotId)
    }
    boost(slotId: number, buy: number) {
        this.recruit.normal.slots[slotId.toString()].state = 3
        this.recruit.normal.slots[slotId.toString()].realFinishTs = parseInt((new Date().getTime() / 1000).toString())
    }
    toJSON(): PlayerRecruit {
        return this.recruit
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

    private static parseRecruitableChars(s: string): Set<string> {
        const ret = new Set<string>();
        let minPos = s.indexOf("★" + "\\n");
        for (let rarity = 1; rarity <= 6; rarity++) {
            const startS = "★".repeat(rarity) + "\\n";
            let startPos = s.indexOf(startS, minPos) + startS.length;
            let endPos = s.indexOf("\n-", startPos);
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

    private static async generateRecruitableData(): Promise<[Record<number, string[]>, CharData]> {
        await excel.init();
        const tag2name = excel.GachaTable.gachaTags.slice(0, -2).reduce((acc, v) => {
            acc[v.tagId] = v.tagName;
            return acc;
        }, {} as Record<number, string>);
        const name2tag = Object.fromEntries(Object.entries(tag2name).map(([k, v]) => [v, parseInt(k)]));
        const profession2tag: Record<string, number> = {
            "MEDIC": 4,
            "WARRIOR": 1,
            "PIONEER": 8,
            "TANK": 3,
            "SNIPER": 2,
            "CASTER": 6,
            "SUPPORT": 5,
            "SPECIAL": 7,
        };
        const charsList: Record<number, string[]> = {};
        const charData: CharData = {};

        const recruitable = this.parseRecruitableChars(excel.GachaTable.recruitDetail);

        for (const [charId, value] of Object.entries(excel.CharacterTable)) {
            if (value.tagList === null || !recruitable.has(value.name)) {
                continue;
            }
            const data = {
                name: value.name,
                rarity: parseInt(value.rarity.slice(-1))-1,
                tags: [] as number[]
            };

            const tags = value.tagList.map(tag_name => name2tag[tag_name]);
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

    static async refreshTagList(): Promise<number[]> {
        await excel.init();
        const rankWeights = {
            "6star": 0.210417,
            "5star": 0.523127,
            "4star": 14.988323,
            "3star": 79.11354,
            "2star": 3.51041,
            "1star": 0.554183
        };
        let tagsSet: number[] = [];

        const [charsList, charData] = await this.generateRecruitableData();
        const ranks = Object.keys(rankWeights);
        const probs = Object.values(rankWeights);

        while (tagsSet.length < 5) {
            const randomGroup = this.randomChoices(ranks, probs, 10);
            const charPool = randomGroup.map(group => this.randomChoice(charsList[parseInt(group[0])-1]));
            tagsSet = [...new Set(charPool.flatMap(char => charData[char].tags))] as number[];
        }

        const tagList = this.randomSample(tagsSet, 5).sort((a, b) => a - b);
        return tagList;
    }
    static async generateValidTags(duration: number, tagList: number[]): Promise<[string, number[]]> {
        const [charList, charData] = await this.generateRecruitableData();
        const selectedTags = this.randomSample(tagList, this.randomInt(0, 3));
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

        const alternateCharData = Object.fromEntries(Object.entries(charData).filter(([k]) => alternateList.includes(k)));
        const matchingChars = Object.fromEntries(Object.entries(alternateCharData).filter(([char]) => {
            return selectedTags.some(tag => alternateCharData[char].tags.includes(tag));
        }));
        const sortedMatchingChars = Object.entries(matchingChars).sort((a, b) => {
            return b[1].tags.filter(tag => selectedTags.includes(tag)).length - a[1].tags.filter(tag => selectedTags.includes(tag)).length;
        });

        if (selectedTags.length === 1 && !selectedTags.includes(11)) {
            const compensation = 6.3 - (duration / 600 * 0.05);
            const crossTag = this.randomChoices([0, 1], [100 - compensation, compensation], 1)[0];
        }

        let randomCharId: string;
        if (sortedMatchingChars.length === 0) {
            charRange[1] += 1;
            const groupWeights = [5, 15, 77, 2, 1].slice(charRange[0], charRange[1] + 1);
            const group = this.randomChoices(Array.from({ length: charRange[1] - charRange[0] + 1 }, (_, i) => i + charRange[0]), groupWeights, 1)[0];
            const allChars = charList[group];
            randomCharId = this.randomChoice(allChars);
        } else {
            randomCharId = this.randomChoice(sortedMatchingChars.map(x => x[0]));
        }

        const filterTags = selectedTags.filter(x => !charData[randomCharId].tags.includes(x));

        return [randomCharId, filterTags];
    }
    static randomInt(min: number, max: number): number {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }

    private static randomChoices<T>(arr: T[], weights: number[], k: number): T[] {
        const result: T[] = [];
        for (let i = 0; i < k; i++) {
            const totalWeight = weights.reduce((a, b) => a + b, 0);
            let random = Math.random() * totalWeight;
            for (let j = 0; j < arr.length; j++) {
                random -= weights[j];
                if (random <= 0) {
                    result.push(arr[j]);
                    break;
                }
            }
        }
        return result;
    }

    private static randomSample<T>(arr: T[], k: number): T[] {
        return arr.sort(() => 0.5 - Math.random()).slice(0, k);
    }

    private static randomChoice<T>(arr: T[]): T {
        return arr[Math.floor(Math.random() * arr.length)];
    }
}