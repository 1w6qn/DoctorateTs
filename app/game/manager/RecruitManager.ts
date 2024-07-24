import EventEmitter from "events";
import { PlayerRecruit } from "../model/playerdata";
import * as fs from 'fs';
import * as path from 'path';
import { CharacterTable } from "../../excel/character_table";
import { GachaData } from "../../excel/gacha_table";
import excel from "../../excel/excel";

/*
function parseRecruitableChars(s: string): Set<string> {
    const ret = new Set<string>();
    let minPos = s.indexOf("★" + "\\n");
    for (let rarity = 1; rarity <= 6; rarity++) {
        const startS = "★".repeat(rarity) + "\\n";
        const startPos = s.indexOf(startS, minPos) + startS.length;
        let endPos = s.indexOf("\n-", startPos);
        if (endPos === -1) {
            endPos = s.length;
        }
        let s2 = s.substring(startPos, endPos);
        minPos = endPos;
        s2 = s2.replace(/<.*?>/g, "");
        const sl = s2.split("/");
        for (const v of sl) {
            ret.add(v.trim());
        }
    }
    return ret;
}

function generateRecruitableData(): { charsList: { [key: number]: string[] }; charData: { [key: string]: { name: string; rarity: string; tags: number[] } } } {
    const gachaTable: GachaData = excel.GachaTable
    const characterTable: CharacterTable = excel.CharacterTable

    const tag2name: { [key: number]: string } = gachaTable.gachaTags.slice(0, -2).reduce((acc, v) => ({ ...acc, [v.tagId]: v.tagName }), {});
    const name2tag: { [key: string]: number } = Object.entries(tag2name).reduce((acc, [k, v]) => ({ ...acc, [v]: parseInt(k) }), {});
    const profession2tag: { [key: string]: number } = {
        "MEDIC": 4,
        "WARRIOR": 1,
        "PIONEER": 8,
        "TANK": 3,
        "SNIPER": 2,
        "CASTER": 6,
        "SUPPORT": 5,
        "SPECIAL": 7,
    };

    const charsList: { [key: number]: string[] } = {};
    const charData: { [key: string]: { name: string; rarity: string; tags: number[] } } = {};

    const recruitable = parseRecruitableChars(gachaTable.recruitDetail);

    for (const [charId, value] of Object.entries(characterTable)) {
        if (value.tagList === null) {
            continue;
        }
        const name = value.name;

        if (!recruitable.has(name)) {
            continue;
        }
        const data = {
            name: value.name,
            rarity: value.rarity,
            tags: value.tagList.map(tag_name => name2tag[tag_name]),
        };

        if (value.rarity === "TIER_6") {
            data.tags.push(11);
        } else if (value.rarity === "TIER_5") {
            data.tags.push(14);
        }

        if (value.position === "MELEE") {
            data.tags.push(9);
        } else if (value.position === "RANGED") {
            data.tags.push(10);
        }

        data.tags.push(profession2tag[value.profession]);

        charData[charId] = data;
    }

    for (const [charId, data] of Object.entries(charData)) {
        if (charId.startsWith("char_")) {
            const rarity = parseInt(data.rarity.slice(-1));
            if (!charsList[rarity]) {
                charsList[rarity] = [];
            }
            charsList[rarity].push(charId);
        }
    }

    return { charsList, charData };
}

function refreshTagList(): number[] {
    const rankWeights = {
        "6star": 0.210417,
        "5star": 0.523127,
        "4star": 14.988323,
        "3star": 79.11354,
        "2star": 3.51041,
        "1star": 0.554183
    };
    let tagsSet: number[] = [];

    const { charsList, charData } = generateRecruitableData();
    const ranks = Object.keys(rankWeights);
    const probs = Object.values(rankWeights);

    while (tagsSet.length < 5) {
        const randomGroup = randomChoices(ranks, probs, 10);
        const charPool = randomGroup.map(group => randomChoice(charsList[parseInt(group[0]) - 1]));
        tagsSet = Array.from(new Set(charPool.flatMap(char => charData[char].tags)));
    }

    const tagList = shuffleArray(tagsSet).slice(0, 5).sort((a, b) => a - b);
    playerData.track.recruit.pool = charPool;

    const gachaTable: GachaData = excel.GachaTable;
    const tag2name = gachaTable.gachaTags.slice(0, -2).reduce((acc, v) => ({ ...acc, [v.tagId]: v.tagName }), {} as {[key:number]:string});
    console.log("-".repeat(20));
    for (const i of tagList) {
        console.log(tag2name[i]);
    }
    console.log("-".repeat(20));
    return tagList;
}

function generateValidTags(duration: number,tagList:number[]): [string, number[]] {
    const { charsList, charData } = generateRecruitableData();
    const selectedTags = shuffleArray<number>(tagList).slice(0, Math.floor(Math.random() * 4));
    console.log(`selected_tags：\t\t${selectedTags}\nduration：\t\t${duration}`);
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

    const charPool = playerData.track.recruit.pool!;

    const alternateList: string[] = [];
    for (const charId of charPool) {
        if (charRange[0] <= charData[charId].rarity && charData[charId].rarity <= charRange[1]) {
            alternateList.push(charId);
        }
    }

    const alternateCharData = Object.fromEntries(Object.entries(charData).filter(([k]) => alternateList.includes(k)));
    const matchingChars = Object.fromEntries(Object.entries(alternateCharData).filter(([_, v]) => v.tags.some(tag => selectedTags.includes(tag))));
    const sortedMatchingChars = Object.entries(matchingChars).sort((a, b) => b[1].tags.filter(tag => selectedTags.includes(tag)).length - a[1].tags.filter(tag => selectedTags.includes(tag)).length);
    console.log(`matching_chars：\t${JSON.stringify(sortedMatchingChars)}`);

    if (selectedTags.length === 1 && !selectedTags.includes(11)) {
        const compensation = 6.3 - (Math.floor(duration / 600) * 0.05);
        const crossTag = randomChoices([0, 1], [100 - compensation, compensation], 1)[0];
        if (crossTag) {
            sortedMatchingChars.length = 0;
            console.log("\x1b[1;31mcross_tag：\t\tTrue\x1b[0;0m");
        } else {
            console.log("cross_tag：\t\tFalse");
        }
    }

    let randomCharId: string;
    if (sortedMatchingChars.length === 0) {
        charRange[1] += 1;
        const groupWeights = charRange.map(rank => rank === 0 ? 5 : rank === 1 ? 15 : rank === 2 ? 77 : rank === 3 ? 2 : 1);
        const group = randomChoices(Array.from({ length: charRange[1] - charRange[0] + 1 }, (_, i) => i + charRange[0]), groupWeights, 1)[0];
        const allChars = charsList[group];
        randomCharId = randomChoice(allChars);
    } else {
        randomCharId = randomChoice(sortedMatchingChars.map(x => x[0]));
    }

    const filterTags = selectedTags.filter(x => !charData[randomCharId].tags.includes(x));
    console.log(`random_char_id：\t${randomCharId}\nfilter_tags：\t\t${filterTags}`);

    return [randomCharId, filterTags];
}

function randomChoices<T>(arr: T[], weights: number[], k: number): T[] {
    const cumulativeWeights = [];
    let sum = 0;
    for (const weight of weights) {
        sum += weight;
        cumulativeWeights.push(sum);
    }

    const result = [];
    for (let i = 0; i < k; i++) {
        const rand = Math.random() * sum;
        for (let j = 0; j < cumulativeWeights.length; j++) {
            if (rand < cumulativeWeights[j]) {
                result.push(arr[j]);
                break;
            }
        }
    }
    return result;
}

function randomChoice<T>(arr: T[]): T {
    return arr[Math.floor(Math.random() * arr.length)];
}

function shuffleArray<T>(array: T[]): T[] {
    for (let i = array.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}
*/
export class RecruitManager {
    recruit:PlayerRecruit
    _trigger:EventEmitter
    constructor(recruit:PlayerRecruit,_trigger:EventEmitter) {
        this.recruit=recruit
        this._trigger=_trigger
    }
    refreshTags(slotId:number):void{
        this.recruit.normal.slots[slotId.toString()].tags=[1,3,6,8,18]
    }
    sync(){

    }
    cancle(slotId:number){
        this.recruit.normal.slots[slotId.toString()].state=1
        this.recruit.normal.slots[slotId.toString()].selectTags=[]
        this.recruit.normal.slots[slotId.toString()].startTs=-1
        this.recruit.normal.slots[slotId.toString()].maxFinishTs=-1
        this.recruit.normal.slots[slotId.toString()].realFinishTs=-1
        this.recruit.normal.slots[slotId.toString()].durationInSec=-1

    }
    buyRecruitSlot(slotId:number){
        this.recruit.normal.slots[slotId.toString()].state=1
    }
    normalGacha(slotId:number,tagList:number[],specialTagId:number,duration:number){
        this.recruit.normal.slots[slotId.toString()].state=2
        this.recruit.normal.slots[slotId.toString()].selectTags=tagList.map(tag=>({tagId:tag,pick:1}))
        this.recruit.normal.slots[slotId.toString()].startTs=parseInt((new Date().getTime()/1000).toString())
        this.recruit.normal.slots[slotId.toString()].maxFinishTs=parseInt((new Date().getTime()/1000).toString())+duration
        this.recruit.normal.slots[slotId.toString()].realFinishTs=-1
        this.recruit.normal.slots[slotId.toString()].durationInSec=duration
        this.refreshTags(slotId)
    }
    finish(slotId:number){
        let selected=this.recruit.normal.slots[slotId.toString()].selectTags
        let chars=Object.values(excel.CharacterTable).filter((char)=>{
            for(let tag of selected){
                let tagName=excel.GachaTable.gachaTags.find(t=>t.tagId==tag.tagId)!.tagName
                if(char.tagList?.includes(tagName)){
                    return true
                }
            }
            return false
        }).sort((a,b)=>{
            return parseInt(a.rarity.slice(-1))-parseInt(b.rarity.slice(-1))
        })
        let char_id=chars[0]
        this.cancle(slotId)
    }
    boost(slotId:number,buy:number){
        this.recruit.normal.slots[slotId.toString()].state=3
        this.recruit.normal.slots[slotId.toString()].realFinishTs=parseInt((new Date().getTime()/1000).toString())
    }
    toJSON():PlayerRecruit{
        return this.recruit
    }
}