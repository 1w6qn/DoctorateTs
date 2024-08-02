
import { RoguelikeGameRelicData } from '@excel/roguelike_topic_table';

export interface RoguelikeConst {
    outbuff:{[key:string]:RoguelikeGameRelicData}
    recruitGrps:{[key:string]:string[]}
}
export class RoguelikeExcel {
    RoguelikeConsts!:{[key:string]:RoguelikeConst}
    initPromise:Promise<void>;
    constructor() {
        this.initPromise=this.init()
    }
    async init():Promise<void> {
        this.RoguelikeConsts = (await import('../../../../data/rlv2.json')).default
    }
}
export default new RoguelikeExcel()