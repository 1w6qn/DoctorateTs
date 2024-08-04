

import { RoguelikeBuff } from '@game/model/rlv2';

export interface RoguelikeConst {
    outbuff:{[key:string]:RoguelikeBuff[]}
    modebuff:{[key:string]:RoguelikeBuff[]}
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