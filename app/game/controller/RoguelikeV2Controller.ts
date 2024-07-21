import { CurrentData, OuterData, PlayerRoguelikeV2, RoguelikeNodePosition } from "../model/rlv2";

export class RoguelikeV2Controller {
    pinned?: string;
    outer: { [key: string]: OuterData; };
    current: CurrentData;
    setPinned(id: string):void{
        this.pinned=id
    }
    giveUpGame():void{
        this.current={
            player: null,
            record: null,
            map: null,
            inventory: null,
            game: null,
            troop: null,
            buff: null,
            module: null
        }
    }
    createGame(theme:string,mode:string,modeGrade:number,predefinedId:string):void{
        //TODO
        switch(theme){
            case "rogue_1":
                break;
            case "rogue_2":
                break;
            case "rogue_3":
                break;
            default:
                break;
        }
    }
    moveTo(to:RoguelikeNodePosition):void{
        this.current.player!.cursor.position=to
        this.current.player!.state="PENDING"
        //TODO

    }
    constructor(data:PlayerRoguelikeV2) {
        this.outer=data.outer
        this.current=data.current
        this.pinned=data.pinned
    }
}