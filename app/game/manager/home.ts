import EventEmitter from 'events';
import { PlayerDataModel, PlayerHomeBackground, PlayerHomeTheme, PlayerSetting } from '../model/playerdata';
import { now } from '@utils/time';
export class HomeManager {
    background:PlayerHomeBackground;
    homeTheme: PlayerHomeTheme;
    _trigger:EventEmitter;
    setting: PlayerSetting;
    npcAudio: { [key: string]: { npcShowAudioInfoFlag: string; }; };
    
    constructor(playerdata:PlayerDataModel,_trigger:EventEmitter) {
        this.background=playerdata.background
        this.homeTheme=playerdata.homeTheme
        this.setting=playerdata.setting
        this.npcAudio=playerdata.npcAudio
        this._trigger=_trigger
        this._trigger.on('background:condition:update',this.updateBackgroundCondition.bind(this))
        this._trigger.on('background:unlock',this.unlockBackground.bind(this))
        this._trigger.on('hometheme:condition:update',this.updateHomeThemeCondition.bind(this))
        this._trigger.on('hometheme:unlock',this.unlockHomeTheme.bind(this))
    }
    setBackground(bgID:string){
        this.background.selected=bgID
    }
    updateBackgroundCondition(bgID:string,conditionId:string,target:number){
        if(this.background.bgs[bgID]!.conditions!){
            let cond=this.background.bgs[bgID]!.conditions![conditionId]
            cond.v=target
            if(cond.t==cond.v){
                this._trigger.emit('background:unlock',bgID)
            }
        }
    }
    unlockBackground(bgID:string){
        this.background.bgs[bgID].unlock=now()
    }
    setHomeTheme(themeId:string){
        this.homeTheme.selected=themeId
    }
    updateHomeThemeCondition(themeId:string,conditionId:string,target:number){
        if(this.homeTheme.themes[themeId]!.conditions!){
            let cond=this.homeTheme!.themes[themeId]!.conditions![conditionId]
            cond.v=target
            if(cond.t==cond.v){
                this._trigger.emit('hometheme:unlock',themeId)
            }
        }
    }
    unlockHomeTheme(themeId:string){
        this.homeTheme.themes[themeId].unlock=now()
    }
    setLowPower(newValue:number){
        this.setting.perf.lowPower=newValue
    }
    npcAudioChangeLan(id:string,VoiceLan:string){
        this.npcAudio[id].npcShowAudioInfoFlag=VoiceLan
    }
    toJSON(){
        return {
            background:this.background,
            homeTheme:this.homeTheme,
            setting:this.setting,
            npcAudio:this.npcAudio,
        }
    }
}