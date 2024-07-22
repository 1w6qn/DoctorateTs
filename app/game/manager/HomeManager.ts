import EventEmitter from 'events';
import { PlayerHomeBackground, PlayerHomeTheme } from '../model/playerdata';
export class HomeManager {
    background:PlayerHomeBackground;
    homeTheme: PlayerHomeTheme;
    _trigger:EventEmitter;
    
    constructor(background:PlayerHomeBackground,homeTheme:PlayerHomeTheme,_trigger:EventEmitter) {
        this.background=background
        this.homeTheme=homeTheme
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
        if(this.background.bgs[bgID].conditions){
            let cond=this.background.bgs[bgID].conditions[conditionId]
            cond.v=target
            if(cond.t==cond.v){
                this._trigger.emit('background:unlock',bgID)
            }
        }
    }
    unlockBackground(bgID:string){
        this.background.bgs[bgID].unlock=parseInt((new Date().getTime()/1000).toString())
    }
    setHomeTheme(themeId:string){
        this.homeTheme.selected=themeId
    }
    updateHomeThemeCondition(themeId:string,conditionId:string,target:number){
        if(this.homeTheme.themes[themeId].conditions){
            let cond=this.homeTheme.themes[themeId].conditions[conditionId]
            cond.v=target
            if(cond.t==cond.v){
                this._trigger.emit('hometheme:unlock',themeId)
            }
        }
    }
    unlockHomeTheme(themeId:string){
        this.homeTheme.themes[themeId].unlock=parseInt((new Date().getTime()/1000).toString())
    }
    toJSON(){
        return {
            background:this.background,
            homeTheme:this.homeTheme
        }
    }
}