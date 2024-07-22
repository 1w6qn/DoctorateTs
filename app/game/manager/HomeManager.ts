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
    }
    setBackground(bgID:string){
        this.background.selected=bgID
    }
    setHomeTheme(themeId:string){
        this.homeTheme.selected=themeId
    }
    toJSON(){
        return {
            background:this.background,
            homeTheme:this.homeTheme
        }
    }
}