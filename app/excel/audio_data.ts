export interface AudioData {
    bgmBanks:         BGMBank[];
    soundFXBanks:     SoundFXBank[];
    soundFXCtrlBanks: SoundFXCtrlBank[];
    snapshotBanks:    SnapshotBank[];
    battleVoice:      BattleVoice;
    musics:           Music[];
    duckings:         Ducking[];
    fadeStyles:       FadeStyle[];
    soundFxVoiceLang: { [key: string]: { [key: string]: string } };
    bankAlias:        { [key: string]: string };
}

export interface BattleVoice {
    crossfade:                         number;
    minTimeDeltaForEnemyEncounter:     number;
    minSpCostForImportantPassiveSkill: number;
    voiceTypeOptions:                  VoiceTypeOption[];
}

export interface VoiceTypeOption {
    voiceType:             number;
    priority:              number;
    overlapIfSamePriority: boolean;
    cooldown:              number;
    delay:                 number;
}

export interface BGMBank {
    intro:        null | string;
    loop:         null | string;
    volume:       number;
    crossfade:    number;
    delay:        number;
    name:         string;
    fadeStyleId?: string;
}

export interface Ducking {
    bank:         string;
    volume:       number;
    fadeTime:     number;
    delay:        number;
    fadeStyleId?: string;
}

export interface FadeStyle {
    styleName:   string;
    fadeinTime:  number;
    fadeoutTime: number;
    fadeinType:  string;
    fadeoutType: string;
}

export interface Music {
    id:   string;
    name: string;
    bank: string;
}

export interface SnapshotBank {
    targetSnapshot:  { [key: string]: string };
    hookSoundFxBank: string;
    delay:           number;
    duration:        number;
    name:            string;
}


export interface SoundFXBank {
    sounds:           Sound[] | null;
    maxSoundAllowed:  number;
    popOldest:        boolean;
    customMixerGroup: {[key: string]: string} | null;
    loop:             boolean;
    name:             string;
}



export interface Sound {
    asset:           string;
    weight:          number;
    important:       boolean;
    is2D:            boolean;
    delay:           number;
    minPitch:        number;
    maxPitch:        number;
    minVolume:       number;
    maxVolume:       number;
    ignoreTimeScale: boolean;
}

export interface SoundFXCtrlBank {
    targetBank:       string;
    ctrlStop:         boolean;
    ctrlStopFadetime: number;
    name:             string;
}
const AudioData:AudioData=require('./data/excel/audio_data.json');
export default AudioData;