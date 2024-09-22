//
export interface AudioData {
  readonly bgmBanks: BGMBank[];
  readonly soundFXBanks: SoundFXBank[];
  readonly soundFXCtrlBanks: SoundFXCtrlBank[];
  readonly snapshotBanks: SnapshotBank[];
  readonly battleVoice: BattleVoice;
  readonly musics: Music[];
  readonly duckings: Ducking[];
  readonly fadeStyles: FadeStyle[];
  readonly soundFxVoiceLang: { [key: string]: { [key: string]: string } };
  readonly bankAlias: { [key: string]: string };
}

export interface BattleVoice {
  readonly crossfade: number;
  readonly minTimeDeltaForEnemyEncounter: number;
  readonly minSpCostForImportantPassiveSkill: number;
  readonly voiceTypeOptions: VoiceTypeOption[];
}

export interface VoiceTypeOption {
  readonly voiceType: number;
  readonly priority: number;
  readonly overlapIfSamePriority: boolean;
  readonly cooldown: number;
  readonly delay: number;
}

export interface BGMBank {
  readonly intro: null | string;
  readonly loop: null | string;
  readonly volume: number;
  readonly crossfade: number;
  readonly delay: number;
  readonly name: string;
  readonly fadeStyleId?: string;
}

export interface Ducking {
  readonly bank: string;
  readonly volume: number;
  readonly fadeTime: number;
  readonly delay: number;
  readonly fadeStyleId?: string;
}

export interface FadeStyle {
  readonly styleName: string;
  readonly fadeinTime: number;
  readonly fadeoutTime: number;
  readonly fadeinType: string;
  readonly fadeoutType: string;
}

export interface Music {
  readonly id: string;
  readonly name: string;
  readonly bank: string;
}

export interface SnapshotBank {
  readonly targetSnapshot: string;
  readonly hookSoundFxBank: string;
  readonly delay: number;
  readonly duration: number;
  readonly name: string;
}

export interface SoundFXBank {
  readonly sounds: Sound[] | null;
  readonly maxSoundAllowed: number;
  readonly popOldest: boolean;
  readonly customMixerGroup: { [key: string]: string } | null;
  readonly loop: boolean;
  readonly name: string;
}

export interface Sound {
  readonly asset: string;
  readonly weight: number;
  readonly important: boolean;
  readonly is2D: boolean;
  readonly delay: number;
  readonly minPitch: number;
  readonly maxPitch: number;
  readonly minVolume: number;
  readonly maxVolume: number;
  readonly ignoreTimeScale: boolean;
}

export interface SoundFXCtrlBank {
  readonly targetBank: string;
  readonly ctrlStop: boolean;
  readonly ctrlStopFadetime: number;
  readonly name: string;
}
