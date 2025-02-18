import { PlayerRoguelikePendingEvent } from "../../model/rlv2";
import { RoguelikeV2Controller } from "../rlv2";
import { TypedEventEmitter } from "@game/model/events";

export class RoguelikeEventManager {
  _index: number;
  _player: RoguelikeV2Controller;
  _pending: RoguelikePendingEvent[] = [];
  _trigger: TypedEventEmitter;

  constructor(_player: RoguelikeV2Controller, _trigger: TypedEventEmitter) {
    this._index = 0;
    this._player = _player;
    this._pending = [];
    this._trigger = _trigger;
    this._trigger.on("rlv2:init", this.init.bind(this));
    this._trigger.on("rlv2:continue", this.continue.bind(this));
    this._trigger.on("rlv2:create", this.create.bind(this));
    this._trigger.on("rlv2:event:create", () => {
      this.createEvent.bind(this);
    });
  }

  init(): void {
    this._index = 0;
    this._pending = [];
  }

  continue(): void {}

  createEvent([type, args]: [string, object]): void {
    this._pending.push(
      new RoguelikePendingEvent(
        this._player,
        this._trigger,
        type,
        this._index,
        args,
      ),
    );
    this._index++;
  }

  create(): void {
    this._index = 0;
    this._pending = [];
    const game = this._player.current.game!;
    const theme = this._player.current.game!.theme;
    const initConfig = this._player.initConfig;
    //TODO
    const totalStep = game.outer.support ? 4 : 3;
    this._trigger.emit("rlv2:event:create", [
      "GAME_INIT_RELIC",
      {
        step: [this._index + 1, totalStep],
      },
    ]);
    if (game.outer.support) {
      this._trigger.emit("rlv2:event:create", [
        "GAME_INIT_SUPPORT",
        {
          step: [this._index + 1, totalStep],
          id: "",
        },
      ]);
    }
    this._trigger.emit("rlv2:event:create", [
      "GAME_INIT_RECRUIT_SET",
      {
        step: [this._index + 1, totalStep],
      },
    ]);
    this._trigger.emit("rlv2:event:create", [
      "GAME_INIT_RECRUIT",
      {
        step: [this._index + 1, totalStep],
      },
    ]);
  }

  toJSON(): PlayerRoguelikePendingEvent[] {
    return this._pending.map((e) => e.toJSON());
  }
}
export class RoguelikePendingEvent implements PlayerRoguelikePendingEvent {
  type: string;
  content: PlayerRoguelikePendingEvent.Content;
  _player: RoguelikeV2Controller;
  _trigger: TypedEventEmitter;

  constructor(
    _player: RoguelikeV2Controller,
    _trigger: TypedEventEmitter,
    type: string,
    index: number,
    args: {},
  ) {
    this._player = _player;
    this._trigger = _trigger;
    this.type = type;
    this._index = index;
    this.content = this[type](args) as PlayerRoguelikePendingEvent.Content;
  }

  [key: string]: any;

  _index: number;

  get index(): string {
    return `e_${this._index}`;
  }

  GAME_INIT_RELIC(args: {
    step: [number, number];
  }): PlayerRoguelikePendingEvent.Content {
    const initConfig = this._player.initConfig;
    return {
      initRelic: {
        step: args.step,
        items: initConfig.initialBandRelic.reduce((acc, cur, idx) => {
          return { ...acc, [idx.toString()]: { id: cur, count: 1 } };
        }, {}),
      },
    };
  }

  GAME_INIT_SUPPORT(args: {
    step: [number, number];
    id: string;
  }): PlayerRoguelikePendingEvent.Content {
    const game = this._player.current.game!;
    const initConfig = this._player.initConfig;
    return {
      initSupport: {
        step: args.step,
        scene: {
          id: `scene_ro${game.theme.slice(-1)}_startbuff_enter`,
          choices: {
            choice_ro4_startbuff_1: 1,
            choice_ro4_startbuff_2: 1,
            choice_ro4_startbuff_3: 1,
            choice_ro4_startbuff_4: 1,
            choice_ro4_startbuff_5: 1,
            choice_ro4_startbuff_6: 1,
          },
        },
      },
    };
  }

  GAME_INIT_RECRUIT_SET(args: {
    step: [number, number];
  }): PlayerRoguelikePendingEvent.Content {
    const initConfig = this._player.initConfig;
    return {
      initRecruitSet: {
        step: args.step,
        option: initConfig.initialRecruitGroup!,
      },
    };
  }

  GAME_INIT_RECRUIT(args: {
    step: [number, number];
  }): PlayerRoguelikePendingEvent.Content {
    this._trigger.on(
      "rlv2:choose_init_recruit_set",
      ([tickets]: [string[]]) => {
        this.content.initRecruit!.tickets = tickets;
      },
    );
    return {
      initRecruit: {
        step: args.step,
        tickets: [],
        showChar: [],
        team: null,
      },
    };
  }

  RECRUIT(args: { tickets: string }): PlayerRoguelikePendingEvent.Content {
    return {
      recruit: {
        ticket: args.tickets,
      },
    };
  }

  BATTLE_SHOP(args: {}): PlayerRoguelikePendingEvent.Content {
    return {};
    /*
            this._trigger.on("rlv2:bankPut", (broken:boolean)=>{
                this.content.battleShop!.bank.canPut=broken
            })
            return {
                
    
                battleShop: {
                    bank:{
                        open:true,
                        canPut:true,
                        canWithdraw:true,
                        withdraw:0,
                        cost:1,
                        withdrawLimit:20
                    },
                }
            }*/
  }

  BATTLE(
    args: PlayerRoguelikePendingEvent.BattleContent,
  ): PlayerRoguelikePendingEvent.Content {
    return {
      battle: args,
    };
  }

  BATTLE_REWARD(
    args: PlayerRoguelikePendingEvent.BattleRewardContent,
  ): PlayerRoguelikePendingEvent.Content {
    return {
      battleReward: args,
    };
  }

  toJSON(): PlayerRoguelikePendingEvent {
    return {
      index: this.index,
      type: this.type,
      content: this.content,
    };
  }
}
