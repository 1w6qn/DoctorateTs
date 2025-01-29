import { PlayerDataManager } from "./PlayerDataManager";
import { TypedEventEmitter } from "@game/model/events";
import { decryptBattleData } from "@utils/crypt";

export class AprilFoolManager {
  _player: PlayerDataManager;
  _trigger: TypedEventEmitter;

  constructor(player: PlayerDataManager, _trigger: TypedEventEmitter) {
    this._player = player;
    this._trigger = _trigger;
  }

  async act5funBattleFinish(args: {
    data: string;
    battleData: { isCheat: string; completeTime: number };
  }) {
    return await this._player.update(async (draft) => {
      const { data } = args;
      let score = 0;
      let totalWin = 0;
      const battleLog = await decryptBattleData(data, draft.pushFlags.status);
      Object.keys(battleLog.battleData.stats.extraBattleInfo).forEach(
        (info: string) => {
          const infoArr = info.split(",");
          if (infoArr[0] === "SIMPLE" && infoArr[1] === "money") {
            score = parseInt(infoArr[2]);
          }
          if (
            infoArr[0] === "DETAILED" &&
            infoArr[1] === "player" &&
            infoArr[3] === "win"
          ) {
            totalWin += 1;
          }
        },
      );
      return {
        result: 0,
        score: score,
        isHighScore: false,
        npcResult: {},
        playerResult: { totalWin, streak: 0, totalRound: 10 },
        reward: [],
      };
    });
  }
}
