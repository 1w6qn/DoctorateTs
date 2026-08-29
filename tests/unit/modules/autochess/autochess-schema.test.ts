import { describe, it, expect } from "vitest";
import {
  autoChessCreateTeamSchema,
  autoChessMultiBattleFinishSchema,
  autoChessQueryMatchSchema,
  autoChessSetChessPoolDeploySchema,
  autoChessSettleGameSchema,
  autoChessStartMatchSchema,
  autoChessSyncInfoSchema,
} from "@game/modules/autochess/autochess.schema";

describe("autochess zod schema（schema-first 校验）", () => {
  it("syncInfo 缺 actId 拒绝；合法请求通过", () => {
    expect(() => autoChessSyncInfoSchema.parse({})).toThrow();
    expect(() =>
      autoChessSyncInfoSchema.parse({ actId: 123 }),
    ).toThrow();
    expect(autoChessSyncInfoSchema.parse({ actId: "act2autochess" })).toEqual({
      actId: "act2autochess",
    });
  });

  it("setChessPoolDeploy 校验 chessPool 结构", () => {
    expect(() =>
      autoChessSetChessPoolDeploySchema.parse({ actId: "act2autochess" }),
    ).toThrow();
    expect(() =>
      autoChessSetChessPoolDeploySchema.parse({
        actId: "act2autochess",
        chessPool: { chess_char_1_01_a: { skillIndex: "x" } },
      }),
    ).toThrow();
    const parsed = autoChessSetChessPoolDeploySchema.parse({
      actId: "act2autochess",
      chessPool: {
        chess_char_1_01_a: { skillIndex: 2, currentEquip: null },
      },
    });
    expect(parsed.chessPool.chess_char_1_01_a.skillIndex).toBe(2);
  });

  it("startMatch/queryMatch/createTeam/finish/settle 放行合法负载", () => {
    expect(
      autoChessStartMatchSchema.parse({
        activityId: "act2autochess",
        option: { mode: "mode_single_funny" },
      }).option?.mode,
    ).toBe("mode_single_funny");
    expect(autoChessQueryMatchSchema.parse({ activityId: "act2autochess" }).needLeave).toBe(0);
    expect(
      autoChessCreateTeamSchema.parse({
        activityId: "act2autochess",
        modeId: "mode_single_funny",
      }).matchFlag,
    ).toBe(false);
    expect(
      autoChessMultiBattleFinishSchema.parse({
        activityId: "act2autochess",
        sceneId: "act1autochess_m01",
        data: "encrypted",
        battleData: { isCheat: "0", completeTime: 1 },
      }).sceneId,
    ).toBe("act1autochess_m01");
    expect(autoChessSettleGameSchema.parse({ activityId: "act2autochess" }).quitBattle).toBe(false);
  });
});
