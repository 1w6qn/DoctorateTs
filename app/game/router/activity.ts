import { Router } from "express";
import httpContext from "express-http-context2";
import { PlayerDataManager } from "../manager/PlayerDataManager";

const router = Router();

router.post("/getChainLogInReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    reward: await player.openServer.getChainLogInReward(req.body),
    ...player.delta,
  });
});

router.post("/getChainLogInFinalRewards", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    reward: await player.openServer.getChainLogInFinalRewards(),
    ...player.delta,
  });
});

router.post("/getOpenServerCheckInReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  res.send({
    reward: await player.openServer.getCheckInReward(req.body),
    ...player.delta,
  });
});

router.post("/getActivityCheckInReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as { activityId: string; index: number };
  
  await player.update(async (draft) => {
    const activityId = body.activityId;
    const targetIndex = body.index;
    
    if (!draft.activity.CHECKIN_ONLY[activityId]) {
      draft.activity.CHECKIN_ONLY[activityId] = {
        lastTs: 0,
        history: [],
      };
    }
    draft.activity.CHECKIN_ONLY[activityId].history[targetIndex] = 0;
  });
  
  res.send({
    ...player.delta,
    items: [],
  });
});

router.post("/actCheckinvs/sign", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as { actId: string; tasteChoice: number };
  
  await player.update(async (draft) => {
    const actId = body.actId;
    const tasteChoice = body.tasteChoice;
    
    const vsData = draft.activity.CHECKIN_VS as any;
    if (!vsData[actId]) {
      vsData[actId] = {
        sweetVote: 0,
        saltyVote: 0,
        canVote: true,
        todayVoteState: 0,
        voteRewardState: 0,
        signedCnt: 0,
        availSignCnt: 1,
        socialState: 2,
        actDay: 1,
      };
    }
    vsData[actId].signedCnt++;
    vsData[actId].canVote = false;
    if (tasteChoice === 1) {
      vsData[actId].sweetVote++;
    } else {
      vsData[actId].saltyVote++;
    }
  });
  
  res.send({
    ...player.delta,
    items: [
      { type: "AP_SUPPLY", id: "ap_supply_lt_120", count: 1 },
      { type: "GOLD", id: "4001", count: 30000 },
    ],
  });
});

router.post("/getSwitchOnlyReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as { activityId: string; reward: string };
  
  await player.update(async (draft) => {
    const activityId = body.activityId;
    const rewardId = body.reward;
    
    const switchData = draft.activity.SWITCH_ONLY as any;
    if (!switchData[activityId]) {
      switchData[activityId] = {};
    }
    switchData[activityId][rewardId] = 0;
  });
  
  res.send(player.delta);
});

router.post("/getCheckInReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  const body = req.body as { activityId: string };
  
  const activityId = body.activityId;
  
  if (activityId.endsWith("access")) {
    await player.update(async (draft) => {
      if (!draft.activity.CHECKIN_ACCESS[activityId]) {
        draft.activity.CHECKIN_ACCESS[activityId] = {
          rewardsCount: 0,
          currentStatus: 0,
          lastTs: 0,
        };
      }
      draft.activity.CHECKIN_ACCESS[activityId].rewardsCount++;
      draft.activity.CHECKIN_ACCESS[activityId].lastTs = Math.floor(Date.now() / 1000);
    });
    
    res.send({
      ...player.delta,
      items: [
        { type: "AP_SUPPLY", id: "ap_supply_lt_80", count: 1 },
        { type: "DIAMOND_SHD", id: "4003", count: 200 },
      ],
    });
  } else if (activityId.endsWith("blessing")) {
    await player.update(async (draft) => {
      const blessData = draft.activity.BLESS_ONLY as any;
      if (!blessData[activityId]) {
        blessData[activityId] = {};
      }
    });
    
    res.send({
      ...player.delta,
      items: [],
    });
  } else {
    res.send({
      ...player.delta,
      items: [],
    });
  }
});

router.post("/changeFestivalChar", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/rewardMilestone", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    item: [],
  });
});

router.post("/rewardAllMilestone", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    item: [],
  });
});

router.post("/confirmActivityMission", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/confirmActivityMissionList", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/confirmActivityMissionGroup", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/autoConfirmMissions", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/exchangeActivityShopItem", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send(player.delta);
});

router.post("/getActivityCollectionReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    item: [],
  });
});

router.post("/getActivityShopInfo", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    shopInfo: {},
  });
});

router.post("/recycleCharms", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    result: 0,
    recycleNum: 0,
  });
});

router.post("/tryGetCharmFirstReward", async (req, res) => {
  const player = httpContext.get<PlayerDataManager>("playerData")!;
  
  res.send({
    ...player.delta,
    isFirst: false,
    reward: [],
  });
});

export default router;