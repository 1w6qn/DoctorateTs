# User 模块完整实现 — 设计文档

> 日期：2026-08-29 ｜ 依据：反编译 C# 2.7.61、tmp/capture/records 抓包、data/excel、prts.wiki（不可达，以 excel 文本为准）
> 状态：用户已确认设计（2026-08-29）

## 范围

补全/修正 `app/game/modules/user/`（routes.ts、status.ts、freshPlayer.ts、account/user.ts、account/user.schema.ts），
并最小化触达 `app/game/modules/checkin/checkin.ts`（维护 `checkIn.showCount`）。

## 已核实的线格式契约（反编译 ↔ 抓包 ↔ excel 三方一致）

| 端点 | 请求 | 响应要点 |
|---|---|---|
| `/user/checkIn` | `{}` | `{ signInRewards, subscriptionRewards, playerDataDelta }`；delta 不含 showCount |
| `/user/buyAp` | `{}` | 成功仅 delta（status.buyApRemainTimes/androidDiamond/ap/lastApAddTime）；每买 135 AP、1 源石 |
| `/user/recvLongTermCheckInReward` | `{ groupId }` | `{ rewards: RewardItemModel[], ...delta }` |
| `/mainlineClue/unlockClue` `/readClue` | `{ id }` | delta `mainline.clue.state[id]=2`（ClueState LOCK=1/UNLOCK=2） |
| `/mainlineClue/getRewards` | `{ ids: string[] }` | `{ items: RewardItemModel[], ...delta }`；`mainline.clue.reward[id]=1` |
| `/mainline/enterCharVoiceRecord` | `{ topicId }` | `{ reward: ItemGet[], ...delta }`；写 `mainline.charVoiceRecord[topicId].isOpen/confirmEnterReward=true` |
| `/mainline/confirmCharVoiceRecordReward` | `{ topicId, nodeId }` | `{ reward: ItemGet[], ...delta }`；`nodes[nodeId]=2`（CLAIMED） |
| `/cg/getCgCollection` `/addCgCollection` `/removeCgCollection` | `{}`/`{cgId}` | `{ cgList: string[], ...delta }`（delta 为空 modified） |
| `/troop/SpecialOperatorUnlockNode` | `{ instId, nodeId }` | delta `troop.spOperator[charId][nodeType][nodeId]={id,state:1,type}` |
| `/performanceStory/startStory` | `{ storyId }` | 写 `performanceStory.unlock[storyId]` |
| `/share/confirmShareMission` | `{ shareMissionId }` | 写 `share.shareMissions[id].counter+1` |
| `/medal/setCustomData` | `{ index, data }` | delta 含 `medal.custom.currentIndex` + `customs[index]` |

## 关键决策（用户已确认）

1. **累计签到天数 = `checkIn.showCount`**：在 `CheckInManager.dailyRefresh()` 递增（官服"登录自动签到"语义，签到抓包 delta 无 showCount 佐证）。
   老档缺失 showCount 时按 `daysSince(registerTs)` 回填（满配号可领全部长期档；新号从 0 累积）。
2. **线索解锁条件宽松**：不做 unlockDesc 自然语言校验；仅幂等 + 记录存在性。
3. **语音入口奖励 = 干员本体 CHAR（charId 取 topic 首个 clip）**，节点奖励 = `p_char_{charId}` 信物（抓包铁证）。
4. **CG 收藏按 uid 持久化**：`data/user/cgCollection.json`（仿 mails.json `{user:{uid:[...]}}`），新增 `cg-store.ts`。
5. **物品发放一律走 `player.gainItem` 管道**（AGENTS.md §35.3），发放移到 `player.update` recipe 之外（避免嵌套 update）。
6. **buyAp 额度耗尽返回 `{result:1}`**（成功无 result，对齐抓包与 CS ExaminResponse）。

## 状态字段与类型

- 全部顶层字段已在生成类型 `types-playerdata.ts` 声明：`checkIn: PlayerCheckIn`（含 `showCount`/`longTermRecvRecord`）、
  `mainline: PlayerMainlineRecord`（`charVoiceRecord` 为 `{[k]: object}`，需 cast）、`share: PlayerCrossAppShare`、
  `performanceStory: PlayerPerformanceStory`、`gallery: PlayerGallery`、`troop.spOperator`（PlayerSpecialOperatorNode 三元嵌套）、`medal: PlayerMedal`。
- `account/user.ts` 新增：`ItemGet`、`RewardItemModel`（本地定义，避免跨模块 import 违约）、
  `RecvLongTermCheckInRewardRequest/Response`、`EnterCharVoiceRecordRequest/Response`、`ConfirmCharVoiceRecordRewardRequest/Response`、
  `GetClueRewardsRequest{ids}/Response{items}`、`StartStoryRequest`、`ConfirmShareMissionRequest`、`SpecialOperatorUnlockNodeRequest`。

## excel 依据

- 长期签到：`excel.OpenServerTable.longTermCheckInData.groupList`（signin_1~4：Lv80 + 180/360/1000/1500 天）+
  `constData.startTs`。
- 线索：`excel.ActivityTable.anniv7thData`（clueData 19 条 / clueRewardData：clueActivity_N{clueRecord,rewards}）。
- 语音档案：`excel.ActivityTable.missionArchives[topicId]`（nodes[{nodeId,clips[{charId}]}]）。
- 特勤：`excel.SpecialOperatorTable.operatorDetailData[charId].nodeUnlockData[nodeId].nodeType`。
- share：`excel.MissionTable.crossAppShareMissions`（当前 rewardsList=null、limitCount=0 → 仅计数）。

## 测试

- 新增：`user-mainline-clue`、`user-char-voice-record`、`user-cg`（node:fs mock）、`user-long-term-checkin`、
  `user-troop`、`user-misc`（startStory/share）、`user-status`（buyAp/exchange/useItem 管道）。
- 扩展：`checkin.test.ts`（showCount 递增/回填）、`status.test.ts`（buyAp 返回布尔 + gainItem）、`user-medal.test.ts`（currentIndex）。
- helpers：`mockPlayerData` 增加 `gainItem` fluent mock。

## 验证

`pnpm exec tsc --noEmit` → `pnpm exec vitest run`（全量 + 定向）。

## 交付物（Git 提交约定见 AGENTS.md，本次按用户指示不自动 commit）
