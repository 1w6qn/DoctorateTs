# 反编译源码 vs 本服务器：未实现 / Stub 接口清单

> 分析日期：2026-08-17　|　分析对象：`reference/arknights-2.7.61-csharp`（官方客户端反编译 C# 2.7.61）vs `app/`（DoctorateTs 私服）
> 方法论：`scripts/_extract-routes.py` 从反编译源码提取官方路由全集（544 条），`scripts/_diff-client-routes.py` 解析当前 `routes.ts` 挂载表 + 全部 router 文件 + auth 层 + index.ts 别名，还原客户端可见 URL 后逐一比对。

---

## 一、总体结论

| 项 | 数量 | 说明 |
|---|---|---|
| 官方接口（反编译 C# 提取） | **544** | 客户端发起请求的全部路径 |
| 服务器已实现 | **529** | 精确路径匹配（含 auth 层、index.ts 别名、misc-alignment 对齐） |
| 大小写变体（运行时可达） | 9 | `/deepSea/*` vs 服务端 `/deepsea/*`——Express 默认大小写不敏感，实际可命中 |
| **完全未实现** | **6** | 全部集中在肉鸽V2（`/rlv2/*`），服务器无任何注册 |
| Stub / 占位实现 | ~220 条 | 有路由但仅返回空增量 / 固定值 / 202，见第二部分 |

6 条未实现接口在 2026-08-13 的 curl 实测（`reference/client-routes-missing.txt`）中同样为 404，期间其余曾缺失的 40 条均已补齐（explore/siracusaMap/deepSea 路由挂载、user 根级路由、auth 层、misc-alignment 全量对齐等），仅这 6 条始终未动。

---

## 二、完全未实现的官方接口（6 条）

均无任何实现（全项目 grep 无注册、无处理逻辑），官方定义见反编译源码：

| 路径 | 官方定义（反编译源码） | 功能说明 | 现状 |
|---|---|---|---|
| `/rlv2/battlePass/buyReward` | `Torappu.UI.RoguelikeTopic.RoguelikeTopicService.BATTLEPASS_PURCHASE` | 肉鸽V2 赛季战令**购买**奖励（服务端已有 `battlePass/getReward` 领奖，缺购买入口） | 无 |
| `/rlv2/copper/change` | `Torappu.UI.Roguelike.RL05Service.CHANGE_COPPER` | 黄铜货币**转化**（铜币兑换体系，服务端已有 `copper/gild`、`copper/redraw`） | 无 |
| `/rlv2/copper/confirmDraw` | `Torappu.UI.Roguelike.RL05Service.CONFIRM_DRAW_COPPER` | 黄铜**确认抽取** | 无 |
| `/rlv2/finishGame` | `RoguelikeTopicService.FINISH_GAME` | 肉鸽V2 **通关结算**（服务端已有 `gameSettle` / `giveUpGame`，缺正式的 finishGame 链路） | 无 |
| `/rlv2/normal/unlockBuff` | `RoguelikeTopicService.UNLOCK_BUFF` | 常规模式**解锁增益** | 无 |
| `/rlv2/setSeed` | `RoguelikeTopicService.SET_SEED`（客户端使用方：`RoguelikeActivitySeedModePanel`） | **种子模式**设置对局种子 | 无 |

> 影响：肉鸽V2 的战令购买、黄铜交易、通关结算、增益解锁、种子模式功能在客户端不可用（点击即 404）。其余肉鸽V2 接口（64 条）均已实现。

---

## 三、Stub / 占位实现清单

### 3.1 `router/misc-alignment.ts` —— 全量对齐 stub 路由器（约 57 条）

按 ODPY 清单「全量对齐」补的路径可达性 stub，全部返回空对象 / 固定值：

| 分组 | 路由 | 返回 |
|---|---|---|
| 遥测 / 埋点 / 外部服务（10） | `/analytics/collect`、`/beat`、`/event`、`/gameBulletin`、`/loggw/logUpload.do`、`/mgw.htm`、`/deviceprofile/v4`、`/iedsafe/Client/android/19791/config2.xml`、`/survey/startSurvey`、`/general/v1/send_phone_code` | `{}` |
| YoStar 登录链路（3） | `/account/yostar_auth_request`、`/account/yostar_auth_submit`、`/user/yostar_createlogin` | `{result:0, uid:"", token:""}` |
| ODPY 独有 app/api（8 路径 / 9 注册） | `/app/getCode`、`/app/getSettings`、`/api/gacha/cate`、`/api/gacha/history`、`/api/autoChess/act1autochess/playerSummary`、`/api/autoChess/act2autochess/playerSummary`、`/api/is/rogue_1/bulletinVersion`(GET+POST) | 空 / 固定结构 |
| 协议确认（2） | `/user/agreement`、`/user/auth/v2/token_by_phone_code` | `{result:0}` / 提示已替代 |
| 支付变体（10） | `/pay/confirmOrderAppstore`、`/pay/confirmOrderAppstoreNew`、`/pay/createOrderAppstore`、`/pay/order/v1/check`、`/pay/order/v1/state`、`/pay/v1/query_show_app_product`、`/user/pay/order/v1/create/app_product/alipay`、`/user/pay/order/v1/create/app_product/wechat`、`/user/pay/order/v2/create/app_product`、`/user/pay/v1/query_payment_config` | `{result:0}` + delta（注释：CN 2.7.61 客户端不调用） |
| recalRune 根路径别名（2） | `/recalRune/battleStart`、`/recalRune/battleFinish` | 固定 battleId 空结算 |
| admin 别名（5） | `/admin/cheat`、`/admin/getVersion`、`/admin/login/by_phone_password`、`/admin/saveUserData`、`/admin/verify` | `{status:0, result:0}`（本项目管理端为自有实现，此处仅保证路径可达） |
| 官方资源文件（1） | `/official/Android/assets/:assetsHash/:fileName` | `{}` |
| DoctoratePy 支付变体（5） | `/pay/createOrderAlipay`、`/pay/createOrderWechat`、`/pay/confirmOrderAlipay`、`/pay/confirmOrderWechat`、`/pay/success` | `{result:0}` / `{status:0}` |
| 管理登录 / 协议（2） | `/login`、`/user/agreement/confirm` | `{result:0, msg:"OK"}` |
| EN/YoStar 端点（8） | `/common/client-code`、`/common/client-info`、`/common/client-log`、`/common/config`、`/common/version`、`/yostar/get-auth`、`/user/detail`、`/user/quick-login` | `{}` |
| 根路径（1） | `/` | `{result:0}` |

### 3.2 `router/activity.ts` —— 活动小游戏 stub 批量（107 条，其中纯 stub ≈ 97 条）

区间注释：`活动小游戏 stub 批量（参考 ODPY 均为 202 stub）`。核心模式：战斗类返回固定 `battleId` 空结算（`miniBattleStart`/`miniBattleFinish`），玩法类返回 `player.delta` 空增量或空 `items`。

| 分组 | 路由 | 说明 |
|---|---|---|
| 街机（2） | `arcade/battleStart`、`arcade/battleFinish` | 固定 battleId 空结算 |
| 熔炉活动 act42d0（5） | `battleStart`、`battleFinish`、`challengeStart`、`challengeFinish`、`recvMilestone` | 战斗 stub + 挑战/里程碑空奖励 |
| 半挂机 act1vhalfidle 战斗（2） | `battleStart`、`battleFinish` | 固定 battleId 空结算 |
| act13side（8） | `clearFlag` + `dailyMissionAccept/Cancel/Replace/Random/Commit` + `longMissionCommit/Batch` | 空增量 |
| act27side（7） | `inquirePurchase`、`inquireSell`、`nextDay`、`purchase`、`saleSettle`、`saleStart`、`sell` | 空增量 |
| act35side（9） | `create` + `buyCard`、`buySlot`、`nextRound`、`process`、`refreshShop`、`settle`、`toBuy`、`toProcess` | 空增量 |
| act38side（3） | `completePuzzle`、`getInfo`、`useHint` | 空增量 |
| act42side（4） | `acceptTask`、`confirmTask`、`getDailyRewards`、`getDailyTrustedItem` | 空增量 |
| act44side（4） | `nextState`、`selectChoice`、`startGame`、`useInsight` | 空增量 |
| act45side（2） | `confirmChar`、`confirmMail` | 空增量 |
| act46side（5） | `startGame` + `settleGame`、`move`、`endRound`、`mining` | 空增量 |
| 登录活动（3） | `loginOnly/getReward`、`loginOnlyUnique/getReward`、`prayOnly/getReward` | 空增量 |
| 庆典活动（3） | `actBlessOnly/changeFestivalChar`、`actBlessOnly/getCheckInReward`、`actCheckinAccess/getCheckInReward` | 空增量 |
| 团队任务（1） | `teamQuest/refreshInfo` | 空增量 |
| typeAct3d0（4） | `gacha`、`getGachaInfo`、`getMilestoneReward`、`selectFaction` | 空增量 |
| typeAct4d0（3） | `finishStory`、`getReward`、`unlockStory` | 空增量 |
| typeAct5d0 / 5d1（5） | `typeAct5d0/getReward`、`typeAct5d1/buyGoods`、`buyRune`、`getGoodsList`、`getInfo` | 空增量 |
| typeAct9d0（1） | `readNews` | 空增量 |
| typeAct20side（7） | `competitionStart/Finish`、`confirmExhiCar`、`judge`、`pick`、`quickGetMilestoneAward`、`quickRecycle` | 空 `items` |
| 年5综合（1） | `year5General/getInfReward` | 空增量 |
| 自走棋赛季（18） | `autochessSeason/createTeam`、`joinTeam`、`queryMatch`、`startMatch`、`syncInfo`、`quitSingleGame`、`startGuideBattle`、`finishGuideBattle`、`multiBattleStart/Finish`、`settleGame`、`settleLike`、`report`、`getFriendCharAssistList`、`setChessPoolAssist/Deploy/DiyChar`、`removeChessPoolChar` | 多人流程 stub，空增量 |
| 根路径活动（act29side / act36side / trainingGround，另一 stub 区间，6 条） | `act29side/commitMelody`、`startMajorInvest`、`syncthesize`、`act36side/confirmDexNavReward`、`trainingGround/battleStart`、`battleFinish` | 202 / 空 stub |

> 注：act1vhalfidle 的**非战斗接口**（`refreshProduct`/`harvest`/`evolveChar`/`recruitNormal`/`recruitDirect`/`unlockTech`/`upgradeChar`/`upgradeSkill`/`replaceRate`/`setAssistChar`，10 条）为参考 ODPY 的**简化实现**（有基础产出/招募/升级逻辑），非纯 stub。

### 3.3 `router/sandbox.ts` —— 沙盒 stub（约 57 条）

| 分组 | 路由 | 返回 |
|---|---|---|
| 沙盒 V2 玩法（~28） | `/v2/alchemy`、`baseUpgrade`、`build`、`cook`、`cookDrink`、`cookFood`、`discardAp`、`eatFood`、`enterChallenge`、`exitChallenge`、`extract`、`getChallengeReward`、`guideLoad`、`load`、`nextDay`、`removeSupply`、`riftClose`、`riftCreate`、`riftSetDifficulty`、`riftSetTeam`、`riftSettle`、`setSupply`、`settleChallenge`、`settleDay`、`shopBuy`、`startMission`、`switchMode`、`unlockTech` | 202（注释均为「空响应（202）」） |
| 沙盒 V3 玩法（~20） | `/v3/battleStart`、`battleFinish`、`chooseBand`、`dailyRecruit`、`eatFood`、`eventChoice`、`getDailyRecruitList`、`homeShopBuy`、`homeShopSell`、`homeUpgrade`、`homeSave`、`initRecruit`、`nextDay`、`productionHarvest`、`productionRefresh`、`settleGame`、`shopBuy`、`shopBuyRecruit`、`shopRefresh`、`shopSell`、`switchMode`、`unlockTech` | 202 |
| 竞速小游戏（12） | `/v2/racing/battleStart`、`battleFinish`、`learnTalent`、`register`、`release`、`saveMark`（返回 delta）+ `/racingBattleStart`、`/racingBattleFinish`、`/racingLearnTalent`、`/racingRegister`、`/racingRelease`、`/racingSaveMark`（返回 202） | delta / 202（注释：参考 ODPY racing 未实现） |
| 话题置顶（1） | `pinTopic` | 202 |

### 3.4 `router/campaignV2.ts` —— 主线战役V2（3 条）

| 路由 | 说明 |
|---|---|
| `battleSweep` | 简化实现：返回固定扫荡奖励结构（未走完整掉落逻辑） |
| `getBreakReward` | **暂不实现，等待后续迭代补全**（原 202 已改为 JSON 增量） |
| `getExMissionReward` | 同上，额外任务奖励完整逻辑未实现 |

### 3.5 `router/audit.ts` —— 资源版本审计（全 stub）

| 路由 | 返回 |
|---|---|
| `/audit/official/Android/assets/:assetsHash/:fileName` | `{}` |
| 其余审计路径（`version_<subpath>` / `Windows/<subpath>` 等） | `{}`（router.use 通配） |

### 3.6 单点 stub（散落在各模块）

| 模块 | 路由 | 说明 |
|---|---|---|
| quest | `battleContinue` | 固定 `result:1` + 全零 battleId（战斗数据由 battleFinish 结算） |
| rune | `battleFinish` | 战斗结算真实，但 `score/from/to` 固定 0 |
| gacha | `POST /gacha`（裸路径） | 返回空增量（会话状态占位） |
| autochess | `/autoChess/act1autochess`、`/act2autochess` | 赛季信息空增量 stub |
| aprilFool | `act3fun~act7fun/battleStart` 系 | 固定 battleId（`aprilFoolBattleStart`） |
| aprilFool | `act4fun/liveSettle` | 服务端自定义 stub，空增量 |
| arkodc | `battleStart` | 固定 battleId 空结算（参考 OBS） |
| shop | `getCashGoodPurchaseResult` | 占位（参考实现 202）；此处返回 CASH 购买记录 |
| shop | `getVoucherSkinGoodList` | 占位（202）→ 筛选可兑换凭证皮肤返回 |
| shop | `useVoucherSkin` | 占位（202）→ 实际发放皮肤（部分实现） |
| shop | `checkForbidden` | 占位（202）→ 返回可购校验 |
| auth | `user/info/v1/logout` | EN 客户端路径 stub |
| auth | `user/info/v1/update_agreement`、`u8/user/auth/v1/update_agreement` | 协议确认 stub |
| user | `gallery/jpg/:jpgName(.png)`、`announce/images/:subpath` | 私服无素材文件，返回 1×1 透明 PNG 占位图 |

---

## 四、与历史记录的对比（2026-08-13 → 2026-08-17）

`reference/client-routes-missing.txt`（46 条 curl 实测 404）逐条核对：

| 曾缺失分组 | 当时 | 现在 |
|---|---|---|
| explore（8） | 404 | ✅ 已实现（`router/explore.ts` 挂载） |
| siracusaMap（6） | 404 | ✅ 已实现（`router/siracusaMap.ts` 挂载） |
| deepSea（7） | 404 | ✅ 运行时可达（`/deepsea/*` 大小写不敏感命中） |
| rlv2（6） | 404 | ❌ **仍缺失**（本报告第二部分） |
| user/auth（4） | 404 | ✅ 已实现（`app/core/auth/auth.ts` + index.ts 别名） |
| mainline / mainlineClue（5） | 404 | ✅ 已实现（`user.ts` rootRouter） |
| misc（10） | 404 | ✅ 已实现（activity/misc-alignment/quest/shop/aprilFool 等） |

---

## 五、附：分析工具

- `scripts/_extract-routes.py` —— 从反编译 C# 提取官方路由全集（544 条 → `reference/client-routes.txt`）
- `scripts/_diff-client-routes.py` —— 解析 `routes.ts` 挂载表 + 各 router（含 rootRouter 分节、URL 重写别名、循环注册、auth 层、index.ts 别名），与官方清单对比输出缺失（→ `reference/client-routes-missing-current.json`）
- 结论数据口径：**未实现 = 官方清单中存在但服务端无任何可达注册**；**Stub = 有注册但仅占位返回**
