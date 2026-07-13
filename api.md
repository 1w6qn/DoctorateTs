# DoctorateTs API 接口文档

## 概述

本文档记录了 DoctorateTs 服务器提供的所有 API 接口。所有接口均为 POST 请求，返回 JSON 格式数据。

## 基础路径

- 认证接口：`/auth`
- 游戏接口：`/`

## 通用响应格式

```json
{
  "result": 0,
  "playerDataDelta": { ... },
  "data": { ... }
}
```

- `result`: 错误码，0 表示成功
- `playerDataDelta`: 玩家数据变更（增量更新）
- `data`: 接口返回的具体数据

---

## 认证模块

### GET /auth/general/v1/server_time
获取服务器时间

**响应**:
```json
{
  "status": 0,
  "type": "A",
  "msg": "OK",
  "data": {
    "serverTime": 1700000000,
    "isHoliday": false
  }
}
```

### GET /auth/app/v1/config
获取应用配置

**响应**: 返回应用配置 JSON

### POST /auth/user/auth/v1/token_by_phone_password
通过手机号和密码获取 Token

**请求参数**:
```json
{
  "phone": "string",
  "password": "string"
}
```

**响应**:
```json
{
  "status": 0,
  "msg": "OK",
  "data": {
    "token": "string"
  }
}
```

### GET /auth/user/info/v1/basic
获取用户基本信息

**请求参数**:
- `token`: 用户 Token（URL 参数）

**响应**:
```json
{
  "status": 0,
  "msg": "OK",
  "data": {
    "hgId": "string",
    "phone": "string",
    "email": "string"
  }
}
```

### POST /auth/user/oauth2/v2/grant
OAuth2 授权

**请求参数**:
```json
{
  "token": "string"
}
```

**响应**:
```json
{
  "status": 0,
  "msg": "OK",
  "data": {
    "code": "string",
    "uid": "string"
  }
}
```

---

## 账号模块

### POST /account/login
用户登录

**响应**:
```json
{
  "result": 0,
  "uid": "string",
  "secret": "string",
  "serviceLicenseVersion": 0
}
```

### POST /account/syncData
同步用户数据

**响应**:
```json
{
  "result": 0,
  "ts": 1700000000,
  "user": { ... },
  "playerDataDelta": { ... }
}
```

### POST /account/syncStatus
同步用户状态

**响应**:
```json
{
  "ts": 1700000000,
  "result": {},
  "playerDataDelta": { ... }
}
```

### POST /account/syncPushMessage
同步推送消息

**响应**:
```json
{
  "playerDataDelta": { ... }
}
```

---

## 用户模块

### POST /user/changeSecretary
更换助理干员

**请求参数**:
```json
{
  "charInstId": 123
}
```

### POST /user/changeAvatar
更换头像

**请求参数**:
```json
{
  "avatarId": "string"
}
```

### POST /user/changeResume
修改个人简介

**请求参数**:
```json
{
  "resume": "string"
}
```

### POST /user/bindNickName
绑定昵称

**请求参数**:
```json
{
  "nickName": "string"
}
```

**响应**:
- `result: 0` - 成功
- `result: 1` - 昵称过长（超过16字符）
- `result: 2` - 包含特殊字符
- `result: 3` - 包含敏感词

### POST /user/useRenameCard
使用改名卡

**请求参数**:
```json
{
  "nickName": "string",
  "itemId": "string",
  "instId": 123
}
```

### POST /user/receiveTeamCollectionReward
领取编队收集奖励

**请求参数**:
```json
{
  "groupId": "string"
}
```

### POST /user/buyAp
购买理智

### POST /user/exchangeDiamondShard
兑换源石碎片

**请求参数**:
```json
{
  "count": 10
}
```

### POST /user/useItem
使用物品

**请求参数**:
```json
{
  "itemId": "string",
  "count": 1,
  "instId": 123
}
```

### POST /user/useItems
批量使用物品

**请求参数**:
```json
{
  "items": [
    { "itemId": "string", "cnt": 1, "instId": 123 }
  ]
}
```

### POST /user/checkIn
签到

**响应**:
```json
{
  "rewards": [...],
  "playerDataDelta": { ... }
}
```

---

## 抽卡模块

### POST /gacha/syncNormalGacha
同步公开招募状态

### POST /gacha/finishNormalGacha
完成公开招募

**请求参数**:
```json
{
  "slotId": "string"
}
```

**响应**:
```json
{
  "charGet": { ... },
  "playerDataDelta": { ... }
}
```

### POST /gacha/normalGacha
开始公开招募

**请求参数**:
```json
{
  "slotId": "string",
  "tags": [1, 2, 3]
}
```

**响应**:
```json
{
  "charGet": { ... },
  "playerDataDelta": { ... }
}
```

### POST /gacha/boostNormalGacha
加速公开招募

**请求参数**:
```json
{
  "slotId": "string"
}
```

### POST /gacha/cancelNormalGacha
取消公开招募

**请求参数**:
```json
{
  "slotId": "string"
}
```

### POST /gacha/buyRecruitSlot
购买招募栏位

**请求参数**:
```json
{
  "num": 1
}
```

### POST /gacha/refreshTags
刷新招募标签

**请求参数**:
```json
{
  "slotId": "string"
}
```

### POST /gacha/getPoolDetail
获取卡池详情

**请求参数**:
```json
{
  "poolId": "string"
}
```

**响应**:
```json
{
  "detailInfo": { ... },
  "gachaObjGroupType": 0,
  "playerDataDelta": { ... }
}
```

### POST /gacha/advancedGacha
高级抽卡（单抽）

**请求参数**:
```json
{
  "poolId": "string",
  "useTkt": 1,
  "itemId": "string"
}
```

**响应**:
```json
{
  "result": 0,
  "charGet": { ... },
  "playerDataDelta": { ... }
}
```

### POST /gacha/tenAdvancedGacha
高级抽卡（十连）

**请求参数**:
```json
{
  "poolId": "string",
  "useTkt": 1,
  "itemList": [...]
}
```

**响应**:
```json
{
  "result": 0,
  "gachaResultList": [...],
  "playerDataDelta": { ... }
}
```

---

## 角色养成模块

### POST /charBuild/setDefaultSkill
设置默认技能

**请求参数**:
```json
{
  "charInstId": 123,
  "skillIndex": 1
}
```

### POST /charBuild/upgradeChar
升级角色

**请求参数**:
```json
{
  "charInstId": 123,
  "targetLevel": 50
}
```

### POST /charBuild/evolveChar
精英化角色

**请求参数**:
```json
{
  "charInstId": 123
}
```

### POST /charBuild/lockChar
锁定角色

**请求参数**:
```json
{
  "charInstId": 123,
  "isLock": true
}
```

### POST /charBuild/sellChar
出售角色

**请求参数**:
```json
{
  "charInstIds": [123]
}
```

### POST /charBuild/boostPotential
提升潜能

**请求参数**:
```json
{
  "charInstId": 123
}
```

### POST /charBuild/upgradeSkill
升级技能

**请求参数**:
```json
{
  "charInstId": 123,
  "skillId": "string",
  "level": 7
}
```

### POST /charBuild/upgradeSpecialization
专精技能

**请求参数**:
```json
{
  "charInstId": 123,
  "skillId": "string"
}
```

### POST /charBuild/completeUpgradeSpecialization
完成技能专精

**请求参数**:
```json
{
  "charInstId": 123,
  "skillId": "string"
}
```

### POST /charBuild/changeCharSkin
更换角色皮肤

**请求参数**:
```json
{
  "charInstId": 123,
  "skinId": "string"
}
```

### POST /charBuild/changeCharTemplate
切换角色模板

**请求参数**:
```json
{
  "charInstId": 123,
  "templateId": "string"
}
```

### POST /charBuild/unlockEquipment
解锁模组

**请求参数**:
```json
{
  "charInstId": 123,
  "equipId": "string"
}
```

### POST /charBuild/upgradeEquipment
升级模组

**请求参数**:
```json
{
  "charInstId": 123,
  "equipId": "string"
}
```

### POST /charBuild/setEquipment
装备模组

**请求参数**:
```json
{
  "charInstId": 123,
  "equipId": "string"
}
```

### POST /charBuild/setCharVoiceLan
设置角色语音语言

**请求参数**:
```json
{
  "charInstId": 123,
  "voiceLan": "string"
}
```

### POST /charBuild/batchSetCharVoiceLan
批量设置角色语音语言

**请求参数**:
```json
{
  "charInstIds": [123],
  "voiceLan": "string"
}
```

---

## 社交模块

### POST /social/deleteFriend
删除好友

**请求参数**:
```json
{
  "friendUid": "string"
}
```

### POST /social/sendFriendRequest
发送好友请求

**请求参数**:
```json
{
  "friendUid": "string"
}
```

### POST /social/processFriendRequest
处理好友请求

**请求参数**:
```json
{
  "friendUid": "string",
  "isAccept": true
}
```

### POST /social/searchPlayer
搜索玩家

**请求参数**:
```json
{
  "keyword": "string"
}
```

**响应**:
```json
{
  "players": [...],
  "playerDataDelta": { ... }
}
```

### POST /social/getSortListInfo
获取好友排序列表信息

**请求参数**:
```json
{
  "friendUids": ["string"]
}
```

### POST /social/getFriendList
获取好友列表

### POST /social/getFriendRequestList
获取好友请求列表

### POST /social/setAssistCharList
设置助战干员

**请求参数**:
```json
{
  "assistCharList": [...]
}
```

### POST /social/setFriendAlias
设置好友备注

**请求参数**:
```json
{
  "friendUid": "string",
  "alias": "string"
}
```

### POST /social/receiveSocialPoint
领取社交点数

### POST /social/setCardShowMedal
设置名片展示勋章

**请求参数**:
```json
{
  "medalIds": [...]
}
```

---

## 名片模块

### POST /businessCard/changeNameCardSkin
更换名片皮肤

**请求参数**:
```json
{
  "skinId": "string"
}
```

### POST /businessCard/changeNameCardComponent
更换名片组件

**请求参数**:
```json
{
  "componentOrder": ["string"]
}
```

### POST /businessCard/editNameCard
编辑名片

**请求参数**:
```json
{
  "birthday": { "month": 1, "day": 1 },
  "showDetail": true,
  "showBirthday": true
}
```

### POST /businessCard/getOtherPlayerNameCard
获取其他玩家名片

**请求参数**:
```json
{
  "uid": "string"
}
```

**响应**:
```json
{
  "nameCard": { ... },
  "playerDataDelta": { ... }
}
```

---

## 商店模块

### POST /shop/decomposePotentialItem
分解潜能材料

**请求参数**:
```json
{
  "charInstIds": [123]
}
```

**响应**:
```json
{
  "items": [...],
  "playerDataDelta": { ... }
}
```

### POST /shop/decomposeClassicPotentialItem
分解经典潜能材料

**请求参数**:
```json
{
  "charInstIds": [123]
}
```

### POST /shop/getGoodPurchaseState
获取商品购买状态

### POST /shop/getLowGoodList
获取低级商店商品列表

### POST /shop/getHighGoodList
获取高级商店商品列表

### POST /shop/getClassicGoodList
获取经典商店商品列表

### POST /shop/getEPGSGoodList
获取联合行动商品列表

### POST /shop/getLMTGSGoodList
获取限定商品列表

### POST /shop/getExtraGoodList
获取额外商店商品列表

### POST /shop/getREPGoodList
获取声望商店商品列表

### POST /shop/getSkinGoodList
获取皮肤商店商品列表

### POST /shop/getCashGoodList
获取现金商店商品列表

### POST /shop/getGPGoodList
获取信用商店商品列表

### POST /shop/getSocialGoodList
获取社交商店商品列表

### POST /shop/getFurniGoodList
获取家具商店商品列表

### POST /shop/buyLowGood
购买低级商店商品

**请求参数**:
```json
{
  "goodId": "string",
  "count": 1
}
```

### POST /shop/buyHighGood
购买高级商店商品

**请求参数**:
```json
{
  "goodId": "string",
  "count": 1
}
```

### POST /shop/buyExtraGood
购买额外商店商品

### POST /shop/buyCashGood
购买现金商品

### POST /shop/buyEPGSGood
购买联合行动商品

### POST /shop/buyREPGood
购买声望商品

### POST /shop/buyClassicGood
购买经典商店商品

### POST /shop/buyLMTGSGood
购买限定商品

### POST /shop/buyFurniGood
购买家具

### POST /shop/buySkinGood
购买皮肤

---

## 肉鸽模式模块

### POST /rlv2/giveUpGame
放弃肉鸽游戏

### POST /rlv2/createGame
创建肉鸽游戏

**请求参数**:
```json
{
  "theme": "string",
  "mode": "string",
  "modeGrade": 0,
  "predefinedId": "string"
}
```

### POST /rlv2/chooseInitialRelic
选择初始遗物

**请求参数**:
```json
{
  "select": "string"
}
```

### POST /rlv2/chooseInitialRecruitSet
选择初始招募组

**请求参数**:
```json
{
  "select": "string"
}
```

### POST /rlv2/activeRecruitTicket
激活招募券

**请求参数**:
```json
{
  "id": "string"
}
```

### POST /rlv2/recruitChar
招募角色

**请求参数**:
```json
{
  "ticketIndex": "string",
  "optionId": "string"
}
```

**响应**:
```json
{
  "chars": [...],
  "playerDataDelta": { ... }
}
```

### POST /rlv2/finishEvent
完成事件

### POST /rlv2/moveTo
移动到节点

**请求参数**:
```json
{
  "to": { "x": 0, "y": 0 }
}
```

### POST /rlv2/moveAndBattleStart
移动并开始战斗

**请求参数**:
```json
{
  "to": { "x": 0, "y": 0 },
  "stageId": "string",
  "squad": { ... }
}
```

### POST /rlv2/battleFinish
战斗结束

**请求参数**:
```json
{
  "battleLog": "string",
  "data": "string",
  "battleData": { ... }
}
```

### POST /rlv2/chooseBattleReward
选择战斗奖励

**请求参数**:
```json
{
  "index": 0,
  "sub": 0
}
```

### POST /rlv2/finishBattleReward
完成战斗奖励选择

### POST /rlv2/setTroopCarry
设置编队携带

**请求参数**:
```json
{
  "troopCarry": ["string"]
}
```

### POST /rlv2/loseFragment
失去碎片

**请求参数**:
```json
{
  "fragmentIndex": "string"
}
```

### POST /rlv2/useInspiration
使用灵感

**请求参数**:
```json
{
  "fragmentIndex": "string"
}
```

### POST /rlv2/setPinned
设置置顶

**请求参数**:
```json
{
  "id": "string"
}
```

---

## 基建模块

### POST /building/sync
同步基建数据

### POST /building/upgradeRoom
升级房间

**请求参数**:
```json
{
  "roomId": "string"
}
```

### POST /building/completeUpgradeRoom
完成房间升级

### POST /building/settleManufacture
结算制造站

**请求参数**:
```json
{
  "roomId": "string"
}
```

### POST /building/buildRoom
建造房间

**请求参数**:
```json
{
  "roomType": "string",
  "roomId": "string"
}
```

### POST /building/cleanRoomSlot
清理房间槽位

**请求参数**:
```json
{
  "roomSlotId": "string"
}
```

### POST /building/visitBuilding
访问基建

### POST /building/changeManufactureSolution
更换制造配方

**请求参数**:
```json
{
  "roomId": "string",
  "formulaId": "string"
}
```

### POST /building/changeSaleSolution
更换贸易配方

**请求参数**:
```json
{
  "roomId": "string",
  "formulaId": "string"
}
```

### POST /building/assignChar
分配干员

**请求参数**:
```json
{
  "roomSlotId": "string",
  "charInstId": 123
}
```

### POST /building/settleSale
结算贸易站

**请求参数**:
```json
{
  "roomId": "string"
}
```

### POST /building/deliveryOrder
交付订单

**请求参数**:
```json
{
  "roomId": "string",
  "orderId": "string"
}
```

### POST /building/changeStrategy
更换策略

**请求参数**:
```json
{
  "roomId": "string",
  "strategy": "string"
}
```

---

## 任务模块

### POST /mission/exchangeMissionRewards
兑换任务奖励

**请求参数**:
```json
{
  "missionGroupId": "string"
}
```

### POST /mission/confirmMission
确认任务完成

**请求参数**:
```json
{
  "missionId": "string"
}
```

### POST /mission/confirmMissionGroup
确认任务组完成

**请求参数**:
```json
{
  "missionGroupId": "string"
}
```

### POST /mission/autoConfirmMissions
自动确认所有已完成任务

---

## 邮件模块

### POST /mail/listMailBox
获取邮件列表

### POST /mail/receiveMail
领取邮件

**请求参数**:
```json
{
  "mailId": "string"
}
```

### POST /mail/receiveAllMail
领取所有邮件

### POST /mail/removeAllReceivedMail
删除所有已领取邮件

---

## 活动模块

### POST /activity/getChainLogInReward
获取连续登录奖励

**请求参数**:
```json
{
  "index": 0
}
```

### POST /activity/getOpenServerCheckInReward
获取开服签到奖励

**请求参数**:
```json
{
  "index": 0
}
```

---

## 角色轮换模块

### POST /charRotation/setCurrent
设置当前轮换

**请求参数**:
```json
{
  "presetId": "string"
}
```

### POST /charRotation/createPreset
创建轮换预设

**请求参数**:
```json
{
  "name": "string",
  "background": "string",
  "homeTheme": "string",
  "profile": "string",
  "slots": [...]
}
```

### POST /charRotation/updatePreset
更新轮换预设

**请求参数**:
```json
{
  "presetId": "string",
  "name": "string",
  "slots": [...]
}
```

### POST /charRotation/deletePreset
删除轮换预设

**请求参数**:
```json
{
  "presetId": "string"
}
```

---

## 故事回顾模块

### POST /storyreview/unlockStoryByCoin
使用金币解锁故事

**请求参数**:
```json
{
  "groupId": "string"
}
```

### POST /storyreview/readStory
标记故事已读

**请求参数**:
```json
{
  "storyId": "string"
}
```

### POST /storyreview/rewardGroup
领取故事奖励

**请求参数**:
```json
{
  "groupId": "string"
}
```

---

## 资源文件模块

### GET /assetbundle/official/Android/assets/:assetsHash/:fileName
获取资源文件

**路径参数**:
- `assetsHash`: 资源哈希
- `fileName`: 文件名

**响应**: 返回资源文件二进制数据

---

## 配置模块

### GET /config/prod
获取生产环境配置

**响应**: 返回生产环境配置 JSON