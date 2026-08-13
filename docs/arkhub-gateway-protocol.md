# arkhub 网关协议完全解析（arkodc）

> 文档对象：官服 arkhub 网关 `arkhub-gateway.hypergryph.com:30000` 的 TCP 私有协议。
> 解析器：`app/proxy/arkodc.ts`；工具：`scripts/parse-arkhub-gateway.ts`（重解析抓包）、
> `scripts/dump-gateway-dict.ts`（协议字典）。
> 数据来源：capture 模式经 30000 转发器抓取的 12+ 个会话（up.bin/down.bin + parsed.json）。

## 1. 帧格式（长度前缀帧）

```
[4B 大端总长度][4B 大端消息 ID][8B 头字段][payload]
```

- **总长度**：含 4B 长度自身 + 4B 消息 ID + 8B 头 + payload（实测 up 流 3176 帧零断帧）
- **消息 ID**：见 §3 字典
- **头字段 8B**：
  - bytes 8-11（`seq`）：序列号——msgId 8 帧中变化（102326、177078 等），msgId 1 恒 0，疑请求序号
  - bytes 12-15（`flag`）：msgId 1/4 恒 0 或 4001/4002（登录请求/响应计数），msgId 8 帧中为**会话级常量**（如 0x38b31d8f，同会话恒定、跨会话变化 → 疑会话/连接 ID）
- **payload**：protobuf（msgId 4/8）或定长二进制（msgId 1/2）

## 2. 消息族（按 payload 形态）

| msgId | 方向 | 形态 | 解析 |
|---|---|---|---|
| 1 | up | 定长二进制 `[uint32 type][uint32 param]` | `{type, param}` 移动输入命令（type 0-3） |
| 2 | down | 定长二进制 `[uint32 type][uint32 param][8B]` | `{type, param, extra1, extra2}` 位置广播——**type/param 与 up msgId1 一致 = 服务器对其他玩家回显移动广播** |
| 4 | up/down | protobuf | UserLoginReq / UserLoginResp（见 §3） |
| 8 | up/down | protobuf | 位置/探针通道（见 §4） |

## 3. Login（msgId 4，字段号已实测验证）

**up = UserLoginReq**：
| 字段 | 名称 | 类型 | 样例 |
|---|---|---|---|
| 1 | uid | string | `"100566259"` |
| 2 | secret | string | `"NHa9zMxyry+..."`（token） |
| 3 | loginChannel | varint | `1` |
| 4 | deviceId | string | `"6a381486..."`（hex） |
| 5 | gameContext | string | 可选 |

**down = UserLoginResp**：
| 字段 | 名称 | 类型 | 样例 |
|---|---|---|---|
| 1 | code | varint | `100`（uid） |
| 2 | heartbeatInterval | varint | `2000`（ms） |
| 3 | reconnectToken | string | base64 JWT `eyJ1dWlkIjoi...`（内含 uuid/device_id/expire_time） |
| 4 | ip / 5 | port | varint |

重连登录变体：up 字段 2 = base64 JWT（`eyJ1dWlk...`），down 字段 1 = 101/112 等。

## 4. 位置/探针通道（msgId 8）

- **up**：`field1`(varint)=1、`field2`(varint)=256/257（探针 ID）、`field3`(len 15)=**Vector3 位置**、`field4`(varint)≈200
- **down**：`field1`(nested，~34B)=位置/探针响应、余字段为广播数据
- **15B 位置块 = protobuf Vector3（2026-08-11 破解）**：`[0x0d][f32 X][0x15][f32 Y][0x1d][f32 Z]`——
  0x0d/0x15/0x1d 即 field1/2/3 wire5(fixed32) 标签，三个 float32 为大厅坐标
  （实测 X∈[-3,12] 均值 4.1、Y∈[-0.3,1.5] 均值 0.6、Z∈[-7,9] 均值 2.3；连续帧位置平滑移动
  = 移动中的玩家）。`decodeVector3` 自动识别解码。
- 形态极多（up 151 / down 410 种）——位置与探针数据多变

## 5. down 登录后记录流（帧边界未完全破解，内容已识别）

登录后 down 流在热闹大厅场景变为**连续记录流**（无外层长度前缀）：
```
[00 00 00 <type>][protobuf 记录]...
```
- **记录内容 = PixelArtInfo（2026-08-11 识别，14/14 样本匹配）**：
  `{1:id, 2:32hex Md5, 4:createTime, 5:updateTime, 7:revision}`——即大厅展示的像素画列表同步
  （客户端 `PixelArtInfo {Id, Md5, Status, CreateTime, UpdateTime, PublishTime, Revision, CollectedCount}`）
- 另有 `field2`(string)=uid / 昵称 的嵌套消息（如 `"25866054"` + `"liataynat"`）——玩家信息记录
- **恢复现状**：`recoverProtobufWithPrefixSkip` 部分恢复（会话 18-245 字段，字段1 元素已命名 PixelArtInfo）；
  完整帧边界（type 语义、消息自定界）仍需客户端精确 schema
- **陷阱**：`00 00 00 XX` 在余量中出现 ~1.9 万次，但**大量是 protobuf 内部零字节假象**，不能全部当记录边界

## 5.1 msgId 1/2 移动协议（2026-08-11 补全）

- **msgId 1 (up)**：`[uint32 type][uint32 param]`——输入命令，type 0-4（≥5 种），param 每会话单调递增
- **msgId 2 (down)**：`[uint32 type][uint32 param][uint32 extra1][uint32 extra2]`——
  位置广播，**type/param 与 up 一致 = 服务器对其他玩家回显移动广播**；
  extra1 恒定 415（疑标志），extra2 单调递增 ~2000/帧（疑序号/时间）

## 6. 已提取的网关消息类（字段名，来自 .cs）

37 类字段名已提取（UserLoginReq/Resp、EnterSceneReq/Notify、MoveReq、SyncSceneNotify、
InteractionActionReq、RolePlayingReq、SubmitAVGParam、SubmitActorOpParam、PixelArtData、
PlayerSyncData、PlayerBrief、HallInfo、TaskData 等）——**但 msgId→消息类型注册表在编译体内
无法提取**（serializer 方法体仅签名，ProtoMember 属性仅类定义），字段号仅登录类由实测验证。
补全方法：`npx tsx scripts/dump-gateway-dict.ts` 观测新帧 → 对照字段名声明顺序反推字段号。

## 7. 剩余未知项（精确清单，2026-08-11 已收敛）

1. **down 登录后记录流的完整帧边界**——内容已识别为 PixelArtInfo/玩家记录，但 [00 00 00 type] 的 type 语义与消息自定界方式未确认（需客户端精确 schema 或活动重开后新抓包）
2. **msgId 注册表**（msgId 1/2/8 之外的正式消息名，需客户端二进制/新观测）
3. msgId 1 的 type 0-4 具体命令语义（疑 MoveReq Status/Shrink/Position/Time 对应，具体待确认）

~~msgId 8 的 15B 位置块布局~~ —— **已破解：protobuf Vector3（field1/2/3 wire5 × f32）**

## 8. 工具用法

```bash
npx tsx scripts/parse-arkhub-gateway.ts                 # 重解析全部抓包 → parsed.json
npx tsx scripts/parse-arkhub-gateway.ts <连接目录ID>     # 单会话
npx tsx scripts/dump-gateway-dict.ts                    # 输出协议字典（msgId×方向×形态）
```
