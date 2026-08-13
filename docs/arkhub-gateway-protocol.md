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

- **up**：`field1`(varint)=1、`field2`(varint)=256/257（探针 ID）、`field3`(len 15)=位置块、`field4`(varint)≈200
- **down**：`field1`(nested，~34B)=位置/探针响应、余字段为广播数据
- 15B 位置块样例：`0d 8e a4 62 40 15 0c e1 d7 3b 1d b1 f8 ce 40`——**具体浮点布局待逆向**（非简单 4B LE float）
- 形态极多（up 151 / down 410 种）——位置与探针数据多变

## 5. down 登录后记录流（未完全破解）

登录后 down 流在热闹大厅场景变为**连续记录流**（无外层长度前缀）：
```
[00 00 00 <type>][protobuf 记录]...
```
- 每条记录：`field1`(varint)=ID、`field2`(len 32)=32hex 哈希、`field4/5`(varint)=时间戳（≈Unix 秒，如 1786526084）、`field7`(varint)=1
- 另有 `field2`(string)=uid / 昵称 的嵌套消息（如 `"25866054"` + `"liataynat"`）
- **恢复现状**：`recoverProtobufWithPrefixSkip` 从前缀边界起步部分恢复（会话 18-245 字段）；完整边界需客户端精确 schema
- **陷阱**：`00 00 00 XX` 在余量中出现 ~1.9 万次，但**大量是 protobuf 内部零字节假象**，不能全部当记录边界

## 6. 已提取的网关消息类（字段名，来自 .cs）

37 类字段名已提取（UserLoginReq/Resp、EnterSceneReq/Notify、MoveReq、SyncSceneNotify、
InteractionActionReq、RolePlayingReq、SubmitAVGParam、SubmitActorOpParam、PixelArtData、
PlayerSyncData、PlayerBrief、HallInfo、TaskData 等）——**但 msgId→消息类型注册表在编译体内
无法提取**（serializer 方法体仅签名，ProtoMember 属性仅类定义），字段号仅登录类由实测验证。
补全方法：`npx tsx scripts/dump-gateway-dict.ts` 观测新帧 → 对照字段名声明顺序反推字段号。

## 7. 剩余未知项（精确清单）

1. **msgId 8 的 15B 位置块布局**（浮点/定点编码待逆向）
2. **down 登录后记录流的完整帧边界**（[00 00 00 type] 的 type 语义、消息自定界方式）
3. **msgId 注册表**（msgId 1/2/8 之外的正式消息名，需客户端二进制/新观测）
4. msgId 1 的 type 0-3 具体命令语义（疑移动输入分类）

## 8. 工具用法

```bash
npx tsx scripts/parse-arkhub-gateway.ts                 # 重解析全部抓包 → parsed.json
npx tsx scripts/parse-arkhub-gateway.ts <连接目录ID>     # 单会话
npx tsx scripts/dump-gateway-dict.ts                    # 输出协议字典（msgId×方向×形态）
```
