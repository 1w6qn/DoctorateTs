# FBO schema 交叉校验报告：本地 vs OpenArknightsFBS

## 结论（TL;DR）

本地 `scripts/vendor/fbs-schemas/*.json` 与社区 OpenArknightsFBS 参考**整体吻合**：61 组同名文件里字段序（FBO vtable slot 布局）**0 处**不一致、本地 slot 与字段序**完全自洽**、root_type 全等；差异集中在**本地缺表 / 缺字段**这一类“静默丢数据”的问题上。

**根因**：`scripts/cs2schema.ts --write` 只重写**已存在**的表键 + 补齐 KV 表，**从不新增 `clz_` 表**。因此老 vendored schema 没覆盖到的类（新版活动的数据类、`UnityEngine.Vector2/3` 这类非 `Torappu` 结构）永远不会被补上，而缺口不会报错——只是解出 `{}`。

**P0（已用真实数据证实，非推断）**

1. **`clz_UnityEngine_Vector2/Vector3` 缺失** → 27 个字段解成 `{}`（Vector2 16 处 / Vector3 11 处）。实测 `data/excel/arkvent_table.json` 中 `actorPosition` 335 处、`safePos` 335 处、`position` 251 处、`bounds` 251 处全为空对象；`display_meta_table.skinDefaultPos` 10 处为空（同表的 `pos` 有值，说明字段确实在报文里）。
2. **`Act54SideData` / `ActVasebreakerData` 整族 22 张表缺失**（新版活动）→ 实测 `data/excel/activity_table.json` 中 `"Act54SideData": {"act54side": {}}`，内容整体丢失。
3. **`clz_Newtonsoft_Json_Linq_JObject` 未定义却被 3 个字段引用**（`GachaPoolClientData.DynMeta/LinkageParam/LimitParam`）→ 实测 `data/excel/gacha_table.json` 中三字段各 446 处全为 `{}`（FBS 对应表叫 `hg__internal__JObject { base64: string; }`，本地在 `activity_table` 里定义过同名 `hg__internal__JObject`，`gacha_table` 没有）。

**P1（需复核）**

4. **宽度不匹配 7 处**：FBS 的 `enum__Torappu_PlayerSideMask : ubyte` / `edgeWalkableMask: ubyte` 是 1 字节，本地 schema 一律写 `enum`/`int`，而 `fbo.ts#readFieldValue` 对 `int`/`enum` 按 **i32（4 字节）** 读取 → 读宽不一致（`RuneData_Selector`×5、`LevelData_GlobalBuffData`、`BuildingData_ObstaclePoint`）。
5. **`FifthAnnivExploreMissionData` 本地只有 1 个字段**（FBS 20 个）：该 C# 类继承 `Torappu.MissionData`，FBO 会把基类字段平铺进同一张表，而 `cs2schema` 只取类体自身字段 → 19 个字段解不出。

**低风险、无需动作**：历史合成字段 `*AsNumpy`（100 处，`excel-convert` 本就丢弃、解码器读作 `null`）；同槽位字段名差异 41 表（官方改名 + snake_case/PascalCase 风格）；本地比 FBS 多字段 14 表（CS 已跟上官方新增）。

**复跑**：`pnpm run schema:crosscheck`（加 `-- --md <path>` 重出本报告，`-- --strict` 在检出硬漂移时非 0 退出）。数据章节由该工具生成、可随时重放；本「结论」段为人工撰写，用同一路径重放会被覆盖。

---

- 生成时间：2026-09-12T02:35:30.840Z
- 参考侧：`reference/OpenArknightsFBS-main/FBS`（OpenArknightsFBS，社区从游戏结构解析）
- 本地侧：`scripts/vendor/fbs-schemas`（由 CS 反编译派生）
- 比对范围：61 组同名 schema 文件；FBS 2964 表 / 本地 2928 表

## 摘要

| 检查项 | 结果 |
| --- | --- |
| FBS 独有表（本地缺失 → 解码为 `{}`） | 35 |
| FBS 独有 `list_X` 向量包装表（本地内联 `vec:X`，非缺口） | 11 |
| 本地独有表 | 2 |
| 表内字段缺失（本地解不出） | 5 表 |
| 同槽位改名（布局不变） | 41 表 |
| 本地多出字段 | 14 表 |
| 字段序（slot 布局）不一致 | 0 表 |
| 类型宽度不一致 | 10 表 |
| 本地悬空引用 | 33 处 |
| 本地未解析类型 token（`unknown`） | 100 处 |
| FBS 悬空引用 | 0 处 |
| 本地 slot 与字段序不自洽 | 0 处 |
| root_type 不一致 | 0 处 |
| FBS 枚举引用未定义 | 0 处 |
| 非 int 基类型枚举（宽度风险） | 9 个 |

## 1. FBS 有、本地缺失的表

本地 schema 没有这些表定义，而 FBS 有 → 字段引用它们时 `scripts/vendor/fbo.ts#tableToJson` 返回 `{}`，数据静默丢失。

| schema 文件 | 表名 | FBS 字段数 |
| --- | --- | --- |
| activity_table | `clz_UnityEngine_Vector2` | 2 |
| activity_table | `clz_UnityEngine_Vector3` | 3 |
| activity_table | `clz_Torappu_Act54SideData_Act54SideCardData` | 7 |
| activity_table | `dict__string__clz_Torappu_Act54SideData_Act54SideCardData` | 2 |
| activity_table | `clz_Torappu_Act54SideData_Act54SideSpreadItemInfo` | 3 |
| activity_table | `clz_Torappu_Act54SideData_Act54SideSpreadData` | 10 |
| activity_table | `dict__string__clz_Torappu_Act54SideData_Act54SideSpreadData` | 2 |
| activity_table | `clz_Torappu_Act54SideData_Act54SideSpecialZoneStageInfo` | 3 |
| activity_table | `clz_Torappu_Act54SideData_Act54SideZoneAdditionData` | 2 |
| activity_table | `dict__string__clz_Torappu_Act54SideData_Act54SideZoneAdditionData` | 2 |
| activity_table | `clz_Torappu_Act54SideData_Act54SideConstData` | 4 |
| activity_table | `clz_Torappu_Act54SideData` | 5 |
| activity_table | `clz_Torappu_ActVasebreakerData_ActVasebreakerZoneAdditionData` | 2 |
| activity_table | `dict__string__clz_Torappu_ActVasebreakerData_ActVasebreakerZoneAdditionData` | 2 |
| activity_table | `clz_Torappu_ActVasebreakerData_ActVasebreakerStageAdditionData` | 4 |
| activity_table | `dict__string__clz_Torappu_ActVasebreakerData_ActVasebreakerStageAdditionData` | 2 |
| activity_table | `clz_Torappu_ActVasebreakerData_ActVasebreakerStageUnlockToastData` | 2 |
| activity_table | `dict__string__clz_Torappu_ActVasebreakerData_ActVasebreakerStageUnlockToastData` | 2 |
| activity_table | `clz_Torappu_ActVasebreakerData_ActVasebreakerStageDropData` | 8 |
| activity_table | `dict__string__clz_Torappu_ActVasebreakerData_ActVasebreakerStageDropData` | 2 |
| activity_table | `clz_Torappu_ActVasebreakerData_ActVasebreakerMilestoneItemData` | 5 |
| activity_table | `clz_Torappu_ActVasebreakerData_ActVasebreakerStickerData` | 5 |
| activity_table | `clz_Torappu_ActVasebreakerData_ActVasebreakerConstData` | 7 |
| activity_table | `clz_Torappu_ActVasebreakerData` | 7 |
| activity_table | `hg__internal__JObject` | 1 |
| arkvent_table | `clz_UnityEngine_Vector3` | 3 |
| campaign_table | `clz_UnityEngine_Vector2` | 2 |
| display_meta_table | `clz_UnityEngine_Vector2` | 2 |
| gacha_table | `hg__internal__JObject` | 1 |
| gacha_table | `clz_Torappu_GachaData_LinkageGachaTkt` | 4 |
| prts___levels | `hg__internal__MapData` | 3 |
| prts___levels | `clz_UnityEngine_Vector3` | 3 |
| prts___levels | `clz_UnityEngine_Vector2` | 2 |
| sandbox_perm_table | `clz_UnityEngine_Vector2` | 2 |
| special_operator_table | `clz_UnityEngine_Vector2` | 2 |

## 2. 本地独有表

| schema 文件 | 表名 | 本地字段数 |
| --- | --- | --- |
| audio_data | `dict__string__clz_Torappu_Audio_Middleware_Data_SoundFXVoiceLangData` | 2 |
| gacha_table | `clz_Torappu_GachaData_LinkageTenGachaTkt` | 3 |

## 3. 表内字段差异

按表字段（已剔除本地 `*AsNumpy` 历史合成字段）逐位置对齐后分类。

### 3.1 本地缺字段（FBS 有、本地解不出 → 数据静默丢失）

| schema 文件 | 表 | FBS 字段 | 本地字段 | 本地缺失字段（前 6） |
| --- | --- | --- | --- | --- |
| activity_table | `clz_Torappu_ActivityBossRushData_DisplayDetailRewards` | 5 | 4 | type, id, droptype |
| activity_table | `clz_Torappu_FifthAnnivExploreMissionData` | 20 | 1 | id, sortid, description, type, itembgtype, premissionids |
| buff_table | `clz_Torappu_BuffData` | 39 | 38 | remainingtimekey |
| sandbox_table | `clz_Torappu_SandboxBuildingItemData` | 3 | 2 | itemsubtype |
| sandbox_table | `clz_Torappu_SandboxDevelopmentData` | 13 | 13 | buffid, bufflimitedid, canbuffresearch, buffresearchdesc, buffname, bufficonid |

### 3.2 字段名差异（同槽位 1:1，FBO 布局不变）

成因两类：官方重构改名（如 `levelUpCostCond → specializeLevelUpData`），以及命名风格差异（FBS snake_case vs 本地 PascalCase、`def → def_` 之类的转义）。二者都不影响解码，但下游按名取值需对齐。

| schema 文件 | 表 | 字段名对照（FBS → 本地） |
| --- | --- | --- |
| activity_table | `clz_Torappu_ActivityTable_ActivityDetailTable` | default → defaultactivitydata; checkin_only → defaultcheckindata; checkin_all_player → allplayercheckindata; checkin_vs → versuscheckindata; type_act3d0 → typeact3d0data; type_act4d0 → typeact4d0data |
| activity_table | `clz_Torappu_ActivityTable_ActivityExtraData` | mainline_bp → typemainlinebpdata |
| char_master_table | `clz_Torappu_SimpleKVTable_clz_Torappu_CharacterData_MasterDataBundle` | master_data_bundles → masterdatabundles |
| char_patch_table | `clz_Torappu_CharPatchData_PatchInfo` | default → defaultpatch |
| char_patch_table | `clz_Torappu_CharacterData_MainSkill` | levelupcostcond → specializelevelupdata; unlockcond → initialunlockcond |
| char_patch_table | `clz_Torappu_AttributesDeltaData` | def → def_ |
| character_table | `clz_Torappu_CharacterData_MainSkill` | levelupcostcond → specializelevelupdata; unlockcond → initialunlockcond |
| character_table | `clz_Torappu_AttributesDeltaData` | def → def_ |
| enemy_database | `clz_Torappu_Undefinable_1_System_String_` | m_defined → mdefined; m_value → mvalue |
| enemy_database | `clz_Torappu_Undefinable_1_System_Int32_` | m_defined → mdefined; m_value → mvalue |
| enemy_database | `clz_Torappu_Undefinable_1_System_Single_` | m_defined → mdefined; m_value → mvalue |
| enemy_database | `clz_Torappu_Undefinable_1_System_Boolean_` | m_defined → mdefined; m_value → mvalue |
| enemy_database | `clz_Torappu_EnemyDatabase_AttributesData` | def → def_ |
| enemy_database | `clz_Torappu_Undefinable_1_Torappu_SourceApplyWay_` | m_defined → mdefined; m_value → mvalue |
| enemy_database | `clz_Torappu_Undefinable_1_Torappu_MotionMode_` | m_defined → mdefined; m_value → mvalue |
| enemy_database | `clz_Torappu_Undefinable_1_System_String___` | m_defined → mdefined; m_value → mvalue |
| enemy_database | `clz_Torappu_Undefinable_1_Torappu_EnemyLevelType_` | m_defined → mdefined; m_value → mvalue |
| ep_breakbuff_table | `clz_Torappu_SimpleKVTable_clz_Torappu_EPBreakBuffData` | ep_breakbuffs → epbreakbuffs |
| extra_battlelog_table | `clz_Torappu_SimpleKVTable_clz_Torappu_ExtraBattleLogData` | extra_battlelogs → extrabattlelogs |
| gacha_table | `clz_Torappu_GachaData` | linkagegachaitem → linkagetengachaitem |
| handbook_team_table | `clz_Torappu_SimpleKVTable_clz_Torappu_HandbookTeamData` | handbook_teams → handbookteams |
| legion_mode_buff_table | `clz_Torappu_SimpleKVTable_clz_Torappu_Battle_Legion_LegionModeBuffData` | legion_mode_buffs → legionmodebuffs |
| prts___levels | `clz_Torappu_Undefinable_1_System_String_` | m_defined → mdefined; m_value → mvalue |
| prts___levels | `clz_Torappu_Undefinable_1_System_Int32_` | m_defined → mdefined; m_value → mvalue |
| prts___levels | `clz_Torappu_Undefinable_1_System_Single_` | m_defined → mdefined; m_value → mvalue |
| prts___levels | `clz_Torappu_Undefinable_1_System_Boolean_` | m_defined → mdefined; m_value → mvalue |
| prts___levels | `clz_Torappu_EnemyDatabase_AttributesData` | def → def_ |
| prts___levels | `clz_Torappu_Undefinable_1_Torappu_SourceApplyWay_` | m_defined → mdefined; m_value → mvalue |
| prts___levels | `clz_Torappu_Undefinable_1_Torappu_MotionMode_` | m_defined → mdefined; m_value → mvalue |
| prts___levels | `clz_Torappu_Undefinable_1_System_String___` | m_defined → mdefined; m_value → mvalue |
| prts___levels | `clz_Torappu_Undefinable_1_Torappu_EnemyLevelType_` | m_defined → mdefined; m_value → mvalue |
| retro_table | `clz_Torappu_StageData` | extracondition → s_extracondition; extrainfo → s_extrainfo |
| retro_table | `clz_Torappu_ActivityCustomData` | type_act17side → typeact17sidedata; type_act25side → typeact25sidedata; type_act20side → typeact20sidedata; type_act21side → typeact21sidedata |
| roguelike_topic_table | `clz_Torappu_RoguelikeActivityTable` | seed_mode → seedmodedict |
| roguelike_topic_table | `clz_Torappu_RoguelikeTopicCustomizeData` | rogue_1 → rl01; rogue_2 → rl02; rogue_3 → rl03; rogue_4 → rl04; rogue_5 → rl05; rogue_6 → rl06 |
| sandbox_perm_table | `clz_Torappu_SandboxPermDetailData` | sandbox_v2 → sandboxv2templatedata; sandbox_v3 → sandboxv3templatedata |
| shop_client_table | `clz_Torappu_ShopClientData` | ls → limitedshopschedule; os → overlayschedule |
| stage_table | `clz_Torappu_StageData` | extracondition → s_extracondition; extrainfo → s_extrainfo |
| story_review_table | `clz_Torappu_SimpleKVTable_clz_Torappu_StoryReviewGroupClientData` | story_reviews → storyreviews |
| token_table | `clz_Torappu_CharacterData_MainSkill` | levelupcostcond → specializelevelupdata; unlockcond → initialunlockcond |
| token_table | `clz_Torappu_AttributesDeltaData` | def → def_ |

### 3.3 本地多出字段（CS 新增，本地已跟上）

| schema 文件 | 表 | FBS 字段 | 本地字段 | 本地多出（前 6） |
| --- | --- | --- | --- | --- |
| activity_table | `clz_Torappu_StageData_DisplayDetailRewards` | 4 | 5 | getpercent, cannotgetpercent, expectation, sumofcountweight |
| char_patch_table | `clz_Torappu_AttributesData` | 28 | 34 | epdamageresistance, epresistance, damagehitratephysical, damagehitratemagical, maxep, eprecoverypersec |
| character_table | `clz_Torappu_AttributesData` | 28 | 34 | epdamageresistance, epresistance, damagehitratephysical, damagehitratemagical, maxep, eprecoverypersec |
| item_table | `clz_Torappu_ItemData_StageDropInfo` | 3 | 4 | expectperap |
| prts___levels | `clz_Torappu_LevelData_Options` | 15 | 18 | enemytauntlevelpow, deploycostpostdelta, deploycostpostdeltamincost |
| prts___levels | `clz_Torappu_TileData` | 7 | 8 | advancedbuildablemask |
| prts___levels | `clz_Torappu_AttributesData` | 28 | 34 | epdamageresistance, epresistance, damagehitratephysical, damagehitratemagical, maxep, eprecoverypersec |
| prts___levels | `clz_Torappu_LevelData_WaveData_FragmentData_ActionData` | 19 | 24 | useextraroute, isvalid, notcountintotal, extrameta, actionid |
| prts___levels | `clz_Torappu_CharacterInst_Metadata` | 5 | 6 | favorbattlephase, playerinstid |
| sandbox_table | `clz_Torappu_SandboxDevelopmentLineSegmentData` | 6 | 8 | linestyle, unlockbasementlevel |
| sandbox_table | `clz_Torappu_RuneData_Selector` | 10 | 18 | playersidemask, sidetype, charidexcludefilter, enemyleveltypefilter, enemyactionhiddengroupfilter, filtertagexcludefilter |
| shop_client_table | `clz_Torappu_ShopRecommendData` | 6 | 7 | islocked |
| story_table | `clz_Torappu_StoryData` | 10 | 11 | forceomitcommit |
| token_table | `clz_Torappu_AttributesData` | 28 | 34 | epdamageresistance, epresistance, damagehitratephysical, damagehitratemagical, maxep, eprecoverypersec |

### 3.4 字段序不一致（同名字段换位，会解码错位）

（无）

## 4. 类型宽度不一致

| 表 | 字段（FBS→本地） |
| --- | --- |
| `clz_Torappu_RuneData_Selector` | playersidemask: 8→32 |
| `clz_Torappu_Audio_Middleware_Data_TorappuAudioData` | soundfxvoicelang: vec(map(str,vec(map(str,vec(map(32,str))))))→vec(map(str,ref:clz_Torappu_Audio_Middleware_Data_SoundFXVoiceLangData)) |
| `clz_Torappu_BuildingData_ObstaclePoint` | edgewalkablemask: 8→32 |
| `clz_Torappu_RuneData_Selector` | playersidemask: 8→32 |
| `clz_Torappu_RuneData_Selector` | playersidemask: 8→32 |
| `clz_Torappu_RuneData_Selector` | playersidemask: 8→32 |
| `clz_Torappu_GachaPoolClientData` | dynmeta: ref:hg__internal__JObject→ref:clz_Newtonsoft_Json_Linq_JObject; linkageparam: ref:hg__internal__JObject→ref:clz_Newtonsoft_Json_Linq_JObject; limitparam: ref:hg__internal__JObject→ref:clz_Newtonsoft_Json_Linq_JObject |
| `clz_Torappu_LevelData_GlobalBuffData` | playersidemask: 8→32 |
| `clz_Torappu_RuneData_Selector` | playersidemask: 8→32 |
| `clz_Torappu_RuneData_Selector` | playersidemask: 8→32 |

## 5. 悬空引用

### 5.1 本地（字段类型指向本文件未定义的表）

| schema 文件 | 所在表 | 字段 | 缺失表 |
| --- | --- | --- | --- |
| activity_table | `clz_Torappu_Act1VHalfIdleDiagramData_PointPosData` | Pos | `clz_UnityEngine_Vector2` |
| activity_table | `clz_Torappu_Act1VHalfIdleDiagramData_LinePosData` | StartPos | `clz_UnityEngine_Vector2` |
| activity_table | `clz_Torappu_Act1VHalfIdleDiagramData_LinePosData` | EndPos | `clz_UnityEngine_Vector2` |
| activity_table | `clz_Torappu_ArkventRangeData` | Position | `clz_UnityEngine_Vector3` |
| activity_table | `clz_Torappu_ArkventRangeData` | Bounds | `clz_UnityEngine_Vector3` |
| activity_table | `clz_Torappu_ActArkHubInteractiveUnitData` | Position | `clz_UnityEngine_Vector3` |
| activity_table | `clz_Torappu_ActArkHubInteractiveUnitData` | SafePos | `clz_UnityEngine_Vector3` |
| arkvent_table | `clz_Torappu_ArkventRangeData` | Position | `clz_UnityEngine_Vector3` |
| arkvent_table | `clz_Torappu_ArkventRangeData` | Bounds | `clz_UnityEngine_Vector3` |
| arkvent_table | `clz_Torappu_ArkventTaskActorData` | ActorPosition | `clz_UnityEngine_Vector3` |
| arkvent_table | `clz_Torappu_ArkventTaskActorData` | SafePos | `clz_UnityEngine_Vector3` |
| arkvent_table | `clz_Torappu_ArkventCameraPlatformConfig` | TrackedObjectOffset | `clz_UnityEngine_Vector3` |
| arkvent_table | `clz_Torappu_ArkventSceneData` | SpawnPos | `clz_UnityEngine_Vector3` |
| campaign_table | `clz_Torappu_CampaignStageMapData` | Position | `clz_UnityEngine_Vector2` |
| display_meta_table | `clz_Torappu_MagazineLeafItemData` | SkinDefaultPos | `clz_UnityEngine_Vector2` |
| display_meta_table | `clz_Torappu_MagazineLeafDecorTypeData` | TemplateUseCardPosBias | `clz_UnityEngine_Vector2` |
| gacha_table | `clz_Torappu_GachaPoolClientData` | DynMeta | `clz_Newtonsoft_Json_Linq_JObject` |
| gacha_table | `clz_Torappu_GachaPoolClientData` | LinkageParam | `clz_Newtonsoft_Json_Linq_JObject` |
| gacha_table | `clz_Torappu_GachaPoolClientData` | LimitParam | `clz_Newtonsoft_Json_Linq_JObject` |
| prts___levels | `clz_Torappu_MapEffectData` | Offset | `clz_UnityEngine_Vector3` |
| prts___levels | `clz_Torappu_MapData` | Map | `hg__internal__MapData` |
| prts___levels | `clz_Torappu_RouteData_CheckpointData` | ReachOffset | `clz_UnityEngine_Vector2` |
| prts___levels | `clz_Torappu_RouteData` | SpawnRandomRange | `clz_UnityEngine_Vector2` |
| prts___levels | `clz_Torappu_RouteData` | SpawnOffset | `clz_UnityEngine_Vector2` |
| prts___levels | `clz_Torappu_LevelData_WaveData_FragmentData_ActionData` | ExtraMeta | `clz_System_Object` |
| prts___levels | `clz_Torappu_LevelData_WaveData_FragmentData_ActionData` | ActionId | `clz_Torappu_LevelData_ActionID` |
| sandbox_perm_table | `clz_Torappu_SandboxV2MapZoneData` | Center | `clz_UnityEngine_Vector2` |
| sandbox_perm_table | `clz_Torappu_SandboxV2MapZoneData` | Vertices | `clz_UnityEngine_Vector2` |
| sandbox_perm_table | `clz_Torappu_SandboxV2MapConfig` | CameraBoundMin | `clz_UnityEngine_Vector2` |
| sandbox_perm_table | `clz_Torappu_SandboxV2MapConfig` | CameraBoundMax | `clz_UnityEngine_Vector2` |
| special_operator_table | `clz_Torappu_SpecialOperatorPointPosData` | Pos | `clz_UnityEngine_Vector2` |
| special_operator_table | `clz_Torappu_SpecialOperatorLinePosData` | StartPos | `clz_UnityEngine_Vector2` |
| special_operator_table | `clz_Torappu_SpecialOperatorLinePosData` | EndPos | `clz_UnityEngine_Vector2` |

### 5.2 FBS 侧

（无，FBS 自洽）

### 5.3 本地未解析类型 token（`unknown`）

`cs2schema.ts` 无法映射的泛型实例化会写成字面量 `unknown`，`fbo.ts#readFieldValue` 对它返回 `null`。

| schema 文件 | 所在表 | 字段 | 类型 token |
| --- | --- | --- | --- |
| activity_table | `clz_Torappu_ActivityEnemyDuelData` | BasicScoresAsNumpy | `unknown` |
| activity_table | `dict__string__list_int` | ValueAsNumpy | `unknown` |
| activity_table | `clz_Torappu_Act1VHalfIdleConstData` | DiscountAsNumpy | `unknown` |
| activity_table | `clz_Torappu_Act1VHalfIdleConstData` | SkillLevelsAsNumpy | `unknown` |
| activity_table | `dict__string__list_long` | ValueAsNumpy | `unknown` |
| activity_table | `clz_Torappu_CartComponents` | PosListAsNumpy | `unknown` |
| bake_muzzle_data | `clz_Torappu_Battle_BakedMountPointData` | TrsDataAsNumpy | `unknown` |
| bake_muzzle_data | `clz_Torappu_Battle_BakedEventTimeline` | EventTimeAsNumpy | `unknown` |
| battle_equip_table | `clz_Torappu_EquipTalentData` | ValidModeIndicesAsNumpy | `unknown` |
| buff_table | `clz_Torappu_AttributeModifierData` | AbnormalFlagsAsNumpy | `unknown` |
| buff_table | `clz_Torappu_AttributeModifierData` | AbnormalImmunesAsNumpy | `unknown` |
| buff_table | `clz_Torappu_AttributeModifierData` | AbnormalAntisAsNumpy | `unknown` |
| buff_table | `clz_Torappu_AttributeModifierData` | AbnormalCombosAsNumpy | `unknown` |
| buff_table | `clz_Torappu_AttributeModifierData` | AbnormalComboImmunesAsNumpy | `unknown` |
| building_data | `clz_Torappu_BuildingData_WorkshopRarityInfo` | RarityListAsNumpy | `unknown` |
| building_data | `clz_Torappu_BuildingData` | ManufactManpowerCostByNumAsNumpy | `unknown` |
| building_data | `clz_Torappu_BuildingData` | TradingManpowerCostByNumAsNumpy | `unknown` |
| building_data | `clz_Torappu_BuildingData` | PrivateFavorLevelThresholdsAsNumpy | `unknown` |
| building_data | `clz_Torappu_BuildingData` | AssistantUnlockAsNumpy | `unknown` |
| char_patch_table | `clz_Torappu_AttributeModifierData` | AbnormalFlagsAsNumpy | `unknown` |
| char_patch_table | `clz_Torappu_AttributeModifierData` | AbnormalImmunesAsNumpy | `unknown` |
| char_patch_table | `clz_Torappu_AttributeModifierData` | AbnormalAntisAsNumpy | `unknown` |
| char_patch_table | `clz_Torappu_AttributeModifierData` | AbnormalCombosAsNumpy | `unknown` |
| char_patch_table | `clz_Torappu_AttributeModifierData` | AbnormalComboImmunesAsNumpy | `unknown` |
| character_table | `clz_Torappu_AttributeModifierData` | AbnormalFlagsAsNumpy | `unknown` |
| character_table | `clz_Torappu_AttributeModifierData` | AbnormalImmunesAsNumpy | `unknown` |
| character_table | `clz_Torappu_AttributeModifierData` | AbnormalAntisAsNumpy | `unknown` |
| character_table | `clz_Torappu_AttributeModifierData` | AbnormalCombosAsNumpy | `unknown` |
| character_table | `clz_Torappu_AttributeModifierData` | AbnormalComboImmunesAsNumpy | `unknown` |
| charword_table | `clz_Torappu_VoiceLangGroupData` | MembersAsNumpy | `unknown` |
| charword_table | `clz_Torappu_ExtraVoiceConfigData` | ValidVoiceLangAsNumpy | `unknown` |
| charword_table | `clz_Torappu_CharWordTable` | DisplayGroupTypeListAsNumpy | `unknown` |
| charword_table | `clz_Torappu_CharWordTable` | DisplayTypeListAsNumpy | `unknown` |
| climb_tower_table | `clz_Torappu_MissionGroup` | PeriodAsNumpy | `unknown` |
| display_meta_table | `clz_Torappu_EmoticonData_EmoticonThemeTypeData` | PicSceneListAsNumpy | `unknown` |
| display_meta_table | `clz_Torappu_KeyItem` | KeyCodesAsNumpy | `unknown` |
| display_meta_table | `clz_Torappu_KeySettingGroupData` | RelatedActTypesAsNumpy | `unknown` |
| display_meta_table | `clz_Torappu_ArtMagazineLeafElementData` | PosAsNumpy | `unknown` |
| enemy_handbook_table | `clz_Torappu_EnemyHandBookData` | DamageTypeAsNumpy | `unknown` |
| gacha_table | `dict__int__list_int` | ValueAsNumpy | `unknown` |
| gamedata_const | `clz_Torappu_GameDataConsts` | PlayerExpMapAsNumpy | `unknown` |
| gamedata_const | `clz_Torappu_GameDataConsts` | PlayerApMapAsNumpy | `unknown` |
| gamedata_const | `clz_Torappu_GameDataConsts` | InitRecruitTagListAsNumpy | `unknown` |
| gamedata_const | `clz_Torappu_GameDataConsts` | FriendAssistRarityLimitAsNumpy | `unknown` |
| gamedata_const | `clz_Torappu_GameDataConsts` | PushForcesAsNumpy | `unknown` |
| gamedata_const | `clz_Torappu_GameDataConsts` | NormalGachaUnlockPriceAsNumpy | `unknown` |
| gamedata_const | `clz_Torappu_GameDataConsts` | PullForcesAsNumpy | `unknown` |
| mission_table | `clz_Torappu_MissionGroup` | PeriodAsNumpy | `unknown` |
| mission_table | `clz_Torappu_DailyMissionGroupInfo_periodInfo` | PeriodAsNumpy | `unknown` |
| open_server_table | `clz_Torappu_MissionGroup` | PeriodAsNumpy | `unknown` |
| resource_manifest | `clz_Torappu_Resource_ResourceManifest_BundleMeta` | AllDependenciesAsNumpy | `unknown` |
| roguelike_topic_table | `clz_Torappu_RoguelikeTopicBasicData` | ModuleTypesAsNumpy | `unknown` |
| roguelike_topic_table | `clz_Torappu_RoguelikeGameStageData` | VutresProbAsNumpy | `unknown` |
| roguelike_topic_table | `clz_Torappu_RoguelikeGameStageData` | BoxProbAsNumpy | `unknown` |
| roguelike_topic_table | `clz_Torappu_RoguelikeGameRecruitTicketData` | ProfessionListAsNumpy | `unknown` |
| roguelike_topic_table | `clz_Torappu_RoguelikeGameRecruitTicketData` | RarityListAsNumpy | `unknown` |
| roguelike_topic_table | `clz_Torappu_RoguelikeGameRecruitTicketData` | ExtraFreeRarityAsNumpy | `unknown` |
| roguelike_topic_table | `clz_Torappu_RoguelikeGameUpgradeTicketData` | ProfessionListAsNumpy | `unknown` |
| roguelike_topic_table | `clz_Torappu_RoguelikeGameUpgradeTicketData` | RarityListAsNumpy | `unknown` |
| roguelike_topic_table | `clz_Torappu_RoguelikeGameRelicParamData` | CheckCharBoxTypesAsNumpy | `unknown` |
| roguelike_topic_table | `clz_Torappu_RoguelikeGameConst` | OnceNodeTypeListAsNumpy | `unknown` |
| roguelike_topic_table | `clz_Torappu_RoguelikeTotemLinkedNodeTypeData` | EffectiveNodeTypesAsNumpy | `unknown` |
| roguelike_topic_table | `clz_Torappu_RoguelikeTotemLinkedNodeTypeData` | BlurNodeTypesAsNumpy | `unknown` |
| roguelike_topic_table | `clz_Torappu_RoguelikeAlchemyData` | FragmentTypeListAsNumpy | `unknown` |
| roguelike_topic_table | `clz_Torappu_RoguelikeCopperModuleConsts` | CopperDrawFreezeCostCountAsNumpy | `unknown` |
| roguelike_topic_table | `clz_Torappu_RoguelikeModule` | ModuleTypesAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxFoodData` | AttributesAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV2GameConst` | SeasonTransitionLoopAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV2GameConst` | SeasonDurationLoopAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV2GameConst` | SeasonTransitionAngleLoopAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV2NpcData` | NpcLocationAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV2ExpeditionData` | ProfessionsAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV2TutorialRepoCharData` | SpecSkillListAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV2RacerBasicInfo` | AttributeMaxValueAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV2RacingConstData` | RacerMaxValueAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV2RacingConstData` | CollisionForceSectorAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV2RacingConstData` | CollisionForceLevelAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV2RacingConstData` | CollisionSpeedLossAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV2RacingConstData` | CollisionHpLossAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV2RacingConstData` | TileCollisionSpeedLossAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV2RacingConstData` | TileCollisionHpLossAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV2RacingConstData` | AutoUseItemTimeRangeAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV2Data` | ShopUpdateTimeDataAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV3StageData` | DayTargetValuesAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV3StoryStageData` | InitialSubStageIndexListAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV3NpcData` | NpcLocationAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV3TaskData` | IntParamsAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV3GameConst` | DayPassRecruitRefreshCountAsNumpy | `unknown` |
| sandbox_perm_table | `clz_Torappu_SandboxV3Data` | ShopUpdateTimeDataAsNumpy | `unknown` |
| sandbox_table | `clz_Torappu_SandboxMissionData` | ProfessionIdsAsNumpy | `unknown` |
| sandbox_table | `clz_Torappu_SandboxItemData` | RecommendTypeListAsNumpy | `unknown` |
| shop_client_table | `clz_Torappu_ShopRecommendGroup` | RecommendGroupAsNumpy | `unknown` |
| special_operator_table | `clz_Torappu_MissionGroup` | PeriodAsNumpy | `unknown` |
| token_table | `clz_Torappu_AttributeModifierData` | AbnormalFlagsAsNumpy | `unknown` |
| token_table | `clz_Torappu_AttributeModifierData` | AbnormalImmunesAsNumpy | `unknown` |
| token_table | `clz_Torappu_AttributeModifierData` | AbnormalAntisAsNumpy | `unknown` |
| token_table | `clz_Torappu_AttributeModifierData` | AbnormalCombosAsNumpy | `unknown` |
| token_table | `clz_Torappu_AttributeModifierData` | AbnormalComboImmunesAsNumpy | `unknown` |
| zone_table | `clz_Torappu_WeeklyZoneData` | DaysOfWeekAsNumpy | `unknown` |
| zone_table | `clz_Torappu_MainlineZoneData` | DiffGroupAsNumpy | `unknown` |

## 6. 其它

### 非 int 基类型枚举（本地 `enum` 按 i32 读取，存在读宽不匹配）

| 文件 | 枚举 | 基类型 |
| --- | --- | --- |
| activity_table | `enum__Torappu_PlayerSideMask` | ubyte |
| buff_table | `enum__Torappu_BuffData_StatusResistable` | ubyte |
| buff_table | `enum__Torappu_LifeType` | ubyte |
| charm_table | `enum__Torappu_PlayerSideMask` | ubyte |
| climb_tower_table | `enum__Torappu_PlayerSideMask` | ubyte |
| crisis_v2_table | `enum__Torappu_PlayerSideMask` | ubyte |
| prts___levels | `enum__Torappu_PlayerSideMask` | ubyte |
| retro_table | `enum__Torappu_PlayerSideMask` | ubyte |
| sandbox_perm_table | `enum__Torappu_PlayerSideMask` | ubyte |
