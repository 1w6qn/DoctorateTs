import { describe, it, expect } from 'vitest';
import type {
  PlayerCharacter,
  PlayerCharPatch,
  PlayerCharSkill,
  PlayerCharEquipInfo,
  SharedCharData,
  TmplData,
  SharedCharSkillData,
  CharEquipInfo,
  PlayerTroop,
  PlayerSquad,
  PlayerSquadItem,
  PlayerFriendAssist,
  FriendCommonData,
  AvatarInfo,
  OrigChar,
  SquadFriendData,
  PlayerHandBookAddon,
} from '@game/kernel/model';
import type { PlayerCharRotationPreset } from '@game/kernel/playerdata';
import { asModel } from '../../helpers/mockPlayerData';

/**
 * 头像信息夹具视图
 *
 * `AvatarInfo.type` 真实为枚举 `PlayerAvatarType`（`NONE`/`ASSISTANT`/`ICON`/`DEFAULT`），
 * 本文件的用例沿用早期自由字符串（`'frame'`/`'t'`/`'avatar_type_01'`…，仅形状冒烟）。
 * 为不改夹具数据，仅就地放宽 `type`；其余字段仍受真实模型约束。
 */
type AvatarInfoFixture = Omit<AvatarInfo, 'type'> & { type: string };

/** 好友通用数据夹具视图：仅 `avatar` 放宽（见 {@link AvatarInfoFixture}） */
type FriendCommonDataFixture = Omit<FriendCommonData, 'avatar'> & { avatar: AvatarInfoFixture };

/** 原始干员夹具视图：仅 `avatar` 放宽（见 {@link AvatarInfoFixture}） */
type OrigCharFixture = Omit<OrigChar, 'avatar'> & { avatar: AvatarInfoFixture };

/** 好友小队数据夹具视图：仅 `avatar` 放宽（见 {@link AvatarInfoFixture}） */
type SquadFriendDataFixture = Omit<SquadFriendData, 'avatar'> & { avatar: AvatarInfoFixture };

/**
 * 编队夹具视图
 *
 * `PlayerSquad.slots` 真值为 `PlayerSquadItem[]`（条目 `tmpl` 必填），本文件用例沿用
 * 「空位 null + 缺 tmpl」的早期夹具（仅形状冒烟）。为不改夹具数据，仅就地放宽 `slots`。
 */
type PlayerSquadFixture = Omit<PlayerSquad, 'slots'> & {
  slots: (Omit<PlayerSquadItem, 'tmpl'> | null)[];
};

/** 干员夹具视图：`equip` 真实为装备字典，用例沿用 `null` 表示「无装备补丁」 */
type PlayerCharacterFixture = Omit<PlayerCharacter, 'equip'> & { equip: PlayerCharacter['equip'] | null };

/** 玩家队伍夹具视图：`squads` 条目沿用 {@link PlayerSquadFixture} 的早期编队夹具 */
type PlayerTroopFixture = Omit<PlayerTroop, 'squads'> & { squads: { [key: string]: PlayerSquadFixture } };

describe('Character 模型', () => {
  describe('PlayerCharacter', () => {
    it('应该包含所有必需的基础属性', () => {
      const char: PlayerCharacter = asModel<PlayerCharacter>({
        instId: 1001,
        charId: 'char_001',
        level: 50,
        exp: 1200,
        evolvePhase: 2,
        potentialRank: 4,
        favorPoint: 50,
        mainSkillLvl: 7,
        gainTime: 1700000000,
        voiceLan: 'zh_cn',
      });

      expect(char.instId).toBe(1001);
      expect(char.charId).toBe('char_001');
      expect(char.level).toBe(50);
      expect(char.exp).toBe(1200);
      expect(char.evolvePhase).toBe(2);
      expect(char.potentialRank).toBe(4);
      expect(char.favorPoint).toBe(50);
      expect(char.mainSkillLvl).toBe(7);
      expect(char.gainTime).toBe(1700000000);
      expect(char.voiceLan).toBe('zh_cn');
    });

    it('应该正确处理可选属性', () => {
      const char: PlayerCharacterFixture = asModel<PlayerCharacterFixture>({
        instId: 1001,
        charId: 'char_001',
        level: 50,
        exp: 1200,
        evolvePhase: 2,
        potentialRank: 4,
        favorPoint: 50,
        mainSkillLvl: 7,
        gainTime: 1700000000,
        voiceLan: 'zh_cn',
        starMark: 6,
        currentTmpl: 'tmpl_01',
        tmpl: {
          tmpl_01: {
            skinId: 'skin_001',
            defaultSkillIndex: 0,
            skills: [],
            currentEquip: '',
            equip: {},
          },
        },
        skin: 'skin_001',
        defaultSkillIndex: 0,
        skills: [
          {
            unlock: 1,
            skillId: 'skill_001',
            state: 2,
            specializeLevel: 3,
            completeUpgradeTime: 1700000000,
          },
        ],
        currentEquip: null,
        equip: null,
      });

      expect(char.starMark).toBe(6);
      expect(char.currentTmpl).toBe('tmpl_01');
      expect(char.tmpl).toBeDefined();
      expect(char.tmpl!['tmpl_01'].skinId).toBe('skin_001');
      expect(char.skills).toHaveLength(1);
      expect(char.skills![0].specializeLevel).toBe(3);
    });

    it('应该正确表示干员精英化阶段 evolvePhase', () => {
      const e0: PlayerCharacter = asModel<PlayerCharacter>({
        instId: 1, charId: 'c1', level: 1, exp: 0,
        evolvePhase: 0, potentialRank: 0, favorPoint: 0,
        mainSkillLvl: 1, gainTime: 0, voiceLan: 'zh_cn',
      });
      const e1: PlayerCharacter = {
        ...e0, instId: 2, evolvePhase: 1, level: 30,
      };
      const e2: PlayerCharacter = {
        ...e0, instId: 3, evolvePhase: 2, level: 50,
      };

      expect(e0.evolvePhase).toBe(0);
      expect(e1.evolvePhase).toBe(1);
      expect(e2.evolvePhase).toBe(2);
    });

    it('应该正确表示技能等级 mainSkillLvl 和专精 specializeLevel', () => {
      const skill: PlayerCharSkill = {
        unlock: 1,
        skillId: 'skill_001',
        state: 2,
        specializeLevel: 3,
        completeUpgradeTime: 1700000000,
      };

      expect(skill.skillId).toBe('skill_001');
      expect(skill.state).toBe(2);
      expect(skill.specializeLevel).toBe(3);
      expect(skill.unlock).toBe(1);
    });

    it('PlayerCharPatch 应该包含模板补丁信息', () => {
      const patch: PlayerCharPatch = {
        skinId: 'skin_002',
        defaultSkillIndex: 1,
        skills: [
          {
            unlock: 1,
            skillId: 'skill_002',
            state: 0,
            specializeLevel: 1,
            completeUpgradeTime: 0,
          },
        ],
        currentEquip: 'equip_001',
        equip: {
          equip_001: { locked: 0, level: 5, hide: 0 },
        },
      };

      expect(patch.skinId).toBe('skin_002');
      expect(patch.defaultSkillIndex).toBe(1);
      expect(patch.skills).toHaveLength(1);
      expect(patch.equip['equip_001'].level).toBe(5);
    });
  });

  describe('PlayerCharEquipInfo', () => {
    it('装备信息应包含 locked/level/hide 属性', () => {
      const equip: PlayerCharEquipInfo = {
        locked: 0,
        level: 10,
        hide: 0,
      };

      expect(equip.locked).toBe(0);
      expect(equip.level).toBe(10);
      expect(equip.hide).toBe(0);
    });

    it('锁定状态应正确反映', () => {
      const locked: PlayerCharEquipInfo = { locked: 1, level: 0, hide: 0 };
      expect(locked.locked).toBe(1);

      const unlocked: PlayerCharEquipInfo = { locked: 0, level: 5, hide: 1 };
      expect(unlocked.hide).toBe(1);
    });
  });

  describe('SharedCharData', () => {
    it('共享角色数据应包含所有关键字段', () => {
      const shared: SharedCharData = {
        charId: 'char_shared_01',
        potentialRank: 5,
        mainSkillLvl: 8,
        evolvePhase: 2,
        level: 60,
        favorPoint: 100,
        crisisRecord: { stage_01: 3 },
        crisisV2Record: { season_1: 5 },
      };

      expect(shared.charId).toBe('char_shared_01');
      expect(shared.potentialRank).toBe(5);
      expect(shared.crisisRecord).toEqual({ stage_01: 3 });
      expect(shared.crisisV2Record).toEqual({ season_1: 5 });
    });

    it('共享角色数据应支持模板可选字段', () => {
      const shared: SharedCharData = {
        charId: 'char_shared_02',
        potentialRank: 2,
        mainSkillLvl: 4,
        evolvePhase: 1,
        level: 30,
        favorPoint: 20,
        crisisRecord: {},
        crisisV2Record: {},
        currentTmpl: 'tmpl_a',
        tmpl: {
          tmpl_a: {
            skillIndex: 0,
            skinId: 'skin_a',
            skills: [],
            selectEquip: '',
            equips: {},
          },
        },
      };

      expect(shared.currentTmpl).toBe('tmpl_a');
      expect(shared.tmpl).toBeDefined();
      expect(shared.tmpl!['tmpl_a'].skillIndex).toBe(0);
    });
  });

  describe('PlayerTroop', () => {
    it('玩家队伍应包含干员、小队和群组', () => {
      const troop: PlayerTroopFixture = asModel<PlayerTroopFixture>({
        curCharInstId: 1001,
        curSquadCount: 2,
        squads: {
          squad_1: {
            squadId: 'squad_1',
            name: 'Alpha',
            slots: [
              { charInstId: 1001, skillIndex: 0, currentEquip: null },
              null,
            ],
          },
        },
        chars: {
          '1001': {
            instId: 1001,
            charId: 'char_001',
            level: 50,
            exp: 0,
            evolvePhase: 2,
            potentialRank: 4,
            favorPoint: 50,
            mainSkillLvl: 7,
            gainTime: 0,
            voiceLan: 'zh_cn',
          },
        },
        addon: {
          book_001: {
            stage: { 'stage_01': { fts: 100, rts: 200 } },
          },
        },
        charGroup: {
          group_1: { favorPoint: 30 },
        },
        charMission: {
          mission_001: { stage_01: 1 },
        },
      });

      expect(troop.curCharInstId).toBe(1001);
      expect(troop.chars['1001'].charId).toBe('char_001');
      expect(troop.squads['squad_1'].name).toBe('Alpha');
      expect(troop.addon.book_001.stage!['stage_01'].fts).toBe(100);
      expect(troop.charGroup.group_1.favorPoint).toBe(30);
    });

    it('小队 slots 应该支持 null 空位', () => {
      const squad: PlayerSquadFixture = asModel<PlayerSquadFixture>({
        squadId: 'squad_test',
        name: 'Test Squad',
        slots: [
          { charInstId: 1, skillIndex: 0, currentEquip: null },
          null,
          { charInstId: 2, skillIndex: 1, currentEquip: 'equip_01' },
          null,
          null,
        ],
      });

      expect(squad.slots).toHaveLength(5);
      expect(squad.slots[0]).not.toBeNull();
      expect(squad.slots[1]).toBeNull();
      expect(squad.slots[2]!.currentEquip).toBe('equip_01');
    });
  });

  describe('PlayerSquadItem', () => {
    it('应包含干员实例ID、技能索引和装备信息', () => {
      const item: PlayerSquadItem = asModel<PlayerSquadItem>({
        charInstId: 1001,
        skillIndex: 2,
        currentEquip: 'equip_weapon_01',
        currentTmpl: 'tmpl_skin_01',
      });

      expect(item.charInstId).toBe(1001);
      expect(item.skillIndex).toBe(2);
      expect(item.currentEquip).toBe('equip_weapon_01');
      expect(item.currentTmpl).toBe('tmpl_skin_01');
    });

    it('currentEquip 可以为 null', () => {
      const item: PlayerSquadItem = asModel<PlayerSquadItem>({
        charInstId: 1002,
        skillIndex: 0,
        currentEquip: null,
      });

      expect(item.currentEquip).toBeNull();
      expect(item.currentTmpl).toBeUndefined();
    });
  });

  describe('PlayerFriendAssist (类型别名)', () => {
    it('应该与 PlayerSquadItem 结构相同', () => {
      const assist: PlayerFriendAssist = asModel<PlayerFriendAssist>({
        charInstId: 2001,
        skillIndex: 1,
        currentEquip: null,
      });

      expect(assist.charInstId).toBe(2001);
      expect(assist.skillIndex).toBe(1);
    });
  });

  describe('FriendCommonData', () => {
    it('好友通用数据应包含社交属性', () => {
      const friend: FriendCommonDataFixture = {
        nickName: 'TestFriend',
        uid: 'user_001',
        serverName: 'Server CN',
        nickNumber: '0001',
        level: 120,
        lastOnlineTime: new Date('2025-01-01T12:00:00Z'),
        recentVisited: true,
        avatar: { type: 'avatar_type_01', id: 'avatar_001' },
      };

      expect(friend.nickName).toBe('TestFriend');
      expect(friend.level).toBe(120);
      expect(friend.lastOnlineTime).toBeInstanceOf(Date);
      expect(friend.avatar.id).toBe('avatar_001');
    });
  });

  describe('AvatarInfo', () => {
    it('头像信息应包含 type 和 id', () => {
      const avatar: AvatarInfoFixture = { type: 'frame', id: 'frame_gold' };
      expect(avatar.type).toBe('frame');
      expect(avatar.id).toBe('frame_gold');
    });
  });

  describe('OrigChar', () => {
    it('原始干员应继承好友数据并包含协助信息', () => {
      const orig: OrigCharFixture = {
        nickName: 'Player',
        uid: 'me',
        serverName: 'CN',
        nickNumber: '0000',
        level: 100,
        lastOnlineTime: new Date(),
        recentVisited: false,
        avatar: { type: 'type', id: 'id_1' },
        assistSlotIndex: 0,
        aliasName: 'My Alt',
        assistCharList: [
          {
            charId: 'char_001',
            potentialRank: 4,
            mainSkillLvl: 7,
            evolvePhase: 2,
            level: 50,
            favorPoint: 50,
            crisisRecord: {},
            crisisV2Record: {},
          },
        ],
        isFriend: false,
        canRequestFriend: false,
      };

      expect(orig.assistSlotIndex).toBe(0);
      expect(orig.assistCharList).toHaveLength(1);
      expect(orig.assistCharList[0].charId).toBe('char_001');
    });
  });

  describe('SquadFriendData', () => {
    it('好友小队数据应包含协助干员列表', () => {
      const data: SquadFriendDataFixture = {
        nickName: 'FriendPlayer',
        uid: 'friend_001',
        serverName: 'US',
        nickNumber: '0123',
        level: 85,
        lastOnlineTime: new Date(),
        recentVisited: true,
        avatar: { type: 't', id: 'id' },
        assistChar: [
          {
            charId: 'char_friend_01',
            potentialRank: 5,
            mainSkillLvl: 9,
            evolvePhase: 2,
            level: 90,
            favorPoint: 200,
            crisisRecord: {},
            crisisV2Record: {},
          },
        ],
        assistSlotIndex: 2,
      };

      expect(data.assistSlotIndex).toBe(2);
      expect(data.assistChar[0].level).toBe(90);
    });
  });

  describe('PlayerHandBookAddon', () => {
    it('档案加成数据应包含 stage 和 story 记录', () => {
      const addon: PlayerHandBookAddon = asModel<PlayerHandBookAddon>({
        stage: {
          stage_001: { fts: 1000, rts: 2000 },
        },
        story: {
          story_001: { fts: 3000, rts: 4000 },
        },
      });

      expect(addon.stage!['stage_001'].fts).toBe(1000);
      expect(addon.story!['story_001'].rts).toBe(4000);
    });

    it('档案加成数据可以为空对象', () => {
      const addon: PlayerHandBookAddon = asModel<PlayerHandBookAddon>({});
      expect(addon.stage).toBeUndefined();
      expect(addon.story).toBeUndefined();
    });
  });

  describe('TmplData', () => {
    it('模板数据应包含技能索引、皮肤、装备等', () => {
      const tmpl: TmplData = {
        skillIndex: 2,
        skinId: 'skin_003',
        skills: [
          { skillId: 'skill_s1', specializeLevel: 3 },
        ],
        selectEquip: 'equip_sel_01',
        equips: {
          equip_key: { locked: false, level: 10 },
        },
      };

      expect(tmpl.skillIndex).toBe(2);
      expect(tmpl.equips['equip_key'].level).toBe(10);
      expect(tmpl.skills[0].specializeLevel).toBe(3);
    });
  });

  describe('PlayerCharRotationPreset', () => {
    it('干员轮换预设应包含完整配置', () => {
      const preset: PlayerCharRotationPreset = asModel<PlayerCharRotationPreset>({
        name: 'Season 1',
        background: 'bg_001',
        homeTheme: 'theme_classic',
        profile: 'profile_img',
        profileInst: 1001,
        slots: [
          { charId: 'char_001', skinId: 'skin_001' },
          { charId: 'char_002', skinId: 'skin_002' },
        ],
      });

      expect(preset.name).toBe('Season 1');
      expect(preset.slots).toHaveLength(2);
      expect(preset.slots[0].charId).toBe('char_001');
    });
  });
});