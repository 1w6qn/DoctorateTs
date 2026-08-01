import { describe, it, expect } from 'vitest';
import { encryptBattleData, decryptBattleData, encryptIsCheat, decryptIsCheat, decryptBattleReplay } from '@utils/crypt';
import JSZip from 'jszip';

describe('encryptBattleData / decryptBattleData', () => {
  it('加密后应该能正确解密（往返测试）', async () => {
    const originalData = { result: 'success', level: 10, score: 9500 };
    const loginTime = 1700000000;
    const encrypted = await encryptBattleData(originalData, loginTime);
    const decrypted = await decryptBattleData(encrypted, loginTime);
    expect(decrypted).toEqual(originalData);
  });

  it('不同的登录时间应该产生不同的加密结果', async () => {
    const data = { test: 'value' };
    const encrypted1 = await encryptBattleData(data, 1000);
    const encrypted2 = await encryptBattleData(data, 2000);
    expect(encrypted1).not.toBe(encrypted2);
  });

  it('使用错误的登录时间解密应该失败', async () => {
    const data = { test: 'value' };
    const encrypted = await encryptBattleData(data, 1000);
    await expect(decryptBattleData(encrypted, 9999)).rejects.toThrow();
  });

  it('应该能处理复杂的嵌套对象', async () => {
    const originalData = {
      player: { name: 'test', level: 50, inventory: { items: ['sword', 'shield'], gold: 9999 } },
      battle: { rounds: 10, victory: true, stats: { hp: 100, mp: 50 } },
    };
    const loginTime = 1700000000;
    const encrypted = await encryptBattleData(originalData, loginTime);
    const decrypted = await decryptBattleData(encrypted, loginTime);
    expect(decrypted).toEqual(originalData);
  });

  it('应该能处理空对象', async () => {
    const originalData = {};
    const loginTime = 1700000000;
    const encrypted = await encryptBattleData(originalData, loginTime);
    const decrypted = await decryptBattleData(encrypted, loginTime);
    expect(decrypted).toEqual(originalData);
  });

  it('每次加密应该产生不同的密文（由于随机 IV）', async () => {
    const data = { test: 'value' };
    const loginTime = 1700000000;
    const encrypted1 = await encryptBattleData(data, loginTime);
    const encrypted2 = await encryptBattleData(data, loginTime);
    expect(encrypted1).not.toBe(encrypted2);
    const decrypted1 = await decryptBattleData(encrypted1, loginTime);
    const decrypted2 = await decryptBattleData(encrypted2, loginTime);
    expect(decrypted1).toEqual(decrypted2);
  });
});

describe('encryptIsCheat / decryptIsCheat', () => {
  it('加密后应该能正确解密（往返测试）', async () => {
    const battleId = 'battle_12345_win';
    const encrypted = await encryptIsCheat(battleId);
    const decrypted = await decryptIsCheat(encrypted);
    expect(decrypted).toBe(battleId);
  });

  it('加密结果应该是 Base64 格式', async () => {
    const battleId = 'test_battle_id';
    const encrypted = await encryptIsCheat(battleId);
    expect(encrypted).toBeTruthy();
    const decoded = Buffer.from(encrypted, 'base64').toString();
    expect(decoded).toBeTruthy();
  });

  it('不同的输入应该产生不同的输出', async () => {
    const id1 = 'battle_001';
    const id2 = 'battle_002';
    const encrypted1 = await encryptIsCheat(id1);
    const encrypted2 = await encryptIsCheat(id2);
    expect(encrypted1).not.toBe(encrypted2);
  });

  it('应该能处理特殊字符', async () => {
    const battleId = 'test@#$%^&*()';
    const encrypted = await encryptIsCheat(battleId);
    const decrypted = await decryptIsCheat(encrypted);
    expect(decrypted).toBe(battleId);
  });

  it('应该能处理空字符串', async () => {
    const battleId = '';
    const encrypted = await encryptIsCheat(battleId);
    const decrypted = await decryptIsCheat(encrypted);
    expect(decrypted).toBe(battleId);
  });

  it('解密加 7 再减 7 应该还原原始值', async () => {
    const battleId = 'abc';
    const encrypted = await encryptIsCheat(battleId);
    const decoded = Buffer.from(encrypted, 'base64');
    const manualDecrypt = Buffer.from(decoded.map((v) => v - 7)).toString();
    expect(manualDecrypt).toBe(battleId);
  });
});

describe('decryptBattleReplay', () => {
  it('应该能解密有效的战斗回放数据', async () => {
    const replayData = { actions: ['attack', 'defend'], rounds: 3, winner: 'player' };
    const jsonStr = JSON.stringify(replayData);
    const zip = new JSZip();
    zip.file('default_entry', jsonStr);
    const zipBuffer = await zip.generateAsync({ type: 'nodebuffer' });
    const base64Data = zipBuffer.toString('base64');
    const result = await decryptBattleReplay(base64Data);
    expect(result).toEqual(replayData);
  });

  it('应该能处理包含中文字符的回放数据', async () => {
    const replayData = { actions: ['攻击', '防御'], rounds: 5, description: '激烈的战斗' };
    const jsonStr = JSON.stringify(replayData);
    const zip = new JSZip();
    zip.file('default_entry', jsonStr);
    const zipBuffer = await zip.generateAsync({ type: 'nodebuffer' });
    const base64Data = zipBuffer.toString('base64');
    const result = await decryptBattleReplay(base64Data);
    expect(result).toEqual(replayData);
  });

  it('应该能处理空的回放数据', async () => {
    const replayData = {};
    const jsonStr = JSON.stringify(replayData);
    const zip = new JSZip();
    zip.file('default_entry', jsonStr);
    const zipBuffer = await zip.generateAsync({ type: 'nodebuffer' });
    const base64Data = zipBuffer.toString('base64');
    const result = await decryptBattleReplay(base64Data);
    expect(result).toEqual(replayData);
  });

  it('应该能处理简单的字符串回放数据', async () => {
    const replayData = { result: 'win', hp: 100 };
    const jsonStr = JSON.stringify(replayData);
    const zip = new JSZip();
    zip.file('default_entry', jsonStr);
    const zipBuffer = await zip.generateAsync({ type: 'nodebuffer' });
    const base64Data = zipBuffer.toString('base64');
    const result = await decryptBattleReplay(base64Data);
    expect(result).toEqual(replayData);
  });

  it('无效的 Base64 数据应该抛出错误', async () => {
    await expect(decryptBattleReplay('invalid_base64_data')).rejects.toThrow();
  });
});