import { describe, it, expect } from 'vitest';
import { toCamelCase } from '@utils/string';

describe('toCamelCase', () => {
  it('应该将简单的下划线命名转换为驼峰命名', () => {
    expect(toCamelCase('hello_world')).toBe('helloWorld');
    expect(toCamelCase('foo_bar_baz')).toBe('fooBarBaz');
  });

  it('应该处理单个单词（无下划线）', () => {
    expect(toCamelCase('hello')).toBe('hello');
    expect(toCamelCase('foobar')).toBe('foobar');
  });

  it('应该处理空字符串', () => {
    expect(toCamelCase('')).toBe('');
  });

  it('应该处理连续的下划线', () => {
    expect(toCamelCase('a__b')).toBe('a_B');
  });

  it('应该全部转为小写后再处理', () => {
    expect(toCamelCase('HELLO_WORLD')).toBe('helloWorld');
    expect(toCamelCase('Hello_World')).toBe('helloWorld');
  });

  it('应该处理带下划线前缀的字符串（_h 匹配转换为 H）', () => {
    expect(toCamelCase('_hello')).toBe('Hello');
  });

  it('应该处理带下划线后缀的字符串', () => {
    expect(toCamelCase('hello_')).toBe('hello_');
  });

  it('应该处理数字（数字不匹配 _[a-z] 模式）', () => {
    expect(toCamelCase('item_1_value')).toBe('item_1Value');
  });

  it('应该处理多个下划线分隔的单词', () => {
    expect(toCamelCase('a_b_c_d')).toBe('aBCD');
  });

  it('应该处理带大写字母的下划线命名', () => {
    expect(toCamelCase('USER_NAME')).toBe('userName');
  });

  it('应该处理中间下划线的字符串', () => {
    expect(toCamelCase('first_second')).toBe('firstSecond');
  });
});