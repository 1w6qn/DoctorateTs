/**
 * 随机数工具模块
 * 
 * 提供常用的随机数生成和随机选择功能，用于抽卡、招募等游戏随机机制。
 */

/**
 * 生成指定范围内的随机整数
 * 
 * @param min - 最小值（包含）
 * @param max - 最大值（包含）
 * @returns 随机整数
 */
export function randomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

/**
 * 加权随机选择
 * 
 * 根据权重数组从数组中随机选择 k 个元素，权重越高被选中的概率越大。
 * 
 * @param arr - 待选择的数组
 * @param weights - 对应的权重数组
 * @param k - 选择的数量
 * @returns 选中的元素数组
 */
export function randomChoices<T>(arr: T[], weights: number[], k: number): T[] {
  const result: T[] = [];
  for (let i = 0; i < k; i++) {
    const totalWeight = weights.reduce((a, b) => a + b, 0);
    let random = Math.random() * totalWeight;
    for (let j = 0; j < arr.length; j++) {
      random -= weights[j];
      if (random <= 0) {
        result.push(arr[j]);
        break;
      }
    }
  }
  return result;
}

/**
 * 无放回随机抽样
 * 
 * 随机打乱数组并取前 k 个元素。
 * 
 * @param arr - 待抽样的数组
 * @param k - 抽样数量
 * @returns 抽样结果数组
 */
export function randomSample<T>(arr: T[], k: number): T[] {
  return arr.sort(() => 0.5 - Math.random()).slice(0, k);
}

/**
 * 随机选择一个元素
 * 
 * @param arr - 待选择的数组
 * @returns 随机选中的元素
 */
export function randomChoice<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

/**
 * 整除和取模运算
 * 
 * 返回一个包含商和余数的元组。
 * 
 * @param x - 被除数
 * @param y - 除数
 * @returns [商, 余数]
 */
export function divmod(x: number, y: number): [number, number] {
  return [Math.floor(x / y), x % y];
}