export function randomInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

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

export function randomSample<T>(arr: T[], k: number): T[] {
  return arr.sort(() => 0.5 - Math.random()).slice(0, k);
}

export function randomChoice<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}
export function divmod(x: number, y: number): [number, number] {
  return [Math.floor(x / y), x % y];
}
