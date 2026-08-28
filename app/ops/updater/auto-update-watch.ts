/**
 * 运行期自动更新 watcher（检测官服 CDN 数据变动 → 自动拉取 + 解包重签）
 *
 * 周期性探测官服 resVersion；发现与本地 config.version 不一致时，自动执行
 * 完整 `update-data.main(false)`（下载 → 解包 → 解码转换 → 生成类型 → 同步版本），
 * 成功后热重载 excel 数据（复用 index.ts 的 `excel.init()` + `warmupLazyTables()` 模式）。
 *
 * 设计：
 * - 单例 autoUpdateWatch：start() 幂等启动定时器；stop() 关闭。
 * - running 锁：一次只允许一轮更新，避免间隔内叠加触发。
 * - 用 `getResVersion()` 轻量探测（不写配置）；真实解包重签走 update-data.main()。
 */
import { logger } from "@utils/logger";
import { getResVersion } from "../../../scripts/official-api";

/** 默认探测间隔（毫秒）：15 分钟 */
const DEFAULT_INTERVAL_MS = 15 * 60 * 1000;

/**
 * 运行期自动更新 watcher
 *
 * 供 index.ts 启动时按配置/CLI 挂起；也可被脚本/测试直接调用。
 */
class AutoUpdateWatch {
  private _timer: NodeJS.Timeout | null = null;
  private _running = false;

  /**
   * 启动周期检测（幂等；已运行则忽略）
   *
   * @param intervalMs - 探测间隔（毫秒）
   */
  start(intervalMs: number = DEFAULT_INTERVAL_MS): void {
    if (this._timer) return;
    this._timer = setInterval(() => void this.check().catch(() => undefined), intervalMs);
    this._timer.unref?.();
    logger.info(
      "AutoUpdateWatch",
      `已启动运行期自动更新（每 ${Math.round(intervalMs / 60000)} 分钟检测官服 CDN 数据变动）`,
    );
    // 启动后即刻探测一轮，无需等待首个间隔
    void this.check().catch(() => undefined);
  }

  /** 关闭周期检测 */
  stop(): void {
    if (this._timer) {
      clearInterval(this._timer);
      this._timer = null;
    }
  }

  /** 是否正在执行一轮更新 */
  get busy(): boolean {
    return this._running;
  }

  /**
   * 探测官服 resVersion，如与本地不一致则自动拉取并解包重签
   *
   * 幂等安全：一方已在跑则本调用直接返回；网络/管线失败仅告警不崩溃。
   */
  async check(): Promise<void> {
    if (this._running) return;
    this._running = true;
    try {
      const android = await getResVersion();
      const { default: config } = await import("../../core/config");
      const local =
        (config.version as { windows?: { resVersion?: string } })?.windows?.resVersion ??
        (config.version as { resVersion?: string })?.resVersion;
      if (!local) return;
      if (android.resVersion === local) return;

      logger.info(
        "AutoUpdateWatch",
        `检测到官服数据变动 ${local} → ${android.resVersion}，自动拉取并解包重签`,
      );
      const updateModule = await import("../../../scripts/update-data");
      const code = await updateModule.main(false);
      if (code === 0) {
        // 全管线成功：切到新 excel 数据（复用 index 启动时的热重载方式）
        const { default: excel } = await import("@excel/excel");
        await excel.init();
        void excel.warmupLazyTables().catch(() => undefined);
        logger.info("AutoUpdateWatch", `自动更新完成：${android.resVersion}，excel 已热重载`);
      } else {
        logger.warn("AutoUpdateWatch", `自动更新未完全成功（code=${code}），保留本地数据`);
      }
    } catch (error) {
      logger.warn("AutoUpdateWatch", `检测官服 CDN 数据变动失败: ${(error as Error).message}`);
    } finally {
      this._running = false;
    }
  }
}

/** 运行期自动更新 watcher 单例 */
export const autoUpdateWatch = new AutoUpdateWatch();