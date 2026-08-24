/**
 * 抓包写入端口（CaptureRecorder）
 *
 * 定义业务/工具层面向的窄接口：仅暴露落库一条记录的能力，
 * 隐藏 CaptureManager 的会话管理、查询、导出、订阅等实现细节。
 *
 * 目的：解耦业务层（game/reqres-log、utils/traffic-recorder）对具体单例
 * `captureManager` 的依赖——它们只依赖该端口，默认注入真实单例，
 * 测试时可替换为 mock（见 reqres-log.test / traffic-recorder.test）。
 *
 * `CaptureManager` 天然结构性满足本接口，组装层（index.ts）保持默认注入即可。
 */
import type {
  CaptureBodiesInput,
  CaptureRecord,
  CaptureRecordInput,
} from "./capture-manager";

/**
 * 抓包写入端口
 *
 * @remarks
 * 仅声明 addRecord 一条写入能力，供 HTTP 抓包中间件（traffic-recorder / reqres-log）
 * 面向接口写入统一抓包存储。
 */
export interface CaptureRecorder {
  /**
   * 写入一条抓包记录
   * @param input - 记录元信息（方法/路径/来源/会话等）
   * @param bodies - 请求/响应体（可选）
   * @returns 落库后的记录
   */
  addRecord(
    input: CaptureRecordInput,
    bodies?: CaptureBodiesInput,
  ): Promise<CaptureRecord>;
}