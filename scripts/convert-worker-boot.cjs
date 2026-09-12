/**
 * 转换 worker 引导（CommonJS）。
 *
 * worker_threads 以**普通 Node 进程**启动，不继承主进程 tsx 的转译上下文，
 * 因此不能直接 spawn `convert-worker.ts`——`.ts` 在 `"type": "commonjs"` 的包里
 * 会被 Node 按 CJS 解析并执行源码，`import` 语句直接抛
 * `Cannot use import statement outside a module`；改成 `.mts`（ESM）则会在加载
 * 其依赖 `excel-convert.ts`（CJS）时抛同样错误；`execArgv` 注入 tsx loader 亦无效
 * （worker 不读主进程的模块解析钩子设置）。
 *
 * 唯一可靠做法：先用一个**纯 CJS** 文件同步注册 tsx 的 CJS 转译钩子，
 * 再由它 require 真正的 TS worker 逻辑。实测该方式下单表转换正常返回 ok。
 *
 * 历史缺陷：这条链路此前完全不可用（63/63 全败），错误被主线程
 * `on("error", () => resolve())` 吞掉，管线仍报「转换完成 N ok」，
 * 导致 28/63 张表长期停留在旧批次而不被发现（2026-09-11 修复）。
 */
require("tsx/cjs");
require("./convert-worker.ts");
