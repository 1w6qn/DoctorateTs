/**
 * 商店业务错误
 *
 * 余额不足/超限购/已拥有等业务失败统一抛 ShopError，路由层捕获后返回
 * result:1 业务错误而非 500；购买流程在抛出前必须未产生任何副作用
 * （不扣费、不发放、不写记录）。
 */
export class ShopError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ShopError";
  }
}
