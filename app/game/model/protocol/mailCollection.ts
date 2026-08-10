/**
 * 邮件收藏（mailCollection）协议类型
 *
 * 对应客户端 com.hypergryph.arknights_2.7.61.cs 中
 * Torappu.MailCollectionGetListRequest / MailCollectionGetListResponse；
 * CS 响应的 unlockIdList/extraData 字段在服务端输出为 collections/extra
 * （参考 OpenBachelorS bp_mail.py mailCollection_getList），以服务端契约为准。
 */
import { MailArchiveItemData } from "@excel/types_excel_gen";

/** 获取邮件收藏列表请求（CS: MailCollectionGetListRequest，无字段；服务端不读取 body） */
export interface MailCollectionGetListRequest {}

/**
 * 获取邮件收藏列表响应
 * CS: MailCollectionGetListResponse { unlockIdList, extraData }，
 * 服务端字段名为 collections/extra（CS 的 extraData 元素即 MailArchiveItemData）；
 * CS 响应不继承 PlayerDeltaResponse，服务端也不返回增量
 */
export interface MailCollectionGetListResponse {
  collections: string[];
  extra: MailArchiveItemData[];
}
