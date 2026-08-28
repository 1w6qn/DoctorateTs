/**
 * 邮件模板
 *
 * 预置常见系统邮件（补偿/公告/欢迎等），支持 {占位符} 参数替换。
 * 供 CLI `mail send --template`、管理 API 与 Dashboard 使用。
 * 物品 ID 支持中文名/别名（发放时经 resolveItemRef 解析）。
 */
export interface MailTemplate {
  name: string;
  subject: string;
  content: string;
  items: { id: string; count: number }[];
}

export const MAIL_TEMPLATES: MailTemplate[] = [
  {
    name: "补偿",
    subject: "补偿发放",
    content: "感谢支持，特此发放补偿。\n发放时间：{date}",
    items: [
      { id: "4001", count: 10000 },
      { id: "4003", count: 100 },
    ],
  },
  {
    name: "公告",
    subject: "服务器公告",
    content: "{date} 服务器维护更新公告。",
    items: [],
  },
  {
    name: "欢迎",
    subject: "欢迎来到 DoctorateTs",
    content: "欢迎加入私服！赠送新手礼包，祝游戏愉快。",
    items: [
      { id: "4001", count: 100000 },
      { id: "4003", count: 1000 },
      { id: "7003", count: 10 },
    ],
  },
];

/**
 * 按名称展开模板（支持名称包含匹配），并替换 {占位符}
 * @param name - 模板名（支持前缀/包含匹配）
 * @param vars - 占位符变量（如 {date}）
 * @returns 展开后的模板；未命中返回 null
 */
export function expandTemplate(
  name: string,
  vars: { [key: string]: string },
): MailTemplate | null {
  const t = MAIL_TEMPLATES.find(
    (x) => x.name === name || x.name.includes(name),
  );
  if (!t) return null;
  let subject = t.subject;
  let content = t.content;
  for (const [k, v] of Object.entries(vars)) {
    subject = subject.split("{" + k + "}").join(v);
    content = content.split("{" + k + "}").join(v);
  }
  return { ...t, subject, content };
}
