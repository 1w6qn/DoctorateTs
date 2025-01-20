import { MailItem, MailMetaInfo } from "../model/mail";
import { ItemBundle } from "app/excel/character_table";
import { now } from "@utils/time";
import { writeFile } from "fs/promises";
import { readFileSync } from "fs";

export class MailManager {
  database: MailDB;

  //TODO survey mail
  constructor() {
    this.database = JSON.parse(
      readFileSync(`${__dirname}/../../../data/user/mails.json`, "utf8"),
    );
  }

  async listMailbox(
    uid: string,
    args: {
      sysMailIdList: number[];
      surveyMailIdList: string[];
      mailIdList: number[];
    },
  ): Promise<MailItem[]> {
    return this.database.user[uid].filter((mail) => {
      return (
        args.sysMailIdList.includes(mail.mailId) ||
        args.surveyMailIdList.includes(mail.mailId.toString()) ||
        args.mailIdList.includes(mail.mailId)
      );
    });
  }

  async receiveMail(
    uid: string,
    args: { mailId: number; type: number },
  ): Promise<ItemBundle[]> {
    const mail = this.database.user[uid].find(
      (mail) => mail.mailId === args.mailId && mail.type === args.type,
    );
    let items: ItemBundle[] = [];
    if (mail && mail.receiveAt == -1) {
      mail.receiveAt = now();
      if (mail.hasItem) {
        items = mail.items;
      }
    }
    await this.saveDatabase();
    return items;
  }

  async getMetaInfoList(
    uid: string,
    args: { from: number },
  ): Promise<MailMetaInfo[]> {
    console.log(args);
    return this.database.user[uid].map((mail) => {
      return {
        mailId: mail.mailId,
        createAt: mail.createAt,
        state: mail.state,
        hasItem: mail.hasItem,
        type: mail.type,
      } as MailMetaInfo;
    });
  }

  async receiveAllMail(
    uid: string,
    args: {
      sysMailIdList: number[];
      surveyMailIdList: string[];
      mailIdList: number[];
    },
  ): Promise<ItemBundle[]> {
    const mailList = this.database.user[uid].filter((mail) => {
      return (
        args.sysMailIdList.includes(mail.mailId) ||
        args.surveyMailIdList.includes(mail.mailId.toString()) ||
        args.mailIdList.includes(mail.mailId)
      );
    });
    const items: ItemBundle[] = [];
    mailList.forEach((mail) => {
      if (mail && mail.receiveAt == -1) {
        mail.receiveAt = now();
        if (mail.hasItem) {
          items.push(...mail.items);
        }
      }
    });
    await this.saveDatabase();
    return items;
  }

  async removeAllReceivedMail(
    uid: string,
    args: {
      sysMailIdList: number[];
      surveyMailIdList: string[];
      mailIdList: number[];
    },
  ) {
    this.database.user[uid] = this.database.user[uid].filter((mail) => {
      return !(
        args.sysMailIdList.includes(mail.mailId) ||
        args.surveyMailIdList.includes(mail.mailId.toString()) ||
        args.mailIdList.includes(mail.mailId)
      );
    });
    await this.saveDatabase();
  }

  async sendMail() {}

  async saveDatabase() {
    await writeFile(
      `${__dirname}/../../../data/user/mails.json`,
      JSON.stringify(this.database),
    );
  }
}
export interface MailDB {
  user: { [key: string]: MailItem[] };
}

export const mailManager = new MailManager();
