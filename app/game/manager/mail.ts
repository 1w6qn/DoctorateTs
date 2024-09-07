import { readFileSync, writeFileSync } from "fs";
import { MailItem, MailMetaInfo } from "../model/mail";
import { ItemBundle } from "app/excel/character_table";
import { now } from "@utils/time";

export class MailManager {
    database: MailDB
    //TODO survey mail
    constructor() {
        this.database = JSON.parse(readFileSync(`${__dirname}/../../../data/user/mails.json`, 'utf8'))
    }
    listMailbox(uid: string, args: { sysMailIdList: number[], surveyMailIdList: string[], mailIdList: number[] }):MailItem[] {
        let mailList = this.database.user[uid].filter(mail => {
            return (args.sysMailIdList.includes(mail.mailId) || args.surveyMailIdList.includes(mail.mailId.toString()) || args.mailIdList.includes(mail.mailId))
        })
        return mailList
    }
    receiveMail(uid:string,args:{mailId:number,type:number}):ItemBundle[] {
        let mail=this.database.user[uid].find(mail => mail.mailId === args.mailId&&mail.type===args.type)
        let items:ItemBundle[]=[]
        if(mail && mail.receiveAt==-1){
            mail.receiveAt=now()
            if(mail.hasItem){
                items.push(...mail.items)
            }
        }
        this.saveDatabase()
        return items
    }
    getMetaInfoList(uid: string, args: { from: number }): MailMetaInfo[] {
        let mails = this.database.user[uid].map(mail => {
            return {
                mailId: mail.mailId,
                createAt: mail.createAt,
                state: mail.state,
                hasItem: mail.hasItem,
                type: mail.type,
            } as MailMetaInfo
        })
        return mails
    }
    receiveAllMail(uid: string, args: { sysMailIdList: number[], surveyMailIdList: string[], mailIdList: number[] }): ItemBundle[] {
        
        let mailList = this.database.user[uid].filter(mail=>{
            return (args.sysMailIdList.includes(mail.mailId) || args.surveyMailIdList.includes(mail.mailId.toString()) || args.mailIdList.includes(mail.mailId))
        })
        let items:ItemBundle[]=[]
        mailList.forEach(mail=>{
            if(mail && mail.receiveAt==-1){
                mail.receiveAt=now()
                if(mail.hasItem){
                    items.push(...mail.items)
                }
            }
        })
        this.saveDatabase()
        return items
     }
    removeAllReceivedMail(uid: string, args: { sysMailIdList: number[], surveyMailIdList: string[], mailIdList: number[] }) {
        this.database.user[uid]=this.database.user[uid].filter(mail=>{
            return !(args.sysMailIdList.includes(mail.mailId) || args.surveyMailIdList.includes(mail.mailId.toString()) || args.mailIdList.includes(mail.mailId))
        })
        this.saveDatabase()
    }
    sendMail() { }
    saveDatabase(){
        writeFileSync(`${__dirname}/../../../data/user/mails.json`, JSON.stringify(this.database), 'utf8')
    }
}
export interface MailDB {
    user: { [key: string]: MailItem[] },
}

export const mailManager = new MailManager()