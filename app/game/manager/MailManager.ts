import { readFileSync, writeFileSync } from "fs";
import { BaseMailItem, MailItem, MailMetaInfo } from "../model/mail";

export class MailManager {
    database: MailDB
    //TODO survey mail
    constructor() {
        this.database = JSON.parse(readFileSync(`${__dirname}/../../../data/user/mails.json`, 'utf8'))
    }
    listMailbox(uid: string, args: { sysMailIdList: number[], surveyMailIdList: string[], mailIdList: number[] }) {
        let mailList = this.database.user[uid].filter(mail => {
            return (args.sysMailIdList.includes(mail.mailId) || args.surveyMailIdList.includes(mail.mailId.toString()) || args.mailIdList.includes(mail.mailId))
        })
        return mailList
    }
    receiveMail(uid:string,args:{mailId:number,type:number}) {
        let mail=this.database.user[uid].find(mail => mail.mailId === args.mailId&&mail.type===args.type)
        if(mail && mail.receiveAt==-1){
            mail.receiveAt=parseInt((new Date().getTime()/1000).toString())
        }
        this.saveDatabase()
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
    receiveAllMail(uid: string, args: { sysMailIdList: number[], surveyMailIdList: string[], mailIdList: number[] }) {
        
        let mailList = this.database.user[uid].filter(mail=>{
            return (args.sysMailIdList.includes(mail.mailId) || args.surveyMailIdList.includes(mail.mailId.toString()) || args.mailIdList.includes(mail.mailId))
        })
        mailList.forEach(mail=>{
            if(mail && mail.receiveAt==-1){
                mail.receiveAt=parseInt((new Date().getTime()/1000).toString())
            }
        })
        this.saveDatabase()
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