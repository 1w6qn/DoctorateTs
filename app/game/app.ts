import express from 'express';
import httpContext from "express-http-context"
import account from './account';
import { accountManager } from './manager/AccountManger';
import { PlayerDataManager } from './manager/PlayerDataManager';
const app = express()
app.use(httpContext.middleware)
app.use((req, res, next) => {
    if (req.headers?.secret){
        //TODO
        let data=accountManager.getPlayerData(req.headers.secret as string)
        httpContext.set("playerdata", data)
    }
    next()
})
app.use("/account",account)
export default app