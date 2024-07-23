import express from 'express';
import httpContext from "express-http-context"
import bodyParser from 'body-parser';
import account from './router/account';
import charBuild from './router/charBuild';
import building from './router/building';
import quest from './router/quest';
import home from './router/home';
import user from './router/user';
import activity from './router/activity';
import storyreview from './router/storyreview';

import { accountManager } from './manager/AccountManger';

const app = express()
app.use(bodyParser.json())
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
app.use("/charBuild",charBuild)
app.use("/building",building)
app.use("/quest",quest)
app.use("/user",user)
app.use("/activity",activity)
app.use("/storyreview",storyreview)
app.use("/",home)
export default app