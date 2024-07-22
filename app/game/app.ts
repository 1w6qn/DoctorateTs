import express from 'express';
import httpContext from "express-http-context"
import bodyParser from 'body-parser';
import account from './account';
import charBuild from './charBuild';
import building from './building';
import quest from './quest';
import home from './home';
import user from './user';
import activity from './activity';
import storyreview from './storyreview';

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