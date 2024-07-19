import express from 'express';
import { readFileSync } from 'fs';
const app = express()
app.use((req, res, next) => {
    //TODO: secret
    req.body.playerdata=JSON.parse(readFileSync("../../data/user/user.json", "utf-8")).user
})
