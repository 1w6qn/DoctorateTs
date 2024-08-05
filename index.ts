import express from 'express';
import prod from "./app/config/prod"
import auth from "./app/auth/auth";
import game from "./app/game/app";
import asset from "./app/asset";
import config from './app/config';
import morgan from 'morgan';

const app = express();
app.use(morgan("short"))
app.use("/config/prod",prod)
app.use("/",auth)
app.use("/",game)
app.use("/assetbundle",asset)
app.get('/', (req, res) => {
  res.send('Hello world');
});
app.listen(config.PORT, () => {
  console.log(`Express with Typescript! http://localhost:${config.PORT}`);
});
