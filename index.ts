import express from "express";
import config from "./app/config";
import excel from "@excel/excel";
import { enablePatches } from "immer";
import morgan from "morgan";
import prod from "./app/config/prod";
import auth from "./app/auth/auth";
import asset from "./app/asset";
import game, { setup } from "./app/game/app";

(async () => {
  console.time();
  enablePatches();
  await excel.init();
  const app = express();

  app.use(morgan("short"));
  app.use("/config/prod", prod);
  app.use("/", auth);
  await setup(game);
  app.use("/", game);
  app.use("/assetbundle", asset);
  app.listen(config.PORT, async () => {
    console.timeEnd();
    console.log(`--------------DoctorateTs--------------`);
    console.log(`running at http://localhost:${config.PORT}`);
  });
})();
