import express from "express";
import prod from "./app/config/prod";
import auth from "./app/auth/auth";
import game, { setup } from "./app/game/app";
import asset from "./app/asset";
import config from "./app/config";
import morgan from "morgan";
import excel from "@excel/excel";

(async () => {
  console.time();
  await excel.init();
  const app = express();
  app.use(morgan("short"));
  app.use("/config/prod", prod);
  app.use("/", auth);
  await setup(game);
  app.use("/", game);
  app.use("/assetbundle", asset);
  app.use("/", async (req, res) => {
    res.send("Hello");
  });
  app.listen(config.PORT, async () => {
    console.timeEnd();
    console.log(`--------------DoctorateTs--------------`);
    console.log(`running at http://localhost:${config.PORT}`);
  });
})();
