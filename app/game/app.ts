import express from "express";
import httpContext from "express-http-context";
import bodyParser from "body-parser";
import { accountManager } from "./manager/AccountManger";

const app = express();
app.use(bodyParser.json());
app.use(httpContext.middleware);
app.use(async (req, res, next) => {
  if (req.headers?.secret) {
    if (req.headers.secret != "1") {
      req.headers.secret = "1";
    }
    const data = accountManager.getPlayerData(req.headers.secret as string);
    httpContext.set("playerData", data);
  }
  next();
});

export async function setup(app: express.Application) {
  await accountManager.init();
  app.use("/businessCard", (await import("./router/businessCard")).default);
  app.use("/account", (await import("./router/account")).default);
  app.use("/charBuild", (await import("./router/charBuild")).default);
  app.use("/building", (await import("./router/building")).default);
  app.use("/quest", (await import("./router/quest")).default);
  app.use("/user", (await import("./router/user")).default);
  app.use("/activity", (await import("./router/activity")).default);
  app.use("/storyreview", (await import("./router/storyreview")).default);
  app.use("/mission", (await import("./router/mission")).default);
  app.use("/shop", (await import("./router/shop")).default);
  app.use("/rlv2", (await import("./router/rlv2")).default);
  app.use("/gacha", (await import("./router/gacha")).default);
  app.use("/mail", (await import("./router/mail")).default);
  app.use("/", (await import("./router/home")).default);
}
export default app;
