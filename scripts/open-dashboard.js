#!/usr/bin/env node
/**
 * One-click start helper: poll until the server is up, then open the admin
 * dashboard in the browser.
 *
 * Usage:
 *   node scripts/open-dashboard.js            wait for server, then open browser
 *   node scripts/open-dashboard.js --no-open  print URL only (headless/test)
 *
 * PORT is read from data/config.json (default 8443). /admin/dashboard is
 * auth-free; admin API access still requires admin.enable=true in config.
 *
 * NOTE: keep console messages ASCII — this runs inside a GBK cmd window on
 * Windows and UTF-8 output would be garbled.
 */
const http = require("http");
const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const noOpen = process.argv.includes("--no-open");

function readPort() {
  // 端口覆盖与 config.ts 一致：命令行 --port > 环境变量 PORT > config.json
  const argIdx = process.argv.indexOf("--port");
  if (argIdx !== -1 && process.argv[argIdx + 1] !== undefined) {
    const p = Number(process.argv[argIdx + 1]);
    if (Number.isInteger(p) && p > 0 && p < 65536) return p;
  }
  if (process.env.PORT !== undefined) {
    const p = Number(process.env.PORT);
    if (Number.isInteger(p) && p > 0 && p < 65536) return p;
  }
  try {
    const config = JSON.parse(
      fs.readFileSync(path.join(__dirname, "..", "data", "config.json"), "utf8"),
    );
    return config.PORT || 8443;
  } catch {
    return 8443;
  }
}

const url = `http://localhost:${readPort()}/admin/dashboard`;

/** Server is ready: open the browser (cross-platform) then exit */
function openBrowser() {
  console.log(`server ready, dashboard: ${url}`);
  if (noOpen) {
    process.exit(0);
  }
  if (process.platform === "win32") {
    spawn("cmd", ["/c", "start", "", url], { detached: true, stdio: "ignore" }).unref();
  } else if (process.platform === "darwin") {
    spawn("open", [url], { detached: true, stdio: "ignore" }).unref();
  } else {
    spawn("xdg-open", [url], { detached: true, stdio: "ignore" }).unref();
  }
  process.exit(0);
}

/** Poll until the server responds or waitSecs runs out */
function poll(waitSecs) {
  const req = http.get(url, (res) => {
    res.resume();
    openBrowser();
  });
  req.on("error", () => {
    if (waitSecs <= 0) {
      console.log(`server not ready in time, open manually: ${url}`);
      process.exit(1);
    }
    setTimeout(() => poll(waitSecs - 1), 1000);
  });
  req.setTimeout(3000, () => req.destroy());
}

console.log(`waiting for server: ${url} (up to 30s)`);
poll(30);
