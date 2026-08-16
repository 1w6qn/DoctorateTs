/**
 * 调用 archcore MCP 工具：list_documents / create_document / add_relation。
 * 通过 stdio 与 archcore mcp 服务通信。
 * 用法: node scripts/archcore-mcp.js <命令> [json参数文件]
 */
const { spawn } = require("child_process");
const fs = require("fs");

const cli = "C:\\Users\\Administrator\\AppData\\Local\\Programs\\archcore\\archcore.exe";
const [, , cmd, argFile] = process.argv;

const child = spawn(cli, ["mcp", "--project", process.cwd()], {
  stdio: ["pipe", "pipe", "inherit"],
});

let buf = "";
const pending = {};
let nextId = 1;

child.stdout.on("data", (d) => {
  buf += d.toString();
  let idx;
  while ((idx = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, idx).trim();
    buf = buf.slice(idx + 1);
    if (line) handle(JSON.parse(line));
  }
});

function handle(msg) {
  if (msg.id && pending[msg.id]) {
    pending[msg.id](msg);
    delete pending[msg.id];
  }
}

function call(method, params) {
  return new Promise((resolve) => {
    const id = nextId++;
    pending[id] = resolve;
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
}

async function main() {
  if (cmd === "list") {
    const res = await call("tools/call", {
      name: "list_documents",
      arguments: {},
    });
    console.log(JSON.stringify(res, null, 2));
  } else if (cmd === "relations") {
    const res = await call("tools/call", {
      name: "list_relations",
      arguments: {},
    });
    console.log(JSON.stringify(res, null, 2));
  } else if (cmd === "create") {
    const ops = JSON.parse(fs.readFileSync(argFile, "utf-8"));
    for (const op of ops) {
      const res = await call("tools/call", {
        name: "create_document",
        arguments: op.doc,
      });
      const text = res.result?.content?.[0]?.text || JSON.stringify(res);
      console.log(`CREATE ${op.doc.filename}: ${text}`);
      if (op.relations) {
        for (const rel of op.relations) {
          const rres = await call("tools/call", {
            name: "add_relation",
            arguments: rel,
          });
          const rtext = rres.result?.content?.[0]?.text || JSON.stringify(rres);
          console.log(`  RELATE ${rel.source} -> ${rel.target} (${rel.type}): ${rtext}`);
        }
      }
    }
  } else if (cmd === "relate") {
    const relations = JSON.parse(fs.readFileSync(argFile, "utf-8"));
    for (const rel of relations) {
      const rres = await call("tools/call", {
        name: "add_relation",
        arguments: rel,
      });
      const rtext = rres.result?.content?.[0]?.text || JSON.stringify(rres);
      console.log(`RELATE ${rel.source} -> ${rel.target} (${rel.type}): ${rtext}`);
    }
  }
  child.kill();
  process.exit(0);
}

main();