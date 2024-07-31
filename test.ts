import express from 'express';
import fetch from 'node-fetch';
import fs from 'fs';
import path from 'path';
import config from 'app/config';

const app = express();
const port = 8443;
let r = 1000;

app.use(express.json());

function printj(data: string, filepath: string): void {
    r += 1;
    const fullPath = path.join("tmp", filepath + `${r}.json`);
    try {
        const j = JSON.parse(data);
        fs.writeFileSync(fullPath, JSON.stringify(j, null, 4), 'utf-8');
    } catch (e) {
        fs.writeFileSync(fullPath, data, 'utf-8');
    }
}

app.get("/config/prod/official/network_config", (req, res) => {
    let content = JSON.stringify(config.NetworkConfig);
    const data = {
        sign: "sign",
        content: content.replace(/{server}/g, `${config.Host}:${config.PORT}`)
    };
    res.json(data);
});

app.get("/config/prod/official/remote_config", (req, res) => {
    const data = {
        enableGameBI: false,
        enableSDKNetSecure: true,
        enableBestHttp: true
    };
    res.json(data);
});

app.get("/config/prod/official/Android/version", (req, res) => {
    const data = config.version;
    res.json(data);
});

app.get("/config/prod/announce_meta/Android/preannouncement.meta.json", async (req, res) => {
    const headers = { ...req.headers };
    delete headers.host;
    const response = await fetch("https://ak-conf.hypergryph.com/config/prod/announce_meta/Android/preannouncement.meta.json", {
        method: 'GET',
        headers: headers as any
    });
    const data = await response.text();
    res.send(data);
});

app.get("/config/prod/announce_meta/Android/announcement.meta.json", async (req, res) => {
    const headers = { ...req.headers };
    delete headers.host;
    const response = await fetch("https://ak-conf.hypergryph.com/config/prod/announce_meta/Android/announcement.meta.json", {
        method: 'GET',
        headers: headers as any
    });
    const data = await response.text();
    res.send(data);
});

app.post("/u8/user/v1/getToken", async (req, res) => {
    const headers = { ...req.headers };
    delete headers.host;
    const response = await fetch("https://as.hypergryph.com/u8/user/v1/getToken", {
        method: 'POST',
        body: JSON.stringify(req.body),
        headers: headers as any
    });
    const data = await response.text();
    res.send(data);
});

app.get("/user/info/v1/basic", async (req, res) => {
    const headers = { ...req.headers };
    delete headers.host;
    const response = await fetch(`https://as.hypergryph.com/user/info/v1/basic?token=${req.query.token}`, {
        method: 'GET',
        headers: headers as any
    });
    const data = await response.text();
    res.send(data);
});

app.get("/u8/user/auth/v1/agreement_version", (req, res) => {
    const data = {
        status: 0,
        msg: "OK",
        data: {
            agreementUrl: {
                privacy: "https://user.hypergryph.com/protocol/plain/ak/privacy",
                service: "https://user.hypergryph.com/protocol/plain/ak/service",
                updateOverview: "https://user.hypergryph.com/protocol/plain/ak/overview_of_changes",
                childrenPrivacy: "https://user.hypergryph.com/protocol/plain/ak/children_privacy"
            },
            authorized: true,
            isLatestUserAgreement: true
        }
    };
    res.json(data);
});

app.get("/general/v1/server_time", async (req, res) => {
    const headers = { ...req.headers };
    delete headers.host;
    const response = await fetch("https://as.hypergryph.com/general/v1/server_time", {
        method: 'GET',
        headers: headers as any
    });
    const data = await response.text();
    res.send(data);
});

app.get("/app/v1/config", async (req, res) => {
    const headers = { ...req.headers };
    delete headers.host;
    const response = await fetch(`https://as.hypergryph.com/app/v1/config?appCode=${req.query.appCode}`, {
        method: 'GET',
        headers: headers as any
    });
    const data = await response.text();
    res.send(data);
});

app.get("/u8/user/auth/v1/agreement_version", async (req, res) => {
    const headers = { ...req.headers };
    delete headers.host;
    const response = await fetch(`https://as.hypergryph.com/u8/user/auth/v1/agreement_version?code=${req.query.code}`, {
        method: 'GET',
        headers: headers as any
    });
    const data = await response.text();
    console.log(data);
    res.send(data);
});

app.post("/user/oauth2/v2/grant", async (req, res) => {
    const headers = { ...req.headers };
    delete headers.host;
    const response = await fetch("https://as.hypergryph.com/user/oauth2/v2/grant", {
        method: 'POST',
        body: JSON.stringify(req.body),
        headers: headers as any
    });
    const data = await response.text();
    res.send(data);
});

app.post("/user/auth/v1/token_by_phone_password", async (req, res) => {
    const headers = { ...req.headers };
    delete headers.host;
    const response = await fetch("https://as.hypergryph.com/user/auth/v1/token_by_phone_password", {
        method: 'POST',
        body: JSON.stringify(req.body),
        headers: headers as any
    });
    const data = await response.text();
    res.send(data);
});

app.post("/pre_get_token", async (req, res) => {
    const headers = { ...req.headers };
    delete headers.host;
    const response = await fetch("https://as.hypergryph.com/pre_get_token", {
        method: 'POST',
        body: JSON.stringify(req.body),
        headers: headers as any
    });
    const data = await response.text();
    res.send(data);
});

app.post("/user/online/v1/loginout", async (req, res) => {
    const headers = { ...req.headers };
    delete headers.host;
    const response = await fetch("https://as.hypergryph.com/user/online/v1/loginout", {
        method: 'POST',
        body: JSON.stringify(req.body),
        headers: headers as any
    });
    const data = await response.text();
    res.send(data);
});

app.post("/u8/pay/getAllProductList", async (req, res) => {
    const response = await fetch("https://as.hypergryph.com/u8/pay/getAllProductList", {
        method: 'POST',
        body: JSON.stringify(req.body)
    });
    const data = await response.text();
    printj(data, "getAllProductList");
    res.send(data);
});

app.post("/pay/:a", async (req, res) => {
    console.log(req.headers);
    const headers = { ...req.headers };
    delete headers.host;
    const response = await fetch(`https://as.hypergryph.com/pay/${req.params.a}`, {
        method: 'POST',
        body: JSON.stringify(req.body),
        headers: headers as any
    });
    const data = await response.text();
    printj(data, `pay_${req.params.a}_res_`);
    printj(JSON.stringify(req.body), `pay_${req.params.a}_req_`);
    res.send(data);
});

app.post("/:b/:a", async (req, res) => {
    const headers = { ...req.headers };
    delete headers.host;
    const response = await fetch(`https://ak-gs-gf.hypergryph.com/${req.params.b}/${req.params.a}`, {
        method: 'POST',
        body: JSON.stringify(req.body),
        headers: headers as any
    });
    const data = await response.text();
    printj(data, `${req.params.b}_${req.params.a}_res_`);
    printj(JSON.stringify(req.body), `${req.params.b}_${req.params.a}_req_`);
    res.send(data);
});

app.post("/:b/:a/:c", async (req, res) => {
    const headers = { ...req.headers };
    delete headers.host;
    const response = await fetch(`https://ak-gs-gf.hypergryph.com/${req.params.b}/${req.params.a}/${req.params.c}`, {
        method: 'POST',
        body: JSON.stringify(req.body),
        headers: headers as any
    });
    const data = await response.text();
    printj(data, `${req.params.b}_${req.params.a}_${req.params.c}_res_`);
    printj(JSON.stringify(req.body), `${req.params.b}_${req.params.a}_${req.params.c}_req_`);
    res.send(data);
});

app.listen(port, '0.0.0.0', () => {
    console.log(`Server is running at http://0.0.0.0:${port}`);
});
