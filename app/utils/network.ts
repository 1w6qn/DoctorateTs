import os from 'os';
export function getIPAdress(isIPV4:boolean = true) {
    let interfaces = os.networkInterfaces();
    for (let devName in interfaces) {
        let iface = interfaces[devName]!;
        for (let i = 0; i < iface.length; i++) {
            let alias = iface[i];
            if (isIPV4) {
                if (alias.family === 'IPv4' && alias.address !== '127.0.0.1' && !alias.internal) {
                    return alias.address;
                }
            } else if (alias.address !== '127.0.0.1' && !alias.internal) {
                if (alias.family === 'IPv6') {
                    return alias.address;
                }
            }
        }
    }
}