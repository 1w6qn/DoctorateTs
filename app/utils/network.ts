import os from "os";

export function getIPAddress(isIPV4: boolean = true) {
  const interfaces = os.networkInterfaces();
  for (const devName in interfaces) {
    const ifs = interfaces[devName]!;
    for (let i = 0; i < ifs.length; i++) {
      const alias = ifs[i];
      if (isIPV4) {
        if (
          alias.family === "IPv4" &&
          alias.address !== "127.0.0.1" &&
          !alias.internal
        ) {
          return alias.address;
        }
      } else if (alias.address !== "127.0.0.1" && !alias.internal) {
        if (alias.family === "IPv6") {
          return alias.address;
        }
      }
    }
  }
}
