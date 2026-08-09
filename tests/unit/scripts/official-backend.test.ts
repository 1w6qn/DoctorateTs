import { describe, it, expect } from "vitest";

// mock config：自定义后端启用（模块加载时 official-api 读取）
vi.mock("../../../app/config", () => ({
  default: {
    officialBackend: {
      enabled: true,
      game: "http://custom-game",
      account: "http://custom-account",
      conf: "http://custom-conf",
    },
  },
}));

import { GAME_API, ACCOUNT_API, CONF_API } from "../../../scripts/official-api";

describe("官服自定义后端", () => {
  it("enabled=true 时应使用自定义地址", () => {
    expect(GAME_API).toBe("http://custom-game");
    expect(ACCOUNT_API).toBe("http://custom-account");
    expect(CONF_API).toBe("http://custom-conf");
  });
});
