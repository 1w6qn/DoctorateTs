import { describe, it, expect, vi, beforeEach } from "vitest";

// 模拟官服 HTTP 响应
const fetchMock = vi.fn();
vi.stubGlobal("fetch", fetchMock);

import {
  getResVersion,
  getToken,
  syncPlayerData,
  u8Sign,
} from "../../../scripts/official-api";

function jsonRes(body: any) {
  return { ok: true, json: async () => body };
}

describe("official-api", () => {
  beforeEach(() => {
    fetchMock.mockReset();
  });

  it("u8Sign 应生成 HMAC-SHA1 签名", () => {
    const sign = u8Sign({ appId: "1", platform: 1 });
    expect(sign).toMatch(/^[0-9a-f]{40}$/);
  });

  it("getResVersion 应获取版本信息", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonRes({ resVersion: "1.0.0", clientVersion: "2.0.0" }),
    );
    const v = await getResVersion();
    expect(v.resVersion).toBe("1.0.0");
    expect(v.clientVersion).toBe("2.0.0");
  });

  it("getToken 三步登录应返回 uid 与 token", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonRes({ data: { token: "t1" } })) // token_by_phone_password
      .mockResolvedValueOnce(jsonRes({ data: { token: "t2" } })) // grant
      .mockResolvedValueOnce(jsonRes({ data: { token: "t3", uid: "10001" } })); // u8 getToken
    const r = await getToken("13800000000", "pwd", "dev1", "dev2", "dev3");
    expect(r.uid).toBe("10001");
    expect(r.token).toBe("t3");
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it("getToken 登录失败应抛出错误", async () => {
    fetchMock.mockResolvedValueOnce(jsonRes({ data: {} }));
    await expect(getToken("13800000000", "pwd", "d1", "d2", "d3")).rejects.toThrow();
  });

  it("syncPlayerData 应完成登录并返回玩家数据", async () => {
    fetchMock
      .mockResolvedValueOnce(jsonRes({ resVersion: "1.0.0", clientVersion: "2.0.0" })) // version
      .mockResolvedValueOnce(jsonRes({ data: { token: "t1" } })) // token_by_phone_password
      .mockResolvedValueOnce(jsonRes({ data: { token: "t2" } })) // grant
      .mockResolvedValueOnce(jsonRes({ data: { token: "t3", uid: "10001" } })) // getToken
      .mockResolvedValueOnce(jsonRes({ secret: "s1" })) // /account/login
      .mockResolvedValueOnce(jsonRes({ user: { status: { uid: "10001", nickName: "A" }, troop: {} } })); // syncData
    const data = await syncPlayerData("13800000000", "pwd");
    expect(data.status.uid).toBe("10001");
    expect(data.status.nickName).toBe("A");
    expect(fetchMock).toHaveBeenCalledTimes(6);
  });
});
