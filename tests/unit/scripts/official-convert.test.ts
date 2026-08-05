import { describe, it, expect } from "vitest";
import { convertOfficialData } from "../../../scripts/official-convert";

describe("convertOfficialData", () => {
  it("应保留官服主体字段并替换 uid", () => {
    const data = convertOfficialData(
      {
        status: { uid: "10001", nickName: "A", level: 60 },
        troop: { chars: {} },
        dungeon: { stages: {} },
      } as any,
      { newUid: "3001", template: {} as any },
    );
    expect(data.status.uid).toBe("3001");
    expect(data.status.nickName).toBe("A");
    expect(data.troop).toBeDefined();
    expect(data.dungeon).toBeDefined();
  });

  it("私服特有字段应从模板兜底", () => {
    const template = {
      recruit: { normal: { slots: {} } },
      checkIn: { canCheckIn: 0 },
      openServer: { checkIn: { isAvailable: false } },
    };
    const data = convertOfficialData(
      { status: { uid: "10001" } } as any,
      { newUid: "3001", template: template as any },
    );
    expect(data.recruit).toEqual(template.recruit);
    expect(data.checkIn).toEqual(template.checkIn);
    expect(data.openServer).toEqual(template.openServer);
  });

  it("官方已有私服特有字段时应优先保留官方数据", () => {
    const template = { recruit: { normal: { slots: { "0": { state: 1 } } } } };
    const officialRecruit = { normal: { slots: { "0": { state: 3 } } } };
    const data = convertOfficialData(
      { status: { uid: "10001" }, recruit: officialRecruit } as any,
      { newUid: "3001", template: template as any },
    );
    expect(data.recruit).toEqual(officialRecruit);
  });

  it("应移除官服连接态字段", () => {
    const data = convertOfficialData(
      { status: { uid: "10001" }, secret: "s", seqnum: 1 } as any,
      { newUid: "3001", template: {} as any },
    );
    expect(data.secret).toBeUndefined();
    expect(data.seqnum).toBeUndefined();
  });

  it("不应修改模板对象（深拷贝）", () => {
    const template = { recruit: { normal: { slots: {} } } };
    const data = convertOfficialData(
      { status: { uid: "10001" } } as any,
      { newUid: "3001", template: template as any },
    );
    data.recruit.normal.slots["x"] = 1;
    expect(template.recruit.normal.slots).toEqual({});
  });
});
