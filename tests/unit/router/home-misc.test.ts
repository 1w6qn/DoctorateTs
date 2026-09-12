import { describe, it, expect, vi } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import type { Response } from "express";
import homeRouter from "@game/modules/home/routes";
import httpContext from "express-http-context2";

/** home 请求体视图（本文件各端点字段合集） */
interface HomeBody {
  slots?: { x?: number }[];
  animal?: string;
  car?: { carId?: string };
  trapDomainId?: string;
  trapSquad?: number[];
  instId?: string;
}

/** 路由测试请求视图（只声明被测分支读到的三个成员） */
interface MockReq {
  method: string;
  url: string;
  body: HomeBody;
}

/** 路由测试响应视图（只声明被测分支读到的四个方法） */
interface MockRes {
  send: Response["send"];
  status: Response["status"];
  sendStatus: Response["sendStatus"];
  json: Response["json"];
}

/** 各端点写入的 draft 夹具视图（每个用例只喂一棵子树，故取并集） */
interface FireworkPlateDraft {
  firework: { plate: { slots?: { x?: number }[] } };
}
interface FireworkAnimalDraft {
  firework: { animal: { select?: string } };
}
interface CarDraft {
  car: { battleCar?: { carId?: string } };
}
interface TemplateTrapDraft {
  templateTrap: { domains: { [domainId: string]: { squad?: number[] } } };
}
interface TroopDraft {
  troop: { chars: { [instId: string]: { charId?: string } } };
  mission: { pinnedSpecialOperator?: string };
}
type HomeDraftFixture =
  | FireworkPlateDraft
  | FireworkAnimalDraft
  | CarDraft
  | TemplateTrapDraft
  | TroopDraft;

type RouterReq = Parameters<typeof homeRouter>[0];

function mockRes(): MockRes {
  return {
    send: vi.fn<Response["send"]>(),
    status: vi.fn<Response["status"]>().mockReturnThis(),
    sendStatus: vi.fn<Response["sendStatus"]>(),
    json: vi.fn<Response["json"]>(),
  };
}

async function call(req: MockReq, res: MockRes): Promise<MockRes> {
  // mock 请求/响应只覆盖被测分支用到的成员，故按窄视图断言为 express Request/Response
  homeRouter(req as RouterReq, res as Response, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("home 路由（OBS misc_bp 移植端点）", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  function mockUpdate(draft: HomeDraftFixture) {
    const update = vi.fn<(recipe: (draft: HomeDraftFixture) => void) => Promise<void>>(async (recipe) => {
      recipe(draft);
    });
    vi.mocked(httpContext.get).mockReturnValue({
      update,
      delta: { modified: {} },
    });
    return update;
  }

  it("firework/savePlateSlots 应写入 firework.plate.slots", async () => {
    const draft: FireworkPlateDraft = { firework: { plate: {} } };
    mockUpdate(draft);
    const res = mockRes();
    await call({ method: "POST", url: "/firework/savePlateSlots", body: { slots: [{ x: 1 }] } }, res);
    expect(draft.firework.plate.slots).toEqual([{ x: 1 }]);
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });

  it("firework/changeAnimal 应写入 firework.animal.select 并回显 animal", async () => {
    const draft: FireworkAnimalDraft = { firework: { animal: {} } };
    mockUpdate(draft);
    const res = mockRes();
    await call({ method: "POST", url: "/firework/changeAnimal", body: { animal: "dog" } }, res);
    expect(draft.firework.animal.select).toBe("dog");
    expect(res.send).toHaveBeenCalledWith(expect.objectContaining({ animal: "dog", modified: {} }));
  });

  it("car/confirmBattleCar 应写入 car.battleCar", async () => {
    const draft: CarDraft = { car: {} };
    mockUpdate(draft);
    const res = mockRes();
    await call({ method: "POST", url: "/car/confirmBattleCar", body: { car: { carId: "car_1" } } }, res);
    expect(draft.car.battleCar).toEqual({ carId: "car_1" });
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });

  it("templateTrap/setTrapSquad 应写入 templateTrap.domains[id].squad 并回显", async () => {
    const draft: TemplateTrapDraft = { templateTrap: { domains: { d1: {} } } };
    mockUpdate(draft);
    const res = mockRes();
    await call(
      { method: "POST", url: "/templateTrap/setTrapSquad", body: { trapDomainId: "d1", trapSquad: [1, 2] } },
      res,
    );
    expect(draft.templateTrap.domains.d1.squad).toEqual([1, 2]);
    expect(res.send).toHaveBeenCalledWith(
      expect.objectContaining({ trapDomainId: "d1", trapSquad: [1, 2], modified: {} }),
    );
  });

  it("troop/pinSpecialOperator 应写入 mission.pinnedSpecialOperator", async () => {
    const draft: TroopDraft = { troop: { chars: { "10": { charId: "char_1001" } } }, mission: {} };
    mockUpdate(draft);
    const res = mockRes();
    await call({ method: "POST", url: "/troop/pinSpecialOperator", body: { instId: "10" } }, res);
    expect(draft.mission.pinnedSpecialOperator).toBe("char_1001");
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });
});
