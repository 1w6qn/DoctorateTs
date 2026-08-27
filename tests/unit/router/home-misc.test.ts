import { describe, it, expect, vi } from "vitest";

vi.mock("express-http-context2", () => ({
  default: { get: vi.fn(), set: vi.fn() },
}));

import homeRouter from "../../../app/game/domain/router/home";
import httpContext from "express-http-context2";

function mockRes() {
  return { send: vi.fn(), status: vi.fn().mockReturnThis(), sendStatus: vi.fn(), json: vi.fn() };
}

async function call(req: any, res: any) {
  homeRouter(req, res, () => {});
  await new Promise((r) => setTimeout(r, 20));
  return res;
}

describe("home 路由（OBS misc_bp 移植端点）", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  function mockUpdate(draft: any) {
    const update = vi.fn(async (fn: (d: any) => void) => {
      fn(draft);
    });
    (vi.mocked(httpContext.get) as any).mockReturnValue({
      update,
      delta: { modified: {} },
    });
    return update;
  }

  it("firework/savePlateSlots 应写入 firework.plate.slots", async () => {
    const draft: any = { firework: { plate: {} } };
    mockUpdate(draft);
    const res = mockRes();
    await call({ method: "POST", url: "/firework/savePlateSlots", body: { slots: [{ x: 1 }] } }, res);
    expect(draft.firework.plate.slots).toEqual([{ x: 1 }]);
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });

  it("firework/changeAnimal 应写入 firework.animal.select 并回显 animal", async () => {
    const draft: any = { firework: { animal: {} } };
    mockUpdate(draft);
    const res = mockRes();
    await call({ method: "POST", url: "/firework/changeAnimal", body: { animal: "dog" } }, res);
    expect(draft.firework.animal.select).toBe("dog");
    expect(res.send).toHaveBeenCalledWith(expect.objectContaining({ animal: "dog", modified: {} }));
  });

  it("car/confirmBattleCar 应写入 car.battleCar", async () => {
    const draft: any = { car: {} };
    mockUpdate(draft);
    const res = mockRes();
    await call({ method: "POST", url: "/car/confirmBattleCar", body: { car: { carId: "car_1" } } }, res);
    expect(draft.car.battleCar).toEqual({ carId: "car_1" });
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });

  it("templateTrap/setTrapSquad 应写入 templateTrap.domains[id].squad 并回显", async () => {
    const draft: any = { templateTrap: { domains: { d1: {} } } };
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
    const draft: any = { troop: { chars: { "10": { charId: "char_1001" } } }, mission: {} };
    mockUpdate(draft);
    const res = mockRes();
    await call({ method: "POST", url: "/troop/pinSpecialOperator", body: { instId: "10" } }, res);
    expect(draft.mission.pinnedSpecialOperator).toBe("char_1001");
    expect(res.send).toHaveBeenCalledWith({ modified: {} });
  });
});
