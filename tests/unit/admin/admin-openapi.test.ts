import { describe, it, expect } from "vitest";
import { buildOpenApi, type OpenApiDocument } from "@ops/admin/openapi";

describe("buildOpenApi", () => {
  it("应生成 OpenAPI 3.0 文档且路径参数转为 {param} 模板", () => {
    const doc: OpenApiDocument = buildOpenApi();
    expect(doc.openapi).toBe("3.0.3");
    expect(doc.info.title).toContain("DoctorateTs");
    expect(doc.paths["/api/users/{uid}"]).toBeDefined();
    expect(doc.paths["/api/pools/{poolId}"]).toBeDefined();
    // 认证声明
    expect(doc.components.securitySchemes.adminToken).toEqual({
      type: "apiKey",
      in: "header",
      name: "X-Admin-Token",
    });
  });

  it("POST 端点应带请求体示例", () => {
    const doc: OpenApiDocument = buildOpenApi();
    const op = doc.paths["/api/users/{uid}/grant"].post;
    expect(op.summary).toBeDefined();
    expect(op.requestBody!.content["application/json"].example).toEqual({
      itemId: "4001",
      count: 100,
    });
  });

  it("GET 端点声明的参数应转 query 参数", () => {
    const doc: OpenApiDocument = buildOpenApi();
    const op = doc.paths["/api/logs"].get;
    expect(op.parameters.some((p) => p.name === "limit" && p.in === "query")).toBe(
      true,
    );
  });
});
