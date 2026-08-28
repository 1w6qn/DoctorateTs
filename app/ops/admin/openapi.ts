/**
 * OpenAPI 3.0 规范生成器
 *
 * 从 api-spec.ts 的 ADMIN_ENDPOINTS 自动生成管理 API 的 OpenAPI 文档
 * （GET /admin/api/openapi.json），供外部工具/Swagger UI 消费。
 * 路径参数（:uid → {uid}）与请求体示例自动转换。
 */
import { ADMIN_ENDPOINTS } from "./api-spec";

/** 生成 OpenAPI 3.0.3 文档对象 */
export function buildOpenApi(): object {
  const paths: { [key: string]: any } = {};
  for (const e of ADMIN_ENDPOINTS) {
    const pathKey = e.path.replace(/:([A-Za-z_]+)/g, "{$1}");
    const op: any = {
      summary: e.summary,
      parameters: [],
      responses: {
        "200": { description: "成功" },
        "400": { description: "参数错误" },
        "401": { description: "令牌无效或缺失" },
        "403": { description: "管理接口未启用" },
      },
    };
    // 路径参数
    for (const m of pathKey.matchAll(/\{([^}]+)\}/g)) {
      op.parameters.push({
        name: m[1],
        in: "path",
        required: true,
        schema: { type: "string" },
      });
    }
    // GET/DELETE 的声明参数 → query 参数
    if (e.method === "GET" || e.method === "DELETE") {
      for (const p of e.params ?? []) {
        op.parameters.push({
          name: p.name,
          in: "query",
          schema: { type: p.type === "number" ? "integer" : "string" },
          description: p.desc,
        });
      }
    }
    // POST 请求体示例
    if (e.body) {
      try {
        op.requestBody = {
          required: true,
          content: { "application/json": { example: JSON.parse(e.body) } },
        };
      } catch {
        // 非法示例 JSON 忽略
      }
    }
    paths[pathKey] = { [e.method.toLowerCase()]: op };
  }

  return {
    openapi: "3.0.3",
    info: {
      title: "DoctorateTs 管理 API",
      version: "1.0.0",
      description: "管理后台 REST API（X-Admin-Token 认证；admin.enable=true 时可用）",
    },
    security: [{ adminToken: [] }],
    components: {
      securitySchemes: {
        adminToken: { type: "apiKey", in: "header", name: "X-Admin-Token" },
      },
    },
    paths,
  };
}
