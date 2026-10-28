import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ADMIN_TOKEN, report, startApp } from "./test-app.ts";

// Contract tests (ADR 0014): every response the API sends must match openapi.json.

type Spec = {
  info: { version: string };
  paths: Record<string, Record<string, { responses: Record<string, { $ref?: string; content?: Record<string, { schema: object }> }> }>>;
  components: { responses: Record<string, { content: Record<string, { schema: object }> }> };
};

const spec = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Spec;
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(spec, "openapi");

const docsDir = mkdtempSync(join(tmpdir(), "attacksim-docs-"));
writeFileSync(join(docsDir, "index.html"), "<!doctype html><title>API</title>");

let app: Awaited<ReturnType<typeof startApp>>;
let base: string;
const covered = new Set<string>();

beforeAll(async () => {
  app = await startApp({ version, openapi: spec, docsDir });
  base = app.base;
});

afterAll(() => app.close());

/** Calls the API and checks status, content type and body against the description. */
async function call(method: string, path: string, init: RequestInit = {}, concrete = path) {
  const res = await fetch(base + concrete, { ...init, method });
  const operation = spec.paths[path]?.[method.toLowerCase()];
  expect(operation, `${method} ${path} is not in openapi.json`).toBeDefined();
  covered.add(`${method} ${path}`);

  const declared = operation!.responses[String(res.status)];
  expect(declared, `${method} ${concrete} answered ${res.status}, which openapi.json does not list`).toBeDefined();
  const shared = declared!.$ref?.split("/").pop();
  const response = shared ? spec.components.responses[shared]! : declared!;
  const at = shared
    ? `openapi#/components/responses/${shared}`
    : `openapi#/paths/${path.replaceAll("/", "~1")}/${method.toLowerCase()}/responses/${res.status}`;

  if (!response.content) {
    expect(res.headers.get("content-length") ?? "0", `${method} ${path} ${res.status} should have no body`).toBe("0");
    return { res, body: undefined };
  }
  const type = res.headers.get("content-type")!.split(";")[0]!;
  expect(response.content?.[type], `${method} ${path} ${res.status} sent ${type}, which openapi.json does not list`).toBeDefined();

  const body = type.endsWith("json") ? await res.json() : await res.text();
  const schema = `${at}/content/${type.replace("/", "~1")}/schema`;
  const validate = ajv.getSchema(schema)!;
  expect(validate, `no schema at ${schema}`).toBeDefined();
  expect(validate(body), JSON.stringify(validate.errors)).toBe(true);
  return { res, body: body as any };
}

const auth = (token: string, body?: unknown) => ({
  headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
  ...(body !== undefined && { body: typeof body === "string" ? body : JSON.stringify(body) }),
});
const admin = (body?: unknown) => auth(ADMIN_TOKEN, body);
const anyone = (body?: unknown) => ({ headers: { "content-type": "application/json" }, ...(body !== undefined && { body: JSON.stringify(body) }) });

describe("openapi.json", () => {
  it("has the version of this release", () => {
    expect(spec.info.version).toBe(version);
  });

  it("is served with the running version", async () => {
    const served = (await (await fetch(`${base}/api/openapi.json`)).json()) as Spec;
    expect(served.info.version).toBe(version);
    expect(Object.keys(served.paths).filter((p) => !p.startsWith("/api/v1/auth/"))).toEqual(Object.keys(spec.paths));
    expect(served.paths["/api/v1/auth/login"]).toBeDefined();
  });

  it("serves the API reference at /api/docs/", async () => {
    expect((await fetch(`${base}/api/docs`, { redirect: "manual" })).headers.get("location")).toBe("/api/docs/");
    const res = await fetch(`${base}/api/docs/`);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect((await fetch(`${base}/api/docs/../../package.json`)).status).not.toBe(200);
  });
});

describe("responses match openapi.json", () => {
  let secret = "";
  let tokenId = "";
  let hostId = "";
  let runId = "";
  let stepId = "";
  const agent = (body: unknown) => auth(secret, body);

  it("product and health", async () => {
    await call("GET", "/api/v1/version");
    await call("GET", "/api/v1/products", admin());
    await call("GET", "/api/v1/summary", admin());
    await call("GET", "/api/v1/tests", admin());
    await call("GET", "/api/v1/coverage", admin());
    await call("GET", "/healthz");
    await call("GET", "/readyz");
    await call("GET", "/metrics");
  });

  it("enrolment, allowing, and the agent", async () => {
    const t = await call("POST", "/api/v1/enrollment-tokens", admin({ name: "hosts", maxUses: 2 }));
    tokenId = t.body.id;
    await call("POST", "/api/v1/enrollment-tokens", admin({ name: "x", maxUses: -1 }));
    await call("POST", "/api/v1/enrollment-tokens", anyone({ name: "x" }));
    await call("GET", "/api/v1/enrollment-tokens", admin());

    const e = await call("POST", "/api/v1/agent/enroll", anyone({ token: t.body.token, name: "sim-host-01", report: report() }));
    secret = e.body.secret;
    hostId = ((await (await app.admin("/api/v1/hosts")).json()) as { hosts: Array<{ id: string }> }).hosts[0]!.id;
    await call("POST", "/api/v1/agent/enroll", anyone({ token: "nope", name: "x", report: report() }));
    await call("POST", "/api/v1/agent/enroll", anyone({ token: t.body.token, name: "sim-host-01", report: report() })); // 409 name taken

    await call("GET", "/api/v1/hosts", admin());
    await call("PUT", "/api/v1/hosts/{id}/allow", admin({ allowed: true }), `/api/v1/hosts/${hostId}/allow`); // 422 no reason
    await call("PUT", "/api/v1/hosts/{id}/allow", admin({ allowed: true, reason: "lab host, safe to attack" }), `/api/v1/hosts/${hostId}/allow`);
  });

  it("a run and its steps", async () => {
    const r = await call("POST", "/api/v1/runs", admin({ name: "contract", hostId, tests: ["discovery-whoami", "c2-dns-marker-lookup"] }));
    runId = r.body.id;
    await call("POST", "/api/v1/runs", admin({ hostId, tests: ["nope"] })); // 422
    await call("GET", "/api/v1/runs", admin());
    await call("GET", "/api/v1/runs/{id}", admin(), `/api/v1/runs/${runId}`);
    await call("GET", "/api/v1/runs/{id}", admin(), "/api/v1/runs/does-not-exist"); // 404

    const got = (await (await fetch(`${base}/api/v1/agent/assignments`, { method: "POST", ...agent({ report: report() }) })).json()) as {
      assignments: Array<{ stepId: string }>;
    };
    stepId = got.assignments[0]!.stepId;
    // The agent endpoints, with the agent's own secret.
    await call("POST", "/api/v1/agent/assignments", agent({ report: report() }));
    await call("POST", "/api/v1/agent/results", agent({ report: report(), stepId, status: "done", did: "ran it", cleanedUp: true }));
    await call("POST", "/api/v1/agent/results", agent({ report: report(), stepId: "nope", status: "done" })); // 404
    await call("POST", "/api/v1/agent/results", agent({ report: report(), stepId, status: "weird" })); // 422
    await call("POST", "/api/v1/agent/assignments", { headers: { authorization: "Bearer aia_wrong" } }); // 401

    await call("POST", "/api/v1/runs/{id}/cancel", admin(), `/api/v1/runs/${runId}/cancel`);
  });

  it("deletes the token and the host", async () => {
    await call("DELETE", "/api/v1/enrollment-tokens/{id}", admin(), `/api/v1/enrollment-tokens/${tokenId}`);
    await call("DELETE", "/api/v1/hosts/{id}", admin(), `/api/v1/hosts/${hostId}`);
    await call("DELETE", "/api/v1/hosts/{id}", admin(), "/api/v1/hosts/gone"); // 404
  });

  it("covers every operation in openapi.json", () => {
    const all = Object.entries(spec.paths).flatMap(([p, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${p}`));
    expect([...all].sort().filter((o) => !covered.has(o))).toEqual([]);
  });
});
