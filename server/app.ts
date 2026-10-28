import { timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { extname, join, normalize } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { AuthError, identityOrigin, mergeOpenApi, sendProblem, type Auth, type Role } from "@openasy/auth";
import { parseReport, type Agents, type HostRow } from "./agents.ts";
import { log } from "./log.ts";
import { countRequest, renderMetrics } from "./metrics.ts";
import { PACK } from "./pack.ts";
import { isObject, SimError, type ProblemCode } from "./problem.ts";
import type { ProductLink } from "./products.ts";
import type { Runs } from "./runs.ts";

export interface AppOptions {
  db: DatabaseSync;
  agents: Agents;
  runs: Runs;
  version: string;
  /** Sign-in, sessions, members and API tokens (ADR 0002, 0003). */
  auth: Auth;
  /** For tests and local scripts: one shared token with the admin role. main.ts never sets it. */
  adminToken?: string;
  /** Built web UI; omit to run headless (ADR 0018). */
  webDir?: string;
  /** Built API reference (Swagger UI), served at /api/docs. */
  docsDir?: string;
  /** The OpenAPI description, served at /api/openapi.json with this release's version. */
  openapi?: Record<string, unknown>;
  /** false when /metrics is served on its own port instead (ADR 0026). */
  serveMetrics?: boolean;
  /** The install's OpenAsy products and their addresses, from OPENASY_PRODUCTS, for the product switcher. */
  products?: ProductLink[];
}

type Gauged = Pick<AppOptions, "agents" | "runs">;

function metricsText({ runs }: Gauged, version: string) {
  const s = runs.summary();
  return renderMetrics(version, { hosts: s.hosts, runs: s.runs, techniques: s.techniques });
}

/** Serves only /metrics, for a port that is not exposed with the rest (ATTACKSIM_METRICS_PORT). */
export function createMetricsHandler(o: Gauged, version: string) {
  return (req: IncomingMessage, res: ServerResponse) => {
    if (new URL(req.url ?? "/", "http://localhost").pathname !== "/metrics") return problem(res, 404, "not-found");
    send(res, 200, metricsText(o, version), "text/plain; version=0.0.4");
  };
}

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".json": "application/json",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

// Identity keeps people's theme and language when they sign in through it; the pages read them there (ADR 0033).
const IDENTITY = identityOrigin(process.env);

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "content-security-policy": `default-src 'self'; connect-src 'self'${IDENTITY ? ` ${IDENTITY}` : ""}; img-src 'self' data:; style-src 'self' 'unsafe-inline'`,
};

function send(res: ServerResponse, status: number, body: string | Buffer, type = "application/json", headers: Record<string, string> = {}) {
  res.writeHead(status, { ...SECURITY_HEADERS, ...headers, "content-type": type, "content-length": Buffer.byteLength(body) });
  res.end(body);
}

const json = (res: ServerResponse, status: number, data: unknown) => send(res, status, JSON.stringify(data));

const TITLES: Record<ProblemCode, string> = {
  "invalid-token": "Invalid token",
  "invalid-json": "Invalid JSON",
  "invalid-body": "Invalid request body",
  "not-found": "Not found",
  conflict: "Conflict",
  "payload-too-large": "Payload too large",
  "internal-error": "Internal error",
};

/** RFC 9457 Problem Details (ADR 0014). `code` is the stable part clients match on. */
function problem(res: ServerResponse, status: number, code: ProblemCode, detail?: string) {
  const body = { type: `https://openasy.github.io/problems/${code}`, title: TITLES[code], status, code, ...(detail && { detail }) };
  send(res, status, JSON.stringify(body), "application/problem+json");
}

/** Serves a file from dir, or returns false when the path is outside it or missing. */
async function serveFile(res: ServerResponse, dir: string, relative: string): Promise<boolean> {
  const file = normalize(join(dir, relative));
  if (!file.startsWith(normalize(dir)) || !extname(file)) return false;
  try {
    send(res, 200, await readFile(file), TYPES[extname(file)] ?? "application/octet-stream");
    return true;
  } catch {
    return false;
  }
}

async function readJson(req: IncomingMessage, limit = 64 * 1024): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > 4 * limit) throw new SimError(413, "payload-too-large", `The body must be at most ${Math.round(limit / 1024)} KiB.`);
    if (size <= limit) chunks.push(chunk);
  }
  if (size > limit) throw new SimError(413, "payload-too-large", `The body must be at most ${Math.round(limit / 1024)} KiB.`);
  try {
    const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
    if (!isObject(body)) throw new Error("not an object");
    return body;
  } catch {
    throw new SimError(400, "invalid-json", "The body must be a JSON object.");
  }
}

function tokenMatches(header: string | undefined, expected: string | undefined): boolean {
  if (!expected || !header?.startsWith("Bearer ")) return false;
  const a = Buffer.from(header.slice(7));
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** The role a route needs (ADR 0003), or "agent" for attack-simulation-agent with its own secret. */
type Access = "none" | "agent" | Role;
interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  params: string[];
  body: () => Promise<Record<string, unknown>>;
  /** Who made the request, for the record of a decision. */
  actor: () => string;
  /** The calling agent's host, on agent routes. */
  host: () => HostRow;
}
interface Route {
  method: string;
  /** Path pattern; each `:name` matches one segment. */
  path: string;
  auth: Access;
  handle: (ctx: Ctx) => unknown;
}

export function createApp(o: AppOptions) {
  const { db, agents, runs, version, auth, adminToken, webDir, docsDir, openapi, serveMetrics = true, products = [] } = o;
  // The served description includes /api/v1/auth from @openasy/auth, so the API reference documents sign-in too.
  const spec = openapi && JSON.stringify({ ...mergeOpenApi(openapi), info: { ...(openapi.info as object), version } });
  const noContent = (res: ServerResponse) => {
    res.writeHead(204, SECURITY_HEADERS).end();
  };

  /** Every agent call carries the agent's report of itself; it is noted before anything else is kept. */
  const reported = (h: HostRow, b: Record<string, unknown>) => {
    if (isObject(b.report)) agents.saw(h, parseReport(b.report));
  };

  const routes: Route[] = [
    { method: "GET", path: "/api/v1/version", auth: "none", handle: () => ({ product: "attack-simulation", version }) },
    { method: "GET", path: "/api/v1/products", auth: "viewer", handle: () => ({ products }) },
    { method: "GET", path: "/api/v1/summary", auth: "viewer", handle: () => runs.summary() },

    // The fixed, reviewed pack of benign tests. Read-only: the pack is code, not data (ADR 0072).
    { method: "GET", path: "/api/v1/tests", auth: "viewer", handle: () => ({ tests: PACK }) },
    { method: "GET", path: "/api/v1/coverage", auth: "viewer", handle: () => runs.coverage() },

    // Runs: an admin starts one on an allowed host; a viewer reads them.
    { method: "GET", path: "/api/v1/runs", auth: "viewer", handle: () => ({ runs: runs.runs() }) },
    { method: "POST", path: "/api/v1/runs", auth: "admin", handle: async ({ res, body, actor }) => json(res, 201, runs.create(await body(), actor())) },
    { method: "GET", path: "/api/v1/runs/:id", auth: "viewer", handle: ({ params }) => runs.run(params[0]!) },
    { method: "POST", path: "/api/v1/runs/:id/cancel", auth: "admin", handle: ({ params, actor }) => runs.cancel(params[0]!, actor()) },

    // Hosts and the tokens their agents enrol with. Allowing a host for simulation is an admin decision, audited.
    { method: "GET", path: "/api/v1/hosts", auth: "viewer", handle: () => ({ hosts: agents.hosts() }) },
    {
      method: "PUT",
      path: "/api/v1/hosts/:id/allow",
      auth: "admin",
      handle: async ({ params, body, actor }) => agents.setAllowed(params[0]!, await body(), actor()),
    },
    {
      method: "DELETE",
      path: "/api/v1/hosts/:id",
      auth: "admin",
      handle: ({ res, params, actor }) => (agents.deleteHost(params[0]!, actor()), noContent(res)),
    },
    { method: "GET", path: "/api/v1/enrollment-tokens", auth: "admin", handle: () => ({ tokens: agents.tokens() }) },
    {
      method: "POST",
      path: "/api/v1/enrollment-tokens",
      auth: "admin",
      handle: async ({ res, body, actor }) => json(res, 201, agents.createToken(await body(), actor())),
    },
    { method: "DELETE", path: "/api/v1/enrollment-tokens/:id", auth: "admin", handle: ({ res, params }) => (agents.deleteToken(params[0]!), noContent(res)) },

    // What attack-simulation-agent calls. It asks and reports; the server never connects to it and sends it nothing
    // but a pack id and a marker, never a command (ADR 0023, 0072).
    { method: "POST", path: "/api/v1/agent/enroll", auth: "none", handle: async ({ body }) => agents.enroll(await body()) },
    {
      method: "POST",
      path: "/api/v1/agent/assignments",
      auth: "agent",
      handle: async ({ host, body }) => {
        const h = host();
        reported(h, await body());
        return { assignments: runs.assignments(h) };
      },
    },
    {
      method: "POST",
      path: "/api/v1/agent/results",
      auth: "agent",
      handle: async ({ host, body }) => {
        const h = host();
        const b = await body();
        reported(h, b);
        return runs.result(h, b);
      },
    },
  ];

  const compiled = routes.map((r) => ({ ...r, re: new RegExp(`^${r.path.replace(/:[A-Za-z]+/g, "([^/]+)")}$`) }));

  /** Returns who is calling, or null on routes anyone or an agent calls. */
  function authorize(req: IncomingMessage, access: Access): string | null {
    if (access === "none" || access === "agent") return null;
    if (tokenMatches(req.headers.authorization, adminToken)) return "admin token";
    const p = auth.authorize(req, access);
    return p.kind === "session" ? p.user.name : `API token ${p.name}`;
  }

  async function route(req: IncomingMessage, res: ServerResponse): Promise<string> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;

    if (path === "/healthz") return (json(res, 200, { status: "ok" }), "/healthz");

    if (path === "/readyz") {
      try {
        db.prepare("SELECT 1").get();
        json(res, 200, { status: "ready" });
      } catch {
        json(res, 503, { status: "database unavailable" });
      }
      return "/readyz";
    }

    if (path === "/metrics") {
      if (serveMetrics) send(res, 200, metricsText(o, version), "text/plain; version=0.0.4");
      else problem(res, 404, "not-found");
      return "/metrics";
    }

    if (path === "/api/openapi.json" && spec) return (send(res, 200, spec), "/api/openapi.json");

    if (docsDir && (path === "/api/docs" || path.startsWith("/api/docs/"))) {
      if (path === "/api/docs") {
        res.writeHead(301, { ...SECURITY_HEADERS, location: "/api/docs/" }).end();
        return "/api/docs";
      }
      const relative = path.slice("/api/docs/".length) || "index.html";
      if (!(await serveFile(res, docsDir, relative))) problem(res, 404, "not-found");
      return "/api/docs";
    }

    if (await auth.handle(req, res)) return auth.routeName(req) ?? "/api/v1/auth/*";

    for (const r of compiled) {
      const m = path.match(r.re);
      if (!m || r.method !== req.method) continue;
      try {
        const who = authorize(req, r.auth);
        const host = r.auth === "agent" ? agents.hostBySecret(req.headers.authorization) : undefined;
        const params = m.slice(1).map(decodeURIComponent);
        const result = await r.handle({
          req,
          res,
          url,
          params,
          body: () => readJson(req),
          actor: () => who ?? "unknown",
          host: () => host!,
        });
        if (!res.headersSent && result !== undefined) json(res, 200, result);
      } catch (err) {
        if (err instanceof AuthError) {
          sendProblem(res, err);
          if (!req.complete) req.resume();
          return r.path;
        }
        if (!(err instanceof SimError)) throw err;
        problem(res, err.status, err.code, err.message);
        if (!req.complete) req.resume();
      }
      return r.path;
    }

    if (path.startsWith("/api/")) return (problem(res, 404, "not-found"), "/api/*");

    if (webDir && (req.method === "GET" || req.method === "HEAD")) {
      if (!(await serveFile(res, webDir, path === "/" ? "index.html" : path))) send(res, 200, await readFile(join(webDir, "index.html")), TYPES[".html"]);
      return "/web";
    }

    problem(res, 404, "not-found");
    return "unmatched";
  }

  return async (req: IncomingMessage, res: ServerResponse) => {
    const started = performance.now();
    let routeName = "error";
    try {
      routeName = await route(req, res);
    } catch (err) {
      log("error", "request failed", { error: String(err), path: req.url });
      if (!res.headersSent) problem(res, 500, "internal-error");
    }
    countRequest(req.method ?? "GET", routeName, res.statusCode);
    // Agent calls arrive every few seconds; they are counted in /metrics, not logged one by one.
    if (routeName !== "/healthz" && routeName !== "/metrics" && !routeName.startsWith("/api/v1/agent/")) {
      log("info", "request", { method: req.method, path: reqPath(req), status: res.statusCode, ms: Math.round(performance.now() - started) });
    }
  };
}

/** The path without the query string. */
const reqPath = (req: IncomingMessage) => (req.url ?? "/").split("?")[0];
