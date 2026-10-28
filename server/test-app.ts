// Starts the app on a random port for tests, with a clock the tests move, and helpers that speak as an agent does.
import { createServer, type RequestListener, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { createAuth } from "@openasy/auth";
import { createAgents } from "./agents.ts";
import { createApp, type AppOptions } from "./app.ts";
import { openDb } from "./db.ts";
import { createRuns } from "./runs.ts";

export const ADMIN_TOKEN = "test-admin-token";
export const T0 = Date.parse("2026-10-28T13:00:00Z");

export const report = (over: Record<string, unknown> = {}) => ({
  version: "0.1.0",
  os: "Ubuntu 24.04.1 LTS",
  kernel: "6.8.0-45-generic",
  arch: "x64",
  packIds: ["discovery-whoami", "discovery-system-info", "discovery-account", "defense-evasion-marker-file", "c2-dns-marker-lookup", "execution-eicar-file"],
  ...over,
});

export async function startApp(opts: Partial<AppOptions> & { version: string; cooldownSeconds?: number } = { version: "0.1.0" }) {
  const db = openDb(":memory:");
  let now = T0;
  const clock = () => now;
  const { cooldownSeconds = 0, ...appOptions } = opts;
  const agents = createAgents(db, { version: opts.version, clock });
  const runs = createRuns(db, agents, { clock, cooldownSeconds });
  // The origin is known once the port is, so the handler is set after listening.
  let handler: RequestListener = (_req, res) => res.writeHead(503).end();
  const server: Server = createServer((req, res) => handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  const auth = createAuth({ db, product: "attack-simulation", productName: "OpenAsy Attack Simulation", origin: base });
  handler = createApp({ db, agents, runs, auth, adminToken: ADMIN_TOKEN, ...appOptions });
  const as =
    (token: string) =>
    (path: string, init: RequestInit = {}) =>
      fetch(base + path, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...init.headers } });
  const admin = as(ADMIN_TOKEN);
  const get = async (path: string) => (await (await admin(path)).json()) as any;
  const send = (method: string, path: string, body?: unknown) => admin(path, { method, ...(body !== undefined && { body: JSON.stringify(body) }) });

  /** Makes a token and enrols a host with it, as the agent does on its first start. */
  async function enrol(name = "sim-host-01", over: Record<string, unknown> = {}) {
    const { token } = (await (await send("POST", "/api/v1/enrollment-tokens", { name: `for ${name}` })).json()) as { token: string };
    const res = await fetch(`${base}/api/v1/agent/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token, name, report: report(over) }),
    });
    const { hostId, secret } = (await res.json()) as { hostId: string; secret: string };
    const agent = as(secret);
    return {
      hostId,
      secret,
      allow: (reason = "staging host owned by the security team, safe to attack") => send("PUT", `/api/v1/hosts/${hostId}/allow`, { allowed: true, reason }),
      assignments: () => agent("/api/v1/agent/assignments", { method: "POST", body: JSON.stringify({ report: report(over) }) }),
      result: (body: Record<string, unknown>) => agent("/api/v1/agent/results", { method: "POST", body: JSON.stringify({ report: report(over), ...body }) }),
    };
  }
  const close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return { db, agents, runs, auth, base, admin, as, get, send, enrol, close, later: (ms: number) => (now += ms) };
}
