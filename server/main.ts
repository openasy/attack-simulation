import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createAuth, oidcFromEnv, readSecretsKey } from "@openasy/auth";
import { createAgents } from "./agents.ts";
import { createApp, createMetricsHandler } from "./app.ts";
import { openDb } from "./db.ts";
import { createChecker, parseDetectors } from "./detect.ts";
import { log } from "./log.ts";
import { parseProducts } from "./products.ts";
import { createRuns } from "./runs.ts";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const port = Number(process.env.PORT ?? 8080);
const dbPath = process.env.ATTACKSIM_DB ?? "/data/attack-simulation.db";
const webDir = new URL("../dist/web", import.meta.url).pathname;
const docsDir = new URL("../dist/docs", import.meta.url).pathname;
const openapi = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Record<string, unknown>;
const headless = process.env.ATTACKSIM_HEADLESS === "true";
// Set it to keep /metrics off the port that is published or behind an ingress (ADR 0026).
const metricsPort = process.env.ATTACKSIM_METRICS_PORT ? Number(process.env.ATTACKSIM_METRICS_PORT) : undefined;
const number = (name: string, fallback: number, min: number, max: number) => {
  const v = Number(process.env[name] ?? fallback);
  if (!Number.isInteger(v) || v < min || v > max) throw new Error(`${name} must be a whole number from ${min} to ${max}`);
  return v;
};
const cooldownSeconds = number("ATTACKSIM_RUN_COOLDOWN", 60, 0, 86_400);

const db = openDb(dbPath);
// The address people and agents open Attack Simulation at, behind the TLS proxy (ADR 0026).
const publicUrl = (process.env.ATTACKSIM_PUBLIC_URL ?? `http://localhost:${port}`).replace(/\/$/, "");
const secretsKeyFile = process.env.ATTACKSIM_SECRETS_KEY_FILE ?? "/run/secrets/openasy-kek";
const secretsKey = readSecretsKey(secretsKeyFile);
const auth = createAuth({
  db,
  product: "attack-simulation",
  productName: "OpenAsy Attack Simulation",
  origin: publicUrl,
  // Locally the same install is often opened as 127.0.0.1 too.
  trustedOrigins: publicUrl.startsWith("http://localhost:") ? [publicUrl.replace("localhost", "127.0.0.1")] : [],
  passwords: process.env.ATTACKSIM_PASSWORD_SIGN_IN !== "false",
  oidc: oidcFromEnv(process.env, "ATTACKSIM_"),
  secretsKey,
  // Audit log (ADR 0013): every sign-in, failure and change to members and tokens.
  onEvent: (event) => log(event.type === "sign-in-failed" ? "warn" : "info", "auth", { event }),
});
const products = parseProducts(process.env.OPENASY_PRODUCTS);
if (products.invalid.length) log("warn", "OPENASY_PRODUCTS: left out entries that are not id=https://address", { entries: products.invalid });

const clock = Date.now;
const agents = createAgents(db, { version, clock });
const runs = createRuns(db, agents, { clock, cooldownSeconds });
const { detectors, invalid } = parseDetectors(process.env.ATTACKSIM_DETECTORS);
if (invalid.length) log("warn", "ATTACKSIM_DETECTORS: left out entries that are not siem|runtime=https://address|token", { entries: invalid });
if (!detectors.length) log("warn", "no detectors set: steps run but their outcome stays pending. Set ATTACKSIM_DETECTORS to read SIEM and Runtime (ADR 0072)");
const checker = createChecker(runs, detectors);

const server = createServer(
  createApp({
    db,
    agents,
    runs,
    version,
    auth,
    webDir: !headless && existsSync(webDir) ? webDir : undefined,
    docsDir: existsSync(docsDir) ? docsDir : undefined,
    openapi,
    serveMetrics: metricsPort === undefined,
    products: products.products,
  }),
);
const metricsServer = metricsPort !== undefined ? createServer(createMetricsHandler({ agents, runs }, version)) : undefined;
metricsServer?.listen(metricsPort, () => log("info", "metrics on their own port", { port: metricsPort }));

server.listen(port, () => log("info", "attack-simulation started", { version, port, db: dbPath, headless, detectors: detectors.map((d) => d.product) }));
if (!publicUrl.startsWith("https://") && !/^http:\/\/(localhost|127\.0\.0\.1)(:|$)/.test(publicUrl)) {
  log("warn", "ATTACKSIM_PUBLIC_URL is not https: browsers will not keep secure cookies or allow passkeys. Put it behind TLS (ADR 0026)", { url: publicUrl });
}
if (!secretsKey) log("warn", "no secrets key: TOTP secrets are stored unencrypted. Mount a 32-byte key (openssl rand -hex 32)", { file: secretsKeyFile });
const setup = auth.setupLink();
// No default password (ADR 0013): the first person to open this link becomes the owner.
if (setup) log("info", "no owner yet: open this link once to create the owner account", { url: setup });

// One detection sweep at a time, so a slow detector never has two in flight.
let sweeping = false;
const sweep = () => {
  if (sweeping) return;
  sweeping = true;
  void checker
    .sweep()
    .catch((err: unknown) => log("error", "detection check", { error: String(err) }))
    .finally(() => (sweeping = false));
};
const timers: NodeJS.Timeout[] = [setInterval(() => auth.purge(), 5 * 60_000), setInterval(sweep, 10_000)];

function shutdown(signal: string) {
  log("info", "shutting down", { signal });
  for (const t of timers) clearInterval(t);
  metricsServer?.close();
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
