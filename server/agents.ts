// Hosts and how their agents get in (ADR 0021, 0023, 0032), the same way as runtime-agent and siem-agent. An admin
// makes an enrolment token for one host or a fleet; attack-simulation-agent trades it once for a secret of its own,
// which speaks for its host and no other. The server keeps only hashes of both, never connects to an agent, and sends
// an agent nothing but the pack ids of the tests a run asked for (never a command). A host runs nothing until an admin
// marks it allowed for simulation, with a reason, which is written to the audit log (ADR 0013).
import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import { log } from "./log.ts";
import { bad, conflict, isObject, notFound, only, SimError } from "./problem.ts";

export interface HostRow {
  id: string;
  name: string;
  secret_hash: string;
  token_id: string | null;
  version: string;
  os: string | null;
  kernel: string | null;
  arch: string | null;
  pack_ids: string;
  allowed: number;
  allow_reason: string | null;
  allowed_by: string | null;
  allowed_at: string | null;
  enrolled_at: string;
  last_seen_at: string;
}

interface TokenRow {
  id: string;
  name: string;
  token_hash: string;
  max_uses: number;
  uses: number;
  expires_at: string;
  created_by: string;
  created_at: string;
}

export type HostStatus = "allowed" | "paused" | "silent";

/** A Kubernetes node name or a host name. */
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$/;
const TOKEN_NAME = /^[^\u0000-\u001f]{1,100}$/;
const DAY = 86_400_000;
/** An agent polls every few seconds; two minutes without a word is silence. */
export const SILENT_MS = 2 * 60_000;
const MAX_PACK_IDS = 256;
const PACK_ID = /^[a-z][a-z0-9-]{0,63}$/;

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

export interface Report {
  version: string;
  os: string | null;
  kernel: string | null;
  arch: string | null;
  packIds: string[] | null;
}

const text = (v: unknown, max: number, name: string): string | null => {
  if (v === undefined || v === null || v === "") return null;
  if (typeof v !== "string" || v.length > max) throw bad(`${name} is text of at most ${max} characters.`);
  return v;
};

/** What every agent call carries about the agent itself, as `report`. */
export function parseReport(b: Record<string, unknown>): Report {
  only(b, ["version", "os", "kernel", "arch", "packIds"], "{ version, os, kernel, arch, packIds }");
  if (typeof b.version !== "string" || !/^\d+\.\d+\.\d+[\w.+-]*$/.test(b.version) || b.version.length > 32)
    throw bad("version is the agent's version, such as 0.1.0.");
  let packIds: string[] | null = null;
  if (b.packIds !== undefined) {
    if (!Array.isArray(b.packIds) || b.packIds.length > MAX_PACK_IDS || b.packIds.some((p) => typeof p !== "string" || !PACK_ID.test(p)))
      throw bad(`packIds is a list of at most ${MAX_PACK_IDS} pack ids.`);
    packIds = b.packIds as string[];
  }
  return {
    version: b.version,
    os: text(b.os, 128, "os"),
    kernel: text(b.kernel, 128, "kernel"),
    arch: text(b.arch, 32, "arch"),
    packIds,
  };
}

export interface AgentsOptions {
  /** The server's version: an agent of another one is noted (ADR 0019). */
  version: string;
  clock: () => number;
}

export function createAgents(db: DatabaseSync, o: AgentsOptions) {
  const iso = (t = o.clock()) => new Date(t).toISOString();

  // ---- Enrolment tokens -----------------------------------------------------------------------------------------

  const toToken = (t: TokenRow) => ({
    id: t.id,
    name: t.name,
    maxUses: t.max_uses,
    uses: t.uses,
    expiresAt: t.expires_at,
    state: (t.uses >= t.max_uses ? "used" : t.expires_at <= iso() ? "expired" : "active") as "active" | "used" | "expired",
    createdBy: t.created_by,
    createdAt: t.created_at,
  });

  function createToken(b: Record<string, unknown>, by: string) {
    only(b, ["name", "maxUses", "days"], "{ name, maxUses, days }");
    if (typeof b.name !== "string" || !TOKEN_NAME.test(b.name.trim())) throw bad("name says what the token is for, up to 100 characters.");
    const maxUses = b.maxUses ?? 1;
    if (typeof maxUses !== "number" || !Number.isInteger(maxUses) || maxUses < 1 || maxUses > 10_000)
      throw bad("maxUses is how many hosts may enrol with it: 1 for one host, up to 10000 for a fleet.");
    const days = b.days ?? 7;
    if (typeof days !== "number" || !Number.isInteger(days) || days < 1 || days > 30) throw bad("days is how long it is valid: 1 to 30.");
    const token = `aie_${randomBytes(24).toString("base64url")}`;
    const id = randomUUID();
    db.prepare("INSERT INTO enrollment_tokens (id, name, token_hash, max_uses, expires_at, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)").run(
      id,
      b.name.trim(),
      sha256(token),
      maxUses,
      iso(o.clock() + days * DAY),
      by,
      iso(),
    );
    log("info", "enrolment token created", { name: b.name.trim(), maxUses, days, by });
    // The token itself is shown this once (ADR 0021).
    return { ...toToken(db.prepare("SELECT * FROM enrollment_tokens WHERE id = ?").get(id) as unknown as TokenRow), token };
  }

  const tokens = () => (db.prepare("SELECT * FROM enrollment_tokens ORDER BY created_at DESC").all() as unknown as TokenRow[]).map(toToken);

  /** Ends a token at once. Hosts that enrolled with it keep their own secrets. */
  function deleteToken(id: string) {
    if (!db.prepare("DELETE FROM enrollment_tokens WHERE id = ?").run(id).changes) throw notFound("The enrolment token");
  }

  // ---- Hosts ------------------------------------------------------------------------------------------------------

  function statusOf(h: HostRow): HostStatus {
    if (Date.parse(h.last_seen_at) + SILENT_MS < o.clock()) return "silent";
    return h.allowed ? "allowed" : "paused";
  }

  function toHost(h: HostRow) {
    return {
      id: h.id,
      name: h.name,
      status: statusOf(h),
      version: h.version,
      outdated: h.version !== o.version,
      os: h.os,
      kernel: h.kernel,
      arch: h.arch,
      packIds: JSON.parse(h.pack_ids) as string[],
      allowed: !!h.allowed,
      allowReason: h.allow_reason,
      allowedBy: h.allowed_by,
      allowedAt: h.allowed_at,
      enrolledAt: h.enrolled_at,
      lastSeenAt: h.last_seen_at,
    };
  }

  const hostRows = () => db.prepare("SELECT * FROM hosts ORDER BY name").all() as unknown as HostRow[];
  const hosts = () => hostRows().map(toHost);

  function hostRow(id: string) {
    const h = db.prepare("SELECT * FROM hosts WHERE id = ?").get(id) as HostRow | undefined;
    if (!h) throw notFound("The host");
    return h;
  }

  const host = (id: string) => toHost(hostRow(id));

  /** Marks a host allowed for simulation, or pauses it. Allowing needs a reason; both are audited (ADR 0013). */
  function setAllowed(id: string, b: Record<string, unknown>, by: string) {
    only(b, ["allowed", "reason"], "{ allowed, reason }");
    if (typeof b.allowed !== "boolean") throw bad("allowed is true to let this host run simulations, or false to pause it.");
    const reason = b.reason;
    if (b.allowed && (typeof reason !== "string" || reason.trim().length < 3 || reason.length > 500))
      throw bad("reason is required to allow a host: 3 to 500 characters saying why this host may be attacked safely.");
    if (reason !== undefined && reason !== null && (typeof reason !== "string" || reason.length > 500)) throw bad("reason is text of at most 500 characters.");
    const h = hostRow(id);
    db.prepare("UPDATE hosts SET allowed = ?, allow_reason = ?, allowed_by = ?, allowed_at = ? WHERE id = ?").run(
      b.allowed ? 1 : 0,
      b.allowed ? (reason as string).trim() : typeof reason === "string" && reason.trim() ? reason.trim() : null,
      by,
      iso(),
      id,
    );
    // The decision to allow a host to be attacked is the most sensitive one here; it is always in the audit log.
    log("info", b.allowed ? "host allowed for simulation" : "host paused", { host: h.name, by, reason: b.allowed ? (reason as string).trim() : undefined });
    return host(id);
  }

  /** Ends the host's secret at once. Its runs and steps stay, under its name. */
  function deleteHost(id: string, by: string) {
    const h = hostRow(id);
    db.prepare("DELETE FROM hosts WHERE id = ?").run(id);
    log("info", "host removed", { host: h.name, by });
  }

  // ---- What agents call -------------------------------------------------------------------------------------------

  /** Trades an enrolment token for the host's own secret. A name already enrolled is refused: removing it is an admin's decision. */
  function enroll(b: Record<string, unknown>) {
    const token = typeof b.token === "string" ? b.token : "";
    const t = db.prepare("SELECT * FROM enrollment_tokens WHERE token_hash = ?").get(sha256(token)) as TokenRow | undefined;
    if (!t || t.uses >= t.max_uses || t.expires_at <= iso())
      throw new SimError(401, "invalid-token", "The enrolment token is unknown, used up or expired. Make a new one under Hosts.");
    if (typeof b.name !== "string" || !NAME.test(b.name)) throw bad("name is the host's name: letters, digits, dots, dashes and underscores.");
    if (!isObject(b.report)) throw bad("report is the agent's report of itself: { version, os, kernel, arch, packIds }.");
    const r = parseReport(b.report);
    if (db.prepare("SELECT 1 FROM hosts WHERE name = ?").get(b.name))
      throw conflict(`A host named ${b.name} is enrolled. Remove it under Hosts to enrol it again, for a lost volume or a leaked secret.`);
    const secret = `aia_${randomBytes(32).toString("base64url")}`;
    const id = randomUUID();
    db.exec("BEGIN");
    try {
      // Counted in the same statement that checks it, so two hosts racing for the last use cannot both have it.
      if (!db.prepare("UPDATE enrollment_tokens SET uses = uses + 1 WHERE id = ? AND uses < max_uses").run(t.id).changes)
        throw new SimError(401, "invalid-token", "The enrolment token is used up. Make a new one under Hosts.");
      db.prepare(
        `INSERT INTO hosts (id, name, secret_hash, token_id, version, os, kernel, arch, pack_ids, enrolled_at, last_seen_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(id, b.name, sha256(secret), t.id, r.version, r.os, r.kernel, r.arch, JSON.stringify(r.packIds ?? []), iso(), iso());
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
    // A host enrols read-only: it is not allowed to run anything until an admin says so, with a reason.
    log("info", "host enrolled", { host: b.name, version: r.version, token: t.name });
    return { hostId: id, secret };
  }

  /** The host whose agent sent this secret. */
  function hostBySecret(header: string | undefined): HostRow {
    const secret = header?.startsWith("Bearer aia_") ? header.slice(7) : "";
    const h = secret ? (db.prepare("SELECT * FROM hosts WHERE secret_hash = ?").get(sha256(secret)) as HostRow | undefined) : undefined;
    if (!h)
      throw new SimError(401, "invalid-token", "Unknown agent secret. The host was removed, or the agent's volume belongs to another server: enrol it again.");
    return h;
  }

  /** The agent's report of itself, which comes with every call. */
  function saw(h: HostRow, r: Report) {
    db.prepare("UPDATE hosts SET version = ?, os = ?, kernel = ?, arch = ?, pack_ids = COALESCE(?, pack_ids), last_seen_at = ? WHERE id = ?").run(
      r.version,
      r.os,
      r.kernel,
      r.arch,
      r.packIds ? JSON.stringify(r.packIds) : null,
      iso(),
      h.id,
    );
  }

  function counts() {
    const all = hostRows().map(statusOf);
    const by = (s: HostStatus) => all.filter((x) => x === s).length;
    return { total: all.length, allowed: by("allowed"), paused: by("paused"), silent: by("silent") };
  }

  return { createToken, tokens, deleteToken, hosts, host, hostRow, setAllowed, deleteHost, enroll, hostBySecret, saw, counts, statusOf };
}

export type Agents = ReturnType<typeof createAgents>;
