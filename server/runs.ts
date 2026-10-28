// Runs and their steps (ADR 0072). An admin starts a run on one allowed host with a chosen set of tests from the fixed
// pack; the run is rate-limited and tagged with a run id. The agent, pulling its work, is given only the pack id and a
// random marker for each step (never a command). When the agent reports what it did, the step waits the run's window
// and is then checked against the detecting products (detect.ts). Coverage is the roll-up of steps per technique.
import { randomBytes, randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { Agents, HostRow } from "./agents.ts";
import { log } from "./log.ts";
import { PACK, packById } from "./pack.ts";
import { bad, conflict, notFound, only } from "./problem.ts";

export type RunStatus = "pending" | "running" | "done" | "canceled";
export type StepStatus = "pending" | "running" | "done" | "error" | "refused";
export type Outcome = "pending" | "detected" | "missed" | "error";

interface RunRow {
  id: string;
  name: string;
  host_id: string;
  host: string;
  status: RunStatus;
  window_seconds: number;
  started_by: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

interface StepRow {
  id: string;
  run_id: string;
  host_id: string;
  host: string;
  pack_id: string;
  technique: string;
  technique_name: string;
  tactic: string;
  tactic_id: string;
  marker: string;
  status: StepStatus;
  outcome: Outcome;
  did: string | null;
  cleaned_up: number | null;
  detail: string | null;
  error: string | null;
  detections: string;
  ran_at: string | null;
  reported_at: string | null;
  checked_at: string | null;
  created_at: string;
}

export interface Detection {
  product: string;
  id: string;
  title: string;
  url: string | null;
  at: string;
}

const RUN_NAME = /^[^\u0000-\u001f]{1,100}$/;
const MIN_WINDOW = 30;
const MAX_WINDOW = 3600;

export interface RunsOptions {
  clock: () => number;
  /** Shortest gap between two runs on the same host, so simulation never floods a host (ADR 0072). */
  cooldownSeconds: number;
}

export function createRuns(db: DatabaseSync, agents: Agents, o: RunsOptions) {
  const iso = (t = o.clock()) => new Date(t).toISOString();

  const toStep = (s: StepRow) => ({
    id: s.id,
    runId: s.run_id,
    host: { id: s.host_id, name: s.host },
    test: { id: s.pack_id, technique: s.technique, techniqueName: s.technique_name, tactic: s.tactic, tacticId: s.tactic_id },
    status: s.status,
    outcome: s.outcome,
    marker: s.marker,
    did: s.did,
    cleanedUp: s.cleaned_up === null ? null : !!s.cleaned_up,
    detail: s.detail,
    error: s.error,
    detections: JSON.parse(s.detections) as Detection[],
    ranAt: s.ran_at,
    reportedAt: s.reported_at,
    checkedAt: s.checked_at,
  });

  const stepsOf = (runId: string) => (db.prepare("SELECT * FROM steps WHERE run_id = ? ORDER BY rowid").all(runId) as unknown as StepRow[]).map(toStep);

  function toRun(r: RunRow, withSteps = false) {
    const steps = stepsOf(r.id);
    const done = steps.filter((s) => s.status === "done" || s.status === "error" || s.status === "refused").length;
    const detected = steps.filter((s) => s.outcome === "detected").length;
    const missed = steps.filter((s) => s.outcome === "missed").length;
    return {
      id: r.id,
      name: r.name,
      host: { id: r.host_id, name: r.host },
      status: r.status,
      windowSeconds: r.window_seconds,
      total: steps.length,
      done,
      detected,
      missed,
      startedBy: r.started_by,
      createdAt: r.created_at,
      startedAt: r.started_at,
      finishedAt: r.finished_at,
      ...(withSteps && { steps }),
    };
  }

  const runRow = (id: string) => {
    const r = db.prepare("SELECT * FROM runs WHERE id = ?").get(id) as RunRow | undefined;
    if (!r) throw notFound("The run");
    return r;
  };

  const runs = () => (db.prepare("SELECT * FROM runs ORDER BY created_at DESC LIMIT 500").all() as unknown as RunRow[]).map((r) => toRun(r));
  const run = (id: string) => toRun(runRow(id), true);

  /** Starts a run: the host must be enrolled and allowed, the tests must be in the pack, and the host must be off cooldown. */
  function create(b: Record<string, unknown>, by: string) {
    only(b, ["name", "hostId", "tests", "windowSeconds"], "{ name, hostId, tests, windowSeconds }");
    if (b.name !== undefined && (typeof b.name !== "string" || !RUN_NAME.test(b.name.trim()))) throw bad("name is up to 100 characters.");
    if (typeof b.hostId !== "string") throw bad("hostId is the host to run on.");
    if (!Array.isArray(b.tests) || b.tests.length === 0 || b.tests.length > PACK.length || b.tests.some((t) => typeof t !== "string"))
      throw bad("tests is a non-empty list of pack ids to run.");
    const unknown = (b.tests as string[]).filter((id) => !packById.has(id));
    if (unknown.length) throw bad(`Unknown test ${unknown[0]}. Choose from the pack at GET /api/v1/tests.`);
    const windowSeconds = b.windowSeconds ?? 300;
    if (typeof windowSeconds !== "number" || !Number.isInteger(windowSeconds) || windowSeconds < MIN_WINDOW || windowSeconds > MAX_WINDOW)
      throw bad(`windowSeconds is how long a detector has to react: ${MIN_WINDOW} to ${MAX_WINDOW}.`);

    const h = agents.hostRow(b.hostId);
    if (!h.allowed) throw conflict(`${h.name} is not allowed for simulation. An admin must allow it, with a reason, under Hosts first.`);
    // One run at a time per host, and a cooldown between runs, so simulation never floods a host (ADR 0072).
    const active = db.prepare("SELECT 1 FROM runs WHERE host_id = ? AND status IN ('pending', 'running')").get(h.id);
    if (active) throw conflict(`${h.name} already has a run in progress. Wait for it to finish or cancel it.`);
    const last = db.prepare("SELECT MAX(created_at) AS t FROM runs WHERE host_id = ?").get(h.id) as { t: string | null };
    if (last.t && Date.parse(last.t) + o.cooldownSeconds * 1000 > o.clock())
      throw conflict(`${h.name} ran a simulation recently. Runs on one host are at least ${o.cooldownSeconds} seconds apart.`);

    const id = randomUUID();
    const name = typeof b.name === "string" && b.name.trim() ? b.name.trim() : `${(b.tests as string[]).length} tests on ${h.name}`;
    db.exec("BEGIN");
    try {
      db.prepare(
        "INSERT INTO runs (id, name, host_id, host, status, window_seconds, started_by, created_at, started_at) VALUES (?, ?, ?, ?, 'running', ?, ?, ?, ?)",
      ).run(id, name, h.id, h.name, windowSeconds, by, iso(), iso());
      const insert = db.prepare(
        `INSERT INTO steps (id, run_id, host_id, host, pack_id, technique, technique_name, tactic, tactic_id, marker, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      );
      for (const packId of b.tests as string[]) {
        const t = packById.get(packId)!;
        // The marker is a random hex label; the agent uses it only as a file or DNS name, never as a command.
        insert.run(randomUUID(), id, h.id, h.name, t.id, t.technique, t.techniqueName, t.tactic, t.tacticId, randomBytes(8).toString("hex"), iso());
      }
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
    log("info", "run started", { run: id, host: h.name, tests: (b.tests as string[]).length, by });
    return toRun(runRow(id), true);
  }

  function cancel(id: string, by: string) {
    const r = runRow(id);
    if (r.status === "done" || r.status === "canceled") return toRun(r, true);
    db.exec("BEGIN");
    try {
      db.prepare("UPDATE runs SET status = 'canceled', finished_at = ? WHERE id = ?").run(iso(), id);
      // Steps the agent never picked up are closed; what ran keeps its result and its pending detection check.
      db.prepare("UPDATE steps SET status = 'error', error = 'Run canceled' WHERE run_id = ? AND status IN ('pending', 'running')").run(id);
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
    log("info", "run canceled", { run: id, by });
    return toRun(runRow(id), true);
  }

  // ---- What the agent calls ---------------------------------------------------------------------------------------

  /** The steps this host should run now: only its own, only while the run lives, and only if the host is allowed. */
  function assignments(h: HostRow) {
    if (!h.allowed) return [];
    const rows = db
      .prepare("SELECT s.* FROM steps s JOIN runs r ON r.id = s.run_id WHERE s.host_id = ? AND s.status = 'pending' AND r.status = 'running' ORDER BY s.rowid")
      .all(h.id) as unknown as StepRow[];
    for (const s of rows) db.prepare("UPDATE steps SET status = 'running', ran_at = ? WHERE id = ?").run(iso(), s.id);
    // Only the pack id and marker cross to the agent. The agent runs the test from its own built-in pack or refuses.
    return rows.map((s) => ({ stepId: s.id, packId: s.pack_id, marker: s.marker, technique: s.technique }));
  }

  /** The agent's report of what one step did (or that it refused an id it does not have). */
  function result(h: HostRow, b: Record<string, unknown>) {
    // `report` is the agent's report of itself, already taken by the caller; the rest is this step's result.
    only(b, ["report", "stepId", "status", "did", "cleanedUp", "detail", "error"], "{ stepId, status, did, cleanedUp, detail, error }");
    if (typeof b.stepId !== "string") throw bad("stepId is the step this result is for.");
    if (b.status !== "done" && b.status !== "error" && b.status !== "refused") throw bad("status is done, error or refused.");
    const s = db.prepare("SELECT * FROM steps WHERE id = ? AND host_id = ?").get(b.stepId, h.id) as StepRow | undefined;
    if (!s) throw notFound("The step");
    const did = b.did === undefined || b.did === null ? null : typeof b.did === "string" && b.did.length <= 2000 ? b.did : null;
    const detail = typeof b.detail === "string" ? b.detail.slice(0, 2000) : null;
    const error = typeof b.error === "string" ? b.error.slice(0, 2000) : null;
    const cleanedUp = typeof b.cleanedUp === "boolean" ? (b.cleanedUp ? 1 : 0) : null;
    db.prepare("UPDATE steps SET status = ?, did = ?, cleaned_up = ?, detail = ?, error = ?, reported_at = ?, outcome = ? WHERE id = ?").run(
      b.status,
      did,
      cleanedUp,
      detail,
      error,
      iso(),
      b.status === "done" ? "pending" : "error",
      s.id,
    );
    if (b.status === "refused") log("warn", "agent refused a test not in its pack", { host: h.name, test: s.pack_id, detail });
    maybeFinish(s.run_id);
    return { recorded: 1 };
  }

  /** A run is done once every step has a result (or it was canceled). */
  function maybeFinish(runId: string) {
    const left = db.prepare("SELECT COUNT(*) AS n FROM steps WHERE run_id = ? AND status IN ('pending', 'running')").get(runId) as { n: number };
    if (left.n === 0) db.prepare("UPDATE runs SET status = 'done', finished_at = ? WHERE id = ? AND status = 'running'").run(iso(), runId);
  }

  // ---- Detection check (driven by detect.ts) ----------------------------------------------------------------------

  /** Steps that ran, were not checked, and whose window has passed: ready to match against the detecting products. */
  function dueForCheck(): Array<ReturnType<typeof toStep> & { windowSeconds: number }> {
    const rows = db
      .prepare(
        `SELECT s.*, r.window_seconds AS w FROM steps s JOIN runs r ON r.id = s.run_id
           WHERE s.status = 'done' AND s.outcome = 'pending' AND s.reported_at IS NOT NULL
             AND (julianday(?) - julianday(s.reported_at)) * 86400 >= r.window_seconds`,
      )
      .all(iso()) as unknown as Array<StepRow & { w: number }>;
    return rows.map((s) => ({ ...toStep(s), windowSeconds: s.w }));
  }

  function recordCheck(stepId: string, outcome: "detected" | "missed", detections: Detection[]) {
    db.prepare("UPDATE steps SET outcome = ?, detections = ?, checked_at = ? WHERE id = ?").run(outcome, JSON.stringify(detections), iso(), stepId);
  }

  // ---- Coverage ---------------------------------------------------------------------------------------------------

  /** The latest outcome per technique, with counts, and the roll-up per tactic for the matrix. */
  function coverage() {
    const steps = db
      .prepare("SELECT pack_id, technique, technique_name, tactic, tactic_id, outcome, status, reported_at FROM steps ORDER BY rowid")
      .all() as Array<Pick<StepRow, "pack_id" | "technique" | "technique_name" | "tactic" | "tactic_id" | "outcome" | "status" | "reported_at">>;
    const byTech = new Map<
      string,
      {
        technique: string;
        techniqueName: string;
        tactic: string;
        tacticId: string;
        tested: number;
        detected: number;
        missed: number;
        pending: number;
        lastOutcome: Outcome;
        lastRunAt: string | null;
      }
    >();
    for (const s of steps) {
      if (s.status === "refused") continue;
      const t = byTech.get(s.technique) ?? {
        technique: s.technique,
        techniqueName: s.technique_name,
        tactic: s.tactic,
        tacticId: s.tactic_id,
        tested: 0,
        detected: 0,
        missed: 0,
        pending: 0,
        lastOutcome: "pending" as Outcome,
        lastRunAt: null as string | null,
      };
      t.tested++;
      if (s.outcome === "detected") t.detected++;
      else if (s.outcome === "missed") t.missed++;
      else t.pending++;
      // Steps come oldest first, so the last seen is the newest.
      t.lastOutcome = s.outcome;
      t.lastRunAt = s.reported_at;
      byTech.set(s.technique, t);
    }
    const techniques = [...byTech.values()].sort((a, b) => a.technique.localeCompare(b.technique));
    const byTactic = new Map<string, { tactic: string; tacticId: string; detected: number; missed: number; pending: number }>();
    for (const t of techniques) {
      const ta = byTactic.get(t.tacticId) ?? { tactic: t.tactic, tacticId: t.tacticId, detected: 0, missed: 0, pending: 0 };
      // A technique counts once for the tactic, by its latest outcome.
      if (t.lastOutcome === "detected") ta.detected++;
      else if (t.lastOutcome === "missed") ta.missed++;
      else ta.pending++;
      byTactic.set(t.tacticId, ta);
    }
    const tactics = [...byTactic.values()].sort((a, b) => a.tacticId.localeCompare(b.tacticId));
    return { techniques, tactics };
  }

  function summary() {
    const runCounts = db.prepare("SELECT status, COUNT(*) AS n FROM runs GROUP BY status").all() as Array<{ status: RunStatus; n: number }>;
    const byStatus = { pending: 0, running: 0, done: 0, canceled: 0 } as Record<RunStatus, number>;
    for (const r of runCounts) byStatus[r.status] = r.n;
    const cov = coverage();
    const detected = cov.techniques.filter((t) => t.lastOutcome === "detected").length;
    const missed = cov.techniques.filter((t) => t.lastOutcome === "missed").length;
    const pending = cov.techniques.filter((t) => t.lastOutcome === "pending").length;
    const lastRun = (db.prepare("SELECT MAX(created_at) AS t FROM runs").get() as { t: string | null }).t;
    return {
      hosts: agents.counts(),
      runs: { ...byStatus, total: Object.values(byStatus).reduce((a, n) => a + n, 0), lastRunAt: lastRun },
      techniques: { total: cov.techniques.length, detected, missed, pending, available: PACK.length },
      tactics: cov.tactics,
    };
  }

  return { runs, run, create, cancel, assignments, result, dueForCheck, recordCheck, coverage, summary, maybeFinish };
}

export type Runs = ReturnType<typeof createRuns>;
