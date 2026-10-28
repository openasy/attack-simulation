import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

// Forward-only migrations (ADR 0010): append new entries, never edit or remove old ones.
const MIGRATIONS = [
  `-- What an admin hands to hosts so their agents can enrol: for one host, or for a fleet, up to max_uses hosts until
   -- it expires. Only the token's hash is kept (ADR 0021).
   CREATE TABLE enrollment_tokens (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL,
     token_hash TEXT NOT NULL UNIQUE,
     max_uses INTEGER NOT NULL CHECK (max_uses > 0),
     uses INTEGER NOT NULL DEFAULT 0,
     expires_at TEXT NOT NULL,
     created_by TEXT NOT NULL,
     created_at TEXT NOT NULL
   );
   -- A host with attack-simulation-agent on it. The agent's secret is kept as its hash only; it speaks for this host
   -- and no other. A host runs nothing until an admin allows it for simulation, with a reason, which is audited.
   CREATE TABLE hosts (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL UNIQUE,
     secret_hash TEXT NOT NULL UNIQUE,
     token_id TEXT,
     version TEXT NOT NULL,
     os TEXT,
     kernel TEXT,
     arch TEXT,
     -- The pack ids the agent reported it can run, so the UI can show when a host is behind on tests.
     pack_ids TEXT NOT NULL DEFAULT '[]',
     allowed INTEGER NOT NULL DEFAULT 0,
     allow_reason TEXT,
     allowed_by TEXT,
     allowed_at TEXT,
     enrolled_at TEXT NOT NULL,
     last_seen_at TEXT NOT NULL
   );
   -- A simulation run: an admin starts it on one allowed host with a chosen set of tests; every step is tagged with
   -- the run id so a detecting product's signals can be matched to it.
   CREATE TABLE runs (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL,
     host_id TEXT NOT NULL,
     host TEXT NOT NULL,
     status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'done', 'canceled')),
     -- Seconds a detecting product is given to raise a signal before a step counts as missed.
     window_seconds INTEGER NOT NULL,
     started_by TEXT NOT NULL,
     created_at TEXT NOT NULL,
     started_at TEXT,
     finished_at TEXT
   );
   CREATE INDEX runs_created ON runs (created_at);
   -- One test of a run on the host: what the agent did, whether it cleaned up, and whether a detecting product saw it
   -- within the window.
   CREATE TABLE steps (
     id TEXT PRIMARY KEY,
     run_id TEXT NOT NULL,
     host_id TEXT NOT NULL,
     host TEXT NOT NULL,
     pack_id TEXT NOT NULL,
     technique TEXT NOT NULL,
     technique_name TEXT NOT NULL,
     tactic TEXT NOT NULL,
     tactic_id TEXT NOT NULL,
     -- A random label the agent puts in what it does (a file name, a DNS name), so a detector's signal can be tied
     -- to this exact step. It is never a command.
     marker TEXT NOT NULL,
     status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'done', 'error', 'refused')),
     outcome TEXT NOT NULL DEFAULT 'pending' CHECK (outcome IN ('pending', 'detected', 'missed', 'error')),
     did TEXT,
     cleaned_up INTEGER,
     detail TEXT,
     error TEXT,
     -- The detecting products that raised a signal for this step, as JSON [{ product, id, title, url, at }].
     detections TEXT NOT NULL DEFAULT '[]',
     ran_at TEXT,
     reported_at TEXT,
     checked_at TEXT,
     created_at TEXT NOT NULL
   );
   CREATE INDEX steps_run ON steps (run_id);
   CREATE INDEX steps_check ON steps (status, outcome);
   CREATE INDEX steps_technique ON steps (technique)`,
];

/** Opens the product's single SQLite file in WAL mode (ADR 0011) and migrates it forward. */
export function openDb(path: string): DatabaseSync {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
  const row = db.prepare("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").get() as { v: number };
  for (let v = row.v; v < MIGRATIONS.length; v++) {
    db.exec("BEGIN");
    try {
      db.exec(MIGRATIONS[v]!);
      db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)").run(v + 1, new Date().toISOString());
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  }
  return db;
}
