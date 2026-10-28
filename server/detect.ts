// The detection check (ADR 0072, 0023). After a step's window has passed, Attack Simulation asks the detecting
// products whether they raised a signal for it, by reading their public APIs with a scoped, read-only token. It never
// asks the agent, and the agent never reports a detection: the whole point is to find out what the detectors noticed
// on their own. A step is detected when any detector has a signal on the same host, since the step ran, that carries
// the step's marker or the step's MITRE technique.
import type { Detection, Runs } from "./runs.ts";
import { log } from "./log.ts";

export interface Detector {
  /** The product id, such as "siem" or "runtime". */
  product: string;
  url: string;
  token: string;
}

/** Reads ATTACKSIM_DETECTORS: `siem=https://siem:8080|token,runtime=https://runtime:8080|token`. */
export function parseDetectors(value: string | undefined): { detectors: Detector[]; invalid: string[] } {
  const detectors: Detector[] = [];
  const invalid: string[] = [];
  for (const entry of (value ?? "")
    .split(",")
    .map((e) => e.trim())
    .filter(Boolean)) {
    const at = entry.indexOf("=");
    const product = entry.slice(0, at).trim();
    const rest = entry.slice(at + 1);
    const bar = rest.lastIndexOf("|");
    const url = URL.parse(bar < 0 ? rest.trim() : rest.slice(0, bar).trim());
    const token = bar < 0 ? "" : rest.slice(bar + 1).trim();
    if (at < 1 || !["siem", "runtime"].includes(product) || !url || (url.protocol !== "https:" && url.protocol !== "http:") || !token) {
      invalid.push(entry.replace(/\|.*/, "|…"));
      continue;
    }
    detectors.push({ product, url: url.origin + url.pathname.replace(/\/$/, ""), token });
  }
  return { detectors, invalid };
}

type Fetch = typeof fetch;

/** The step fields the check needs. */
interface CheckStep {
  id: string;
  host: { name: string };
  test: { technique: string };
  marker: string;
  ranAt: string | null;
  reportedAt: string | null;
}

async function get(http: Fetch, d: Detector, path: string): Promise<unknown> {
  const res = await http(new URL(path, d.url + "/"), {
    headers: { authorization: `Bearer ${d.token}`, "user-agent": "openasy-attack-simulation" },
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`${d.product} answered ${res.status}`);
  return res.json();
}

const hay = (v: unknown): string => JSON.stringify(v ?? "").toLowerCase();

/** Asks SIEM for events on the host since the step ran, and matches on the marker or the technique. */
async function askSiem(http: Fetch, d: Detector, s: CheckStep, since: string): Promise<Detection[]> {
  const q = new URLSearchParams({ host: s.host.name, since });
  const body = (await get(http, d, `api/v1/events?${q}`)) as { events?: Array<Record<string, unknown>> };
  const out: Detection[] = [];
  for (const e of body.events ?? []) {
    const text = hay(e);
    if (text.includes(s.marker.toLowerCase()) || text.includes(s.test.technique.toLowerCase())) {
      out.push({
        product: "siem",
        id: String(e.id ?? ""),
        title: typeof e.message === "string" ? e.message.slice(0, 200) : "SIEM event",
        url: `${d.url}/events/${String(e.id ?? "")}`,
        at: typeof e.time === "string" ? e.time : since,
      });
    }
  }
  return out;
}

/** Asks Runtime for detections on the host and matches on the marker or the technique (its `attack` tags). */
async function askRuntime(http: Fetch, d: Detector, s: CheckStep, since: string): Promise<Detection[]> {
  const q = new URLSearchParams({ host: s.host.name });
  const body = (await get(http, d, `api/v1/detections?${q}`)) as { detections?: Array<Record<string, unknown>> };
  const out: Detection[] = [];
  for (const det of body.detections ?? []) {
    const lastAt = typeof det.lastAt === "string" ? det.lastAt : "";
    if (lastAt && lastAt < since) continue;
    const attack = Array.isArray(det.attack) ? det.attack.map((a) => String(a).toLowerCase()) : [];
    const text = hay(det);
    if (attack.includes(s.test.technique.toLowerCase()) || text.includes(s.marker.toLowerCase())) {
      out.push({
        product: "runtime",
        id: String(det.id ?? ""),
        title: typeof det.rule === "string" ? det.rule.slice(0, 200) : "Runtime detection",
        url: `${d.url}/detections/${String(det.id ?? "")}`,
        at: lastAt || since,
      });
    }
  }
  return out;
}

export function createChecker(runs: Runs, detectors: Detector[], fetchImpl: Fetch = fetch) {
  /** Checks one step against every detector and records the outcome. Returns the outcome. */
  async function checkStep(step: CheckStep): Promise<"detected" | "missed"> {
    // Give the detector a little slack before the step ran, since clocks drift.
    const since = new Date(Date.parse(step.ranAt ?? step.reportedAt ?? new Date().toISOString()) - 60_000).toISOString();
    const found: Detection[] = [];
    for (const d of detectors) {
      try {
        found.push(...(d.product === "siem" ? await askSiem(fetchImpl, d, step, since) : await askRuntime(fetchImpl, d, step, since)));
      } catch (err) {
        log("warn", "a detector could not be read", { product: d.product, error: String(err) });
      }
    }
    const outcome = found.length ? "detected" : "missed";
    runs.recordCheck(step.id, outcome, found);
    return outcome;
  }

  /** Checks every step whose window has passed. Returns how many it checked. */
  async function sweep(): Promise<number> {
    if (!detectors.length) return 0;
    const due = runs.dueForCheck();
    for (const step of due) await checkStep(step);
    if (due.length) log("info", "detection check", { steps: due.length });
    return due.length;
  }

  return { checkStep, sweep };
}

export type Checker = ReturnType<typeof createChecker>;
