// The UI is an ordinary client of the public API (ADR 0014, 0018). Types follow openapi.json.

export type HostStatus = "allowed" | "paused" | "silent";
export type RunStatus = "pending" | "running" | "done" | "canceled";
export type StepStatus = "pending" | "running" | "done" | "error" | "refused";
export type Outcome = "pending" | "detected" | "missed" | "error";

/** Another OpenAsy product of this install, from OPENASY_PRODUCTS. */
export interface ProductLink {
  id: string;
  url: string;
}

export interface PackTest {
  id: string;
  technique: string;
  techniqueName: string;
  tactic: string;
  tacticId: string;
  name: string;
  description: string;
  expect: string;
  platforms: Array<"linux" | "darwin">;
}

export interface Detection {
  product: string;
  id: string;
  title: string;
  url: string | null;
  at: string;
}

export interface Step {
  id: string;
  runId: string;
  host: { id: string; name: string };
  test: { id: string; technique: string; techniqueName: string; tactic: string; tacticId: string };
  status: StepStatus;
  outcome: Outcome;
  marker: string;
  did: string | null;
  cleanedUp: boolean | null;
  detail: string | null;
  error: string | null;
  detections: Detection[];
  ranAt: string | null;
  reportedAt: string | null;
  checkedAt: string | null;
}

export interface Run {
  id: string;
  name: string;
  host: { id: string; name: string };
  status: RunStatus;
  windowSeconds: number;
  total: number;
  done: number;
  detected: number;
  missed: number;
  startedBy: string;
  createdAt: string;
  startedAt: string | null;
  finishedAt: string | null;
}

export interface RunDetail extends Run {
  steps: Step[];
}

export interface Host {
  id: string;
  name: string;
  status: HostStatus;
  version: string;
  outdated: boolean;
  os: string | null;
  kernel: string | null;
  arch: string | null;
  packIds: string[];
  allowed: boolean;
  allowReason: string | null;
  allowedBy: string | null;
  allowedAt: string | null;
  enrolledAt: string;
  lastSeenAt: string;
}

export interface EnrollmentToken {
  id: string;
  name: string;
  maxUses: number;
  uses: number;
  expiresAt: string;
  state: "active" | "used" | "expired";
  createdBy: string;
  createdAt: string;
  /** Only in the answer that made it. */
  token?: string;
}

export interface CoverageTechnique {
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

export interface CoverageTactic {
  tactic: string;
  tacticId: string;
  detected: number;
  missed: number;
  pending: number;
}

export interface Coverage {
  techniques: CoverageTechnique[];
  tactics: CoverageTactic[];
}

export interface Summary {
  hosts: { total: number; allowed: number; paused: number; silent: number };
  runs: { pending: number; running: number; done: number; canceled: number; total: number; lastRunAt: string | null };
  techniques: { total: number; detected: number; missed: number; pending: number; available: number };
  tactics: CoverageTactic[];
}

export class Unauthorized extends Error {}
/** The signed-in owner or admin has no second factor yet; the sign-in gate asks for one. */
export class MfaSetupRequired extends Error {}
export class ApiError extends Error {}

// The session is an HttpOnly cookie set by sign-in (@openasy/auth); the browser sends it, nothing is stored here.
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: { ...(init.body ? { "content-type": "application/json" } : {}), ...init.headers },
  });
  if (!res.ok) {
    const problem = (await res.json().catch(() => ({}))) as { code?: string; detail?: string };
    if (res.status === 401) throw new Unauthorized(problem.detail);
    if (problem.code === "mfa-setup-required") throw new MfaSetupRequired(problem.detail);
    throw new ApiError(problem.detail ?? `${path}: ${res.status}`);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}
