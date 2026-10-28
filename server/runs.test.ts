import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { report, startApp } from "./test-app.ts";

let app: Awaited<ReturnType<typeof startApp>>;

beforeAll(async () => {
  app = await startApp({ version: "0.1.0" });
});
afterAll(() => app.close());

const enrollWith = (token: string, name: string, over: Record<string, unknown> = {}) =>
  fetch(`${app.base}/api/v1/agent/enroll`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ token, name, report: report(), ...over }),
  });

describe("enrolment and allowing a host", () => {
  it("trades a token for the host's own secret and keeps only hashes", async () => {
    const t = (await (await app.send("POST", "/api/v1/enrollment-tokens", { name: "hosts", maxUses: 2 })).json()) as { token: string };
    const a = await enrollWith(t.token, "node-a");
    expect(a.status).toBe(200);
    const { secret } = (await a.json()) as { secret: string };
    expect(secret).toMatch(/^aia_/);
    expect(JSON.stringify(app.db.prepare("SELECT * FROM hosts").all())).not.toContain(secret);
    expect(JSON.stringify(app.db.prepare("SELECT * FROM enrollment_tokens").all())).not.toContain(t.token);
    // Enrols read-only: not allowed for simulation yet.
    const hosts = (await app.get("/api/v1/hosts")).hosts as Array<{ name: string; allowed: boolean; status: string }>;
    expect(hosts.find((h) => h.name === "node-a")).toMatchObject({ allowed: false, status: "paused" });
  });

  it("needs an admin, and a reason, to allow a host; both are recorded", async () => {
    const { hostId } = await app.enrol("allow-me");
    expect((await app.send("PUT", `/api/v1/hosts/${hostId}/allow`, { allowed: true })).status).toBe(422);
    const res = await app.send("PUT", `/api/v1/hosts/${hostId}/allow`, { allowed: true, reason: "lab host, safe to attack" });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ allowed: true, allowReason: "lab host, safe to attack", allowedBy: "admin token", status: "allowed" });
  });
});

describe("a run", () => {
  it("runs only on an allowed host, is answered to the agent as pack ids, and finishes when every step is reported", async () => {
    const agent = await app.enrol("runner-01");
    // Cannot run before the host is allowed.
    const before = await app.send("POST", "/api/v1/runs", { hostId: agent.hostId, tests: ["discovery-whoami"] });
    expect(before.status).toBe(409);
    await agent.allow();

    const run = (await (
      await app.send("POST", "/api/v1/runs", { name: "smoke", hostId: agent.hostId, tests: ["discovery-whoami", "c2-dns-marker-lookup"] })
    ).json()) as {
      id: string;
      steps: Array<{ id: string; test: { id: string }; marker: string }>;
      status: string;
    };
    expect(run.status).toBe("running");
    expect(run.steps.map((s) => s.test.id)).toEqual(["discovery-whoami", "c2-dns-marker-lookup"]);

    // The agent is given only pack ids and markers, never a command.
    const got = (await (await agent.assignments()).json()) as { assignments: Array<{ stepId: string; packId: string; marker: string }> };
    expect(got.assignments.map((a) => a.packId)).toEqual(["discovery-whoami", "c2-dns-marker-lookup"]);
    expect(JSON.stringify(got.assignments)).not.toContain("command");
    for (const a of got.assignments) expect(a.marker).toMatch(/^[0-9a-f]{16}$/);

    // The agent reports what it did; the run finishes once all steps are in.
    await agent.result({ stepId: got.assignments[0]!.stepId, status: "done", did: "ran whoami", cleanedUp: true });
    expect((await app.get(`/api/v1/runs/${run.id}`)).status).toBe("running");
    await agent.result({ stepId: got.assignments[1]!.stepId, status: "done", did: "looked up marker.sim.openasy.test", cleanedUp: true });
    const done = await app.get(`/api/v1/runs/${run.id}`);
    expect(done.status).toBe("done");
    // Outcome stays pending until a detector is checked (no detectors in this test).
    expect(done.steps.every((s: { outcome: string }) => s.outcome === "pending")).toBe(true);
  });

  it("refuses unknown tests, an empty list and a bad window", async () => {
    const agent = await app.enrol("runner-02");
    await agent.allow();
    expect((await app.send("POST", "/api/v1/runs", { hostId: agent.hostId, tests: ["not-a-test"] })).status).toBe(422);
    expect((await app.send("POST", "/api/v1/runs", { hostId: agent.hostId, tests: [] })).status).toBe(422);
    expect((await app.send("POST", "/api/v1/runs", { hostId: agent.hostId, tests: ["discovery-whoami"], windowSeconds: 5 })).status).toBe(422);
  });

  it("records a refusal when the agent does not have a pack id, without failing the call", async () => {
    const agent = await app.enrol("runner-03");
    await agent.allow();
    const run = (await (await app.send("POST", "/api/v1/runs", { hostId: agent.hostId, tests: ["discovery-account"] })).json()) as { id: string };
    const got = (await (await agent.assignments()).json()) as { assignments: Array<{ stepId: string }> };
    const res = await agent.result({ stepId: got.assignments[0]!.stepId, status: "refused", detail: "pack id not in built-in pack" });
    expect(res.status).toBe(200);
    const detail = await app.get(`/api/v1/runs/${run.id}`);
    expect(detail.steps[0]).toMatchObject({ status: "refused", outcome: "error" });
  });

  it("allows one run per host at a time and keeps runs apart by a cooldown", async () => {
    const cooled = await startApp({ version: "0.1.0", cooldownSeconds: 120 });
    try {
      const agent = await cooled.enrol("cooldown-host");
      await agent.allow();
      const first = await cooled.send("POST", "/api/v1/runs", { hostId: agent.hostId, tests: ["discovery-whoami"] });
      expect(first.status).toBe(201);
      // A second run while the first is in progress is refused.
      expect((await cooled.send("POST", "/api/v1/runs", { hostId: agent.hostId, tests: ["discovery-whoami"] })).status).toBe(409);
      const runId = ((await first.json()) as { id: string; steps: Array<{ id: string }> }).id;
      await cooled.send("POST", `/api/v1/runs/${runId}/cancel`);
      // After it ends, the cooldown still blocks a run until it passes.
      expect((await cooled.send("POST", "/api/v1/runs", { hostId: agent.hostId, tests: ["discovery-whoami"] })).status).toBe(409);
      cooled.later(121_000);
      expect((await cooled.send("POST", "/api/v1/runs", { hostId: agent.hostId, tests: ["discovery-whoami"] })).status).toBe(201);
    } finally {
      await cooled.close();
    }
  });
});

describe("coverage", () => {
  it("rolls steps up per technique and per tactic by their latest outcome", async () => {
    const own = await startApp({ version: "0.1.0" });
    try {
      const agent = await own.enrol("cov-host");
      await agent.allow();
      await own.send("POST", "/api/v1/runs", { hostId: agent.hostId, tests: ["discovery-whoami", "defense-evasion-marker-file"] });
      const got = (await (await agent.assignments()).json()) as { assignments: Array<{ stepId: string; technique: string }> };
      for (const a of got.assignments) await agent.result({ stepId: a.stepId, status: "done", cleanedUp: true });
      // Mark one step detected directly, as the checker would.
      const whoami = got.assignments.find((a) => a.technique === "T1033")!;
      own.runs.recordCheck(whoami.stepId, "detected", [{ product: "runtime", id: "d1", title: "whoami", url: null, at: "2026-10-28T13:00:00Z" }]);
      const cov = await own.get("/api/v1/coverage");
      const t1033 = cov.techniques.find((t: { technique: string }) => t.technique === "T1033");
      expect(t1033).toMatchObject({ tested: 1, detected: 1, lastOutcome: "detected" });
      const discovery = cov.tactics.find((t: { tacticId: string }) => t.tacticId === "TA0007");
      expect(discovery.detected).toBe(1);
      const summary = await own.get("/api/v1/summary");
      expect(summary.techniques.available).toBe(6);
    } finally {
      await own.close();
    }
  });
});
