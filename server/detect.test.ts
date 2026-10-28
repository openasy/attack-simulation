import { describe, expect, it } from "vitest";
import { createChecker, parseDetectors } from "./detect.ts";
import { createAgents } from "./agents.ts";
import { createRuns, type Detection } from "./runs.ts";
import { openDb } from "./db.ts";

describe("parseDetectors", () => {
  it("reads siem and runtime with a token, and leaves out the rest", () => {
    const { detectors, invalid } = parseDetectors("siem=https://siem.example.com/|tok1,runtime=http://runtime:8080|tok2,endpoints=https://x|t,siem=https://y");
    expect(detectors).toEqual([
      { product: "siem", url: "https://siem.example.com", token: "tok1" },
      { product: "runtime", url: "http://runtime:8080", token: "tok2" },
    ]);
    // An unknown product and one without a token are left out; a token is never echoed back in the warning.
    expect(invalid).toEqual(["endpoints=https://x|…", "siem=https://y"]);
  });

  it("is empty when unset", () => {
    expect(parseDetectors(undefined)).toEqual({ detectors: [], invalid: [] });
  });
});

/** A build with the pieces the checker needs and a step already reported and due. */
function dueStep(cooldownSeconds = 0) {
  const db = openDb(":memory:");
  let now = Date.parse("2026-10-28T13:00:00Z");
  const clock = () => now;
  const agents = createAgents(db, { version: "0.1.0", clock });
  const runs = createRuns(db, agents, { clock, cooldownSeconds });
  // Enrol, allow, run one test, and report it.
  const { token } = agents.createToken({ name: "t" }, "admin") as { token: string };
  const { hostId } = agents.enroll({ token, name: "host-1", report: { version: "0.1.0", packIds: ["c2-dns-marker-lookup"] } });
  agents.setAllowed(hostId, { allowed: true, reason: "lab host, safe to attack" }, "admin");
  const run = runs.create({ hostId, tests: ["c2-dns-marker-lookup"], windowSeconds: 60 }, "admin");
  const hostRow = agents.hostRow(hostId);
  const assigned = runs.assignments(hostRow);
  const marker = assigned[0]!.marker;
  runs.result(hostRow, { stepId: assigned[0]!.stepId, status: "done", cleanedUp: true });
  now += 61_000; // past the window
  // The checker takes the full step, as runs.dueForCheck() hands it over.
  const step = runs.run(run.id).steps![0]!;
  return { runs, run, marker, step };
}

describe("the detection check", () => {
  it("marks a step detected when a detector has a signal with the marker, and missed otherwise", async () => {
    const a = dueStep();
    const siemWithMarker = (async (url: string | URL) => {
      const u = new URL(url);
      if (u.pathname === "/api/v1/events")
        return new Response(JSON.stringify({ events: [{ id: 7, time: "2026-10-28T13:00:30Z", message: `dns lookup ${a.marker}.sim.openasy.test` }] }), {
          status: 200,
        });
      return new Response("{}", { status: 404 });
    }) as typeof fetch;
    const detected = await createChecker(a.runs, [{ product: "siem", url: "http://siem", token: "t" }], siemWithMarker).checkStep(a.step);
    expect(detected).toBe("detected");
    const got = a.runs.run(a.run.id).steps![0]!;
    expect(got.outcome).toBe("detected");
    expect((got.detections as Detection[])[0]).toMatchObject({ product: "siem", id: "7" });

    const b = dueStep();
    const siemEmpty = (async () => new Response(JSON.stringify({ events: [] }), { status: 200 })) as typeof fetch;
    expect(await createChecker(b.runs, [{ product: "siem", url: "http://siem", token: "t" }], siemEmpty).checkStep(b.step)).toBe("missed");
  });

  it("sweeps every due step and treats an unreachable detector as no signal", async () => {
    const a = dueStep();
    const broken = (async () => {
      throw new Error("connection refused");
    }) as typeof fetch;
    const n = await createChecker(a.runs, [{ product: "runtime", url: "http://runtime", token: "t" }], broken).sweep();
    expect(n).toBe(1);
    expect(a.runs.run(a.run.id).steps![0]!.outcome).toBe("missed");
  });
});
