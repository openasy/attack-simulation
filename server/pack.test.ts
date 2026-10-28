import { describe, expect, it } from "vitest";
import { PACK, packById } from "./pack.ts";

describe("the test pack", () => {
  it("has a unique, well-formed id for every test", () => {
    const ids = PACK.map((t) => t.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(id).toMatch(/^[a-z][a-z0-9-]{0,63}$/);
    expect(packById.size).toBe(PACK.length);
  });

  it("names a MITRE technique and tactic for every test", () => {
    for (const t of PACK) {
      expect(t.technique).toMatch(/^T\d{4}(\.\d{3})?$/);
      expect(t.tacticId).toMatch(/^TA\d{4}$/);
      expect(t.platforms.length).toBeGreaterThan(0);
      expect(t.description.length).toBeGreaterThan(10);
    }
  });

  it("is the kind of harmless test the scope allows: no credential dumping, persistence or scanning in its words", () => {
    // A light guard that the pack stays benign; the real safety is that the agent runs only its own built-in code.
    const words = JSON.stringify(PACK).toLowerCase();
    for (const banned of ["mimikatz", "/etc/shadow", "ransom", "reverse shell", "nmap", "privilege escalation"]) expect(words).not.toContain(banned);
  });
});
