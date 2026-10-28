// The fixed, reviewed pack of benign tests, in the spirit of Atomic Red Team's harmless atomics (ADR 0072). This is
// the server's view: metadata only. The server never sends a command; a run names a test by its `id`, and the agent
// runs it only from its own built-in copy of this pack, refusing any id it does not have (attack-simulation-agent).
//
// Every test here is harmless by construction: it reads its own host, creates and removes its own marker, or makes a
// benign outbound DNS lookup under a test domain. Nothing here dumps credentials, gains privilege, persists past the
// test, scans a network or carries a real malware sample (an EICAR test string is the most). Adding a test is a code
// change that goes through review in both this repo and the agent's; the server cannot invent one at runtime.

export interface PackTest {
  /** The stable id a run names; the agent matches it against its built-in pack and rejects anything else. */
  id: string;
  /** The MITRE ATT&CK technique this safely imitates, such as T1033. */
  technique: string;
  techniqueName: string;
  tactic: string;
  /** The ATT&CK tactic id, such as TA0007. */
  tacticId: string;
  name: string;
  /** What the test does on the host and how it cleans up, in one sentence. */
  description: string;
  /** Which detecting product is expected to see it, for the coverage view. */
  expect: string;
  platforms: Array<"linux" | "darwin">;
}

export const PACK: PackTest[] = [
  {
    id: "discovery-whoami",
    technique: "T1033",
    techniqueName: "System Owner/User Discovery",
    tactic: "Discovery",
    tacticId: "TA0007",
    name: "Who am I",
    description: "Runs the whoami program once, with no arguments, and reports the user it printed. Nothing is written or removed.",
    expect: "Runtime",
    platforms: ["linux", "darwin"],
  },
  {
    id: "discovery-system-info",
    technique: "T1082",
    techniqueName: "System Information Discovery",
    tactic: "Discovery",
    tacticId: "TA0007",
    name: "System information",
    description: "Runs uname -a once to read the kernel and host details. Read-only; nothing is changed.",
    expect: "Runtime",
    platforms: ["linux", "darwin"],
  },
  {
    id: "discovery-account",
    technique: "T1087.001",
    techniqueName: "Account Discovery: Local Account",
    tactic: "Discovery",
    tacticId: "TA0007",
    name: "Local account discovery",
    description: "Runs id once to read the current account and its groups. Read-only; no account is created or changed.",
    expect: "Runtime",
    platforms: ["linux", "darwin"],
  },
  {
    id: "defense-evasion-marker-file",
    technique: "T1070.004",
    techniqueName: "Indicator Removal: File Deletion",
    tactic: "Defense Evasion",
    tacticId: "TA0005",
    name: "Create and delete a marker file",
    description:
      "Creates a uniquely named marker file in the temp directory, writes a recognisable line to it, then deletes it. Only the agent's own file is touched.",
    expect: "Runtime",
    platforms: ["linux", "darwin"],
  },
  {
    id: "c2-dns-marker-lookup",
    technique: "T1071.004",
    techniqueName: "Application Layer Protocol: DNS",
    tactic: "Command and Control",
    tacticId: "TA0011",
    name: "Marker DNS lookup",
    description:
      "Makes one outbound DNS lookup of a marker name under the reserved test domain, so a network sensor can see the query. No connection is made and no data leaves beyond the name.",
    expect: "Network IDS",
    platforms: ["linux", "darwin"],
  },
  {
    id: "execution-eicar-file",
    technique: "T1204.002",
    techniqueName: "User Execution: Malicious File",
    tactic: "Execution",
    tacticId: "TA0002",
    name: "Write the EICAR test string",
    description:
      "Writes the standard EICAR anti-malware test string to a temp file, then deletes it. The EICAR string is a harmless detection test, not malware.",
    expect: "Malware",
    platforms: ["linux", "darwin"],
  },
];

export const packById = new Map(PACK.map((t) => [t.id, t]));
