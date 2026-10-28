# attack-simulation

[![CI](https://github.com/openasy/attack-simulation/actions/workflows/ci.yml/badge.svg)](https://github.com/openasy/attack-simulation/actions/workflows/ci.yml)
[![Node.js 26 LTS](https://img.shields.io/badge/node-26%20LTS-339933?logo=nodedotjs&logoColor=white)](./.nvmrc)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](./LICENSE)

The [OpenAsy](https://github.com/openasy) Attack Simulation product: **proof that your other products would catch a real
attack** (ADR 0072). It runs harmless MITRE ATT&CK techniques from a fixed, reviewed pack on hosts you allow, then reads
the detecting products ([SIEM](https://github.com/openasy/siem), [Runtime](https://github.com/openasy/runtime)) to see
whether each was caught within a time window, and shows coverage per technique. A rule that has never fired may be
broken; this is how you find out before an attacker does.

```
host you allow ──────────────────────────────────┐
  attack-simulation-agent (its own built-in pack) │
     ▲ asks for a pack id         │ runs a benign test, cleans up, reports
     └── attack-simulation ◀──────┘
            │  reads with a scoped token
            ├──▶ SIEM: did a rule fire?            ──▶ coverage per technique
            └──▶ Runtime: was it detected on the host?
```

## Safety, by design

This product runs attacker techniques, so its scope is fixed by safety (ADR 0072):

- **The agent never runs a command the server sends.** The server asks for a test by its **pack id**; the agent runs it
  from its **own built-in pack** (`ghcr.io/openasy/attack-simulation-agent`) and refuses any id it does not have. The
  only things that cross from server to agent are a pack id and a random hex **marker** the agent uses as a label.
- **The pack is harmless.** Read the host (`whoami`, `uname`, `id`), create and delete a marker file, make one outbound
  DNS lookup of a marker name under a test domain, write and delete the EICAR test string. No credential dumping, no
  persistence, no privilege escalation, no network scanning, no real malware. Every test cleans up after itself.
- **A host is opt-in twice.** It enrols read-only, and runs nothing until an admin marks it **allowed for simulation**,
  with a reason, which is audited and can be paused at any time.
- **Detection is read, never reported by the agent.** The server reads the detecting products' APIs with a scoped,
  read-only token (ADR 0023); the agent is never asked what was detected.

## Tests

The pack is at **Tests**, and at `GET /api/v1/tests`. It is code, not data: it changes only with a release. The six
tests of 0.1.0 cover Discovery (`T1033`, `T1082`, `T1087.001`), Defense Evasion (`T1070.004`), Command and Control
(`T1071.004`) and Execution (`T1204.002`).

## Runs

An admin starts a **run** of chosen tests on one allowed host under **Runs**. Every step is tagged with the run id. One
run per host at a time, and runs on a host are kept apart by a cooldown (`ATTACKSIM_RUN_COOLDOWN`), so simulation never
floods a host. The agent pulls the run's steps, runs each from its pack, cleans up and reports what it did.

## Detection and coverage

With `ATTACKSIM_DETECTORS` set, after each step's window passes the server reads SIEM's events and Runtime's detections
on that host since the step ran. A step is **detected** when a signal carries the step's marker or its MITRE technique,
and **missed** otherwise. **Coverage** rolls steps up per technique and per tactic by their latest outcome, so a gap
shows at a glance.

## Hosts and agents

An admin makes an **enrolment token** under Hosts (for one host, or more uses for a fleet). attack-simulation-agent
trades it once for a **secret of its own**; the server keeps only hashes. A host enrols read-only; **allowing** it for
simulation, with a reason, is the opt-in. The server never connects to an agent and sends it nothing but a pack id and
a marker.

## Run

```bash
openssl rand -hex 32 > openasy-kek
docker compose up -d
docker compose logs attack-simulation | grep 'no owner yet'
```

Open the link from the log once to create the owner account; there is no default password (ADR 0013). The UI and API
are on http://localhost:8080, the API reference at http://localhost:8080/api/docs/. Then, under Hosts, make an
enrolment token, start the agent on a host, and allow that host for simulation.

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port |
| `ATTACKSIM_PUBLIC_URL` | `http://localhost:8080` | The address people and agents open, with `https://` behind your TLS proxy |
| `ATTACKSIM_DETECTORS` | | The detecting products to read, `siem=URL\|token,runtime=URL\|token` (ADR 0023) |
| `ATTACKSIM_RUN_COOLDOWN` | `60` | Shortest gap, in seconds, between two runs on the same host |
| `OPENASY_PRODUCTS` | | The install's other OpenAsy products, for the product switcher |
| `ATTACKSIM_SECRETS_KEY_FILE` | `/run/secrets/openasy-kek` | 32-byte key-encryption key |
| `ATTACKSIM_DB` | `/data/attack-simulation.db` | SQLite file (WAL), on the `/data` volume |
| `ATTACKSIM_METRICS_PORT` | | Serve `/metrics` on this port only (ADR 0026) |
| `ATTACKSIM_HEADLESS` | `false` | `true` serves only the API |
| `ATTACKSIM_PASSWORD_SIGN_IN`, `OPENASY_OIDC_*` | | Sign-in, as in every OpenAsy product ([@openasy/auth](https://github.com/openasy/auth)) |

`/metrics` has `openasy_attacksim_hosts{status}`, `openasy_attacksim_runs_running`, `openasy_attacksim_runs_total` and
`openasy_attacksim_techniques{outcome}`.

The container runs as non-root with a read-only root filesystem, no capabilities and `no-new-privileges`.

## Roles

Viewers see coverage, runs, tests and hosts; admins also start and cancel runs, allow and pause hosts, make enrolment
tokens, remove hosts, and manage members and API tokens (ADR 0003).

## Not yet

- **More detectors.** Endpoints and Network IDS as detectors; 0.1.0 reads SIEM and Runtime.
- **Schedules.** Nightly or on-rule-change runs an admin sets; 0.1.0 runs are started by hand.
- **A larger pack**, campaign chains that order techniques like a real intrusion, and per-host platform filtering.
- **Writing a detection rule from a gap** in the detecting product directly.
- A Kubernetes manifest or Helm values for the agent.

## Develop

```bash
npm install
npm test        # the pack, enrolment and allowing, runs and steps, the detection check, coverage, and every API response against openapi.json
npm run dev     # the UI, with the API on :8080
```

## Licence

AGPL-3.0 (ADR 0008).
