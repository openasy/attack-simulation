import {
  AppShell,
  Badge,
  BrandProvider,
  Button,
  Callout,
  DataTable,
  Dialog,
  EmptyState,
  EntityChip,
  FacetFilter,
  FilterBar,
  KpiCard,
  KpiGrid,
  navigate,
  PageHeader,
  Panel,
  PRODUCT_IDS,
  SelectField,
  StatusBadge,
  Switch,
  TextField,
  toLocale,
  useLocalePreference,
  usePath,
  useThemePreference,
  type Column,
  type ProductId,
  type Tone,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAccountMenu, useAuth, useInstallBrand } from "@openasy/auth/react";
import colophon from "virtual:openasy-colophon";
import {
  Crosshair,
  FlaskConical,
  KeyRound,
  LayoutGrid,
  LogIn,
  LogOut,
  Play,
  Plus,
  Server,
  ShieldCheck,
  Swords,
  Trash2,
  UserRound,
  Users,
  Wrench,
} from "lucide-react";
import { Fragment, useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  MfaSetupRequired,
  Unauthorized,
  type Coverage,
  type CoverageTactic,
  type EnrollmentToken,
  type Host,
  type HostStatus,
  type Outcome,
  type PackTest,
  type ProductLink,
  type Run,
  type RunDetail,
  type RunStatus,
  type Step,
  type Summary,
} from "./api.ts";
import { useT } from "./i18n.ts";
import { search } from "./search.ts";

const PAGES = ["coverage", "runs", "tests", "hosts", "setup", "account", "members", "signin", "tokens", "about"] as const;
type Page = (typeof PAGES)[number];
type Route = { page: Page; id?: string };
export const PATHS = [...PAGES];
function parseRoute(path: string): Route {
  const [page, id] = path.replace(/^\//, "").split("/");
  if ((PAGES as readonly string[]).includes(page ?? "")) return { page: page as Page, ...(id && { id: decodeURIComponent(id) }) };
  return { page: "coverage" };
}

/** Data loading with the session; when it ends, the sign-in screen comes back. */
function useApi() {
  const { expired, refresh } = useAuth();
  return useCallback(
    async <T,>(path: string, init?: RequestInit): Promise<T> => {
      try {
        return await api<T>(path, init);
      } catch (err) {
        if (err instanceof Unauthorized) expired();
        if (err instanceof MfaSetupRequired) void refresh();
        throw err;
      }
    },
    [expired, refresh],
  );
}
type Call = ReturnType<typeof useApi>;

/** Loads a list, again when the path changes and on demand. */
function useList<T>(call: Call, path: string, key: string) {
  const [items, setItems] = useState<T[]>();
  const load = useCallback(
    () =>
      void call<Record<string, T[]>>(path).then(
        (r) => setItems(r[key]),
        () => setItems([]),
      ),
    [call, path, key],
  );
  useEffect(load, [load]);
  return [items, load] as const;
}

/** Runs a change and reports its error, the way every form here does. */
function useAction(after: () => void) {
  const [error, setError] = useState<string>();
  const run = useCallback(
    async (fn: () => Promise<unknown>) => {
      try {
        await fn();
        setError(undefined);
        after();
        return true;
      } catch (err) {
        setError((err as Error).message);
        return false;
      }
    },
    [after],
  );
  return [run, error] as const;
}

const when = (iso: string) => new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
const post = (body: unknown): RequestInit => ({ method: "POST", body: JSON.stringify(body) });

const OUTCOME_TONE: Record<Outcome, Tone> = { detected: "success", missed: "danger", pending: "neutral", error: "warning" };
const STEP_TONE: Record<Step["status"], Tone> = { pending: "neutral", running: "info", done: "success", error: "warning", refused: "warning" };
const RUN_TONE: Record<RunStatus, Tone> = { pending: "neutral", running: "info", done: "success", canceled: "neutral" };
const HOST_TONE: Record<HostStatus, Tone> = { allowed: "success", paused: "neutral", silent: "danger" };

function ErrorText({ message }: { message?: string }) {
  return message ? <p className="m-0 text-xs text-danger">{message}</p> : null;
}

function Code({ children }: { children: ReactNode }) {
  return <pre className="m-0 overflow-x-auto rounded-md bg-subtle px-2.5 py-2 font-mono text-xs whitespace-pre-wrap text-fg">{children}</pre>;
}

function Facts({ items }: { items: Array<[ReactNode, ReactNode] | false | null | undefined | ""> }) {
  return (
    <dl className="as-facts text-sm">
      {items.filter(Boolean).map((item, i) => {
        const [k, v] = item as [ReactNode, ReactNode];
        return (
          <Fragment key={i}>
            <dt className="text-fg-muted">{k}</dt>
            <dd>{v}</dd>
          </Fragment>
        );
      })}
    </dl>
  );
}

// ---------------------------------------------------------------- Coverage (overview)

/** One bar per ATT&CK tactic: detected, missed and pending techniques, so a gap shows at a glance. */
function TacticStrip({ tactics }: { tactics: CoverageTactic[] }) {
  const t = useT();
  const max = Math.max(1, ...tactics.map((x) => x.detected + x.missed + x.pending));
  if (!tactics.length) return <EmptyState title={t("coverage.noTactics")}>{t("coverage.noTacticsDetail")}</EmptyState>;
  return (
    <div className="relative overflow-x-auto">
      <ol className="flex min-w-[640px] gap-1.5" aria-label={t("coverage.byTactic")}>
        {tactics.map((x) => {
          const total = x.detected + x.missed + x.pending;
          return (
            <li key={x.tacticId} className="flex min-w-0 flex-1 flex-col gap-1">
              <div
                role="img"
                aria-label={`${x.tactic}: ${x.detected} ${t("outcomes.detected")}, ${x.missed} ${t("outcomes.missed")}, ${x.pending} ${t("outcomes.pending")}`}
                className="flex h-24 flex-col justify-end rounded bg-subtle p-0.5"
              >
                <div className="flex flex-col overflow-hidden rounded-sm" style={{ height: `${(total / max) * 100}%` }}>
                  {x.missed > 0 && <div className="bg-danger" style={{ flexGrow: x.missed }} />}
                  {x.detected > 0 && <div className="bg-success" style={{ flexGrow: x.detected }} />}
                  {x.pending > 0 && <div className="bg-fg-subtle" style={{ flexGrow: x.pending }} />}
                </div>
              </div>
              <span className="font-mono text-2xs text-fg-muted">{x.tacticId}</span>
              <span className="min-h-7 text-2xs leading-tight font-medium break-words text-fg">{x.tactic}</span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

function CoveragePage({ call, summary }: { call: Call; summary: Summary }) {
  const t = useT();
  const [cov, setCov] = useState<Coverage>();
  const [outcomes, setOutcomes] = useState<string[]>([]);
  useEffect(() => void call<Coverage>("/api/v1/coverage").then(setCov, () => {}), [call]);
  const techniques = (cov?.techniques ?? []).filter((x) => outcomes.length === 0 || outcomes.includes(x.lastOutcome));
  const gaps = (cov?.techniques ?? []).filter((x) => x.lastOutcome === "missed");
  const cols: Column<Coverage["techniques"][number]>[] = [
    {
      id: "technique",
      header: t("coverage.technique"),
      width: "40%",
      sortValue: (x) => x.technique,
      cell: (x) => (
        <span className="flex min-w-0 flex-col">
          <span className="flex items-center gap-1.5">
            <span className="font-mono text-xs text-fg-muted">{x.technique}</span>
            <span className="truncate font-medium">{x.techniqueName}</span>
          </span>
          <span className="truncate text-2xs text-fg-muted">{x.tactic}</span>
        </span>
      ),
    },
    { id: "tested", header: t("coverage.tested"), align: "right", mono: true, sortValue: (x) => x.tested, cell: (x) => x.tested },
    { id: "detected", header: t("outcomes.detected"), align: "right", mono: true, cell: (x) => <span className="text-success">{x.detected}</span> },
    {
      id: "missed",
      header: t("outcomes.missed"),
      align: "right",
      mono: true,
      cell: (x) => <span className={x.missed ? "text-danger" : "text-fg-muted"}>{x.missed}</span>,
    },
    {
      id: "last",
      header: t("coverage.latest"),
      sortValue: (x) => x.lastOutcome,
      cell: (x) => <StatusBadge tone={OUTCOME_TONE[x.lastOutcome]}>{t(`outcomes.${x.lastOutcome}`)}</StatusBadge>,
    },
    { id: "when", header: t("coverage.lastRun"), cell: (x) => <span className="whitespace-nowrap text-xs">{x.lastRunAt ? when(x.lastRunAt) : "–"}</span> },
  ];
  return (
    <>
      <PageHeader title={t("coverage.title")} description={t("coverage.description")} />
      <KpiGrid minWidth={160}>
        <KpiCard label={t("coverage.techniquesTested")} value={summary.techniques.total} unit={t("coverage.ofPack", { n: summary.techniques.available })} />
        <KpiCard label={t("outcomes.detected")} value={summary.techniques.detected} tone="success" />
        <KpiCard label={t("outcomes.missed")} value={summary.techniques.missed} tone={summary.techniques.missed ? "danger" : undefined} />
        <KpiCard label={t("outcomes.pending")} value={summary.techniques.pending} />
        <KpiCard
          label={t("coverage.runs")}
          value={summary.runs.total}
          unit={summary.runs.lastRunAt ? t("coverage.lastRunWhen", { when: when(summary.runs.lastRunAt) }) : t("coverage.never")}
        />
      </KpiGrid>
      <Panel title={t("coverage.byTactic")} description={t("coverage.byTacticDetail")}>
        <TacticStrip tactics={cov?.tactics ?? []} />
      </Panel>
      {gaps.length > 0 && (
        <Callout tone="danger" title={t("coverage.gapsTitle", { n: gaps.length })}>
          <ul className="mt-1 flex flex-col gap-1" aria-label={t("coverage.gaps")}>
            {gaps.slice(0, 8).map((g) => (
              <li key={g.technique}>
                <span className="font-mono text-xs text-fg">{g.technique}</span> <span className="font-medium text-fg">{g.techniqueName}</span>
                <span className="text-2xs"> · {t("coverage.shouldBeCaught", { tactic: g.tactic })}</span>
              </li>
            ))}
          </ul>
        </Callout>
      )}
      <FilterBar onClear={outcomes.length ? () => setOutcomes([]) : undefined}>
        <FacetFilter
          label={t("coverage.latest")}
          selected={outcomes}
          onChange={setOutcomes}
          options={(["detected", "missed", "pending"] as const).map((o) => ({
            value: o,
            label: t(`outcomes.${o}`),
            count: (cov?.techniques ?? []).filter((x) => x.lastOutcome === o).length,
          }))}
        />
      </FilterBar>
      <Panel title={t("coverage.techniques")} description={t("coverage.shown", { count: techniques.length })} flush>
        <DataTable
          label={t("coverage.techniques")}
          columns={cols}
          rows={techniques}
          loading={!cov}
          getRowId={(x) => x.technique}
          minWidth={720}
          empty={<EmptyState title={t("coverage.none")}>{t("coverage.noneDetail")}</EmptyState>}
        />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Runs

function StepsTable({ steps }: { steps: Step[] }) {
  const t = useT();
  const cols: Column<Step>[] = [
    {
      id: "technique",
      header: t("runs.technique"),
      width: "34%",
      cell: (s) => (
        <span className="flex min-w-0 flex-col">
          <span className="flex items-center gap-1.5">
            <span className="font-mono text-xs text-fg-muted">{s.test.technique}</span>
            <span className="truncate font-medium">{s.test.techniqueName}</span>
          </span>
          <span className="truncate text-2xs text-fg-muted">{s.test.id}</span>
        </span>
      ),
    },
    { id: "status", header: t("runs.status"), cell: (s) => <StatusBadge tone={STEP_TONE[s.status]}>{t(`stepStatuses.${s.status}`)}</StatusBadge> },
    {
      id: "cleaned",
      header: t("runs.cleanedUp"),
      cell: (s) => (s.cleanedUp === null ? "–" : s.cleanedUp ? t("runs.yes") : <span className="text-danger">{t("runs.no")}</span>),
    },
    { id: "outcome", header: t("runs.outcome"), cell: (s) => <StatusBadge tone={OUTCOME_TONE[s.outcome]}>{t(`outcomes.${s.outcome}`)}</StatusBadge> },
    {
      id: "signals",
      header: t("runs.signals"),
      cell: (s) =>
        s.detections.length ? (
          <span className="flex flex-wrap gap-1">
            {s.detections.map((d, i) => (
              <Badge key={i} tone="neutral" mono>
                {d.product}
              </Badge>
            ))}
          </span>
        ) : (
          <span className="text-fg-muted">{t("runs.noSignal")}</span>
        ),
    },
  ];
  return <DataTable label={t("runs.steps")} columns={cols} rows={steps} getRowId={(s) => s.id} minWidth={720} />;
}

function RunDetailPage({ call, id, reload }: { call: Call; id: string; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [run, setRun] = useState<RunDetail>();
  const load = useCallback(() => void call<RunDetail>(`/api/v1/runs/${encodeURIComponent(id)}`).then(setRun, () => {}), [call, id]);
  useEffect(load, [load]);
  useEffect(() => {
    if (run?.status !== "running") return;
    const h = setInterval(load, 5000);
    return () => clearInterval(h);
  }, [run?.status, load]);
  const [action] = useAction(() => {
    load();
    reload();
  });
  if (!run) return <EmptyState title={t("product.loading")} />;
  return (
    <>
      <PageHeader
        title={run.name}
        description={t("runs.onHost", { host: run.host.name })}
        meta={<StatusBadge tone={RUN_TONE[run.status]}>{t(`runStatuses.${run.status}`)}</StatusBadge>}
        actions={
          can("admin") && run.status === "running" ? (
            <Button variant="danger" onClick={() => void action(() => call(`/api/v1/runs/${run.id}/cancel`, { method: "POST" }))}>
              {t("runs.cancel")}
            </Button>
          ) : (
            <Button onClick={() => navigate("/runs")}>{t("runs.back")}</Button>
          )
        }
      />
      <KpiGrid minWidth={150}>
        <KpiCard label={t("runs.steps")} value={run.total} />
        <KpiCard label={t("outcomes.detected")} value={run.detected} tone="success" />
        <KpiCard label={t("outcomes.missed")} value={run.missed} tone={run.missed ? "danger" : undefined} />
        <KpiCard label={t("runs.window")} value={run.windowSeconds} unit={t("runs.seconds")} />
      </KpiGrid>
      <Panel>
        <Facts
          items={[
            [t("runs.startedBy"), run.startedBy],
            [t("runs.started"), run.startedAt ? when(run.startedAt) : "–"],
            run.finishedAt && [t("runs.finished"), when(run.finishedAt)],
          ]}
        />
      </Panel>
      <Panel title={t("runs.steps")} flush>
        <StepsTable steps={run.steps} />
      </Panel>
    </>
  );
}

/** Starts a run: pick an allowed host and the tests to run. */
function StartRun({ call, hosts, tests, onStarted }: { call: Call; hosts: Host[]; tests: PackTest[]; onStarted: () => void }) {
  const t = useT();
  const allowed = hosts.filter((h) => h.allowed);
  const [hostId, setHostId] = useState("");
  const [name, setName] = useState("");
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [run, error] = useAction(onStarted);
  const toggle = (id: string) =>
    setPicked((p) => {
      const n = new Set(p);
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  const start = (e: FormEvent) => {
    e.preventDefault();
    const tests = [...picked];
    if (!hostId || tests.length === 0) return;
    void run(() => call("/api/v1/runs", post({ name: name.trim() || undefined, hostId, tests }))).then((ok) => {
      if (ok) {
        setPicked(new Set());
        setName("");
      }
    });
  };
  if (!allowed.length)
    return (
      <Callout tone="warning" title={t("runs.noAllowed")}>
        {t("runs.noAllowedDetail")}
      </Callout>
    );
  return (
    <Panel title={t("runs.start")} description={t("runs.startDetail")} aria-label={t("runs.start")}>
      <form className="flex flex-col gap-3" onSubmit={start}>
        <div className="grid gap-2 sm:grid-cols-2">
          <SelectField
            label={t("runs.host")}
            value={hostId}
            onChange={(e) => setHostId(e.target.value)}
            required
            options={[{ value: "", label: t("runs.chooseHost") }, ...allowed.map((h) => ({ value: h.id, label: h.name }))]}
          />
          <TextField label={t("runs.name")} value={name} onChange={(e) => setName(e.target.value)} placeholder={t("runs.namePlaceholder")} />
        </div>
        <fieldset className="flex flex-col gap-1.5">
          <legend className="text-xs font-medium text-fg-muted">{t("runs.tests")}</legend>
          {tests.map((test) => (
            <div key={test.id} className="rounded border border-line px-2.5 py-1.5">
              <Switch
                checked={picked.has(test.id)}
                onCheckedChange={() => toggle(test.id)}
                label={`${test.technique} ${test.name}`}
                description={test.description}
              />
            </div>
          ))}
        </fieldset>
        <ErrorText message={error} />
        <div>
          <Button type="submit" variant="primary" icon={<Play />} disabled={!hostId || picked.size === 0}>
            {t("runs.startButton", { n: picked.size })}
          </Button>
        </div>
      </form>
    </Panel>
  );
}

function RunsPage({ call, hosts, tests, reload }: { call: Call; hosts: Host[]; tests: PackTest[]; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [runs, load] = useList<Run>(call, "/api/v1/runs", "runs");
  const cols: Column<Run>[] = [
    {
      id: "name",
      header: t("runs.run"),
      width: "34%",
      cell: (r) => (
        <span className="flex min-w-0 flex-col">
          <span className="truncate font-medium">{r.name}</span>
          <span className="font-mono text-2xs text-fg-muted">{r.host.name}</span>
        </span>
      ),
    },
    { id: "status", header: t("runs.status"), cell: (r) => <StatusBadge tone={RUN_TONE[r.status]}>{t(`runStatuses.${r.status}`)}</StatusBadge> },
    { id: "steps", header: t("runs.steps"), align: "right", mono: true, cell: (r) => `${r.done} / ${r.total}` },
    { id: "detected", header: t("outcomes.detected"), align: "right", mono: true, cell: (r) => <span className="text-success">{r.detected}</span> },
    {
      id: "missed",
      header: t("outcomes.missed"),
      align: "right",
      mono: true,
      cell: (r) => <span className={r.missed ? "text-danger" : "text-fg-muted"}>{r.missed}</span>,
    },
    {
      id: "when",
      header: t("runs.started"),
      sortValue: (r) => r.createdAt,
      cell: (r) => <span className="whitespace-nowrap text-xs">{when(r.createdAt)}</span>,
    },
  ];
  return (
    <>
      <PageHeader title={t("runs.title")} description={t("runs.pageDetail")} />
      {can("admin") && <StartRun call={call} hosts={hosts} tests={tests} onStarted={() => (load(), reload())} />}
      <Panel title={t("runs.title")} description={t("runs.count", { count: (runs ?? []).length })} flush>
        <DataTable
          label={t("runs.title")}
          columns={cols}
          rows={runs ?? []}
          loading={!runs}
          getRowId={(r) => r.id}
          onRowClick={(r) => navigate(`/runs/${encodeURIComponent(r.id)}`)}
          minWidth={760}
          empty={<EmptyState title={t("runs.none")}>{t("runs.noneDetail")}</EmptyState>}
        />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Tests (the pack)

function TestsPage({ tests }: { tests: PackTest[] }) {
  const t = useT();
  const cols: Column<PackTest>[] = [
    {
      id: "test",
      header: t("tests.test"),
      width: "36%",
      cell: (x) => (
        <span className="flex min-w-0 flex-col">
          <span className="truncate font-medium">{x.name}</span>
          <span className="font-mono text-2xs text-fg-muted">{x.id}</span>
        </span>
      ),
    },
    {
      id: "technique",
      header: t("tests.technique"),
      cell: (x) => (
        <span className="flex flex-col">
          <span className="font-mono text-xs">{x.technique}</span>
          <span className="text-2xs text-fg-muted">{x.techniqueName}</span>
        </span>
      ),
    },
    { id: "tactic", header: t("tests.tactic"), cell: (x) => <span className="text-xs">{x.tactic}</span> },
    { id: "expect", header: t("tests.expect"), cell: (x) => <Badge tone="neutral">{x.expect}</Badge> },
    { id: "what", header: t("tests.what"), width: "34%", cell: (x) => <span className="block text-xs text-fg-muted">{x.description}</span> },
  ];
  return (
    <>
      <PageHeader title={t("tests.title")} description={t("tests.description")} />
      <Callout tone="info" title={t("tests.safeTitle")}>
        {t("tests.safeDetail")}
      </Callout>
      <Panel title={t("tests.pack")} description={t("tests.count", { count: tests.length })} flush>
        <DataTable label={t("tests.pack")} columns={cols} rows={tests} getRowId={(x) => x.id} minWidth={820} />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Hosts

function TokensPanel({ call }: { call: Call }) {
  const t = useT();
  const [tokens, load] = useList<EnrollmentToken>(call, "/api/v1/enrollment-tokens", "tokens");
  const [name, setName] = useState("");
  const [uses, setUses] = useState("1");
  const [made, setMade] = useState<EnrollmentToken>();
  const [run, error] = useAction(load);
  const create = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => setMade(await call<EnrollmentToken>("/api/v1/enrollment-tokens", post({ name, maxUses: Number(uses) })))).then(
      (ok) => ok && setName(""),
    );
  };
  const cols: Column<EnrollmentToken>[] = [
    { id: "name", header: t("hosts.tokenName"), cell: (x) => x.name },
    { id: "uses", header: t("hosts.uses"), align: "right", mono: true, cell: (x) => `${x.uses} / ${x.maxUses}` },
    { id: "state", header: t("hosts.state"), cell: (x) => <Badge tone={x.state === "active" ? "success" : "neutral"}>{t(`tokenStates.${x.state}`)}</Badge> },
    { id: "expires", header: t("hosts.expires"), cell: (x) => when(x.expiresAt) },
    {
      id: "act",
      header: "",
      width: "60px",
      hideable: false,
      cell: (x) => (
        <Button
          size="xs"
          variant="ghost"
          icon={<Trash2 />}
          aria-label={t("hosts.deleteToken", { name: x.name })}
          onClick={() => void run(() => call(`/api/v1/enrollment-tokens/${x.id}`, { method: "DELETE" }))}
        />
      ),
    },
  ];
  return (
    <Panel title={t("hosts.tokens")} description={t("hosts.tokensDetail")}>
      <div className="flex flex-col gap-2.5">
        <form className="as-token-form" onSubmit={create}>
          <TextField
            label={t("hosts.tokenName")}
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t("hosts.tokenNamePlaceholder")}
            required
          />
          <TextField
            label={t("hosts.maxUses")}
            type="number"
            min={1}
            max={10000}
            value={uses}
            onChange={(e) => setUses(e.target.value)}
            hint={t("hosts.maxUsesHint")}
          />
          <Button type="submit" variant="primary" icon={<Plus />}>
            {t("hosts.makeToken")}
          </Button>
        </form>
        <ErrorText message={error} />
        {made?.token && (
          <Callout tone="success" title={t("hosts.tokenOnce")} onDismiss={() => setMade(undefined)}>
            <Code>{`RUNTIME_ENROLL_TOKEN=${made.token}`.replace("RUNTIME", "ATTACKSIM")}</Code>
          </Callout>
        )}
        <DataTable
          label={t("hosts.tokens")}
          columns={cols}
          rows={tokens ?? []}
          loading={!tokens}
          getRowId={(x) => x.id}
          minWidth={600}
          empty={<EmptyState title={t("hosts.noTokens")} />}
        />
      </div>
    </Panel>
  );
}

function HostsPage({ call, hosts, reload }: { call: Call; hosts: Host[]; reload: () => void }) {
  const t = useT();
  const { can } = useAuth();
  const [status, setStatus] = useState<string[]>([]);
  const [allow, setAllow] = useState<Host>();
  const [reason, setReason] = useState("");
  const [removing, setRemoving] = useState<Host>();
  const [run, error] = useAction(reload);
  const rows = hosts.filter((h) => status.length === 0 || status.includes(h.status));
  const cols: Column<Host>[] = [
    { id: "name", header: t("hosts.host"), pinned: "left", sortValue: (h) => h.name, cell: (h) => <EntityChip kind="host" value={h.name} hideKind /> },
    {
      id: "os",
      header: t("hosts.os"),
      cell: (h) => (
        <span className="flex flex-col">
          <span className="text-xs">{h.os ?? "–"}</span>
          <span className="font-mono text-2xs text-fg-muted">agent {h.version}</span>
        </span>
      ),
    },
    {
      id: "status",
      header: t("hosts.status"),
      sortValue: (h) => h.status,
      cell: (h) => <StatusBadge tone={HOST_TONE[h.status]}>{t(`hostStatuses.${h.status}`)}</StatusBadge>,
    },
    {
      id: "reason",
      header: t("hosts.reason"),
      width: "26%",
      cell: (h) => <span className="block truncate text-xs text-fg-muted">{h.allowReason ?? "–"}</span>,
    },
    { id: "seen", header: t("hosts.lastSeen"), sortValue: (h) => h.lastSeenAt, cell: (h) => <span className="whitespace-nowrap">{when(h.lastSeenAt)}</span> },
    {
      id: "act",
      header: "",
      width: "150px",
      hideable: false,
      cell: (h) =>
        can("admin") ? (
          <span className="flex gap-1">
            {h.allowed ? (
              <Button
                size="xs"
                variant="ghost"
                onClick={() => void run(() => call(`/api/v1/hosts/${h.id}/allow`, { method: "PUT", body: JSON.stringify({ allowed: false }) }))}
              >
                {t("hosts.pause")}
              </Button>
            ) : (
              <Button
                size="xs"
                icon={<ShieldCheck />}
                onClick={() => {
                  setReason("");
                  setAllow(h);
                }}
              >
                {t("hosts.allow")}
              </Button>
            )}
            <Button size="xs" variant="ghost" icon={<Trash2 />} aria-label={t("hosts.remove", { host: h.name })} onClick={() => setRemoving(h)} />
          </span>
        ) : (
          <StatusBadge tone={h.allowed ? "success" : "neutral"}>{h.allowed ? t("hosts.allowedShort") : t("hosts.pausedShort")}</StatusBadge>
        ),
    },
  ];
  return (
    <>
      <PageHeader
        title={t("hosts.title")}
        description={t("hosts.pageDetail")}
        actions={
          <Button icon={<Wrench />} onClick={() => navigate("/setup")}>
            {t("hosts.install")}
          </Button>
        }
      />
      <Callout tone="warning" title={t("hosts.gateTitle")}>
        {t("hosts.gateDetail")}
      </Callout>
      <KpiGrid>
        <KpiCard label={t("hosts.hosts")} value={hosts.length} />
        <KpiCard label={t("hostStatuses.allowed")} value={hosts.filter((h) => h.allowed).length} tone="success" />
        <KpiCard label={t("hostStatuses.paused")} value={hosts.filter((h) => h.status === "paused").length} />
        <KpiCard
          label={t("hostStatuses.silent")}
          value={hosts.filter((h) => h.status === "silent").length}
          tone={hosts.some((h) => h.status === "silent") ? "danger" : undefined}
        />
      </KpiGrid>
      <FilterBar onClear={status.length ? () => setStatus([]) : undefined}>
        <FacetFilter
          label={t("hosts.status")}
          selected={status}
          onChange={setStatus}
          options={(["allowed", "paused", "silent"] as const).map((s) => ({
            value: s,
            label: t(`hostStatuses.${s}`),
            count: hosts.filter((h) => h.status === s).length,
          }))}
        />
      </FilterBar>
      <ErrorText message={error} />
      <Panel title={t("hosts.hosts")} description={t("hosts.shown", { count: rows.length })} flush>
        <DataTable
          label={t("hosts.table")}
          columns={cols}
          rows={rows}
          getRowId={(h) => h.id}
          minWidth={900}
          empty={<EmptyState title={t("hosts.none")}>{t("hosts.noneDetail")}</EmptyState>}
        />
      </Panel>
      {can("admin") && <TokensPanel call={call} />}
      <Dialog
        open={!!allow}
        onOpenChange={(o) => !o && setAllow(undefined)}
        title={t("hosts.allowTitle", { host: allow?.name ?? "" })}
        description={t("hosts.allowDetail")}
        footer={
          <Button
            variant="primary"
            disabled={reason.trim().length < 3}
            onClick={() =>
              void run(() => call(`/api/v1/hosts/${allow!.id}/allow`, { method: "PUT", body: JSON.stringify({ allowed: true, reason }) })).then(() =>
                setAllow(undefined),
              )
            }
          >
            {t("hosts.allowConfirm")}
          </Button>
        }
      >
        <TextField label={t("hosts.reason")} value={reason} onChange={(e) => setReason(e.target.value)} placeholder={t("hosts.reasonPlaceholder")} required />
      </Dialog>
      <Dialog
        open={!!removing}
        onOpenChange={(o) => !o && setRemoving(undefined)}
        title={t("hosts.removeTitle", { host: removing?.name ?? "" })}
        description={t("hosts.removeDetail")}
        footer={
          <Button
            variant="danger"
            onClick={() => void run(() => call(`/api/v1/hosts/${removing!.id}`, { method: "DELETE" })).then(() => setRemoving(undefined))}
          >
            {t("hosts.removeConfirm")}
          </Button>
        }
      />
    </>
  );
}

// ---------------------------------------------------------------- Setup

function SetupPage() {
  const t = useT();
  const origin = window.location.origin;
  return (
    <>
      <PageHeader title={t("setup.title")} description={t("setup.description")} />
      <Panel title={t("setup.agent")} description={t("setup.agentDetail")}>
        <Code>{`# On the host you want to test, with its own key
openssl rand -hex 32 > openasy-agent-kek
ATTACKSIM_URL=${origin} ATTACKSIM_ENROLL_TOKEN=<from Hosts> docker compose up -d`}</Code>
      </Panel>
      <Panel title={t("setup.allow")} description={t("setup.allowDetail")} />
      <Panel title={t("setup.detectors")} description={t("setup.detectorsDetail")}>
        <Code>{`ATTACKSIM_DETECTORS=siem=http://siem:8080|<SIEM read token>,runtime=http://runtime:8080|<Runtime read token>`}</Code>
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const t = useT();
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title={t("settingsPage.adminsOnly")}>{t("settingsPage.askAnAdmin")}</EmptyState>;
  return (
    <>
      <PageHeader
        title={t(`settingsPage.${page}.title`)}
        description={t(`settingsPage.${page}.description`)}
        actions={
          page === "account" && (
            <Button icon={<LogOut />} onClick={() => void signOut()}>
              {t("settingsPage.signOut")}
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product() {
  const msg = useT();
  const [theme, setTheme] = useThemePreference();
  const [, setLocale] = useLocalePreference();
  const { me, can } = useAuth();
  const account = useAccountMenu();
  const route = parseRoute(usePath());
  const [summary, setSummary] = useState<Summary>();
  const [hosts, setHosts] = useState<Host[]>();
  const [tests, setTests] = useState<PackTest[]>([]);
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);
  const call = useApi();
  const onSearch = useMemo(() => search(call, msg), [call, msg]);

  useEffect(() => {
    void call<{ products: ProductLink[] }>("/api/v1/products").then(
      (r) =>
        setProducts(
          r.products.filter((p): p is ProductLink & { id: ProductId } => p.id !== "attack-simulation" && (PRODUCT_IDS as readonly string[]).includes(p.id)),
        ),
      () => {},
    );
    void call<{ tests: PackTest[] }>("/api/v1/tests").then(
      (r) => setTests(r.tests),
      () => {},
    );
  }, [call]);

  const reload = useCallback(() => {
    void call<Summary>("/api/v1/summary").then(setSummary, () => {});
    void call<{ hosts: Host[] }>("/api/v1/hosts").then(
      (r) => setHosts(r.hosts),
      () => {},
    );
  }, [call]);
  useEffect(() => {
    reload();
    const h = setInterval(reload, 15_000);
    return () => clearInterval(h);
  }, [reload]);

  const nav = [
    { id: "coverage", label: msg("product.coverage"), icon: LayoutGrid },
    { id: "runs", label: msg("product.runs"), icon: Swords, count: summary?.runs.running || undefined },
    { id: "tests", label: msg("product.tests"), icon: Crosshair, count: summary?.techniques.available || undefined },
    { id: "hosts", label: msg("product.hosts"), icon: Server },
    { id: "setup", label: msg("product.setup"), icon: Wrench },
  ];
  const footerNav = [
    ...(can("admin")
      ? [
          { id: "members", label: msg("product.members"), icon: Users },
          { id: "signin", label: msg("product.signIn"), icon: LogIn },
          { id: "tokens", label: msg("product.apiTokens"), icon: KeyRound },
        ]
      : []),
    { id: "account", label: msg("product.account"), icon: UserRound },
  ];
  const roleName = me.user.role.charAt(0).toUpperCase() + me.user.role.slice(1);
  const settings = route.page === "account" || route.page === "members" || route.page === "signin" || route.page === "tokens";

  return (
    <AppShell
      product="attack-simulation"
      onSearch={onSearch}
      about={colophon}
      nav={nav}
      activeNav={route.page}
      onNavigate={(id) => navigate(`/${id}`)}
      connectedProducts={products.map((p) => p.id)}
      onSwitchProduct={(id) => {
        const to = products.find((p) => p.id === id);
        if (to) window.location.assign(to.url);
      }}
      footerNav={account.settings(footerNav)}
      setup
      user={{ name: me.user.name, role: roleName, ...account.user }}
      theme={theme}
      onThemeChange={setTheme}
      onLanguageChange={(code) => setLocale(toLocale(code))}
    >
      {settings ? (
        <SettingsPage page={route.page as "account" | "members" | "signin" | "tokens"} />
      ) : !summary || !hosts ? (
        <EmptyState title={msg("product.loading")} icon={<FlaskConical />}>
          {msg("product.reading")}
        </EmptyState>
      ) : route.page === "runs" ? (
        route.id ? (
          <RunDetailPage call={call} id={route.id} reload={reload} />
        ) : (
          <RunsPage call={call} hosts={hosts} tests={tests} reload={reload} />
        )
      ) : route.page === "tests" ? (
        <TestsPage tests={tests} />
      ) : route.page === "hosts" ? (
        <HostsPage call={call} hosts={hosts} reload={reload} />
      ) : route.page === "setup" ? (
        <SetupPage />
      ) : (
        <CoveragePage call={call} summary={summary} />
      )}
    </AppShell>
  );
}

export function App() {
  const installBrand = useInstallBrand();
  const [theme] = useThemePreference();
  const [locale] = useLocalePreference();
  return (
    // The install's brand from config/brand.env (ADR 0053); OpenAsy's own look where it sets none.
    <BrandProvider theme={theme} locale={locale} brand={{ name: "OpenAsy", organization: undefined, ...installBrand }} className="min-h-screen">
      <AuthGate product="OpenAsy Attack Simulation">
        <Product />
      </AuthGate>
    </BrandProvider>
  );
}
