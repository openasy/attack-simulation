// Prometheus text exposition, written by hand: a few lines, no client library needed.
const requests = new Map<string, number>();

export function countRequest(method: string, route: string, status: number) {
  const key = `method="${method}",route="${route}",status="${status}"`;
  requests.set(key, (requests.get(key) ?? 0) + 1);
}

export interface Gauges {
  hosts: { total: number; allowed: number; paused: number; silent: number };
  runs: { running: number; done: number; total: number };
  techniques: { total: number; detected: number; missed: number; pending: number };
}

export function renderMetrics(version: string, g: Gauges): string {
  const lines = [
    "# HELP openasy_build_info Build information.",
    "# TYPE openasy_build_info gauge",
    `openasy_build_info{product="attack-simulation",version="${version}"} 1`,
    "# HELP openasy_http_requests_total HTTP requests handled.",
    "# TYPE openasy_http_requests_total counter",
    ...[...requests].map(([labels, n]) => `openasy_http_requests_total{${labels}} ${n}`),
    "# HELP openasy_attacksim_hosts Hosts by status. Allowed ones may run simulations; paused ones never do.",
    "# TYPE openasy_attacksim_hosts gauge",
    `openasy_attacksim_hosts{status="allowed"} ${g.hosts.allowed}`,
    `openasy_attacksim_hosts{status="paused"} ${g.hosts.paused}`,
    `openasy_attacksim_hosts{status="silent"} ${g.hosts.silent}`,
    "# HELP openasy_attacksim_runs_running Runs in progress now.",
    "# TYPE openasy_attacksim_runs_running gauge",
    `openasy_attacksim_runs_running ${g.runs.running}`,
    "# HELP openasy_attacksim_runs_total Runs started since the first.",
    "# TYPE openasy_attacksim_runs_total counter",
    `openasy_attacksim_runs_total ${g.runs.total}`,
    "# HELP openasy_attacksim_techniques Techniques by their latest outcome across all runs.",
    "# TYPE openasy_attacksim_techniques gauge",
    `openasy_attacksim_techniques{outcome="detected"} ${g.techniques.detected}`,
    `openasy_attacksim_techniques{outcome="missed"} ${g.techniques.missed}`,
    `openasy_attacksim_techniques{outcome="pending"} ${g.techniques.pending}`,
    "# HELP process_uptime_seconds Seconds since the process started.",
    "# TYPE process_uptime_seconds gauge",
    `process_uptime_seconds ${process.uptime().toFixed(0)}`,
  ];
  return lines.join("\n") + "\n";
}
