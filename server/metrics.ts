// Prometheus text exposition, written by hand: a few lines, no client library needed.
const requests = new Map<string, number>();

export function countRequest(method: string, route: string, status: number) {
  const key = `method="${method}",route="${route}",status="${status}"`;
  requests.set(key, (requests.get(key) ?? 0) + 1);
}

export interface Gauges {
  repositories: number;
  /** Open findings on default branches by severity, without triaged ones. */
  findings: Record<string, number>;
  suppressed: number;
  /** Scans of the last 7 days that failed their check. */
  failingChecks: number;
}

export function renderMetrics(version: string, g: Gauges): string {
  const lines = [
    "# HELP openasy_build_info Build information.",
    "# TYPE openasy_build_info gauge",
    `openasy_build_info{product="sast",version="${version}"} 1`,
    "# HELP openasy_http_requests_total HTTP requests handled.",
    "# TYPE openasy_http_requests_total counter",
    ...[...requests].map(([labels, n]) => `openasy_http_requests_total{${labels}} ${n}`),
    "# HELP openasy_sast_repositories Repositories with at least one scan.",
    "# TYPE openasy_sast_repositories gauge",
    `openasy_sast_repositories ${g.repositories}`,
    "# HELP openasy_sast_open_findings Open findings on default branches by severity, without triaged ones.",
    "# TYPE openasy_sast_open_findings gauge",
    ...Object.entries(g.findings).map(([s, n]) => `openasy_sast_open_findings{severity="${s}"} ${n}`),
    "# HELP openasy_sast_suppressed_findings Open findings that someone marked as a false positive or accepted risk.",
    "# TYPE openasy_sast_suppressed_findings gauge",
    `openasy_sast_suppressed_findings ${g.suppressed}`,
    "# HELP openasy_sast_failing_checks Scans of the last 7 days that failed their check.",
    "# TYPE openasy_sast_failing_checks gauge",
    `openasy_sast_failing_checks ${g.failingChecks}`,
    "# HELP process_uptime_seconds Seconds since the process started.",
    "# TYPE process_uptime_seconds gauge",
    `process_uptime_seconds ${process.uptime().toFixed(0)}`,
  ];
  return lines.join("\n") + "\n";
}
