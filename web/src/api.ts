// The UI is an ordinary client of the public API (ADR 0014, 0018). Types follow openapi.json.

export type Severity = "critical" | "high" | "medium" | "low";
export type FailOn = Severity | "none";
export type Counts = Record<Severity, number>;

/** Another OpenAsy product of this install, from OPENASY_PRODUCTS. */
export interface ProductLink {
  id: string;
  url: string;
}

export interface Summary {
  /** Not archived. */
  repositories: number;
  /** Archived on their forge, or gone from it. */
  archived: number;
  open: Counts;
  suppressed: number;
  failingChecks: number;
  lastScanAt: string | null;
}

/** The overview page: open findings over time, new and fixed by week, the noisiest rules and repositories, checks. */
export interface Overview {
  open: Counts;
  days: Array<{ day: string; open: Counts }>;
  weeks: Array<{ week: string; new: number; fixed: number }>;
  topRules: Array<{ rule: string; open: number; severity: Severity }>;
  topRepositories: Array<{ id: string; name: string; open: number }>;
  checks: { days7: { passed: number; failed: number }; days30: { passed: number; failed: number } };
}

export interface Repository {
  id: string;
  name: string;
  defaultBranch: string;
  failOn: FailOn;
  open: Counts;
  suppressed: number;
  lastScan: { at: string; kind: "baseline" | "change"; branch: string; new: number; passed: boolean } | null;
  createdAt: string;
  /** github: from a connection, scanned by sast-agent; ci: sent from CI. */
  source: "github" | "gitlab" | "ci";
  scanEnabled: boolean;
  /** Archived on its forge, or gone from the account: not scanned, its findings not counted as open. */
  archivedAt: string | null;
  /** The repositories file says whether it is scanned. */
  scanFromFile: boolean;
  headCommit: string | null;
  scannedCommit: string | null;
}

/** A rule file the install wrote, in Opengrep's format. */
export interface OwnRule {
  id: string;
  name: string;
  yaml: string;
  createdAt: string;
  updatedAt: string;
}

export interface RuleList {
  own: OwnRule[];
  /** Rule ids no scan reports. */
  disabled: string[];
}

/** A GitHub account whose repositories sast follows (ADR 0036). The token is never sent back. */
export interface Connection {
  id: string;
  kind: "github" | "gitlab";
  account: string;
  apiUrl: string;
  /** file: from the repositories file (OPENASY_REPOSITORIES); ui: made in the UI before it. */
  source: "ui" | "file";
  fileName: string | null;
  /** The environment variable its token is read from; never the token. */
  tokenVar: string | null;
  createdAt: string;
  syncedAt: string | null;
  error: string | null;
  repositories: number;
}

export interface RepositoriesFile {
  path: string;
  appliedAt: string | null;
  forges: number;
  repositories: number;
  error: string | null;
  warnings: string[];
}

export interface Agent {
  id: string;
  name: string;
  status: "waiting-to-enrol" | "online" | "offline";
  version: string | null;
  lastSeen: string | null;
  createdAt: string;
}

export interface Job {
  id: string;
  repository: string;
  branch: string;
  commit: string;
  status: "queued" | "running" | "done" | "failed";
  attempts: number;
  error: string | null;
  scanId: string | null;
  /** The pull request scanned, by number; null for the default branch. */
  pullRequest: string | null;
  /** Why the result could not be posted to the pull request. */
  checkError: string | null;
  createdAt: string;
  finishedAt: string | null;
}

export interface TriageState {
  state: "false-positive" | "accepted";
  reason: string;
  by: string | null;
  at: string | null;
  expiresAt: string | null;
  active: boolean;
}

export interface Finding {
  repository: { id: string; name: string };
  fingerprint: string;
  rule: string;
  severity: Severity;
  path: string;
  line: number | null;
  message: string;
  snippet: string | null;
  firstSeen: string;
  lastSeen: string;
  resolvedAt: string | null;
  triage: TriageState | null;
}

export interface Scan {
  id: string;
  repository: { id: string; name: string };
  kind: "baseline" | "change";
  branch: string;
  commit: string | null;
  pullRequest: string | null;
  tool: string;
  total: number;
  new: number;
  suppressed: number;
  blocking: number;
  failOn: FailOn;
  passed: boolean;
  createdAt: string;
}

export interface ScanDetail extends Scan {
  findings: Array<{
    fingerprint: string;
    rule: string;
    severity: Severity;
    path: string;
    line: number | null;
    message: string;
    snippet: string | null;
    suppressed: boolean;
  }>;
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
