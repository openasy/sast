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
  repositories: number;
  open: Counts;
  suppressed: number;
  failingChecks: number;
  lastScanAt: string | null;
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
  findings: Array<{ fingerprint: string; rule: string; severity: Severity; path: string; line: number | null; message: string; snippet: string | null; suppressed: boolean }>;
}

export class Unauthorized extends Error {}
/** The signed-in owner or admin has no second factor yet; the sign-in gate asks for one. */
export class MfaSetupRequired extends Error {}
export class ApiError extends Error {}

// The session is an HttpOnly cookie set by sign-in (@openasy/auth); the browser sends it, nothing is stored here.
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, { ...init, credentials: "same-origin", headers: { ...(init.body ? { "content-type": "application/json" } : {}), ...init.headers } });
  if (!res.ok) {
    const problem = (await res.json().catch(() => ({}))) as { code?: string; detail?: string };
    if (res.status === 401) throw new Unauthorized(problem.detail);
    if (problem.code === "mfa-setup-required") throw new MfaSetupRequired(problem.detail);
    throw new ApiError(problem.detail ?? `${path}: ${res.status}`);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}
