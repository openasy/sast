import { randomUUID } from "node:crypto";
import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import { parseSarif, SarifError, SEVERITIES, type Finding, type Severity } from "./sarif.ts";

export type ProblemCode =
  "invalid-token" | "invalid-json" | "invalid-body" | "invalid-sarif" | "not-found" | "conflict" | "not-configured" | "payload-too-large" | "internal-error";

export class SastError extends Error {
  readonly status: number;
  readonly code: ProblemCode;
  constructor(status: number, code: ProblemCode, detail: string) {
    super(detail);
    this.status = status;
    this.code = code;
  }
}

export type FailOn = Severity | "none";
export type Triage = "open" | "false-positive" | "accepted";
export type Status = "open" | "suppressed" | "resolved";

const FAIL_ON: FailOn[] = [...SEVERITIES, "none"];
const TRIAGE: Triage[] = ["open", "false-positive", "accepted"];
const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const RANK_SQL = `CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END`;

// owner/name, as the forge writes it, or a plain name.
const REPO_NAME = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$/;
const BRANCH = /^[^\s\x00-\x1f]{1,255}$/;
const MAX_ACCEPT_DAYS = 366;
/** Findings in the answer to a scan, for CI logs. The rest are on the scan's page. */
const SCAN_FINDINGS_IN_ANSWER = 100;

const now = () => new Date().toISOString();
const bad = (detail: string) => new SastError(422, "invalid-body", detail);
const notFound = (what: string) => new SastError(404, "not-found", `${what} does not exist.`);

export interface Page<T> {
  items: T[];
  /** Opaque; pass it back as `cursor` for the next page. Absent on the last page (ADR 0024). */
  nextCursor?: string;
}

const encodeCursor = (offset: number) => Buffer.from(JSON.stringify({ o: offset })).toString("base64url");
function decodeCursor(cursor: string | undefined): number {
  if (!cursor) return 0;
  try {
    const o = (JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as { o?: unknown }).o;
    if (typeof o === "number" && Number.isSafeInteger(o) && o >= 0) return o;
  } catch {
    // fall through
  }
  throw bad("cursor is not one this API returned.");
}

export function parseLimit(value: string | null, max = 500, fallback = 100): number {
  if (value === null) return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > max) throw bad(`limit must be between 1 and ${max}.`);
  return n;
}

export type Counts = Record<Severity, number>;
const zero = (): Counts => ({ critical: 0, high: 0, medium: 0, low: 0 });

export interface FindingFilter {
  status: Status;
  severity?: Severity[];
  q?: string;
  repoId?: string;
}

interface FindingRow {
  repo_id: string;
  repo_name: string;
  fingerprint: string;
  rule_id: string;
  severity: Severity;
  path: string;
  line: number | null;
  message: string;
  snippet: string | null;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
  triage: Triage;
  reason: string | null;
  triaged_by: string | null;
  triaged_at: string | null;
  expires_at: string | null;
}

export interface SastOptions {
  /** Scans, and resolved findings that are no longer reported, older than this are deleted (ADR 0015). */
  retentionDays?: number;
}

export function createSast(db: DatabaseSync, { retentionDays = 365 }: SastOptions = {}) {
  // Triage that has not expired. A finding whose acceptance ran out is open again.
  const SUPPRESSED = `(triage <> 'open' AND (expires_at IS NULL OR expires_at > ?))`;

  const repoRow = (id: string) => {
    const r = db.prepare("SELECT * FROM repositories WHERE id = ?").get(id) as Record<string, string> | undefined;
    if (!r) throw notFound("The repository");
    return r;
  };

  function openCounts(repoId?: string): Counts {
    const c = zero();
    const rows = db
      .prepare(
        `SELECT severity, COUNT(*) AS n FROM findings WHERE resolved_at IS NULL AND NOT ${SUPPRESSED} ${repoId ? "AND repo_id = ?" : ""} GROUP BY severity`,
      )
      .all(...([now(), ...(repoId ? [repoId] : [])] as SQLInputValue[])) as Array<{ severity: Severity; n: number }>;
    for (const r of rows) c[r.severity] = r.n;
    return c;
  }

  function presentRepo(r: Record<string, any>) {
    const last = db
      .prepare("SELECT created_at, kind, branch, new_count, blocking FROM scans WHERE repo_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1")
      .get(r.id) as Record<string, any> | undefined;
    const suppressed = (
      db.prepare(`SELECT COUNT(*) AS n FROM findings WHERE repo_id = ? AND resolved_at IS NULL AND ${SUPPRESSED}`).get(r.id, now()) as { n: number }
    ).n;
    return {
      id: r.id as string,
      name: r.name as string,
      defaultBranch: r.default_branch as string,
      failOn: r.fail_on as FailOn,
      // From a forge connection, scanned by sast-agent, or sent from CI (ADR 0036).
      source: ((r.connection_id &&
        (db.prepare("SELECT kind FROM forge_connections WHERE id = ?").get(r.connection_id) as { kind: string } | undefined)?.kind) ||
        "ci") as "github" | "gitlab" | "ci",
      scanEnabled: r.scan_enabled !== 0,
      headCommit: (r.head_commit ?? null) as string | null,
      scannedCommit: (r.scanned_commit ?? null) as string | null,
      open: openCounts(r.id),
      suppressed,
      lastScan: last
        ? {
            at: last.created_at as string,
            kind: last.kind as "baseline" | "change",
            branch: last.branch as string,
            new: last.new_count as number,
            passed: last.blocking === 0,
          }
        : null,
      createdAt: r.created_at as string,
    };
  }

  function presentFinding(f: FindingRow) {
    const active = f.triage !== "open" && (!f.expires_at || f.expires_at > now());
    return {
      repository: { id: f.repo_id, name: f.repo_name },
      fingerprint: f.fingerprint,
      rule: f.rule_id,
      severity: f.severity,
      path: f.path,
      line: f.line,
      message: f.message,
      snippet: f.snippet,
      firstSeen: f.first_seen,
      lastSeen: f.last_seen,
      resolvedAt: f.resolved_at,
      triage:
        f.triage === "open"
          ? null
          : { state: f.triage as Exclude<Triage, "open">, reason: f.reason!, by: f.triaged_by, at: f.triaged_at, expiresAt: f.expires_at, active },
    };
  }

  function findingsQuery(filter: FindingFilter, cursor: string | undefined, limit: number) {
    const where: string[] = [];
    const args: SQLInputValue[] = [];
    // The same instant for every use of SUPPRESSED in one query.
    const at = now();
    if (filter.status === "resolved") where.push("f.resolved_at IS NOT NULL");
    else {
      where.push("f.resolved_at IS NULL");
      where.push(filter.status === "suppressed" ? SUPPRESSED.replace("?", "'" + at + "'") : `NOT ${SUPPRESSED.replace("?", "'" + at + "'")}`);
    }
    if (filter.repoId) (where.push("f.repo_id = ?"), args.push(filter.repoId));
    if (filter.severity?.length) (where.push(`f.severity IN (${filter.severity.map(() => "?").join(",")})`), args.push(...filter.severity));
    if (filter.q) {
      const like = `%${filter.q.replace(/[\\%_]/g, "\\$&")}%`;
      where.push("(f.rule_id LIKE ? ESCAPE '\\' OR f.path LIKE ? ESCAPE '\\' OR f.message LIKE ? ESCAPE '\\')");
      args.push(like, like, like);
    }
    const offset = decodeCursor(cursor);
    const rows = db
      .prepare(
        `SELECT f.*, r.name AS repo_name FROM findings f JOIN repositories r ON r.id = f.repo_id WHERE ${where.join(" AND ")}
         ORDER BY ${RANK_SQL.replaceAll("severity", "f.severity")} DESC, f.first_seen DESC, f.fingerprint LIMIT ? OFFSET ?`,
      )
      .all(...args, limit + 1, offset) as unknown as FindingRow[];
    const items = rows.slice(0, limit).map(presentFinding);
    return { items, ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }) } satisfies Page<unknown>;
  }

  function presentScan(s: Record<string, any>, repoName: string) {
    return {
      id: s.id as string,
      repository: { id: s.repo_id as string, name: repoName },
      kind: s.kind as "baseline" | "change",
      branch: s.branch as string,
      commit: (s.commit_sha as string | null) ?? null,
      pullRequest: (s.pull_request as string | null) ?? null,
      tool: s.tool as string,
      total: s.total as number,
      new: s.new_count as number,
      suppressed: s.suppressed as number,
      blocking: s.blocking as number,
      failOn: s.fail_on as FailOn,
      passed: s.blocking === 0,
      createdAt: s.created_at as string,
    };
  }

  return {
    /**
     * Takes a SARIF log from CI. Scans of the default branch become the baseline; every other scan is compared with
     * it, and only findings the baseline does not have, and nobody has triaged, can fail the check.
     */
    ingest(
      params: { repository: string | null; branch: string | null; commit?: string | null; pullRequest?: string | null; defaultBranch?: string | null },
      raw: Buffer,
    ) {
      const name = params.repository;
      if (!name || !REPO_NAME.test(name)) throw bad("repository is required: a name such as acme/web, up to 128 letters, digits, . _ - and /.");
      const branch = params.branch;
      if (!branch || !BRANCH.test(branch)) throw bad("branch is required: the branch that was scanned.");
      const commit = params.commit || null;
      if (commit && !/^[A-Za-z0-9]{4,64}$/.test(commit)) throw bad("commit must be a commit hash.");
      const pullRequest = params.pullRequest || null;
      if (pullRequest && !/^[A-Za-z0-9._#/-]{1,64}$/.test(pullRequest)) throw bad("pullRequest must be the number or name of the pull request.");
      if (params.defaultBranch && !BRANCH.test(params.defaultBranch)) throw bad("defaultBranch is not a branch name.");

      let body: unknown;
      try {
        body = JSON.parse(raw.toString("utf8"));
      } catch {
        throw new SastError(422, "invalid-sarif", "The body is not JSON.");
      }
      let parsed: ReturnType<typeof parseSarif>;
      try {
        parsed = parseSarif(body);
      } catch (err) {
        if (err instanceof SarifError) throw new SastError(422, "invalid-sarif", err.message);
        throw err;
      }

      const at = now();
      const id = randomUUID();
      db.exec("BEGIN IMMEDIATE");
      try {
        let repo = db.prepare("SELECT * FROM repositories WHERE name = ?").get(name) as Record<string, string> | undefined;
        if (!repo) {
          const repoId = randomUUID();
          db.prepare("INSERT INTO repositories (id, name, default_branch, fail_on, created_at) VALUES (?, ?, ?, 'high', ?)").run(
            repoId,
            name,
            params.defaultBranch || "main",
            at,
          );
          repo = repoRow(repoId);
        } else if (params.defaultBranch && params.defaultBranch !== repo.default_branch) {
          db.prepare("UPDATE repositories SET default_branch = ? WHERE id = ?").run(params.defaultBranch, repo.id!);
          repo.default_branch = params.defaultBranch;
        }
        const repoId = repo.id!;
        const failOn = repo.fail_on as FailOn;
        const kind = branch === repo.default_branch && !pullRequest ? "baseline" : "change";

        const known = new Map<string, { resolved_at: string | null; triage: Triage; expires_at: string | null }>();
        for (const r of db.prepare("SELECT fingerprint, resolved_at, triage, expires_at FROM findings WHERE repo_id = ?").all(repoId) as Array<{
          fingerprint: string;
          resolved_at: string | null;
          triage: Triage;
          expires_at: string | null;
        }>)
          known.set(r.fingerprint, r);
        const triaged = (f: Finding) => {
          const k = known.get(f.fingerprint);
          return !!k && k.triage !== "open" && (!k.expires_at || k.expires_at > at);
        };
        // New: the baseline has no open finding with this fingerprint.
        const fresh = parsed.findings.filter((f) => !known.has(f.fingerprint) || known.get(f.fingerprint)!.resolved_at !== null);
        const added = fresh.filter((f) => !triaged(f));
        // The default branch is what was merged: its scan adopts what is there and never fails a pipeline. Changes do.
        const blocking = failOn === "none" || kind === "baseline" ? 0 : added.filter((f) => RANK[f.severity] >= RANK[failOn]).length;

        db.prepare(
          "INSERT INTO scans (id, repo_id, kind, branch, commit_sha, pull_request, tool, total, new_count, suppressed, blocking, fail_on, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ).run(
          id,
          repoId,
          kind,
          branch,
          commit,
          pullRequest,
          parsed.tool,
          parsed.findings.length,
          added.length,
          fresh.length - added.length,
          blocking,
          failOn,
          at,
        );

        if (kind === "baseline") {
          const upsert = db.prepare(
            `INSERT INTO findings (repo_id, fingerprint, rule_id, severity, path, line, message, snippet, first_seen, last_seen)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (repo_id, fingerprint) DO UPDATE SET rule_id = excluded.rule_id, severity = excluded.severity, path = excluded.path, line = excluded.line,
               message = excluded.message, snippet = excluded.snippet, last_seen = excluded.last_seen,
               first_seen = CASE WHEN findings.resolved_at IS NULL THEN findings.first_seen ELSE excluded.first_seen END, resolved_at = NULL`,
          );
          for (const f of parsed.findings) upsert.run(repoId, f.fingerprint, f.ruleId, f.severity, f.path, f.line, f.message, f.snippet, at, at);
          // What the default branch no longer reports is fixed.
          db.prepare("UPDATE findings SET resolved_at = ? WHERE repo_id = ? AND resolved_at IS NULL AND last_seen < ?").run(at, repoId, at);
        } else {
          const insert = db.prepare(
            "INSERT INTO scan_findings (scan_id, fingerprint, rule_id, severity, path, line, message, snippet, suppressed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
          );
          for (const f of fresh) insert.run(id, f.fingerprint, f.ruleId, f.severity, f.path, f.line, f.message, f.snippet, triaged(f) ? 1 : 0);
        }
        db.exec("COMMIT");
        const scan = presentScan(db.prepare("SELECT * FROM scans WHERE id = ?").get(id) as Record<string, any>, name);
        return {
          ...scan,
          findings: added
            .sort((a, b) => RANK[b.severity] - RANK[a.severity])
            .slice(0, SCAN_FINDINGS_IN_ANSWER)
            .map((f) => ({ fingerprint: f.fingerprint, rule: f.ruleId, severity: f.severity, path: f.path, line: f.line, message: f.message })),
        };
      } catch (err) {
        db.exec("ROLLBACK");
        throw err;
      }
    },

    summary() {
      const repositories = (db.prepare("SELECT COUNT(*) AS n FROM repositories").get() as { n: number }).n;
      const suppressed = (db.prepare(`SELECT COUNT(*) AS n FROM findings WHERE resolved_at IS NULL AND ${SUPPRESSED}`).get(now()) as { n: number }).n;
      const week = new Date(Date.now() - 7 * 86_400_000).toISOString();
      const failing = (db.prepare("SELECT COUNT(*) AS n FROM scans WHERE kind = 'change' AND blocking > 0 AND created_at > ?").get(week) as { n: number }).n;
      const lastScanAt = (db.prepare("SELECT MAX(created_at) AS t FROM scans").get() as { t: string | null }).t;
      return { repositories, open: openCounts(), suppressed, failingChecks: failing, lastScanAt };
    },

    severityTotals: () => openCounts(),
    repositoryCount: () => (db.prepare("SELECT COUNT(*) AS n FROM repositories").get() as { n: number }).n,
    suppressedCount: () => (db.prepare(`SELECT COUNT(*) AS n FROM findings WHERE resolved_at IS NULL AND ${SUPPRESSED}`).get(now()) as { n: number }).n,

    listRepositories(cursor: string | undefined, limit: number): Page<ReturnType<typeof presentRepo>> {
      const offset = decodeCursor(cursor);
      const rows = db.prepare("SELECT * FROM repositories ORDER BY name LIMIT ? OFFSET ?").all(limit + 1, offset) as Array<Record<string, any>>;
      return { items: rows.slice(0, limit).map(presentRepo), ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }) };
    },

    repository: (id: string) => presentRepo(repoRow(id)),

    updateRepository(id: string, body: Record<string, unknown>) {
      repoRow(id);
      const { defaultBranch, failOn, scanEnabled, ...rest } = body;
      if (Object.keys(rest).length || (defaultBranch === undefined && failOn === undefined && scanEnabled === undefined))
        throw bad("Expected { defaultBranch?, failOn?, scanEnabled? }.");
      if (scanEnabled !== undefined) {
        if (typeof scanEnabled !== "boolean") throw bad("scanEnabled must be true or false.");
        db.prepare("UPDATE repositories SET scan_enabled = ? WHERE id = ?").run(scanEnabled ? 1 : 0, id);
        if (!scanEnabled) db.prepare("DELETE FROM scan_jobs WHERE repo_id = ? AND status = 'queued'").run(id);
      }
      if (defaultBranch !== undefined) {
        if (typeof defaultBranch !== "string" || !BRANCH.test(defaultBranch)) throw bad("defaultBranch must be a branch name.");
        db.prepare("UPDATE repositories SET default_branch = ? WHERE id = ?").run(defaultBranch, id);
      }
      if (failOn !== undefined) {
        if (typeof failOn !== "string" || !FAIL_ON.includes(failOn as FailOn)) throw bad(`failOn must be one of ${FAIL_ON.join(", ")}.`);
        db.prepare("UPDATE repositories SET fail_on = ? WHERE id = ?").run(failOn, id);
      }
      return presentRepo(repoRow(id));
    },

    deleteRepository(id: string) {
      if (db.prepare("DELETE FROM repositories WHERE id = ?").run(id).changes === 0) throw notFound("The repository");
    },

    findings(filter: FindingFilter, cursor: string | undefined, limit: number) {
      if (filter.repoId) repoRow(filter.repoId);
      return findingsQuery(filter, cursor, limit);
    },

    scans(repoId: string, cursor: string | undefined, limit: number) {
      const repo = repoRow(repoId);
      const offset = decodeCursor(cursor);
      const rows = db
        .prepare("SELECT * FROM scans WHERE repo_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?")
        .all(repoId, limit + 1, offset) as Array<Record<string, any>>;
      return {
        items: rows.slice(0, limit).map((s) => presentScan(s, repo.name!)),
        ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }),
      } satisfies Page<unknown>;
    },

    scan(id: string) {
      const s = db.prepare("SELECT s.*, r.name AS repo_name FROM scans s JOIN repositories r ON r.id = s.repo_id WHERE s.id = ?").get(id) as
        Record<string, any> | undefined;
      if (!s) throw notFound("The scan");
      const findings = (
        db.prepare(`SELECT * FROM scan_findings WHERE scan_id = ? ORDER BY ${RANK_SQL} DESC, path, line`).all(id) as Array<Record<string, any>>
      ).map((f) => ({
        fingerprint: f.fingerprint as string,
        rule: f.rule_id as string,
        severity: f.severity as Severity,
        path: f.path as string,
        line: (f.line as number | null) ?? null,
        message: f.message as string,
        snippet: (f.snippet as string | null) ?? null,
        suppressed: f.suppressed === 1,
      }));
      return { ...presentScan(s, s.repo_name), findings };
    },

    /** Sets or clears the triage of one finding. It follows the fingerprint to every branch of the repository. */
    triage(repoId: string, fingerprint: string, body: Record<string, unknown>, by: string) {
      repoRow(repoId);
      const { state, reason, expiresAt, ...rest } = body;
      if (Object.keys(rest).length || typeof state !== "string" || !TRIAGE.includes(state as Triage))
        throw bad(`Expected { state, reason?, expiresAt? }; state is one of ${TRIAGE.join(", ")}.`);
      const held = db.prepare("SELECT 1 FROM findings WHERE repo_id = ? AND fingerprint = ?").get(repoId, fingerprint);
      if (!held) {
        // A finding of a pull request that has not been merged: keep the triage on a baseline row that starts resolved.
        const s = db
          .prepare(
            "SELECT sf.* FROM scan_findings sf JOIN scans s ON s.id = sf.scan_id WHERE s.repo_id = ? AND sf.fingerprint = ? ORDER BY s.created_at DESC LIMIT 1",
          )
          .get(repoId, fingerprint) as Record<string, any> | undefined;
        if (!s) throw notFound("The finding");
        const at = now();
        db.prepare(
          "INSERT INTO findings (repo_id, fingerprint, rule_id, severity, path, line, message, snippet, first_seen, last_seen, resolved_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        ).run(repoId, fingerprint, s.rule_id, s.severity, s.path, s.line, s.message, s.snippet, at, at, at);
      }
      if (state === "open") {
        db.prepare(
          "UPDATE findings SET triage = 'open', reason = NULL, triaged_by = NULL, triaged_at = NULL, expires_at = NULL WHERE repo_id = ? AND fingerprint = ?",
        ).run(repoId, fingerprint);
      } else {
        // A decision without a reason is lost the day its author leaves (ADR 0036).
        if (typeof reason !== "string" || reason.trim().length < 3 || reason.length > 500) throw bad("reason is required: 3 to 500 characters.");
        let expires: string | null = null;
        if (expiresAt !== undefined && expiresAt !== null) {
          const t = typeof expiresAt === "string" ? Date.parse(expiresAt) : NaN;
          if (Number.isNaN(t) || t <= Date.now()) throw bad("expiresAt must be a date in the future.");
          if (t > Date.now() + MAX_ACCEPT_DAYS * 86_400_000) throw bad(`expiresAt must be within ${MAX_ACCEPT_DAYS} days.`);
          expires = new Date(t).toISOString();
        }
        // Accepted risk always ends; a false positive does not need to.
        if (state === "accepted" && !expires) throw bad("expiresAt is required for accepted risk.");
        db.prepare("UPDATE findings SET triage = ?, reason = ?, triaged_by = ?, triaged_at = ?, expires_at = ? WHERE repo_id = ? AND fingerprint = ?").run(
          state,
          reason.trim(),
          by,
          now(),
          expires,
          repoId,
          fingerprint,
        );
      }
      const row = db
        .prepare("SELECT f.*, r.name AS repo_name FROM findings f JOIN repositories r ON r.id = f.repo_id WHERE f.repo_id = ? AND f.fingerprint = ?")
        .get(repoId, fingerprint) as unknown as FindingRow;
      return presentFinding(row);
    },

    purge() {
      const before = new Date(Date.now() - retentionDays * 86_400_000).toISOString();
      db.prepare("DELETE FROM scans WHERE created_at < ?").run(before);
      db.prepare("DELETE FROM findings WHERE resolved_at IS NOT NULL AND resolved_at < ? AND triage = 'open'").run(before);
    },
  };
}

export type Sast = ReturnType<typeof createSast>;
export { SEVERITIES };
