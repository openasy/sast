import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

// Forward-only migrations (ADR 0010): append new entries, never edit or remove old ones.
const MIGRATIONS = [
  `CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
   -- A repository is created by its first scan. Its default branch is the baseline other branches are compared with.
   CREATE TABLE repositories (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL UNIQUE,
     default_branch TEXT NOT NULL,
     fail_on TEXT NOT NULL CHECK (fail_on IN ('critical', 'high', 'medium', 'low', 'none')),
     created_at TEXT NOT NULL
   );
   -- One row per upload. Scans of the default branch replace the baseline; the others are compared with it.
   CREATE TABLE scans (
     id TEXT PRIMARY KEY,
     repo_id TEXT NOT NULL REFERENCES repositories (id) ON DELETE CASCADE,
     kind TEXT NOT NULL CHECK (kind IN ('baseline', 'change')),
     branch TEXT NOT NULL,
     commit_sha TEXT,
     pull_request TEXT,
     tool TEXT NOT NULL,
     total INTEGER NOT NULL,
     new_count INTEGER NOT NULL,
     suppressed INTEGER NOT NULL,
     blocking INTEGER NOT NULL,
     fail_on TEXT NOT NULL,
     created_at TEXT NOT NULL
   );
   CREATE INDEX scans_repo ON scans (repo_id, created_at DESC);
   -- The baseline: one row per finding on the default branch, found by its fingerprint. A row that stops being
   -- reported gets resolved_at and opens again if the same finding comes back. Triage is kept on the row, so it
   -- follows the finding to every branch. A row made only to hold triage for a finding that has not been merged yet
   -- starts resolved.
   CREATE TABLE findings (
     repo_id TEXT NOT NULL REFERENCES repositories (id) ON DELETE CASCADE,
     fingerprint TEXT NOT NULL,
     rule_id TEXT NOT NULL,
     severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
     path TEXT NOT NULL,
     line INTEGER,
     message TEXT NOT NULL,
     snippet TEXT,
     first_seen TEXT NOT NULL,
     last_seen TEXT NOT NULL,
     resolved_at TEXT,
     triage TEXT NOT NULL DEFAULT 'open' CHECK (triage IN ('open', 'false-positive', 'accepted')),
     reason TEXT,
     triaged_by TEXT,
     triaged_at TEXT,
     expires_at TEXT,
     PRIMARY KEY (repo_id, fingerprint)
   );
   CREATE INDEX findings_open ON findings (repo_id, severity) WHERE resolved_at IS NULL;
   -- What a change scan reported that the baseline did not have, for the pull request page.
   CREATE TABLE scan_findings (
     scan_id TEXT NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
     fingerprint TEXT NOT NULL,
     rule_id TEXT NOT NULL,
     severity TEXT NOT NULL,
     path TEXT NOT NULL,
     line INTEGER,
     message TEXT NOT NULL,
     snippet TEXT,
     suppressed INTEGER NOT NULL,
     PRIMARY KEY (scan_id, fingerprint)
   )`,
  // Repositories from a forge, scanned by sast-agent (ADR 0036). A connection reads one account's repositories with a
  // token sealed by openasy-kek; a repository from it is scanned when its default branch moves. sast holds no code.
  `CREATE TABLE forge_connections (
     id TEXT PRIMARY KEY,
     kind TEXT NOT NULL CHECK (kind IN ('github')),
     account TEXT NOT NULL,
     api_url TEXT NOT NULL,
     token TEXT NOT NULL,
     created_at TEXT NOT NULL,
     synced_at TEXT,
     error TEXT,
     UNIQUE (kind, api_url, account)
   );
   ALTER TABLE repositories ADD COLUMN connection_id TEXT REFERENCES forge_connections (id) ON DELETE SET NULL;
   ALTER TABLE repositories ADD COLUMN clone_url TEXT;
   ALTER TABLE repositories ADD COLUMN scan_enabled INTEGER NOT NULL DEFAULT 1;
   ALTER TABLE repositories ADD COLUMN pushed_at TEXT;
   ALTER TABLE repositories ADD COLUMN head_commit TEXT;
   ALTER TABLE repositories ADD COLUMN scanned_commit TEXT;
   CREATE TABLE agents (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL UNIQUE,
     enroll_token_hash TEXT UNIQUE,
     enroll_expires_at TEXT,
     secret_hash TEXT UNIQUE,
     version TEXT,
     last_seen TEXT,
     created_at TEXT NOT NULL
   );
   -- One scan of one commit of a repository. A job an agent took and did not finish goes back to the queue when its
   -- lease runs out, three times at most.
   CREATE TABLE scan_jobs (
     id TEXT PRIMARY KEY,
     repo_id TEXT NOT NULL REFERENCES repositories (id) ON DELETE CASCADE,
     branch TEXT NOT NULL,
     commit_sha TEXT NOT NULL,
     status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'done', 'failed')),
     agent_id TEXT REFERENCES agents (id) ON DELETE SET NULL,
     lease_until TEXT,
     attempts INTEGER NOT NULL DEFAULT 0,
     error TEXT,
     scan_id TEXT,
     created_at TEXT NOT NULL,
     finished_at TEXT
   );
   CREATE INDEX scan_jobs_queue ON scan_jobs (status, created_at)`,
  // Pull requests of a connected repository are scanned too, and the result goes back to GitHub as a commit status
  // (ADR 0036). check_error says why a status could not be posted, such as a token without that permission.
  `ALTER TABLE scan_jobs ADD COLUMN pull_request TEXT;
   ALTER TABLE scan_jobs ADD COLUMN check_error TEXT;
   -- The one comment sast keeps on a pull request, edited at each scan rather than added again.
   CREATE TABLE pr_comments (
     repo_id TEXT NOT NULL REFERENCES repositories (id) ON DELETE CASCADE,
     pull_request TEXT NOT NULL,
     comment_id TEXT NOT NULL,
     PRIMARY KEY (repo_id, pull_request)
   );`,
  // Rules an install writes itself, in Opengrep's format, sent to the agent with each job (ADR 0036). Which rules
  // are switched off is kept in settings as disabled_rules.
  `CREATE TABLE own_rules (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL UNIQUE,
     yaml TEXT NOT NULL,
     created_at TEXT NOT NULL,
     updated_at TEXT NOT NULL
   );`,
];

/** Opens the product's single SQLite file in WAL mode (ADR 0011) and migrates it forward. */
export function openDb(path: string): DatabaseSync {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
  const row = db.prepare("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").get() as { v: number };
  for (let v = row.v; v < MIGRATIONS.length; v++) {
    db.exec("BEGIN");
    try {
      db.exec(MIGRATIONS[v]!);
      db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)").run(v + 1, new Date().toISOString());
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  }
  return db;
}
