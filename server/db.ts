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
