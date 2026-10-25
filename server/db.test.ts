import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { MIGRATIONS, openDb } from "./db.ts";

describe("openDb", () => {
  it("uses WAL and migrates once", () => {
    const path = join(mkdtempSync(join(tmpdir(), "sast-")), "nested", "sast.db");
    const first = openDb(path);
    expect(first.prepare("PRAGMA journal_mode").get()).toEqual({ journal_mode: "wal" });
    first.close();

    const second = openDb(path);
    expect(second.prepare("SELECT COUNT(*) AS n FROM schema_migrations").get()).toEqual({ n: MIGRATIONS.length });
    second.close();
  });

  it("deletes a repository's scans and findings with it", () => {
    const db = openDb(":memory:");
    db.exec(`INSERT INTO repositories (id, name, default_branch, fail_on, created_at) VALUES ('r', 'acme/web', 'main', 'high', 'now');
      INSERT INTO scans VALUES ('s', 'r', 'baseline', 'main', NULL, NULL, 'opengrep', 1, 1, 0, 0, 'high', 'now');
      INSERT INTO findings (repo_id, fingerprint, rule_id, severity, path, message, first_seen, last_seen) VALUES ('r', 'f', 'x', 'low', 'a', 'm', 'now', 'now');
      DELETE FROM repositories`);
    expect(db.prepare("SELECT (SELECT COUNT(*) FROM scans) + (SELECT COUNT(*) FROM findings) AS n").get()).toEqual({ n: 0 });
  });
  it("keeps each repository's connection when GitLab is let into forge_connections", () => {
    const path = join(mkdtempSync(join(tmpdir(), "sast-")), "sast.db");
    const old = new DatabaseSync(path);
    old.exec("PRAGMA foreign_keys = ON; CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
    for (const [i, m] of MIGRATIONS.slice(0, 4).entries()) old.exec(`${m}; INSERT INTO schema_migrations VALUES (${i + 1}, 'then')`);
    old.exec(`INSERT INTO forge_connections (id, kind, account, api_url, token, created_at) VALUES ('c', 'github', 'acme', 'https://api.github.com', 't', 'then');
      INSERT INTO repositories (id, name, default_branch, fail_on, created_at, connection_id) VALUES ('r', 'acme/web', 'main', 'high', 'then', 'c')`);
    old.close();

    const db = openDb(path);
    expect(db.prepare("SELECT connection_id FROM repositories WHERE id = 'r'").get()).toEqual({ connection_id: "c" });
    db.exec(
      "INSERT INTO forge_connections (id, kind, account, api_url, token, created_at) VALUES ('g', 'gitlab', 'acme', 'https://gitlab.com/api/v4', 't', 'now')",
    );
    // The foreign key still holds: removing the connection leaves its repository, unlinked.
    db.exec("DELETE FROM forge_connections WHERE id = 'c'");
    expect(db.prepare("SELECT connection_id FROM repositories WHERE id = 'r'").get()).toEqual({ connection_id: null });
  });
});
