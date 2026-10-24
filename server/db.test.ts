import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { openDb } from "./db.ts";

describe("openDb", () => {
  it("uses WAL and migrates once", () => {
    const path = join(mkdtempSync(join(tmpdir(), "sast-")), "nested", "sast.db");
    const first = openDb(path);
    expect(first.prepare("PRAGMA journal_mode").get()).toEqual({ journal_mode: "wal" });
    first.close();

    const second = openDb(path);
    expect(second.prepare("SELECT COUNT(*) AS n FROM schema_migrations").get()).toEqual({ n: 4 });
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
});
