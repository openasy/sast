import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { parseRepositories, readToken, watchRepositories, type RepositoriesFile } from "./repositories.ts";

describe("the repositories file (ADR 0052)", () => {
  it("reads forges and repository settings", () => {
    expect(
      parseRepositories(`
forges:
  - name: openasy
    forge: github
    account: openasy
    token: SAST_OPENASY_TOKEN
  - name: platform
    forge: gitlab
    account: /acme/platform/
    url: https://gitlab.example.com/
    token: SAST_GITLAB_TOKEN
repositories:
  - name: openasy/openasy.github.io
    scan: false
`),
    ).toEqual({
      forges: [
        { name: "openasy", forge: "github", account: "openasy", url: null, token: "SAST_OPENASY_TOKEN" },
        { name: "platform", forge: "gitlab", account: "acme/platform", url: "https://gitlab.example.com", token: "SAST_GITLAB_TOKEN" },
      ],
      repositories: [{ name: "openasy/openasy.github.io", scan: false }],
    });
    expect(parseRepositories("")).toEqual({ forges: [], repositories: [] });
  });

  it("says what to fix, by entry and field", () => {
    const bad = (yaml: string) => () => parseRepositories(yaml);
    expect(bad("hosts: []")).toThrow(/two lists, forges: and repositories:/);
    expect(bad("forges:\n  - name: a\n    forge: bitbucket\n    account: a\n    token: T")).toThrow("a: forge is github or gitlab.");
    expect(bad("forges:\n  - name: a\n    forge: github\n    account: -bad-\n    token: T")).toThrow(/GitHub organization/);
    expect(bad("forges:\n  - name: a\n    forge: github\n    account: acme\n    token: ghp_0123456789")).toThrow(/name of the environment variable/);
    expect(bad("forges:\n  - name: a\n    forge: github\n    account: acme\n    tokenFile: x")).toThrow("forges[0]: unknown tokenFile");
    expect(bad("forges:\n  - name: a\n    forge: github\n    account: acme\n    url: https://x\n    token: T")).toThrow(/url is for GitLab/);
    expect(bad("forges:\n  - name: a\n    forge: gitlab\n    account: acme\n    url: http://gitlab.example.com\n    token: T")).toThrow(/https address/);
    expect(bad("forges:\n  - { name: a, forge: github, account: acme, token: T }\n  - { name: A, forge: github, account: x, token: T }")).toThrow(
      "A is in the file twice",
    );
    expect(bad("forges:\n  - { name: a, forge: github, account: acme, token: T }\n  - { name: b, forge: github, account: ACME, token: T }")).toThrow(
      "the same account is in the file twice",
    );
    expect(bad("repositories:\n  - name: web\n    scan: false")).toThrow(/path on its forge/);
    expect(bad("repositories:\n  - name: acme/web\n    scan: no")).toThrow("acme/web: scan is true or false.");
    expect(bad("forges: [")).toThrow(/Not valid YAML/);
  });

  it("reads a token from the variable an entry names", () => {
    expect(readToken({ SAST_ACME_TOKEN: " github_pat_0123456789abcdefghijklmnop\n" }, "SAST_ACME_TOKEN")).toBe("github_pat_0123456789abcdefghijklmnop");
    expect(() => readToken({}, "SAST_ACME_TOKEN")).toThrow("SAST_ACME_TOKEN is not set: put it in secrets/sast.env, then restart sast.");
    expect(() => readToken({ SAST_ACME_TOKEN: "short" }, "SAST_ACME_TOKEN")).toThrow(/does not hold a token/);
  });

  it("applies the file when it changes, and keeps the last good one when it breaks", () => {
    const dir = mkdtempSync(join(tmpdir(), "sast-repos-"));
    const path = join(dir, "repositories.yaml");
    writeFileSync(path, "forges:\n  - { name: acme, forge: github, account: acme, token: SAST_ACME_TOKEN }\n");
    const applied: RepositoriesFile[] = [];
    let warn = ["acme: SAST_ACME_TOKEN is not set"];
    const w = watchRepositories(path, (f) => (applied.push(f), warn), { everyMs: 3_600_000 });
    expect(w.state).toMatchObject({ forges: 1, repositories: 0, error: null, warnings: ["acme: SAST_ACME_TOKEN is not set"] });
    // While there are warnings, the same file is applied again at each check.
    warn = [];
    w.read();
    expect(applied).toHaveLength(2);
    w.read();
    expect(applied).toHaveLength(2);
    writeFileSync(path, "forges: [");
    w.read();
    expect(w.state.error).toMatch(/Not valid YAML/);
    expect(applied).toHaveLength(2);
    w.stop();
  });
});
