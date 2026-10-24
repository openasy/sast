// Repositories from a forge, scanned by sast-agent (ADR 0036). An owner connects a GitHub account with a token that
// reads code; sast lists the account's repositories every few minutes, and a repository whose default branch moved
// gets a scan job. An agent enrolled with a one-time token takes the job, clones the commit, runs Opengrep and sends
// the SARIF back, which goes through the same comparison and triage as a scan from CI. sast holds no code.
import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { Keyring } from "./kek.ts";
import { SastError } from "./sast.ts";

const now = () => new Date().toISOString();
const bad = (detail: string) => new SastError(422, "invalid-body", detail);
const notFound = (what: string) => new SastError(404, "not-found", `${what} does not exist.`);
const hash = (s: string) => createHash("sha256").update(s).digest("hex");

const ACCOUNT = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const AGENT_NAME = /^[a-z0-9][a-z0-9.-]{0,62}$/;
const ENROLL_TTL_MS = 7 * 864e5;
const LEASE_MS = 30 * 60_000;
const MAX_ATTEMPTS = 3;
/** Rule sources an install adds of its own: git repositories of Opengrep rules, fetched by the agent at scan time. */
const RULE_SOURCE = /^https:\/\/[A-Za-z0-9.-]+(?::\d+)?\/[A-Za-z0-9._~/-]+$/;
const RULE_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;
// A rule id as Opengrep prints it, such as openasy.javascript.eval.
const RULE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/;
const MAX_OWN_RULES = 100;
const MAX_RULE_BYTES = 256 * 1024;

export interface Connection {
  id: string;
  kind: "github";
  account: string;
  apiUrl: string;
  createdAt: string;
  syncedAt: string | null;
  error: string | null;
  repositories: number;
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

/** What an agent gets to scan one commit. The token reads that repository and nothing else is sent with it. */
export interface Work {
  id: string;
  repository: string;
  cloneUrl: string;
  branch: string;
  commit: string;
  /** For an HTTPS clone; never logged by the agent. */
  token: string;
  ruleSources: string[];
  /** Rules the install wrote, each an Opengrep YAML file. */
  ownRules: Array<{ name: string; yaml: string }>;
  /** Rule ids switched off: Opengrep skips them, whichever file they come from. */
  disabledRules: string[];
}

export interface ForgeOptions {
  db: DatabaseSync;
  /** Seals forge tokens (ADR 0021); without it no connection can be added. */
  keyring?: Keyring;
  /** Takes a SARIF log for a repository, as POST /api/v1/scans does, and returns the scan with whether it passed. */
  ingest: (
    params: { repository: string; branch: string; commit: string; defaultBranch: string; pullRequest?: string | null },
    raw: Buffer,
  ) => { id: string; new: number; blocking: number; passed: boolean; findings: NewFinding[] };
  /** Where people open sast, for the link in a pull request's check. */
  publicUrl?: string;
  /** The GitHub API, https://api.github.com unless GitHub Enterprise Server. */
  githubApi?: string;
  /** For tests: the HTTP client. */
  fetch?: typeof fetch;
  log?: (level: "info" | "warn", msg: string, fields?: Record<string, unknown>) => void;
}

/** A finding a pull request adds, as the scan's answer lists them, most severe first. */
export interface NewFinding {
  rule: string;
  severity: string;
  path: string;
  line: number | null;
  message: string;
}

/** Findings listed in a pull request's comment; the scan's page has them all. */
const COMMENT_FINDINGS = 10;
const COMMENT_MARK = "<!-- openasy-sast -->";

interface GithubPull {
  number: number;
  head: { sha: string; ref: string };
  base: { ref: string };
}

/** The name of a commit status on GitHub: one per pull request commit, replaced as the scan moves on. */
const CHECK_CONTEXT = "OpenAsy SAST";
// A branch the agent will clone; a pull request from a branch with other characters is named after its number.
const AGENT_BRANCH = /^(?!-)(?!.*\.\.)[A-Za-z0-9._/-]{1,255}$/;

interface GithubRepo {
  full_name: string;
  owner: { login: string };
  clone_url: string;
  default_branch: string;
  archived: boolean;
  disabled?: boolean;
  pushed_at: string | null;
}

export function createForge(opts: ForgeOptions) {
  const { db } = opts;
  const http = opts.fetch ?? fetch;
  const githubApi = (opts.githubApi ?? "https://api.github.com").replace(/\/$/, "");

  // ---- connections --------------------------------------------------------

  const toConnection = (r: Record<string, string | null>): Connection => ({
    id: r.id!,
    kind: "github",
    account: r.account!,
    apiUrl: r.api_url!,
    createdAt: r.created_at!,
    syncedAt: r.synced_at ?? null,
    error: r.error ?? null,
    repositories: (db.prepare("SELECT COUNT(*) AS n FROM repositories WHERE connection_id = ?").get(r.id!) as { n: number }).n,
  });

  function listConnections(): Connection[] {
    return (db.prepare("SELECT * FROM forge_connections ORDER BY account").all() as Array<Record<string, string | null>>).map(toConnection);
  }

  /** Checks the token against GitHub before keeping it: a wrong one is refused here, not at the first poll. */
  async function createConnection(body: { kind?: unknown; account?: unknown; token?: unknown }): Promise<Connection> {
    if (!opts.keyring) throw new SastError(503, "not-configured", "Mount openasy-kek: forge tokens are kept only sealed (ADR 0021).");
    if (body.kind !== undefined && body.kind !== "github") throw bad("kind is github.");
    const account = typeof body.account === "string" ? body.account.trim() : "";
    if (!ACCOUNT.test(account)) throw bad("account is a GitHub organization or user, such as acme.");
    const token = typeof body.token === "string" ? body.token.trim() : "";
    if (token.length < 20 || token.length > 400 || /\s/.test(token)) throw bad("token is a GitHub token that reads the account's code.");
    if (db.prepare("SELECT 1 FROM forge_connections WHERE kind = 'github' AND api_url = ? AND account = ? COLLATE NOCASE").get(githubApi, account))
      throw new SastError(409, "conflict", `${account} is connected already.`);
    const me = await github(token, "/user");
    if (!me.ok) throw bad(me.status === 401 ? "GitHub refused the token." : `GitHub answered ${me.status} to the token.`);
    const id = randomUUID();
    db.prepare("INSERT INTO forge_connections (id, kind, account, api_url, token, created_at) VALUES (?, 'github', ?, ?, ?, ?)").run(
      id,
      account,
      githubApi,
      opts.keyring.seal(token),
      now(),
    );
    opts.log?.("info", "forge connected", { kind: "github", account });
    return toConnection(db.prepare("SELECT * FROM forge_connections WHERE id = ?").get(id) as Record<string, string | null>);
  }

  /** Its repositories stay with their findings, no longer scanned from the forge. */
  function deleteConnection(id: string) {
    if (db.prepare("DELETE FROM forge_connections WHERE id = ?").run(id).changes === 0) throw notFound("The connection");
  }

  // ---- GitHub ---------------------------------------------------------------

  async function github(
    token: string,
    path: string,
    post?: unknown,
    method: "POST" | "PATCH" = "POST",
  ): Promise<{ ok: boolean; status: number; body: unknown; next?: string }> {
    const res = await http(path.startsWith("http") ? path : `${githubApi}${path}`, {
      method: post === undefined ? "GET" : method,
      headers: {
        authorization: `Bearer ${token}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        "user-agent": "openasy-sast",
        ...(post !== undefined && { "content-type": "application/json" }),
      },
      ...(post !== undefined && { body: JSON.stringify(post) }),
      signal: AbortSignal.timeout(15_000),
    });
    const next = /<([^>]+)>;\s*rel="next"/.exec(res.headers.get("link") ?? "")?.[1];
    return { ok: res.ok, status: res.status, body: res.ok ? await res.json() : await res.text(), next };
  }

  /** Every repository the token can read that the account owns: an organization's or a user's own. */
  async function accountRepositories(token: string, account: string): Promise<GithubRepo[]> {
    const out: GithubRepo[] = [];
    let url: string | undefined = "/user/repos?per_page=100&affiliation=owner,collaborator,organization_member&sort=full_name";
    for (let pages = 0; url && pages < 50; pages++) {
      const r = await github(token, url);
      if (!r.ok) throw new Error(r.status === 401 ? "GitHub refused the token: make a new one and connect again." : `GitHub answered ${r.status}.`);
      for (const repo of r.body as GithubRepo[]) if (repo.owner.login.toLowerCase() === account.toLowerCase()) out.push(repo);
      url = r.next;
    }
    return out;
  }

  /**
   * Lists every connection's repositories and queues a scan for each whose default branch moved. The branch's head is
   * asked only when the repository was pushed to since the last look, so a quiet account costs one call a page.
   */
  async function poll() {
    for (const c of db.prepare("SELECT * FROM forge_connections").all() as Array<Record<string, string>>) {
      try {
        const token = opts.keyring!.open(c.token!).toString("utf8");
        const repos = await accountRepositories(token, c.account!);
        for (const repo of repos) {
          if (repo.archived || repo.disabled) continue;
          let row = db.prepare("SELECT * FROM repositories WHERE name = ?").get(repo.full_name) as Record<string, string | number | null> | undefined;
          if (!row) {
            db.prepare(
              "INSERT INTO repositories (id, name, default_branch, fail_on, created_at, connection_id, clone_url) VALUES (?, ?, ?, 'high', ?, ?, ?)",
            ).run(randomUUID(), repo.full_name, repo.default_branch, now(), c.id!, repo.clone_url);
            row = db.prepare("SELECT * FROM repositories WHERE name = ?").get(repo.full_name) as Record<string, string | number | null>;
          } else if (row.connection_id !== c.id || row.clone_url !== repo.clone_url || row.default_branch !== repo.default_branch) {
            // A repository CI scanned first joins the connection, and follows a renamed default branch.
            db.prepare("UPDATE repositories SET connection_id = ?, clone_url = ?, default_branch = ? WHERE id = ?").run(
              c.id!,
              repo.clone_url,
              repo.default_branch,
              row.id as string,
            );
          }
          if (row.scan_enabled === 0) continue;
          await pullRequests(token, row.id as string, repo);
          if (row.pushed_at === repo.pushed_at && row.head_commit) continue;
          const branch = await github(token, `/repos/${repo.full_name}/branches/${encodeURIComponent(repo.default_branch)}`);
          // An empty repository has no branch yet.
          if (!branch.ok) continue;
          const head = (branch.body as { commit: { sha: string } }).commit.sha;
          db.prepare("UPDATE repositories SET pushed_at = ?, head_commit = ? WHERE id = ?").run(repo.pushed_at, head, row.id as string);
          if (head !== row.scanned_commit) queue(row.id as string, repo.default_branch, head);
        }
        db.prepare("UPDATE forge_connections SET synced_at = ?, error = NULL WHERE id = ?").run(now(), c.id!);
      } catch (err) {
        db.prepare("UPDATE forge_connections SET error = ? WHERE id = ?").run((err as Error).message.slice(0, 300), c.id!);
        opts.log?.("warn", "forge poll failed", { account: c.account, error: (err as Error).message });
      }
    }
  }

  /**
   * The open pull requests into the default branch, each scanned at its latest commit and compared with the default
   * branch. A fork's pull request is fetched from the base repository, which GitHub serves it from. One call a look.
   */
  async function pullRequests(token: string, repoId: string, repo: GithubRepo) {
    const r = await github(token, `/repos/${repo.full_name}/pulls?state=open&per_page=100`);
    if (!r.ok) return;
    for (const pr of r.body as GithubPull[]) {
      if (pr.base.ref !== repo.default_branch) continue;
      const branch = AGENT_BRANCH.test(pr.head.ref) ? pr.head.ref : `pull/${pr.number}`;
      const jobId = queue(repoId, branch, pr.head.sha, String(pr.number));
      if (jobId) void postStatus(repoId, pr.head.sha, "pending", "Waiting for sast-agent to scan this commit.", null, jobId);
    }
  }

  /**
   * One job per repository, commit and pull request: a commit already queued or scanned is not queued again, and a
   * newer commit of the same branch or pull request makes the queued one moot. Returns the new job's id, if any.
   */
  function queue(repoId: string, branch: string, commit: string, pullRequest: string | null = null): string | null {
    if (
      db
        .prepare("SELECT 1 FROM scan_jobs WHERE repo_id = ? AND commit_sha = ? AND pull_request IS ? AND status IN ('queued', 'running', 'done')")
        .get(repoId, commit, pullRequest)
    )
      return null;
    db.prepare("DELETE FROM scan_jobs WHERE repo_id = ? AND pull_request IS ? AND status = 'queued'").run(repoId, pullRequest);
    const id = randomUUID();
    db.prepare("INSERT INTO scan_jobs (id, repo_id, branch, commit_sha, pull_request, status, created_at) VALUES (?, ?, ?, ?, ?, 'queued', ?)").run(
      id,
      repoId,
      branch,
      commit,
      pullRequest,
      now(),
    );
    return id;
  }

  /** Posts a commit status for a pull request's commit. A token that may not leaves the reason on the job, not a failure. */
  async function postStatus(
    repoId: string,
    sha: string,
    state: "pending" | "success" | "failure" | "error",
    description: string,
    scanId: string | null,
    jobId?: string,
  ) {
    const r = db.prepare("SELECT r.name, c.token FROM repositories r JOIN forge_connections c ON c.id = r.connection_id WHERE r.id = ?").get(repoId) as
      { name: string; token: string } | undefined;
    if (!r || !opts.keyring) return;
    let error: string | null = null;
    try {
      const res = await github(opts.keyring.open(r.token).toString("utf8"), `/repos/${r.name}/statuses/${sha}`, {
        state,
        context: CHECK_CONTEXT,
        description: description.slice(0, 140),
        ...(scanId && opts.publicUrl && { target_url: `${opts.publicUrl.replace(/\/$/, "")}/scans/${scanId}` }),
      });
      if (!res.ok)
        error =
          res.status === 403 || res.status === 404
            ? "The token may not post commit statuses: give it Commit statuses, read and write."
            : `GitHub answered ${res.status} to the commit status.`;
    } catch (err) {
      error = `The commit status could not be posted: ${(err as Error).message}`;
    }
    if (jobId) db.prepare("UPDATE scan_jobs SET check_error = ? WHERE id = ?").run(error, jobId);
    if (error) opts.log?.("warn", "commit status not posted", { repository: r.name, error });
  }

  /** Scans a repository's default branch again at the next agent's turn, as Scan now does. */
  function scanNow(repoId: string) {
    const r = db.prepare("SELECT id, default_branch, head_commit, clone_url FROM repositories WHERE id = ?").get(repoId) as
      { id: string; default_branch: string; head_commit: string | null; clone_url: string | null } | undefined;
    if (!r) throw notFound("The repository");
    if (!r.clone_url || !r.head_commit)
      throw new SastError(409, "conflict", "Only a repository from a connection is scanned by an agent; CI sends the others.");
    db.prepare("DELETE FROM scan_jobs WHERE repo_id = ? AND commit_sha = ? AND status IN ('done', 'failed')").run(r.id, r.head_commit);
    queue(r.id, r.default_branch, r.head_commit);
    return listJobs({ repoId: r.id })[0]!;
  }

  function listJobs(filter: { repoId?: string } = {}): Job[] {
    const rows = db
      .prepare(
        `SELECT j.*, r.name AS repo_name FROM scan_jobs j JOIN repositories r ON r.id = j.repo_id
         ${filter.repoId ? "WHERE j.repo_id = ?" : ""} ORDER BY j.created_at DESC LIMIT 200`,
      )
      .all(...(filter.repoId ? [filter.repoId] : [])) as Array<Record<string, string | number | null>>;
    return rows.map((j) => ({
      id: j.id as string,
      repository: j.repo_name as string,
      branch: j.branch as string,
      commit: j.commit_sha as string,
      status: j.status as Job["status"],
      attempts: j.attempts as number,
      error: j.error as string | null,
      scanId: j.scan_id as string | null,
      pullRequest: (j.pull_request as string | null) ?? null,
      checkError: (j.check_error as string | null) ?? null,
      createdAt: j.created_at as string,
      finishedAt: j.finished_at as string | null,
    }));
  }

  // ---- own rules and switched off rules -------------------------------------

  const toRule = (r: Record<string, string>) => ({ id: r.id!, name: r.name!, yaml: r.yaml!, createdAt: r.created_at!, updatedAt: r.updated_at! });
  const disabledRules = (): string[] => {
    const v = (db.prepare("SELECT value FROM settings WHERE key = 'disabled_rules'").get() as { value: string } | undefined)?.value;
    return v ? (JSON.parse(v) as string[]) : [];
  };
  const listRules = () => ({
    own: (db.prepare("SELECT * FROM own_rules ORDER BY name").all() as Array<Record<string, string>>).map(toRule),
    disabled: disabledRules(),
  });
  /** A rule file is checked for its shape here; Opengrep reads it at the next scan, and a broken one fails that scan. */
  const ruleYaml = (v: unknown) => {
    if (typeof v !== "string" || !v.trim() || Buffer.byteLength(v) > MAX_RULE_BYTES || !/^rules:/m.test(v))
      throw bad("yaml is an Opengrep rule file of up to 256 KiB, starting with rules:.");
    return v;
  };

  function createRule(body: { name?: unknown; yaml?: unknown }) {
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!RULE_NAME.test(name)) throw bad("name is lowercase letters, digits, dots, dashes and underscores, such as no-console-log.");
    const yaml = ruleYaml(body.yaml);
    if ((db.prepare("SELECT COUNT(*) AS n FROM own_rules").get() as { n: number }).n >= MAX_OWN_RULES)
      throw new SastError(409, "conflict", `An install has at most ${MAX_OWN_RULES} rule files; put several rules in one.`);
    if (db.prepare("SELECT 1 FROM own_rules WHERE name = ?").get(name)) throw new SastError(409, "conflict", `A rule file named ${name} exists.`);
    const id = randomUUID();
    db.prepare("INSERT INTO own_rules (id, name, yaml, created_at, updated_at) VALUES (?, ?, ?, ?, ?)").run(id, name, yaml, now(), now());
    return toRule(db.prepare("SELECT * FROM own_rules WHERE id = ?").get(id) as Record<string, string>);
  }

  function updateRule(id: string, body: { yaml?: unknown }) {
    if (!db.prepare("SELECT 1 FROM own_rules WHERE id = ?").get(id)) throw notFound("The rule file");
    db.prepare("UPDATE own_rules SET yaml = ?, updated_at = ? WHERE id = ?").run(ruleYaml(body.yaml), now(), id);
    return toRule(db.prepare("SELECT * FROM own_rules WHERE id = ?").get(id) as Record<string, string>);
  }

  function deleteRule(id: string) {
    if (db.prepare("DELETE FROM own_rules WHERE id = ?").run(id).changes === 0) throw notFound("The rule file");
  }

  /** Rule ids no scan reports any more: a noisy shipped rule, or one from a rule source. */
  function setDisabledRules(list: unknown): string[] {
    if (!Array.isArray(list) || list.length > 500 || list.some((s) => typeof s !== "string" || !RULE_ID.test(s)))
      throw bad("disabled is a list of at most 500 rule ids, such as openasy.javascript.eval.");
    db.prepare("INSERT INTO settings (key, value) VALUES ('disabled_rules', ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value").run(
      JSON.stringify([...new Set(list as string[])].sort()),
    );
    return disabledRules();
  }

  // ---- rule sources -------------------------------------------------------

  const ruleSources = (): string[] => {
    const v = (db.prepare("SELECT value FROM settings WHERE key = 'rule_sources'").get() as { value: string } | undefined)?.value;
    return v ? (JSON.parse(v) as string[]) : [];
  };

  /** Git repositories of Opengrep rules an install adds under its own licence terms; the shipped rules always run. */
  function setRuleSources(list: unknown): string[] {
    if (!Array.isArray(list) || list.length > 10 || list.some((s) => typeof s !== "string" || !RULE_SOURCE.test(s)))
      throw bad("ruleSources is a list of at most 10 https addresses of git repositories with Opengrep rules.");
    db.prepare("INSERT INTO settings (key, value) VALUES ('rule_sources', ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value").run(
      JSON.stringify([...new Set(list as string[])]),
    );
    return ruleSources();
  }

  // ---- agents ---------------------------------------------------------------

  const ONLINE_MS = 2 * 60_000;
  const toAgent = (a: Record<string, string | null>): Agent => ({
    id: a.id!,
    name: a.name!,
    status: !a.secret_hash ? "waiting-to-enrol" : a.last_seen && Date.now() - Date.parse(a.last_seen) < ONLINE_MS ? "online" : "offline",
    version: a.version ?? null,
    lastSeen: a.last_seen ?? null,
    createdAt: a.created_at!,
  });

  const listAgents = () => (db.prepare("SELECT * FROM agents ORDER BY name").all() as Array<Record<string, string | null>>).map(toAgent);

  /** An agent to add, with the one-time token it enrols with; the token is shown once. */
  function createAgent(body: { name?: unknown }) {
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!AGENT_NAME.test(name)) throw bad("name is lowercase letters, digits, dots and dashes, such as dc1.");
    if (db.prepare("SELECT 1 FROM agents WHERE name = ?").get(name)) throw new SastError(409, "conflict", `An agent named ${name} exists.`);
    const id = randomUUID();
    const token = `ose_${randomBytes(24).toString("base64url")}`;
    db.prepare("INSERT INTO agents (id, name, enroll_token_hash, enroll_expires_at, created_at) VALUES (?, ?, ?, ?, ?)").run(
      id,
      name,
      hash(token),
      new Date(Date.now() + ENROLL_TTL_MS).toISOString(),
      now(),
    );
    return { agent: toAgent(db.prepare("SELECT * FROM agents WHERE id = ?").get(id) as Record<string, string | null>), enrollToken: token };
  }

  function deleteAgent(id: string) {
    if (db.prepare("DELETE FROM agents WHERE id = ?").run(id).changes === 0) throw notFound("The agent");
  }

  /** Trades a one-time token for the agent's own secret, which only its hash is kept of (ADR 0032's pattern). */
  function enroll(body: { token?: unknown; version?: unknown }) {
    const token = typeof body.token === "string" ? body.token : "";
    const a = db.prepare("SELECT * FROM agents WHERE enroll_token_hash = ?").get(hash(token)) as Record<string, string> | undefined;
    if (!a || Date.parse(a.enroll_expires_at!) < Date.now())
      throw new SastError(401, "invalid-token", "The enrolment token is unknown, used or expired. Make a new one under GitHub, Agents.");
    const secret = `osa_${randomBytes(32).toString("base64url")}`;
    db.prepare("UPDATE agents SET enroll_token_hash = NULL, enroll_expires_at = NULL, secret_hash = ?, version = ?, last_seen = ? WHERE id = ?").run(
      hash(secret),
      typeof body.version === "string" ? body.version.slice(0, 32) : null,
      now(),
      a.id!,
    );
    return { id: a.id!, name: a.name!, secret };
  }

  /** The agent a bearer secret belongs to, or undefined. */
  function agentBySecret(authorization: string | undefined): string | undefined {
    const secret = authorization?.startsWith("Bearer osa_") ? authorization.slice(7) : undefined;
    if (!secret) return undefined;
    const want = Buffer.from(hash(secret));
    const row = db.prepare("SELECT id, secret_hash FROM agents WHERE secret_hash = ?").get(hash(secret)) as { id: string; secret_hash: string } | undefined;
    return row && timingSafeEqual(Buffer.from(row.secret_hash), want) ? row.id : undefined;
  }

  /**
   * The next job for an agent, leased to it; a lease that ran out goes back to the queue, three times at most. Default
   * branches go first, so a pull request is compared with a baseline that is there.
   */
  function work(agentId: string, version?: unknown): { jobs: Work[] } {
    db.prepare("UPDATE agents SET last_seen = ?, version = COALESCE(?, version) WHERE id = ?").run(
      now(),
      typeof version === "string" ? version.slice(0, 32) : null,
      agentId,
    );
    db.prepare(
      `UPDATE scan_jobs SET status = CASE WHEN attempts >= ${MAX_ATTEMPTS} THEN 'failed' ELSE 'queued' END,
         error = CASE WHEN attempts >= ${MAX_ATTEMPTS} THEN 'The agent did not finish it, ${MAX_ATTEMPTS} times.' ELSE error END,
         agent_id = NULL, lease_until = NULL
       WHERE status = 'running' AND lease_until < ?`,
    ).run(now());
    const job = db
      .prepare(
        `SELECT j.*, r.name, r.clone_url, c.token FROM scan_jobs j JOIN repositories r ON r.id = j.repo_id
         JOIN forge_connections c ON c.id = r.connection_id
         WHERE j.status = 'queued' AND r.scan_enabled = 1 ORDER BY j.pull_request IS NOT NULL, j.created_at LIMIT 1`,
      )
      .get() as Record<string, string> | undefined;
    if (!job || !opts.keyring) return { jobs: [] };
    db.prepare("UPDATE scan_jobs SET status = 'running', agent_id = ?, lease_until = ?, attempts = attempts + 1 WHERE id = ?").run(
      agentId,
      new Date(Date.now() + LEASE_MS).toISOString(),
      job.id!,
    );
    return {
      jobs: [
        {
          id: job.id!,
          repository: job.name!,
          cloneUrl: job.clone_url!,
          branch: job.branch!,
          commit: job.commit_sha!,
          token: opts.keyring.open(job.token!).toString("utf8"),
          ruleSources: ruleSources(),
          ownRules: (db.prepare("SELECT name, yaml FROM own_rules ORDER BY name").all() as Array<{ name: string; yaml: string }>).map((r) => ({
            name: r.name,
            yaml: r.yaml,
          })),
          disabledRules: disabledRules(),
        },
      ],
    };
  }

  const ownJob = (agentId: string, jobId: string) => {
    const j = db.prepare("SELECT j.*, r.name, r.default_branch FROM scan_jobs j JOIN repositories r ON r.id = j.repo_id WHERE j.id = ?").get(jobId) as
      Record<string, string> | undefined;
    if (!j || j.agent_id !== agentId || j.status !== "running") throw new SastError(404, "not-found", "No such running job for this agent.");
    return j;
  };

  /** Text from a finding, safe inside a table cell's code span. */
  const cell = (s: string) => s.replace(/[`|\r\n]/g, " ").slice(0, 120);

  /**
   * The pull request's one comment from sast, with the findings the latest commit adds: written when there are some,
   * and edited at each later scan, also to say there are none any more. A token that may not leaves the reason on the job.
   */
  async function postComment(repoId: string, pullRequest: string, scan: { id: string; new: number; blocking: number; findings: NewFinding[] }, jobId: string) {
    const r = db.prepare("SELECT r.name, c.token FROM repositories r JOIN forge_connections c ON c.id = r.connection_id WHERE r.id = ?").get(repoId) as
      { name: string; token: string } | undefined;
    if (!r || !opts.keyring) return;
    const existing = (
      db.prepare("SELECT comment_id FROM pr_comments WHERE repo_id = ? AND pull_request = ?").get(repoId, pullRequest) as { comment_id: string } | undefined
    )?.comment_id;
    if (!scan.new && !existing) return;
    const link = opts.publicUrl ? `${opts.publicUrl.replace(/\/$/, "")}/scans/${scan.id}` : null;
    const shown = scan.findings.slice(0, COMMENT_FINDINGS);
    const body = [
      COMMENT_MARK,
      scan.new
        ? `**OpenAsy SAST**: this pull request adds ${scan.new} ${scan.new === 1 ? "finding" : "findings"}${scan.blocking ? `, ${scan.blocking} of them blocking` : ", none blocking"}.`
        : "**OpenAsy SAST**: the latest commit adds no findings.",
      ...(shown.length
        ? [
            "",
            "| Severity | Rule | Where |",
            "| --- | --- | --- |",
            ...shown.map((f) => `| ${f.severity} | \`${cell(f.rule)}\` | \`${cell(f.path)}${f.line ? `:${f.line}` : ""}\` |`),
          ]
        : []),
      ...(scan.new > shown.length ? ["", `And ${scan.new - shown.length} more.`] : []),
      ...(link ? ["", `[See the scan](${link})`] : []),
    ].join("\n");
    const token = opts.keyring.open(r.token).toString("utf8");
    let error: string | null = null;
    try {
      let res = existing ? await github(token, `/repos/${r.name}/issues/comments/${existing}`, { body }, "PATCH") : undefined;
      // A comment someone deleted is written again.
      if (!res || res.status === 404) {
        res = await github(token, `/repos/${r.name}/issues/${pullRequest}/comments`, { body });
        if (res.ok)
          db.prepare(
            "INSERT INTO pr_comments (repo_id, pull_request, comment_id) VALUES (?, ?, ?) ON CONFLICT (repo_id, pull_request) DO UPDATE SET comment_id = excluded.comment_id",
          ).run(repoId, pullRequest, String((res.body as { id: number }).id));
      }
      if (!res.ok)
        error =
          res.status === 403
            ? "The token may not comment on pull requests: give it Pull requests, read and write."
            : `GitHub answered ${res.status} to the comment.`;
    } catch (err) {
      error = `The comment could not be posted: ${(err as Error).message}`;
    }
    if (error) {
      const before = (db.prepare("SELECT check_error FROM scan_jobs WHERE id = ?").get(jobId) as { check_error: string | null }).check_error;
      db.prepare("UPDATE scan_jobs SET check_error = ? WHERE id = ?").run(before ? `${before} ${error}` : error, jobId);
      opts.log?.("warn", "pull request comment not posted", { repository: r.name, error });
    }
  }

  /**
   * The SARIF of a finished job, compared and kept as any scan is: a default branch scan is the baseline, a pull
   * request's is compared with it, and its result goes back to the pull request as a commit status.
   */
  async function complete(agentId: string, jobId: string, sarif: Buffer) {
    const j = ownJob(agentId, jobId);
    const scan = opts.ingest(
      { repository: j.name!, branch: j.branch!, commit: j.commit_sha!, defaultBranch: j.default_branch!, pullRequest: j.pull_request ?? null },
      sarif,
    );
    db.prepare("UPDATE scan_jobs SET status = 'done', scan_id = ?, finished_at = ?, lease_until = NULL WHERE id = ?").run(scan.id, now(), jobId);
    if (j.pull_request) {
      const description = scan.passed
        ? `${scan.new ? `${scan.new} new, none blocking` : "Nothing new"}.`
        : `${scan.blocking} new ${scan.blocking === 1 ? "finding blocks" : "findings block"} this pull request.`;
      await postStatus(j.repo_id!, j.commit_sha!, scan.passed ? "success" : "failure", description, scan.id, jobId);
      await postComment(j.repo_id!, j.pull_request, scan, jobId);
    } else db.prepare("UPDATE repositories SET scanned_commit = ? WHERE id = ?").run(j.commit_sha!, j.repo_id!);
    return { scanId: scan.id };
  }

  async function fail(agentId: string, jobId: string, body: { error?: unknown }) {
    const j = ownJob(agentId, jobId);
    const error = typeof body.error === "string" ? body.error.slice(0, 1000) : "The agent could not scan it.";
    db.prepare("UPDATE scan_jobs SET status = 'failed', error = ?, finished_at = ?, lease_until = NULL WHERE id = ?").run(error, now(), jobId);
    opts.log?.("warn", "scan job failed", { job: jobId, error });
    if (j.pull_request) await postStatus(j.repo_id!, j.commit_sha!, "error", `The scan failed: ${error}`, null, jobId);
  }

  return {
    listConnections,
    createConnection,
    deleteConnection,
    poll,
    scanNow,
    listJobs,
    ruleSources,
    setRuleSources,
    listRules,
    createRule,
    updateRule,
    deleteRule,
    setDisabledRules,
    listAgents,
    createAgent,
    deleteAgent,
    enroll,
    agentBySecret,
    work,
    complete,
    fail,
  };
}

export type Forge = ReturnType<typeof createForge>;
