import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { RepositoriesFile } from "./repositories.ts";
import { sarif, startApp } from "./test-app.ts";

const TOKEN = "github_pat_0123456789abcdefghijklmnop";
const { version } = { version: "0.0.0" };

/** GitHub as sast sees it: the token's user, its repositories over two pages, and each one's default branch. */
function fakeGithub() {
  const repos = [
    {
      full_name: "acme/web",
      owner: { login: "acme" },
      clone_url: "https://github.com/acme/web.git",
      default_branch: "main",
      archived: false,
      pushed_at: "2026-10-20T10:00:00Z",
    },
    {
      full_name: "acme/old",
      owner: { login: "acme" },
      clone_url: "https://github.com/acme/old.git",
      default_branch: "main",
      archived: true,
      pushed_at: "2025-01-01T00:00:00Z",
    },
    {
      full_name: "someone/fork",
      owner: { login: "someone" },
      clone_url: "https://github.com/someone/fork.git",
      default_branch: "main",
      archived: false,
      pushed_at: "2026-10-20T10:00:00Z",
    },
    {
      full_name: "acme/api",
      owner: { login: "acme" },
      clone_url: "https://github.com/acme/api.git",
      default_branch: "trunk",
      archived: false,
      pushed_at: "2026-10-21T10:00:00Z",
    },
  ];
  const heads: Record<string, string> = { "acme/web": "a".repeat(40), "acme/api": "b".repeat(40) };
  const calls: string[] = [];
  const server: Server = createServer((req, res) => {
    calls.push(req.url!);
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return res.writeHead(401).end("{}");
    const url = new URL(req.url!, "http://x");
    const send = (body: unknown, headers: Record<string, string> = {}) =>
      res.writeHead(200, { "content-type": "application/json", ...headers }).end(JSON.stringify(body));
    if (url.pathname === "/user") return send({ login: "dev" });
    if (url.pathname === "/user/repos") {
      const page = Number(url.searchParams.get("page") ?? 1);
      const base = `http://${req.headers.host}/user/repos?per_page=100&page=2`;
      return send(page === 1 ? repos.slice(0, 2) : repos.slice(2), page === 1 ? { link: `<${base}>; rel="next"` } : {});
    }
    const m = /^\/repos\/(.+)\/branches\/(.+)$/.exec(url.pathname);
    if (m && heads[m[1]!]) return send({ name: decodeURIComponent(m[2]!), commit: { sha: heads[m[1]!] } });
    res.writeHead(404).end("{}");
  });
  return { server, repos, heads, calls };
}

let gh: ReturnType<typeof fakeGithub>;
let app: Awaited<ReturnType<typeof startApp>>;
const json = async (res: Response) => (await res.json()) as any;

beforeAll(async () => {
  gh = fakeGithub();
  await new Promise<void>((r) => gh.server.listen(0, "127.0.0.1", r));
  app = await startApp({ version, forgeOptions: { githubApi: `http://127.0.0.1:${(gh.server.address() as AddressInfo).port}` } });
});
afterAll(async () => {
  await app.close();
  await new Promise((r) => gh.server.close(r));
});

const post = (path: string, body: unknown) => app.admin(path, { method: "POST", body: JSON.stringify(body) });
type Sync = { forge: { syncFile: (f: RepositoriesFile, token: (file: string) => string) => string[] } };
/** Applies a repositories file to an app, with the environment as a map of variable to token. */
const syncFile = (a: Sync, forges: RepositoriesFile["forges"], tokens: Record<string, string>, repositories: RepositoriesFile["repositories"] = []) =>
  a.forge.syncFile({ forges, repositories }, (file) => {
    if (!(file in tokens)) throw new Error(`${file} is not set: put it in secrets/sast.env, then restart sast.`);
    return tokens[file]!;
  });
const ACME = { name: "acme", forge: "github" as const, account: "acme", url: null, token: "SAST_ACME_TOKEN" };
const asAgent =
  (secret: string) =>
  (path: string, init: RequestInit = {}) =>
    fetch(app.base + path, { ...init, method: "POST", headers: { authorization: `Bearer ${secret}`, "content-type": "application/json", ...init.headers } });

describe("repositories from GitHub, scanned by sast-agent (ADR 0036)", () => {
  let agent: ReturnType<typeof asAgent>;

  it("connects the accounts the repositories file names, with their tokens from the variables it names (ADR 0052)", async () => {
    // A token that is not set is a warning, and the entry waits for it.
    expect(syncFile(app, [ACME], {})).toEqual(["acme: SAST_ACME_TOKEN is not set: put it in secrets/sast.env, then restart sast."]);
    expect((await json(await app.admin("/api/v1/connections"))).connections).toEqual([]);
    expect(syncFile(app, [ACME], { SAST_ACME_TOKEN: TOKEN })).toEqual([]);
    const { connections } = await json(await app.admin("/api/v1/connections"));
    expect(connections).toEqual([
      expect.objectContaining({ kind: "github", account: "acme", source: "file", fileName: "acme", tokenVar: "SAST_ACME_TOKEN", error: null }),
    ]);
    expect(JSON.stringify(connections)).not.toContain(TOKEN);
    // Applying the same file again keeps the same connection.
    syncFile(app, [ACME], { SAST_ACME_TOKEN: TOKEN });
    expect((await json(await app.admin("/api/v1/connections"))).connections.map((c: { id: string }) => c.id)).toEqual([connections[0].id]);
    // There is no route that makes one, and the token is sealed at rest.
    expect((await post("/api/v1/connections", { account: "acme", token: TOKEN })).status).toBe(404);
    expect(JSON.stringify(app.db.prepare("SELECT * FROM forge_connections").all())).not.toContain(TOKEN);
  });

  it("lists the account's repositories, not archived ones or others', and queues a scan of each default branch", async () => {
    await app.forge.poll();
    const repos = (await json(await app.admin("/api/v1/repositories"))).repositories as Array<Record<string, unknown>>;
    expect(repos.map((r) => `${r.name} ${r.source} ${r.defaultBranch}`)).toEqual(["acme/api github trunk", "acme/web github main"]);
    const jobs = (await json(await app.admin("/api/v1/jobs"))).jobs as Array<Record<string, unknown>>;
    expect(jobs.map((j) => `${j.repository} ${j.branch} ${j.status}`).sort()).toEqual(["acme/api trunk queued", "acme/web main queued"]);
    // A quiet account costs one call a page on the next look.
    gh.calls.length = 0;
    await app.forge.poll();
    expect(gh.calls.filter((c) => c.includes("/branches/"))).toEqual([]);
    expect((await json(await app.admin("/api/v1/jobs"))).jobs).toHaveLength(2);
  });

  it("gives a job to an enrolled agent, with the token, and keeps what it sends back", async () => {
    const made = await json(await post("/api/v1/agents", { name: "dc1" }));
    expect(made.agent.status).toBe("waiting-to-enrol");
    expect((await asAgent("osa_nope")("/api/v1/agent/work", { body: "{}" })).status).toBe(401);
    const enrolled = await json(
      await fetch(app.base + "/api/v1/agent/enroll", { method: "POST", body: JSON.stringify({ token: made.enrollToken, version: "0.1.0" }) }),
    );
    expect(enrolled.secret).toMatch(/^osa_/);
    // The token is used once.
    expect((await fetch(app.base + "/api/v1/agent/enroll", { method: "POST", body: JSON.stringify({ token: made.enrollToken }) })).status).toBe(401);
    agent = asAgent(enrolled.secret);

    const { jobs } = await json(await agent("/api/v1/agent/work", { body: JSON.stringify({ version: "0.1.0" }) }));
    expect(jobs).toHaveLength(1);
    const job = jobs[0];
    expect(job).toMatchObject({ token: TOKEN, ruleSources: [] });
    expect(["acme/web", "acme/api"]).toContain(job.repository);
    const res = await agent(`/api/v1/agent/jobs/${job.id}/sarif`, { body: sarif({ rule: "js.eval", level: "error", path: "src/a.js", line: 3 }) });
    expect(res.status).toBe(200);
    const repo = ((await json(await app.admin("/api/v1/repositories"))).repositories as Array<Record<string, any>>).find((r) => r.name === job.repository)!;
    expect(repo.scannedCommit).toBe(job.commit);
    expect(repo.open.high).toBe(1);
    // A job that is not this agent's, or not running, is refused.
    expect((await agent(`/api/v1/agent/jobs/${job.id}/sarif`, { body: sarif() })).status).toBe(404);
    expect((await json(await app.admin("/api/v1/agents"))).agents[0]).toMatchObject({ name: "dc1", status: "online", version: "0.1.0" });
  });

  it("scans a repository again when its default branch moves, not for a repository turned off", async () => {
    // Finish the other job, as failed.
    const { jobs } = await json(await agent("/api/v1/agent/work", { body: "{}" }));
    expect((await agent(`/api/v1/agent/jobs/${jobs[0].id}/failed`, { body: JSON.stringify({ error: "clone timed out" }) })).status).toBe(204);
    expect((await json(await app.admin("/api/v1/jobs"))).jobs.find((j: any) => j.id === jobs[0].id)).toMatchObject({
      status: "failed",
      error: "clone timed out",
    });

    gh.repos[0]!.pushed_at = "2026-10-24T09:00:00Z";
    gh.heads["acme/web"] = "c".repeat(40);
    gh.repos[3]!.pushed_at = "2026-10-24T09:00:00Z";
    gh.heads["acme/api"] = "d".repeat(40);
    const api = ((await json(await app.admin("/api/v1/repositories"))).repositories as Array<Record<string, any>>).find((r) => r.name === "acme/api")!;
    expect((await app.admin(`/api/v1/repositories/${api.id}`, { method: "PATCH", body: JSON.stringify({ scanEnabled: false }) })).status).toBe(200);
    await app.forge.poll();
    const queued = ((await json(await app.admin("/api/v1/jobs"))).jobs as Array<Record<string, any>>).filter((j) => j.status === "queued");
    expect(queued.map((j) => `${j.repository} ${j.commit.slice(0, 1)}`)).toEqual(["acme/web c"]);
  });

  it("puts a job an agent did not finish back in the queue, and lets an admin scan again", async () => {
    const { jobs } = await json(await agent("/api/v1/agent/work", { body: "{}" }));
    app.db.prepare("UPDATE scan_jobs SET lease_until = '2000-01-01T00:00:00Z' WHERE id = ?").run(jobs[0].id);
    const again = await json(await agent("/api/v1/agent/work", { body: "{}" }));
    expect(again.jobs[0].id).toBe(jobs[0].id);
    await agent(`/api/v1/agent/jobs/${jobs[0].id}/sarif`, { body: sarif() });
    const web = ((await json(await app.admin("/api/v1/repositories"))).repositories as Array<Record<string, any>>).find((r) => r.name === "acme/web")!;
    const res = await app.admin(`/api/v1/repositories/${web.id}/scan`, { method: "POST" });
    expect(res.status).toBe(201);
    expect(await json(res)).toMatchObject({ repository: "acme/web", status: "queued" });
  });

  it("sends the install's own rules and the rules switched off with each job", async () => {
    const yaml = "rules:\n  - id: acme.todo\n    pattern-regex: TODO\n    message: A TODO\n    languages: [generic]\n    severity: INFO\n";
    expect((await post("/api/v1/rules", { name: "todo", yaml })).status).toBe(201);
    expect((await post("/api/v1/rules", { name: "todo", yaml })).status).toBe(409);
    expect((await post("/api/v1/rules", { name: "x", yaml: "not a rule file" })).status).toBe(422);
    const res = await app.admin("/api/v1/rules/disabled", {
      method: "PUT",
      body: JSON.stringify({ disabled: ["openasy.javascript.eval", "openasy.javascript.eval"] }),
    });
    expect(await json(res)).toEqual({ disabled: ["openasy.javascript.eval"] });
    await app.forge.scanNow(
      ((await json(await app.admin("/api/v1/repositories"))).repositories as Array<Record<string, any>>).find((r) => r.name === "acme/web")!.id,
    );
    const { jobs } = await json(await agent("/api/v1/agent/work", { body: "{}" }));
    expect(jobs[0]).toMatchObject({ ownRules: [{ name: "todo", yaml }], disabledRules: ["openasy.javascript.eval"] });
    await agent(`/api/v1/agent/jobs/${jobs[0].id}/failed`, { body: JSON.stringify({ error: "not now" }) });
    // Leave a job waiting, as the next test expects.
    await app.forge.scanNow(
      ((await json(await app.admin("/api/v1/repositories"))).repositories as Array<Record<string, any>>).find((r) => r.name === "acme/web")!.id,
    );
  });

  it("takes rule sources an install adds, and sends them with each job", async () => {
    expect((await app.admin("/api/v1/rule-sources", { method: "PUT", body: JSON.stringify({ ruleSources: ["git@github.com:x/y.git"] }) })).status).toBe(422);
    const res = await app.admin("/api/v1/rule-sources", { method: "PUT", body: JSON.stringify({ ruleSources: ["https://github.com/acme/rules"] }) });
    expect(await json(res)).toEqual({ ruleSources: ["https://github.com/acme/rules"] });
    const { jobs } = await json(await agent("/api/v1/agent/work", { body: "{}" }));
    expect(jobs[0].ruleSources).toEqual(["https://github.com/acme/rules"]);
  });

  it("turns off the repositories the file says, which the UI then cannot turn on", async () => {
    syncFile(app, [ACME], { SAST_ACME_TOKEN: TOKEN }, [{ name: "acme/web", scan: false }]);
    const repos = async () => (await json(await app.admin("/api/v1/repositories"))).repositories as Array<Record<string, any>>;
    const web = (await repos()).find((r) => r.name === "acme/web")!;
    expect(web).toMatchObject({ scanEnabled: false, scanFromFile: true });
    expect((await app.admin(`/api/v1/repositories/${web.id}`, { method: "PATCH", body: JSON.stringify({ scanEnabled: true }) })).status).toBe(409);
    // Left out of the file, it is scanned again.
    syncFile(app, [ACME], { SAST_ACME_TOKEN: TOKEN });
    expect((await repos()).find((r) => r.name === "acme/web")).toMatchObject({ scanEnabled: true, scanFromFile: false });
  });

  it("stops scanning a repository archived on GitHub or gone from the account, and takes its findings out of the open ones", async () => {
    const repos = async () => (await json(await app.admin("/api/v1/repositories"))).repositories as Array<Record<string, any>>;
    const api = (await repos()).find((r) => r.name === "acme/api")!;
    app.db
      .prepare(
        "INSERT INTO findings (repo_id, fingerprint, rule_id, severity, path, message, first_seen, last_seen) VALUES (?, 'fp-api', 'js.sql', 'high', 'a.js', 'm', ?, ?)",
      )
      .run(api.id, "2026-10-01T00:00:00Z", "2026-10-01T00:00:00Z");
    const open = async () => (await json(await app.admin("/api/v1/findings?rule=js.sql"))).findings as unknown[];
    expect(await open()).toHaveLength(1);
    const before = (await json(await app.admin("/api/v1/summary"))) as { repositories: number; open: { high: number } };

    gh.repos[3]!.archived = true;
    await app.forge.poll();
    expect((await repos()).find((r) => r.name === "acme/api")!.archivedAt).toEqual(expect.any(String));
    // Archived ones come last, and their findings leave the open ones without being called fixed.
    expect((await repos()).at(-1)!.name).toBe("acme/api");
    expect(await open()).toEqual([]);
    const after = (await json(await app.admin("/api/v1/summary"))) as typeof before & { archived: number };
    expect(after).toMatchObject({ repositories: before.repositories - 1, archived: 1, open: { high: before.open.high - 1 } });
    expect((await json(await app.admin(`/api/v1/repositories/${api.id}/findings`))).findings).toHaveLength(1);
    expect((await app.admin(`/api/v1/repositories/${api.id}/scan`, { method: "POST" })).status).toBe(409);

    // Active again on GitHub, it is scanned again, with its findings.
    gh.repos[3]!.archived = false;
    await app.forge.poll();
    expect((await repos()).find((r) => r.name === "acme/api")!.archivedAt).toBeNull();
    expect(await open()).toHaveLength(1);

    // Gone from the account, deleted or out of the token's reach, it is archived the same way.
    const [gone] = gh.repos.splice(3, 1);
    await app.forge.poll();
    expect((await repos()).find((r) => r.name === "acme/api")!.archivedAt).toEqual(expect.any(String));
    gh.repos.splice(3, 0, gone!);
    await app.forge.poll();
    expect((await repos()).find((r) => r.name === "acme/api")!.archivedAt).toBeNull();
  });

  it("removes a connection with its entry in the file, and keeps its repositories with their findings", async () => {
    const [c] = (await json(await app.admin("/api/v1/connections"))).connections;
    expect(c.repositories).toBe(2);
    // One from the file is not removed here.
    expect((await app.admin(`/api/v1/connections/${c.id}`, { method: "DELETE" })).status).toBe(409);
    expect(syncFile(app, [], {})).toEqual([]);
    expect((await json(await app.admin("/api/v1/connections"))).connections).toEqual([]);
    const repos = (await json(await app.admin("/api/v1/repositories"))).repositories as Array<Record<string, any>>;
    expect(repos.map((r) => `${r.name} ${r.source}`)).toEqual(["acme/api ci", "acme/web ci"]);
  });

  it("takes over a connection made in the UI before, when the file names its account", async () => {
    app.db
      .prepare("INSERT INTO forge_connections (id, kind, account, api_url, token, created_at) VALUES ('old', 'github', 'acme', ?, 'v1.x.y', 'now')")
      .run(`http://127.0.0.1:${(gh.server.address() as AddressInfo).port}`);
    let [c] = (await json(await app.admin("/api/v1/connections"))).connections;
    expect(c).toMatchObject({ id: "old", source: "ui", fileName: null });
    syncFile(app, [ACME], { SAST_ACME_TOKEN: TOKEN });
    [c] = (await json(await app.admin("/api/v1/connections"))).connections;
    expect(c).toMatchObject({ id: "old", source: "file", fileName: "acme" });
    syncFile(app, [], {});
  });
});

describe("pull requests of a connected repository (ADR 0036)", () => {
  const head = "e".repeat(40);
  let prHead = head;
  const statuses: Array<{ path: string; body: Record<string, unknown> }> = [];
  const comments: Array<{ method: string; path: string; body: string }> = [];
  let mayPost = true;
  const server: Server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return res.writeHead(401).end("{}");
    const send = (body: unknown, status = 200) => res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
    const url = new URL(req.url!, "http://x");
    if (url.pathname === "/user") return send({ login: "dev" });
    if (url.pathname === "/user/repos")
      return send([
        {
          full_name: "acme/web",
          owner: { login: "acme" },
          clone_url: "https://github.com/acme/web.git",
          default_branch: "main",
          archived: false,
          pushed_at: "2026-10-20T10:00:00Z",
        },
      ]);
    if (url.pathname === "/repos/acme/web/branches/main") return send({ name: "main", commit: { sha: "a".repeat(40) } });
    if (url.pathname === "/repos/acme/web/pulls")
      return send([
        { number: 7, head: { sha: prHead, ref: "feature/login" }, base: { ref: "main" } },
        { number: 8, head: { sha: "f".repeat(40), ref: "x" }, base: { ref: "release" } },
      ]);
    if (url.pathname === "/repos/acme/web/issues/7/comments" || url.pathname === "/repos/acme/web/issues/comments/99") {
      comments.push({ method: req.method!, path: url.pathname, body: JSON.parse(Buffer.concat(chunks).toString("utf8")).body });
      return send({ id: 99 }, req.method === "POST" ? 201 : 200);
    }
    if (req.method === "POST" && url.pathname.startsWith("/repos/acme/web/statuses/")) {
      if (!mayPost) return send({ message: "Resource not accessible by personal access token" }, 403);
      statuses.push({ path: url.pathname, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) });
      return send({}, 201);
    }
    res.writeHead(404).end("{}");
  });
  let pr: Awaited<ReturnType<typeof startApp>>;
  beforeAll(async () => {
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    pr = await startApp({
      version,
      forgeOptions: { githubApi: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, publicUrl: "https://sast.example.com" },
    });
  });
  afterAll(async () => {
    await pr.close();
    await new Promise((r) => server.close(r));
  });

  it("scans an open pull request into the default branch, compares it, and posts the result as a commit status", async () => {
    syncFile(pr, [ACME], { SAST_ACME_TOKEN: TOKEN });
    await pr.forge.poll();
    const jobs = (await json(await pr.admin("/api/v1/jobs"))).jobs as Array<Record<string, any>>;
    // The default branch, and pull request 7; 8 goes into another branch.
    expect(jobs.map((j) => `${j.branch} ${j.pullRequest}`).sort()).toEqual(["feature/login 7", "main null"]);
    await new Promise((r) => setTimeout(r, 50));
    expect(statuses).toEqual([{ path: `/repos/acme/web/statuses/${head}`, body: expect.objectContaining({ state: "pending", context: "OpenAsy SAST" }) }]);

    const made = await json(await pr.admin("/api/v1/agents", { method: "POST", body: JSON.stringify({ name: "dc1" }) }));
    const { secret } = await json(await fetch(pr.base + "/api/v1/agent/enroll", { method: "POST", body: JSON.stringify({ token: made.enrollToken }) }));
    const agent = (path: string, body: string) => fetch(pr.base + path, { method: "POST", headers: { authorization: `Bearer ${secret}` }, body });
    const take = async () => (await json(await agent("/api/v1/agent/work", "{}"))).jobs[0];
    // The baseline first, then the pull request, which adds one high finding.
    const first = await take();
    await agent(`/api/v1/agent/jobs/${first.id}/sarif`, sarif({ rule: "js.eval", level: "error", path: "src/a.js", line: 3 }));
    const second = await take();
    expect(second).toMatchObject({ branch: "feature/login", commit: head });
    await agent(
      `/api/v1/agent/jobs/${second.id}/sarif`,
      sarif({ rule: "js.eval", level: "error", path: "src/a.js", line: 3 }, { rule: "js.sql", level: "error", path: "src/db.js", line: 9 }),
    );
    expect(statuses.at(-1)).toEqual({
      path: `/repos/acme/web/statuses/${head}`,
      body: {
        state: "failure",
        context: "OpenAsy SAST",
        description: "1 new finding blocks this pull request.",
        target_url: expect.stringMatching(/^https:\/\/sast\.example\.com\/scans\//),
      },
    });
    // One comment lists what the pull request adds.
    expect(comments).toEqual([
      { method: "POST", path: "/repos/acme/web/issues/7/comments", body: expect.stringContaining("adds 1 finding, 1 of them blocking") },
    ]);
    expect(comments[0]!.body).toContain("| high | `js.sql` | `src/db.js:9` |");
    expect(comments[0]!.body).toMatch(/\[See the scan\]\(https:\/\/sast\.example\.com\/scans\//);
    // The default branch's scanned commit is not the pull request's.
    const repo = (await json(await pr.admin("/api/v1/repositories"))).repositories[0];
    expect(repo.scannedCommit).toBe("a".repeat(40));
    secretOf = secret;
  });

  let secretOf = "";
  it("edits its one comment when a later commit adds nothing", async () => {
    prHead = "d".repeat(40);
    await pr.forge.poll();
    const agent = (path: string, body: string) => fetch(pr.base + path, { method: "POST", headers: { authorization: `Bearer ${secretOf}` }, body });
    const job = (await json(await agent("/api/v1/agent/work", "{}"))).jobs[0];
    expect(job).toMatchObject({ commit: prHead });
    await agent(`/api/v1/agent/jobs/${job.id}/sarif`, sarif({ rule: "js.eval", level: "error", path: "src/a.js", line: 3 }));
    expect(comments.at(-1)).toEqual({
      method: "PATCH",
      path: "/repos/acme/web/issues/comments/99",
      body: expect.stringContaining("the latest commit adds no findings"),
    });
    expect(statuses.at(-1)!.body).toMatchObject({ state: "success", description: "Nothing new." });
  });

  it("keeps scanning when the token may not post statuses, and says why on the job", async () => {
    mayPost = false;
    pr.db.prepare("DELETE FROM scan_jobs WHERE pull_request = '7'").run();
    await pr.forge.poll();
    await new Promise((r) => setTimeout(r, 50));
    const job = ((await json(await pr.admin("/api/v1/jobs"))).jobs as Array<Record<string, any>>).find((j) => j.pullRequest === "7");
    expect(job).toMatchObject({ status: "queued", checkError: expect.stringMatching(/Commit statuses, read and write/) });
  });
});

describe("repositories and merge requests from GitLab (ADR 0036)", () => {
  const GL = "glpat-0123456789abcdefghij";
  const head = "c".repeat(40);
  const mrHead = "9".repeat(40);
  const calls: string[] = [];
  const statuses: Array<{ path: string; body: Record<string, unknown> }> = [];
  const notes: Array<{ method: string; path: string; body: string }> = [];
  const project = (path: string, extra: object = {}) => ({
    path_with_namespace: path,
    http_url_to_repo: `https://gitlab.example.com/${path}.git`,
    default_branch: "main",
    archived: false,
    empty_repo: false,
    last_activity_at: "2026-10-22T10:00:00Z",
    ...extra,
  });
  const server: Server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    calls.push(`${req.method} ${req.url}`);
    if (req.headers.authorization !== `Bearer ${GL}`) return res.writeHead(401).end("{}");
    const send = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
      res.writeHead(status, { "content-type": "application/json", ...headers }).end(JSON.stringify(body));
    const url = new URL(req.url!, "http://x");
    // Node keeps %2F encoded in the path, as GitLab expects a project's full path.
    const path = url.pathname;
    if (path === "/api/v4/user") return send({ username: "dev" });
    if (path === "/api/v4/namespaces/acme%2Fplatform") return send({ id: 12, kind: "group", full_path: "acme/platform" });
    if (path === "/api/v4/groups/12/projects") {
      expect(url.searchParams.get("include_subgroups")).toBe("true");
      if (url.searchParams.get("page") !== "2")
        return send([project("acme/platform/api"), project("acme/platform/old", { archived: true })], 200, {
          link: `<http://${req.headers.host}/api/v4/groups/12/projects?include_subgroups=true&page=2>; rel="next"`,
        });
      return send([project("acme/platform/empty", { default_branch: null, empty_repo: true }), project("acme/platform/tools/cli")]);
    }
    const b = /^\/api\/v4\/projects\/(.+)\/repository\/branches\/main$/.exec(path);
    if (b) return send({ name: "main", commit: { id: decodeURIComponent(b[1]!).endsWith("cli") ? "d".repeat(40) : head } });
    if (path === "/api/v4/projects/acme%2Fplatform%2Fapi/merge_requests")
      return send([
        { iid: 4, sha: mrHead, source_branch: "fix/auth", target_branch: "main" },
        { iid: 5, sha: null, source_branch: "wip", target_branch: "main" },
      ]);
    if (/^\/api\/v4\/projects\/.+\/merge_requests$/.test(path)) return send([]);
    if (req.method === "POST" && path.startsWith("/api/v4/projects/acme%2Fplatform%2Fapi/statuses/")) {
      statuses.push({ path, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) });
      return send({}, 201);
    }
    if (
      path === "/api/v4/projects/acme%2Fplatform%2Fapi/merge_requests/4/notes" ||
      path === "/api/v4/projects/acme%2Fplatform%2Fapi/merge_requests/4/notes/55"
    ) {
      notes.push({ method: req.method!, path, body: JSON.parse(Buffer.concat(chunks).toString("utf8")).body });
      return send({ id: 55 }, req.method === "POST" ? 201 : 200);
    }
    res.writeHead(404).end("{}");
  });
  let gl: Awaited<ReturnType<typeof startApp>>;
  beforeAll(async () => {
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    gl = await startApp({
      version,
      forgeOptions: { gitlabUrl: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, publicUrl: "https://sast.example.com" },
    });
  });
  afterAll(async () => {
    await gl.close();
    await new Promise((r) => server.close(r));
  });
  it("connects a group by its path from the file, at the install's GitLab", async () => {
    syncFile(gl, [{ name: "platform", forge: "gitlab", account: "acme/platform", url: null, token: "SAST_GITLAB_TOKEN" }], { SAST_GITLAB_TOKEN: GL });
    const [c] = (await json(await gl.admin("/api/v1/connections"))).connections;
    expect(c).toMatchObject({ kind: "gitlab", account: "acme/platform", source: "file", apiUrl: expect.stringMatching(/\/api\/v4$/) });
    expect(JSON.stringify(c)).not.toContain(GL);
  });

  it("lists the group's projects with its subgroups', not archived or empty ones, and queues each default branch", async () => {
    await gl.forge.poll();
    const repos = (await json(await gl.admin("/api/v1/repositories"))).repositories as Array<Record<string, unknown>>;
    expect(repos.map((r) => `${r.name} ${r.source}`)).toEqual(["acme/platform/api gitlab", "acme/platform/tools/cli gitlab"]);
    const jobs = (await json(await gl.admin("/api/v1/jobs"))).jobs as Array<Record<string, any>>;
    // The merge request without a commit yet waits for the next look.
    expect(jobs.map((j) => `${j.repository} ${j.branch} ${j.pullRequest}`).sort()).toEqual([
      "acme/platform/api fix/auth 4",
      "acme/platform/api main null",
      "acme/platform/tools/cli main null",
    ]);
    await new Promise((r) => setTimeout(r, 50));
    expect(statuses).toEqual([
      { path: `/api/v4/projects/acme%2Fplatform%2Fapi/statuses/${mrHead}`, body: expect.objectContaining({ state: "pending", name: "OpenAsy SAST" }) },
    ]);
  });

  it("sends the merge request's result back as a commit status and one note, edited at the next scan", async () => {
    const made = await json(await gl.admin("/api/v1/agents", { method: "POST", body: JSON.stringify({ name: "dc1" }) }));
    const { secret } = await json(await fetch(gl.base + "/api/v1/agent/enroll", { method: "POST", body: JSON.stringify({ token: made.enrollToken }) }));
    const agent = (path: string, body: string) => fetch(gl.base + path, { method: "POST", headers: { authorization: `Bearer ${secret}` }, body });
    const take = async () => (await json(await agent("/api/v1/agent/work", "{}"))).jobs[0];
    for (let i = 0; i < 2; i++) {
      const base = await take();
      expect(base.pullRequest ?? null).toBeNull();
      expect(base).toMatchObject({ token: GL, cloneUrl: expect.stringMatching(/^https:\/\/gitlab\.example\.com\//) });
      await agent(`/api/v1/agent/jobs/${base.id}/sarif`, sarif({ rule: "js.eval", level: "error", path: "src/a.js", line: 3 }));
    }
    const mr = await take();
    expect(mr).toMatchObject({ repository: "acme/platform/api", branch: "fix/auth", commit: mrHead });
    await agent(
      `/api/v1/agent/jobs/${mr.id}/sarif`,
      sarif({ rule: "js.eval", level: "error", path: "src/a.js", line: 3 }, { rule: "js.sql", level: "error", path: "src/db.js", line: 9 }),
    );
    expect(statuses.at(-1)).toEqual({
      path: `/api/v4/projects/acme%2Fplatform%2Fapi/statuses/${mrHead}`,
      body: {
        state: "failed",
        name: "OpenAsy SAST",
        description: "1 new finding blocks this merge request.",
        target_url: expect.stringMatching(/^https:\/\/sast\.example\.com\/scans\//),
      },
    });
    expect(notes).toEqual([
      {
        method: "POST",
        path: "/api/v4/projects/acme%2Fplatform%2Fapi/merge_requests/4/notes",
        body: expect.stringContaining("this merge request adds 1 finding"),
      },
    ]);

    // The same commit scanned again with nothing new edits the note.
    gl.db.prepare("DELETE FROM scan_jobs WHERE pull_request = '4'").run();
    await gl.forge.poll();
    const again = await take();
    await agent(`/api/v1/agent/jobs/${again.id}/sarif`, sarif({ rule: "js.eval", level: "error", path: "src/a.js", line: 3 }));
    expect(notes.at(-1)).toEqual({
      method: "PUT",
      path: "/api/v4/projects/acme%2Fplatform%2Fapi/merge_requests/4/notes/55",
      body: expect.stringContaining("the latest commit adds no findings"),
    });
    expect(statuses.at(-1)!.body).toMatchObject({ state: "success", description: "Nothing new." });
  });

  it("leaves a repository another connection has to it, and says when GitLab has no such group", async () => {
    gl.db
      .prepare(
        "INSERT INTO forge_connections (id, kind, account, api_url, token, created_at) VALUES ('other', 'github', 'acme', 'https://api.github.com', 'x', 'now')",
      )
      .run();
    gl.db.prepare("UPDATE repositories SET connection_id = 'other' WHERE name = 'acme/platform/tools/cli'").run();
    const cli = async () =>
      ((await json(await gl.admin("/api/v1/repositories"))).repositories as Array<Record<string, any>>).find((r) => r.name === "acme/platform/tools/cli");
    await gl.forge.poll();
    expect((await cli())!.source).toBe("github");
    // Deleting the other connection frees the repository; the next look takes it back.
    gl.db.prepare("DELETE FROM forge_connections WHERE id = 'other'").run();
    await gl.forge.poll();
    expect((await cli())!.source).toBe("gitlab");

    const id = (await json(await gl.admin("/api/v1/connections"))).connections[0].id as string;
    gl.db.prepare("UPDATE forge_connections SET account = 'acme/gone' WHERE id = ?").run(id);
    await gl.forge.poll();
    expect((await json(await gl.admin("/api/v1/connections"))).connections[0].error).toBe("GitLab has no group or user acme/gone the token can see.");
  });
});
