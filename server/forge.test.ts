import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
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
const asAgent =
  (secret: string) =>
  (path: string, init: RequestInit = {}) =>
    fetch(app.base + path, { ...init, method: "POST", headers: { authorization: `Bearer ${secret}`, "content-type": "application/json", ...init.headers } });

describe("repositories from GitHub, scanned by sast-agent (ADR 0036)", () => {
  let agent: ReturnType<typeof asAgent>;

  it("connects an account with a token GitHub accepts, once", async () => {
    expect((await post("/api/v1/connections", { account: "acme", token: "github_pat_wrong_wrong_wrong_wrong" })).status).toBe(422);
    expect((await post("/api/v1/connections", { account: "-bad-", token: TOKEN })).status).toBe(422);
    const res = await post("/api/v1/connections", { account: "acme", token: TOKEN });
    expect(res.status).toBe(201);
    const c = await json(res);
    expect(c).toMatchObject({ kind: "github", account: "acme" });
    expect(JSON.stringify(c)).not.toContain(TOKEN);
    expect((await post("/api/v1/connections", { account: "ACME", token: TOKEN })).status).toBe(409);
    // The token is sealed at rest.
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

  it("takes rule sources an install adds, and sends them with each job", async () => {
    expect((await app.admin("/api/v1/rule-sources", { method: "PUT", body: JSON.stringify({ ruleSources: ["git@github.com:x/y.git"] }) })).status).toBe(422);
    const res = await app.admin("/api/v1/rule-sources", { method: "PUT", body: JSON.stringify({ ruleSources: ["https://github.com/acme/rules"] }) });
    expect(await json(res)).toEqual({ ruleSources: ["https://github.com/acme/rules"] });
    const { jobs } = await json(await agent("/api/v1/agent/work", { body: "{}" }));
    expect(jobs[0].ruleSources).toEqual(["https://github.com/acme/rules"]);
  });

  it("removes a connection, and keeps its repositories with their findings", async () => {
    const [c] = (await json(await app.admin("/api/v1/connections"))).connections;
    expect(c.repositories).toBe(2);
    expect((await app.admin(`/api/v1/connections/${c.id}`, { method: "DELETE" })).status).toBe(204);
    const repos = (await json(await app.admin("/api/v1/repositories"))).repositories as Array<Record<string, any>>;
    expect(repos.map((r) => `${r.name} ${r.source}`)).toEqual(["acme/api ci", "acme/web ci"]);
  });
});
