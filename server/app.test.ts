import { gzipSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { sarif, startApp, type TestResult } from "./test-app.ts";

let app: Awaited<ReturnType<typeof startApp>>;
beforeAll(async () => {
  app = await startApp({ version: "0.1.0" });
});
afterAll(() => app.close());

const sqli: TestResult = { rule: "python.sqli", level: "error", path: "app/db.py", line: 12, code: 'cur.execute("select * from t where id=" + id)' };
const eval_: TestResult = { rule: "python.eval", level: "error", path: "app/util.py", line: 40, code: "eval(expr)" };
const style: TestResult = { rule: "python.assert", level: "note", path: "app/util.py", line: 3, code: "assert x" };
const xss: TestResult = { rule: "js.xss", score: 8, path: "web/view.js", line: 9, code: "el.innerHTML = name" };
const weak: TestResult = { rule: "js.md5", score: 3, path: "web/hash.js", line: 4, code: "md5(pw)" };

const json = async (res: Response) => (await res.json()) as any;
const baseline = (...r: TestResult[]) => app.scan({ repository: "acme/web", branch: "main", commit: "aaaa1111" }, sarif(...r));
const pull = (n: string, ...r: TestResult[]) => app.scan({ repository: "acme/web", branch: `feature-${n}`, pullRequest: n, commit: "bbbb2222" }, sarif(...r));

describe("scans", () => {
  it("makes the first scan of the default branch the baseline and creates the repository", async () => {
    const res = await baseline(sqli, eval_, style);
    expect(res.status).toBe(201);
    const scan = await json(res);
    // Two high findings are new, and still the first scan of a repository passes: it adopts what is there.
    expect(scan).toMatchObject({ kind: "baseline", total: 3, new: 3, blocking: 0, passed: true, repository: { name: "acme/web" }, failOn: "high" });
    const repos = (await json(await app.admin("/api/v1/repositories"))).repositories;
    expect(repos).toHaveLength(1);
    expect(repos[0]).toMatchObject({ name: "acme/web", defaultBranch: "main", open: { critical: 0, high: 2, medium: 0, low: 1 }, suppressed: 0 });
  });

  it("reports on a pull request only what the default branch does not have", async () => {
    // The same findings on other lines are not new; one high and one low are.
    const moved = { ...sqli, line: 80 };
    const scan = await json(await pull("7", moved, eval_, style, xss, weak));
    expect(scan).toMatchObject({ kind: "change", pullRequest: "7", total: 5, new: 2, blocking: 1, passed: false, suppressed: 0 });
    expect(scan.findings.map((f: { rule: string }) => f.rule)).toEqual(["js.xss", "js.md5"]);
  });

  it("passes a pull request that adds nothing, even with old findings", async () => {
    expect(await json(await pull("8", sqli, eval_))).toMatchObject({ new: 0, blocking: 0, passed: true });
  });

  it("does not let a pull request change the baseline", async () => {
    const list = await json(await app.admin("/api/v1/findings"));
    expect(list.findings.map((f: { rule: string }) => f.rule).sort()).toEqual(["python.assert", "python.eval", "python.sqli"]);
  });

  it("keeps triage on a finding that is only in a pull request, and applies it to the next scan", async () => {
    const first = await json(await pull("9", sqli, xss));
    expect(first).toMatchObject({ new: 1, passed: false });
    const [fp] = first.findings.map((f: { fingerprint: string }) => f.fingerprint);
    const repoId = first.repository.id;

    const missing = await app.admin(`/api/v1/repositories/${repoId}/findings/nope`, {
      method: "PUT",
      body: JSON.stringify({ state: "false-positive", reason: "static string" }),
    });
    expect(missing.status).toBe(404);
    const done = await app.admin(`/api/v1/repositories/${repoId}/findings/${fp}`, {
      method: "PUT",
      body: JSON.stringify({ state: "false-positive", reason: "Output is escaped by the template" }),
    });
    expect(done.status).toBe(200);
    expect(await json(done)).toMatchObject({
      rule: "js.xss",
      triage: { state: "false-positive", reason: "Output is escaped by the template", by: "admin token", active: true },
    });

    expect(await json(await pull("9", sqli, xss))).toMatchObject({ new: 0, suppressed: 1, blocking: 0, passed: true });
    // The decision shows on the scan page too.
    const scanId = (await json(await app.admin(`/api/v1/repositories/${repoId}/scans`))).scans[0].id;
    expect((await json(await app.admin(`/api/v1/scans/${scanId}`))).findings).toMatchObject([{ rule: "js.xss", suppressed: true }]);
    // It is not a finding of the default branch yet.
    expect((await json(await app.admin(`/api/v1/repositories/${repoId}/findings?status=suppressed`))).findings).toEqual([]);
  });

  it("brings the triaged finding in with its decision when the pull request is merged", async () => {
    await baseline(sqli, eval_, style, xss);
    const repoId = (await json(await app.admin("/api/v1/repositories"))).repositories[0].id;
    const suppressed = (await json(await app.admin(`/api/v1/repositories/${repoId}/findings?status=suppressed`))).findings;
    expect(suppressed).toMatchObject([{ rule: "js.xss", resolvedAt: null }]);
    const open = (await json(await app.admin(`/api/v1/repositories/${repoId}/findings`))).findings;
    expect(open.map((f: { rule: string }) => f.rule).sort()).toEqual(["python.assert", "python.eval", "python.sqli"]);
    // Most severe first.
    expect(open[2].rule).toBe("python.assert");
  });

  it("resolves what the default branch stops reporting, and opens it again if it returns", async () => {
    await baseline(sqli, style, xss);
    const repoId = (await json(await app.admin("/api/v1/repositories"))).repositories[0].id;
    const resolved = (await json(await app.admin(`/api/v1/repositories/${repoId}/findings?status=resolved`))).findings;
    expect(resolved).toMatchObject([{ rule: "python.eval", resolvedAt: expect.any(String) }]);
    // Back again: it is new for a pull request until the baseline has it.
    expect(await json(await pull("10", sqli, style, xss, eval_))).toMatchObject({ new: 1 });
    await baseline(sqli, style, xss, eval_);
    expect((await json(await app.admin(`/api/v1/repositories/${repoId}/findings?status=resolved`))).findings).toEqual([]);
  });

  it("filters and pages findings", async () => {
    const all = await json(await app.admin("/api/v1/findings?limit=2"));
    expect(all.findings).toHaveLength(2);
    expect(all.nextCursor).toBeDefined();
    const rest = await json(await app.admin(`/api/v1/findings?limit=2&cursor=${all.nextCursor}`));
    expect(rest.findings).toHaveLength(1);
    expect(rest.nextCursor).toBeUndefined();
    expect((await json(await app.admin("/api/v1/findings?severity=low"))).findings.map((f: { rule: string }) => f.rule)).toEqual(["python.assert"]);
    expect((await json(await app.admin("/api/v1/findings?q=eval"))).findings.map((f: { rule: string }) => f.rule)).toEqual(["python.eval"]);
    expect((await json(await app.admin("/api/v1/findings?q=%25"))).findings).toEqual([]);
    expect((await app.admin("/api/v1/findings?severity=urgent")).status).toBe(422);
    expect((await app.admin("/api/v1/findings?status=gone")).status).toBe(422);
    expect((await app.admin("/api/v1/findings?limit=0")).status).toBe(422);
    expect((await app.admin("/api/v1/findings?cursor=junk")).status).toBe(422);
  });
});

describe("triage", () => {
  const triage = async (state: Record<string, unknown>) => {
    const repo = (await json(await app.admin("/api/v1/repositories"))).repositories[0];
    const f = (await json(await app.admin(`/api/v1/repositories/${repo.id}/findings?q=sqli`))).findings[0];
    return app.admin(`/api/v1/repositories/${repo.id}/findings/${f.fingerprint}`, { method: "PUT", body: JSON.stringify(state) });
  };
  const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();

  it("needs a reason, and an end for accepted risk", async () => {
    expect((await triage({ state: "accepted", reason: "Behind the VPN", expiresAt: undefined })).status).toBe(422);
    expect((await triage({ state: "accepted", reason: "Behind the VPN", expiresAt: inDays(-1) })).status).toBe(422);
    expect((await triage({ state: "accepted", reason: "Behind the VPN", expiresAt: inDays(400) })).status).toBe(422);
    expect((await triage({ state: "false-positive", reason: "" })).status).toBe(422);
    expect((await triage({ state: "ignored", reason: "x" })).status).toBe(422);
    expect((await triage({ state: "false-positive", reason: "ok", extra: 1 })).status).toBe(422);
  });

  it("hides an accepted risk until it expires, and open clears it", async () => {
    const res = await triage({ state: "accepted", reason: "Behind the VPN until the rewrite", expiresAt: inDays(30) });
    expect(await json(res)).toMatchObject({ rule: "python.sqli", triage: { state: "accepted", expiresAt: expect.any(String), active: true } });
    expect((await json(await app.admin("/api/v1/findings?status=suppressed"))).findings.map((f: { rule: string }) => f.rule)).toContain("python.sqli");
    expect((await json(await app.admin("/api/v1/summary"))).open.high).toBe(1);

    // The acceptance runs out.
    app.db.prepare("UPDATE findings SET expires_at = ? WHERE triage = 'accepted'").run(new Date(Date.now() - 1000).toISOString());
    expect((await json(await app.admin("/api/v1/summary"))).open.high).toBe(2);
    expect(await json(await pull("11", sqli, style, xss, eval_))).toMatchObject({ new: 0 });

    expect(await json(await triage({ state: "open" }))).toMatchObject({ rule: "python.sqli", triage: null });
  });
});

describe("repositories", () => {
  it("changes the default branch and what fails a check, and deletes", async () => {
    const repo = (await json(await app.admin("/api/v1/repositories"))).repositories[0];
    const patch = (body: unknown) => app.admin(`/api/v1/repositories/${repo.id}`, { method: "PATCH", body: JSON.stringify(body) });
    expect((await patch({ failOn: "critical" })).status).toBe(200);
    expect(await json(await pull("12", sqli, style, xss, eval_, { rule: "x.new", level: "error", path: "n.py", code: "bad()" }))).toMatchObject({
      new: 1,
      blocking: 0,
      passed: true,
      failOn: "critical",
    });
    await patch({ failOn: "none" });
    expect(await json(await pull("13", { rule: "x.new2", score: 9.5, path: "n.py", code: "worse()" }))).toMatchObject({ new: 1, blocking: 0, passed: true });
    expect((await patch({ failOn: "urgent" })).status).toBe(422);
    expect((await patch({})).status).toBe(422);
    expect((await patch({ name: "x" })).status).toBe(422);
    expect((await patch({ defaultBranch: "has space" })).status).toBe(422);
    expect(await json(await patch({ defaultBranch: "trunk", failOn: "high" }))).toMatchObject({ defaultBranch: "trunk", failOn: "high" });
    // The old default branch is an ordinary branch now.
    expect(await json(await baseline(sqli))).toMatchObject({ kind: "change" });
    expect((await app.admin(`/api/v1/repositories/${repo.id}`, { method: "DELETE" })).status).toBe(204);
    expect((await app.admin(`/api/v1/repositories/${repo.id}`)).status).toBe(404);
    expect((await json(await app.admin("/api/v1/summary"))).repositories).toBe(0);
  });
});

describe("sending scans", () => {
  const send = (query: Record<string, string>, body: string | Buffer, headers: Record<string, string> = {}) =>
    app.ingest(`/api/v1/scans?${new URLSearchParams(query)}`, { method: "POST", body, headers });
  const ok = { repository: "acme/api", branch: "main", defaultBranch: "main" };

  it("takes a gzipped body and a new default branch name", async () => {
    const res = await send({ ...ok, defaultBranch: "develop", branch: "develop" }, gzipSync(sarif(sqli)), { "content-encoding": "gzip" });
    expect(res.status).toBe(201);
    expect(await json(res)).toMatchObject({ kind: "baseline", repository: { name: "acme/api" } });
    expect((await send({ ...ok }, Buffer.from("not gzip"), { "content-encoding": "gzip" })).status).toBe(400);
    expect((await send({ ...ok }, sarif(), { "content-encoding": "br" })).status).toBe(400);
  });

  it("refuses what it cannot compare", async () => {
    const problem = async (res: Response, status: number, code: string) => (expect(res.status).toBe(status), expect(await json(res)).toMatchObject({ code }));
    await problem(await send(ok, "{nope"), 422, "invalid-sarif");
    await problem(await send(ok, JSON.stringify({ hello: 1 })), 422, "invalid-sarif");
    await problem(await send({ branch: "main" }, sarif()), 422, "invalid-body");
    await problem(await send({ repository: "../etc", branch: "main" }, sarif()), 422, "invalid-body");
    await problem(await send({ repository: "acme/api" }, sarif()), 422, "invalid-body");
    await problem(await send({ ...ok, commit: "not a hash!" }, sarif()), 422, "invalid-body");
    await problem(await send({ ...ok, pullRequest: "a b" }, sarif()), 422, "invalid-body");
    await problem(await send({ ...ok, defaultBranch: "a b" }, sarif()), 422, "invalid-body");
  });

  it("asks for the ingest token or an editor", async () => {
    const anon = (await fetch(`${app.base}/api/v1/scans?repository=a&branch=main`, { method: "POST", body: sarif() })).status;
    expect(anon).toBe(401);
    const wrong = await fetch(`${app.base}/api/v1/scans?repository=a&branch=main`, {
      method: "POST",
      body: sarif(),
      headers: { authorization: "Bearer nope" },
    });
    expect(wrong.status).toBe(401);
    expect((await app.ingest("/api/v1/summary")).status).toBe(401);
    expect((await app.ingest("/api/v1/findings")).status).toBe(401);
    const closed = await startApp({ version: "0.1.0", ingestToken: undefined, adminToken: undefined });
    expect((await fetch(`${closed.base}/api/v1/scans?repository=a&branch=main`, { method: "POST", body: sarif() })).status).toBe(503);
    await closed.close();
  });
});

describe("product", () => {
  it("answers version, health and metrics", async () => {
    expect(await json(await fetch(`${app.base}/api/v1/version`))).toEqual({ product: "sast", version: "0.1.0" });
    expect((await fetch(`${app.base}/healthz`)).status).toBe(200);
    expect((await fetch(`${app.base}/readyz`)).status).toBe(200);
    const metrics = await (await fetch(`${app.base}/metrics`)).text();
    expect(metrics).toContain('openasy_build_info{product="sast",version="0.1.0"} 1');
    expect(metrics).toMatch(/openasy_sast_repositories \d+/);
    expect(metrics).toContain('openasy_sast_open_findings{severity="high"}');
  });
});
