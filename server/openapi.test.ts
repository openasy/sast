import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ADMIN_TOKEN, INGEST_TOKEN, sarif, startApp } from "./test-app.ts";

// Contract tests (ADR 0024): every response the API sends must match openapi.json.

type Spec = {
  info: { version: string };
  paths: Record<string, Record<string, { responses: Record<string, { $ref?: string; content?: Record<string, { schema: object }> }> }>>;
  components: { responses: Record<string, { content: Record<string, { schema: object }> }> };
};

const spec = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Spec;
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(spec, "openapi");

const docsDir = mkdtempSync(join(tmpdir(), "sast-docs-"));
writeFileSync(join(docsDir, "index.html"), "<!doctype html><title>API</title>");

let app: Awaited<ReturnType<typeof startApp>>;
let base: string;
const covered = new Set<string>();

beforeAll(async () => {
  // GitHub as the connection sees it: the token's user, one repository of acme, and its default branch.
  const github = async (url: string | URL | Request) => {
    const u = new URL(String(url));
    const ok = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
    if (u.pathname === "/user") return ok({ login: "dev" });
    if (u.pathname === "/user/repos")
      return ok([
        {
          full_name: "acme/svc",
          owner: { login: "acme" },
          clone_url: "https://github.com/acme/svc.git",
          default_branch: "main",
          archived: false,
          pushed_at: "2026-10-24T00:00:00Z",
        },
      ]);
    if (u.pathname.startsWith("/repos/acme/svc/branches/")) return ok({ commit: { sha: "e".repeat(40) } });
    return new Response("{}", { status: 404 });
  };
  app = await startApp({ version, openapi: spec, docsDir, forgeOptions: { githubApi: "https://github.test", fetch: github as typeof fetch } });
  base = app.base;
});

afterAll(() => app.close());

/** Calls the API and checks status, content type and body against the description. */
async function call(method: string, path: string, init: RequestInit = {}, concrete = path) {
  const res = await fetch(base + concrete, { ...init, method });
  const operation = spec.paths[path]?.[method.toLowerCase()];
  expect(operation, `${method} ${path} is not in openapi.json`).toBeDefined();
  covered.add(`${method} ${path}`);

  const declared = operation!.responses[String(res.status)];
  expect(declared, `${method} ${concrete} answered ${res.status}, which openapi.json does not list`).toBeDefined();
  // A response is either inline or a $ref to components/responses; build the JSON pointer to its schema either way.
  const shared = declared!.$ref?.split("/").pop();
  const response = shared ? spec.components.responses[shared]! : declared!;
  const at = shared
    ? `openapi#/components/responses/${shared}`
    : `openapi#/paths/${path.replaceAll("/", "~1")}/${method.toLowerCase()}/responses/${res.status}`;

  if (!response.content) {
    expect(res.headers.get("content-length") ?? "0", `${method} ${path} ${res.status} should have no body`).toBe("0");
    return { res, body: undefined };
  }
  const type = res.headers.get("content-type")!.split(";")[0]!;
  expect(response.content?.[type], `${method} ${path} ${res.status} sent ${type}, which openapi.json does not list`).toBeDefined();

  const body = type.endsWith("json") ? await res.json() : await res.text();
  const schema = `${at}/content/${type.replace("/", "~1")}/schema`;
  const validate = ajv.getSchema(schema)!;
  expect(validate(body), JSON.stringify(validate.errors)).toBe(true);
  return { res, body };
}

const auth = (token: string, body?: string, type = "application/json") => ({
  headers: { authorization: `Bearer ${token}`, "content-type": type },
  ...(body !== undefined && { body }),
});
const admin = (body?: unknown) => auth(ADMIN_TOKEN, body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body));
const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();

describe("openapi.json", () => {
  it("has the version of this release", () => {
    expect(spec.info.version).toBe(version);
  });

  it("is served with the running version", async () => {
    const served = (await (await fetch(`${base}/api/openapi.json`)).json()) as Spec;
    expect(served.info.version).toBe(version);
    // sast's own operations, then sign-in from @openasy/auth (tested against its description in that package).
    expect(Object.keys(served.paths).filter((p) => !p.startsWith("/api/v1/auth/"))).toEqual(Object.keys(spec.paths));
    expect(served.paths["/api/v1/auth/login"]).toBeDefined();
  });

  it("serves the API reference at /api/docs/", async () => {
    expect((await fetch(`${base}/api/docs`, { redirect: "manual" })).headers.get("location")).toBe("/api/docs/");
    const res = await fetch(`${base}/api/docs/`);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect((await fetch(`${base}/api/docs/../../package.json`)).status).not.toBe(200);
  });
});

describe("responses match openapi.json", () => {
  let repo = "";
  let scanId = "";
  let fingerprint = "";
  const send = (body = sarif({ rule: "py.sqli", level: "error", path: "a.py", code: "run(q)" }), token = INGEST_TOKEN) => auth(token, body);
  const path = (query: string) => `/api/v1/scans?${query}`;

  it("product and health", async () => {
    await call("GET", "/api/v1/version");
    await call("GET", "/api/v1/products", admin());
    await call("GET", "/api/v1/products", {});
    await call("GET", "/healthz");
    await call("GET", "/readyz");
    await call("GET", "/metrics");
  });

  it("scans: baseline, change, and every refusal", async () => {
    const baseline = (await call("POST", "/api/v1/scans", send(), path("repository=acme/web&branch=main&commit=abc123"))).body as {
      id: string;
      repository: { id: string };
    };
    repo = baseline.repository.id;
    const change = (
      await call(
        "POST",
        "/api/v1/scans",
        send(sarif({ rule: "py.sqli", level: "error", path: "a.py", code: "run(q)" }, { rule: "py.eval", level: "error", path: "a.py", code: "eval(x)" })),
        path("repository=acme/web&branch=fix&pullRequest=3"),
      )
    ).body as {
      id: string;
      findings: Array<{ fingerprint: string }>;
    };
    scanId = change.id;
    fingerprint = change.findings[0]!.fingerprint;
    await call("POST", "/api/v1/scans", send("{nope"), path("repository=acme/web&branch=main"));
    await call("POST", "/api/v1/scans", send(JSON.stringify({ hello: 1 })), path("repository=acme/web&branch=main"));
    await call("POST", "/api/v1/scans", send(), path("branch=main"));
    await call("POST", "/api/v1/scans", auth("wrong", sarif()), path("repository=acme/web&branch=main"));
    await call("POST", "/api/v1/scans", { method: "POST" }, path("repository=acme/web&branch=main"));
    await call("GET", "/api/v1/scans/{id}", admin(), `/api/v1/scans/${scanId}`);
    await call("GET", "/api/v1/scans/{id}", admin(), "/api/v1/scans/missing");
    await call("GET", "/api/v1/scans/{id}", {}, `/api/v1/scans/${scanId}`);
  });

  it("repositories", async () => {
    await call("GET", "/api/v1/repositories", admin());
    await call("GET", "/api/v1/repositories", admin(), "/api/v1/repositories?limit=1");
    await call("GET", "/api/v1/repositories", admin(), "/api/v1/repositories?limit=0");
    await call("GET", "/api/v1/repositories", {});
    await call("GET", "/api/v1/repositories/{id}", admin(), `/api/v1/repositories/${repo}`);
    await call("GET", "/api/v1/repositories/{id}", admin(), "/api/v1/repositories/missing");
    await call("PATCH", "/api/v1/repositories/{id}", admin({ failOn: "critical" }), `/api/v1/repositories/${repo}`);
    await call("PATCH", "/api/v1/repositories/{id}", admin({ failOn: "urgent" }), `/api/v1/repositories/${repo}`);
    await call("PATCH", "/api/v1/repositories/{id}", admin("nope"), `/api/v1/repositories/${repo}`);
    await call("PATCH", "/api/v1/repositories/{id}", admin({ failOn: "high" }), "/api/v1/repositories/missing");
    await call("PATCH", "/api/v1/repositories/{id}", { method: "PATCH" }, `/api/v1/repositories/${repo}`);
    await call("GET", "/api/v1/repositories/{id}/scans", admin(), `/api/v1/repositories/${repo}/scans`);
    await call("GET", "/api/v1/repositories/{id}/scans", admin(), "/api/v1/repositories/missing/scans");
    await call("GET", "/api/v1/repositories/{id}/scans", admin(), `/api/v1/repositories/${repo}/scans?cursor=junk`);
    await call("GET", "/api/v1/repositories/{id}/scans", {}, `/api/v1/repositories/${repo}/scans`);
  });

  it("findings and triage", async () => {
    const { body } = await call("GET", "/api/v1/findings", admin());
    expect((body as { findings: unknown[] }).findings).toHaveLength(1);
    await call("GET", "/api/v1/findings", admin(), "/api/v1/findings?status=resolved&severity=high,critical&q=sql&limit=1");
    await call("GET", "/api/v1/findings", admin(), `/api/v1/findings?repository=${repo}`);
    await call("GET", "/api/v1/findings", admin(), "/api/v1/findings?severity=urgent");
    await call("GET", "/api/v1/findings", {});
    await call("GET", "/api/v1/repositories/{id}/findings", admin(), `/api/v1/repositories/${repo}/findings`);
    await call("GET", "/api/v1/repositories/{id}/findings", admin(), `/api/v1/repositories/${repo}/findings?status=suppressed`);
    await call("GET", "/api/v1/repositories/{id}/findings", admin(), "/api/v1/repositories/missing/findings");
    await call("GET", "/api/v1/repositories/{id}/findings", {}, `/api/v1/repositories/${repo}/findings`);

    const put = (fp: string, state: unknown) =>
      call("PUT", "/api/v1/repositories/{id}/findings/{fingerprint}", admin(state), `/api/v1/repositories/${repo}/findings/${fp}`);
    await put(fingerprint, { state: "false-positive", reason: "The query is a constant" });
    await put(fingerprint, { state: "accepted", reason: "Behind the VPN", expiresAt: inDays(30) });
    await put(fingerprint, { state: "accepted", reason: "No end" });
    await put(fingerprint, "nope");
    await put("missing", { state: "open" });
    await call("GET", "/api/v1/repositories/{id}/findings", admin(), `/api/v1/repositories/${repo}/findings?status=suppressed`);
    await put(fingerprint, { state: "open" });
    await call("PUT", "/api/v1/repositories/{id}/findings/{fingerprint}", { method: "PUT" }, `/api/v1/repositories/${repo}/findings/${fingerprint}`);
    await call("GET", "/api/v1/summary", admin());
    await call("GET", "/api/v1/summary", {});
  });

  it("deletes a repository", async () => {
    await call("DELETE", "/api/v1/repositories/{id}", admin(), `/api/v1/repositories/${repo}`);
    await call("DELETE", "/api/v1/repositories/{id}", admin(), `/api/v1/repositories/${repo}`);
    await call("DELETE", "/api/v1/repositories/{id}", { method: "DELETE" }, "/api/v1/repositories/x");
  });

  it("connections, scan jobs and the agent", async () => {
    const connection = (await call("POST", "/api/v1/connections", admin({ account: "acme", token: "github_pat_0123456789abcdefghijkl" }))).body as {
      id: string;
    };
    await call("POST", "/api/v1/connections", admin({ account: "acme", token: "github_pat_0123456789abcdefghijkl" }));
    await call("POST", "/api/v1/connections", admin({ account: "", token: "x" }));
    await call("POST", "/api/v1/connections", admin("nope"));
    await call("GET", "/api/v1/connections", admin());
    await call("POST", "/api/v1/connections/sync", admin());
    await call("GET", "/api/v1/jobs", admin());
    await call("PUT", "/api/v1/rule-sources", admin({ ruleSources: ["https://github.com/acme/rules"] }));
    await call("PUT", "/api/v1/rule-sources", admin({ ruleSources: ["ftp://x"] }));
    await call("PUT", "/api/v1/rule-sources", admin("nope"));
    await call("GET", "/api/v1/rule-sources", admin());

    const made = (await call("POST", "/api/v1/agents", admin({ name: "dc1" }))).body as { agent: { id: string }; enrollToken: string };
    await call("POST", "/api/v1/agents", admin({ name: "dc1" }));
    await call("POST", "/api/v1/agents", admin({ name: "Not OK" }));
    await call("POST", "/api/v1/agents", admin("nope"));
    await call("GET", "/api/v1/agents", admin());
    await call("POST", "/api/v1/agent/enroll", { body: JSON.stringify({ token: "ose_wrong" }) });
    await call("POST", "/api/v1/agent/enroll", { body: "nope" });
    const { secret } = (await call("POST", "/api/v1/agent/enroll", { body: JSON.stringify({ token: made.enrollToken, version: "0.1.0" }) })).body as {
      secret: string;
    };
    await call("POST", "/api/v1/agent/work", auth("osa_wrong", "{}"));
    await call("POST", "/api/v1/agent/work", auth(secret, "nope"));
    const { jobs } = (await call("POST", "/api/v1/agent/work", auth(secret, JSON.stringify({ version: "0.1.0" })))).body as { jobs: Array<{ id: string }> };
    await call("POST", "/api/v1/agent/jobs/{id}/sarif", auth(secret, "nope"), `/api/v1/agent/jobs/${jobs[0]!.id}/sarif`);
    await call("POST", "/api/v1/agent/jobs/{id}/sarif", auth(secret, sarif({ rule: "x", path: "a.js" })), `/api/v1/agent/jobs/${jobs[0]!.id}/sarif`);
    await call("POST", "/api/v1/agent/jobs/{id}/sarif", auth(secret, sarif()), `/api/v1/agent/jobs/${jobs[0]!.id}/sarif`);
    await call("POST", "/api/v1/agent/jobs/{id}/sarif", auth("osa_wrong", sarif()), `/api/v1/agent/jobs/${jobs[0]!.id}/sarif`);

    const repo = ((await call("GET", "/api/v1/repositories", admin())).body as { repositories: Array<{ id: string; name: string }> }).repositories.find(
      (r) => r.name === "acme/svc",
    )!;
    await call("POST", "/api/v1/repositories/{id}/scan", admin(), `/api/v1/repositories/${repo.id}/scan`);
    await call("POST", "/api/v1/repositories/{id}/scan", admin(), "/api/v1/repositories/missing/scan");
    const again = (await call("POST", "/api/v1/agent/work", auth(secret, "{}"))).body as { jobs: Array<{ id: string }> };
    await call(
      "POST",
      "/api/v1/agent/jobs/{id}/failed",
      auth(secret, JSON.stringify({ error: "clone timed out" })),
      `/api/v1/agent/jobs/${again.jobs[0]!.id}/failed`,
    );
    await call("POST", "/api/v1/agent/jobs/{id}/failed", auth(secret, "nope"), `/api/v1/agent/jobs/${again.jobs[0]!.id}/failed`);
    await call("POST", "/api/v1/agent/jobs/{id}/failed", auth(secret, "{}"), `/api/v1/agent/jobs/${again.jobs[0]!.id}/failed`);
    await call("POST", "/api/v1/agent/jobs/{id}/failed", auth("osa_wrong", "{}"), `/api/v1/agent/jobs/${again.jobs[0]!.id}/failed`);

    await call("DELETE", "/api/v1/agents/{id}", admin(), `/api/v1/agents/${made.agent.id}`);
    await call("DELETE", "/api/v1/agents/{id}", admin(), "/api/v1/agents/missing");
    await call("DELETE", "/api/v1/connections/{id}", admin(), `/api/v1/connections/${connection.id}`);
    await call("DELETE", "/api/v1/connections/{id}", admin(), "/api/v1/connections/missing");
  });
  it("own rules and switched off rules", async () => {
    const yaml =
      "rules:\n  - id: acme.no-console\n    pattern: console.log(...)\n    message: No console.log\n    languages: [javascript]\n    severity: WARNING\n";
    const made = (await call("POST", "/api/v1/rules", admin({ name: "no-console", yaml }))).body as { id: string };
    await call("POST", "/api/v1/rules", admin({ name: "no-console", yaml }));
    await call("POST", "/api/v1/rules", admin({ name: "Bad Name", yaml }));
    await call("POST", "/api/v1/rules", admin({ name: "big", yaml: `rules:\n${"#".repeat(270 * 1024)}` }));
    await call("POST", "/api/v1/rules", {});
    await call("GET", "/api/v1/rules", admin());
    await call("GET", "/api/v1/rules", {});
    await call("PUT", "/api/v1/rules/{id}", admin({ yaml: yaml.replace("No console.log", "No console") }), `/api/v1/rules/${made.id}`);
    await call("PUT", "/api/v1/rules/{id}", admin({ yaml: "nope" }), `/api/v1/rules/${made.id}`);
    await call("PUT", "/api/v1/rules/{id}", admin({ yaml }), "/api/v1/rules/missing");
    await call("PUT", "/api/v1/rules/disabled", admin({ disabled: ["openasy.javascript.eval"] }));
    await call("PUT", "/api/v1/rules/disabled", admin({ disabled: ["; rm"] }));
    await call("PUT", "/api/v1/rules/disabled", {});
    await call("DELETE", "/api/v1/rules/{id}", admin(), `/api/v1/rules/${made.id}`);
    await call("DELETE", "/api/v1/rules/{id}", admin(), `/api/v1/rules/${made.id}`);
  });

  it("covers every operation in openapi.json", () => {
    const all = Object.entries(spec.paths).flatMap(([path, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${path}`));
    expect([...covered].sort()).toEqual(all.sort());
  });
});
