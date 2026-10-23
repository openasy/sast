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
  app = await startApp({ version, openapi: spec, docsDir });
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

  it("covers every operation in openapi.json", () => {
    const all = Object.entries(spec.paths).flatMap(([path, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${path}`));
    expect([...covered].sort()).toEqual(all.sort());
  });
});
