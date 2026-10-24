import { timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { extname, join, normalize } from "node:path";
import type { DatabaseSync } from "node:sqlite";
import { createGunzip } from "node:zlib";
import { AuthError, mergeOpenApi, sendProblem, type Auth, type Role } from "@openasy/auth";
import { log } from "./log.ts";
import { countRequest, renderMetrics } from "./metrics.ts";
import type { ProductLink } from "./products.ts";
import type { Severity } from "./sarif.ts";
import type { Forge } from "./forge.ts";
import { parseLimit, SastError, SEVERITIES, type FindingFilter, type ProblemCode, type Sast, type Status } from "./sast.ts";

export interface AppOptions {
  db: DatabaseSync;
  sast: Sast;
  /** Forge connections, scan jobs and the agents that run them (ADR 0036). */
  forge: Forge;
  version: string;
  /** Sign-in, sessions, members and API tokens (ADR 0002, 0003). */
  auth: Auth;
  /** Token CI sends with SARIF. It can add scans and nothing else (ADR 0003). An API token with the editor role works too. */
  ingestToken?: string;
  /** For tests and local scripts: one shared token with the admin role. main.ts never sets it. */
  adminToken?: string;
  /** Built web UI; omit to run headless (ADR 0018). */
  webDir?: string;
  /** Built API reference (Swagger UI), served at /api/docs. */
  docsDir?: string;
  /** The OpenAPI description, served at /api/openapi.json with this release's version. */
  openapi?: Record<string, unknown>;
  /** false when /metrics is served on its own port instead (ADR 0026). */
  serveMetrics?: boolean;
  /** The install's OpenAsy products and their addresses, from OPENASY_PRODUCTS, for the product switcher. */
  products?: ProductLink[];
}

function metricsText(sast: Sast, version: string) {
  return renderMetrics(version, {
    repositories: sast.repositoryCount(),
    findings: sast.severityTotals(),
    suppressed: sast.suppressedCount(),
    failingChecks: sast.summary().failingChecks,
  });
}

/** Serves only /metrics, for a port that is not exposed with the rest (SAST_METRICS_PORT). */
export function createMetricsHandler(sast: Sast, version: string) {
  return (req: IncomingMessage, res: ServerResponse) => {
    if (new URL(req.url ?? "/", "http://localhost").pathname !== "/metrics") return problem(res, 404, "not-found");
    send(res, 200, metricsText(sast, version), "text/plain; version=0.0.4");
  };
}

const TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript",
  ".json": "application/json",
  ".css": "text/css",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "content-security-policy": "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'",
};

/** Largest SARIF log accepted, after decompression. */
const SARIF_LIMIT = 64 * 1024 * 1024;

function send(res: ServerResponse, status: number, body: string | Buffer, type = "application/json", headers: Record<string, string> = {}) {
  res.writeHead(status, { ...SECURITY_HEADERS, ...headers, "content-type": type, "content-length": Buffer.byteLength(body) });
  res.end(body);
}

const json = (res: ServerResponse, status: number, data: unknown, headers?: Record<string, string>) =>
  send(res, status, JSON.stringify(data), "application/json", headers);

const TITLES: Record<ProblemCode, string> = {
  "invalid-token": "Invalid token",
  "invalid-json": "Invalid JSON",
  "invalid-body": "Invalid request body",
  "invalid-sarif": "Invalid SARIF",
  "not-found": "Not found",
  conflict: "Conflict",
  "not-configured": "Not configured",
  "payload-too-large": "Payload too large",
  "internal-error": "Internal error",
};

/** RFC 9457 Problem Details (ADR 0024). `code` is the stable part clients match on. */
function problem(res: ServerResponse, status: number, code: ProblemCode, detail?: string) {
  const body = { type: `https://openasy.github.io/problems/${code}`, title: TITLES[code], status, code, ...(detail && { detail }) };
  send(res, status, JSON.stringify(body), "application/problem+json");
}

/** Serves a file from dir, or returns false when the path is outside it or missing. */
async function serveFile(res: ServerResponse, dir: string, relative: string): Promise<boolean> {
  const file = normalize(join(dir, relative));
  if (!file.startsWith(normalize(dir)) || !extname(file)) return false;
  try {
    send(res, 200, await readFile(file), TYPES[extname(file)] ?? "application/octet-stream");
    return true;
  } catch {
    return false;
  }
}

/** Reads the whole body, gunzipping it when sent with `Content-Encoding: gzip`, up to limit bytes. */
async function readBody(req: IncomingMessage, limit: number): Promise<Buffer> {
  const encoding = req.headers["content-encoding"];
  if (encoding && encoding !== "gzip" && encoding !== "identity") throw new SastError(400, "invalid-body", "Content-Encoding must be gzip or absent.");
  const source = encoding === "gzip" ? req.pipe(createGunzip()) : req;
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    for await (const chunk of source as AsyncIterable<Buffer>) {
      size += chunk.length;
      if (size > limit) throw new SastError(413, "payload-too-large", `The body must be at most ${Math.round(limit / 1024 / 1024)} MiB.`);
      chunks.push(chunk);
    }
  } catch (err) {
    if (err instanceof SastError) throw err;
    throw new SastError(400, "invalid-body", "The gzip body could not be read.");
  }
  return Buffer.concat(chunks);
}

async function readJson(req: IncomingMessage, limit = 64 * 1024): Promise<Record<string, unknown>> {
  const raw = await readBody(req, limit).catch((err: unknown) => {
    if (err instanceof SastError && err.code === "payload-too-large")
      throw new SastError(400, "invalid-json", `The body must be JSON, at most ${Math.round(limit / 1024)} KiB.`);
    throw err;
  });
  try {
    const body = JSON.parse(raw.toString("utf8")) as unknown;
    if (body === null || typeof body !== "object" || Array.isArray(body)) throw new Error("not an object");
    return body as Record<string, unknown>;
  } catch {
    throw new SastError(400, "invalid-json", "The body must be a JSON object.");
  }
}

function tokenMatches(header: string | undefined, expected: string | undefined): boolean {
  if (!expected || !header?.startsWith("Bearer ")) return false;
  const a = Buffer.from(header.slice(7));
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

/** The role a route needs (ADR 0003), or "ingest" for scans sent from CI. */
type Access = "none" | "ingest" | "agent" | Role;
interface Ctx {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  params: string[];
  body: () => Promise<Record<string, unknown>>;
  /** Who made the request, for the audit trail of a decision. */
  actor: () => string;
  /** On "agent" routes: the enrolled sast-agent that sent the request. */
  agent: string;
}
interface Route {
  method: string;
  /** Path pattern; each `:name` matches one segment. */
  path: string;
  auth: Access;
  handle: (ctx: Ctx) => unknown;
}

function findingFilter(url: URL, repoId?: string): FindingFilter {
  const status = url.searchParams.get("status") ?? "open";
  if (status !== "open" && status !== "suppressed" && status !== "resolved")
    throw new SastError(422, "invalid-body", "status must be open, suppressed or resolved.");
  const severity = url.searchParams.get("severity")?.split(",").filter(Boolean) as Severity[] | undefined;
  if (severity?.some((s) => !SEVERITIES.includes(s)))
    throw new SastError(422, "invalid-body", `severity is a comma-separated list of ${SEVERITIES.join(", ")}.`);
  const q = url.searchParams.get("q")?.trim();
  if (q && q.length > 128) throw new SastError(422, "invalid-body", "q must be at most 128 characters.");
  return { status: status as Status, severity, q: q || undefined, repoId: repoId ?? url.searchParams.get("repository") ?? undefined };
}

export function createApp({
  db,
  sast,
  forge,
  version,
  auth,
  adminToken,
  ingestToken,
  webDir,
  docsDir,
  openapi,
  serveMetrics = true,
  products = [],
}: AppOptions) {
  // The served description includes /api/v1/auth from @openasy/auth, so the API reference documents sign-in too.
  const spec = openapi && JSON.stringify({ ...mergeOpenApi(openapi), info: { ...(openapi.info as object), version } });
  const noContent = (res: ServerResponse) => {
    res.writeHead(204, SECURITY_HEADERS).end();
  };
  const cursor = (url: URL) => url.searchParams.get("cursor") ?? undefined;
  const limit = (url: URL) => parseLimit(url.searchParams.get("limit"));
  const page = <K extends string, T>(key: K, p: { items: T[]; nextCursor?: string }) =>
    ({ [key]: p.items, ...(p.nextCursor && { nextCursor: p.nextCursor }) }) as Record<K, T[]> & { nextCursor?: string };

  const routes: Route[] = [
    { method: "GET", path: "/api/v1/version", auth: "none", handle: () => ({ product: "sast", version }) },
    { method: "GET", path: "/api/v1/products", auth: "viewer", handle: () => ({ products }) },
    { method: "GET", path: "/api/v1/summary", auth: "viewer", handle: () => sast.summary() },

    // SARIF in, from CI. The answer says whether the check passes, so a pipeline can fail on it.
    {
      method: "POST",
      path: "/api/v1/scans",
      auth: "ingest",
      handle: async ({ req, res, url }) => {
        const q = (name: string) => url.searchParams.get(name);
        const scan = sast.ingest(
          { repository: q("repository"), branch: q("branch"), commit: q("commit"), pullRequest: q("pullRequest"), defaultBranch: q("defaultBranch") },
          await readBody(req, SARIF_LIMIT),
        );
        json(res, 201, scan, { location: `/api/v1/scans/${scan.id}` });
      },
    },
    { method: "GET", path: "/api/v1/scans/:id", auth: "viewer", handle: ({ params }) => sast.scan(params[0]!) },

    // Repositories from a forge, scanned by sast-agent (ADR 0036). A token reads code, so connections are the owner's.
    { method: "GET", path: "/api/v1/connections", auth: "admin", handle: () => ({ connections: forge.listConnections() }) },
    {
      method: "POST",
      path: "/api/v1/connections",
      auth: "owner",
      handle: async ({ res, body }) => {
        const c = await forge.createConnection(await body());
        // The account's repositories, and their first scans, without waiting for the next look.
        void forge.poll();
        json(res, 201, c);
      },
    },
    { method: "DELETE", path: "/api/v1/connections/:id", auth: "owner", handle: ({ res, params }) => (forge.deleteConnection(params[0]!), noContent(res)) },
    { method: "POST", path: "/api/v1/connections/sync", auth: "admin", handle: async () => (await forge.poll(), { connections: forge.listConnections() }) },
    { method: "GET", path: "/api/v1/rule-sources", auth: "viewer", handle: () => ({ ruleSources: forge.ruleSources() }) },
    {
      method: "PUT",
      path: "/api/v1/rule-sources",
      auth: "admin",
      handle: async ({ body }) => ({ ruleSources: forge.setRuleSources((await body()).ruleSources) }),
    },
    { method: "GET", path: "/api/v1/jobs", auth: "viewer", handle: () => ({ jobs: forge.listJobs() }) },
    { method: "POST", path: "/api/v1/repositories/:id/scan", auth: "editor", handle: ({ res, params }) => json(res, 201, forge.scanNow(params[0]!)) },
    { method: "GET", path: "/api/v1/agents", auth: "admin", handle: () => ({ agents: forge.listAgents() }) },
    { method: "POST", path: "/api/v1/agents", auth: "admin", handle: async ({ res, body }) => json(res, 201, forge.createAgent(await body())) },
    { method: "DELETE", path: "/api/v1/agents/:id", auth: "admin", handle: ({ res, params }) => (forge.deleteAgent(params[0]!), noContent(res)) },
    // sast-agent: enrol once with the token, then ask for work and send back what a scan found.
    { method: "POST", path: "/api/v1/agent/enroll", auth: "none", handle: async ({ body }) => forge.enroll(await body()) },
    { method: "POST", path: "/api/v1/agent/work", auth: "agent", handle: async ({ agent, body }) => forge.work(agent, (await body()).version) },
    {
      method: "POST",
      path: "/api/v1/agent/jobs/:id/sarif",
      auth: "agent",
      handle: async ({ req, agent, params }) => forge.complete(agent, params[0]!, await readBody(req, SARIF_LIMIT)),
    },
    {
      method: "POST",
      path: "/api/v1/agent/jobs/:id/failed",
      auth: "agent",
      handle: async ({ res, agent, params, body }) => (forge.fail(agent, params[0]!, await body()), noContent(res)),
    },

    // Repositories.
    { method: "GET", path: "/api/v1/repositories", auth: "viewer", handle: ({ url }) => page("repositories", sast.listRepositories(cursor(url), limit(url))) },
    { method: "GET", path: "/api/v1/repositories/:id", auth: "viewer", handle: ({ params }) => sast.repository(params[0]!) },
    { method: "PATCH", path: "/api/v1/repositories/:id", auth: "admin", handle: async ({ params, body }) => sast.updateRepository(params[0]!, await body()) },
    { method: "DELETE", path: "/api/v1/repositories/:id", auth: "admin", handle: ({ res, params }) => (sast.deleteRepository(params[0]!), noContent(res)) },
    {
      method: "GET",
      path: "/api/v1/repositories/:id/scans",
      auth: "viewer",
      handle: ({ url, params }) => page("scans", sast.scans(params[0]!, cursor(url), limit(url))),
    },
    {
      method: "GET",
      path: "/api/v1/repositories/:id/findings",
      auth: "viewer",
      handle: ({ url, params }) => page("findings", sast.findings(findingFilter(url, params[0]!), cursor(url), limit(url))),
    },

    // Findings of every repository.
    {
      method: "GET",
      path: "/api/v1/findings",
      auth: "viewer",
      handle: ({ url }) => page("findings", sast.findings(findingFilter(url), cursor(url), limit(url))),
    },
    {
      // Triage follows the finding's fingerprint to every branch (ADR 0036).
      method: "PUT",
      path: "/api/v1/repositories/:id/findings/:fingerprint",
      auth: "editor",
      handle: async ({ params, body, actor }) => sast.triage(params[0]!, params[1]!, await body(), actor()),
    },
  ];

  const compiled = routes.map((r) => ({ ...r, re: new RegExp(`^${r.path.replace(/:[a-z]+/g, "([^/]+)")}$`) }));

  /** Returns who is calling, or null for the ingest token. */
  function authorize(req: IncomingMessage, access: Access): string | null {
    if (access === "none") return null;
    if (access === "agent") {
      const agent = forge.agentBySecret(req.headers.authorization);
      if (!agent) throw new SastError(401, "invalid-token", "Send the agent's own secret, from enrolment, as a bearer token.");
      return agent;
    }
    if (access === "ingest" && tokenMatches(req.headers.authorization, ingestToken)) return null;
    if (tokenMatches(req.headers.authorization, adminToken)) return "admin token";
    if (access === "ingest") {
      // An API token or a session with the editor role can send scans too, for CI set up from Settings.
      if (!ingestToken && !req.headers.authorization?.startsWith("Bearer oa_"))
        throw new SastError(503, "not-configured", "Set SAST_INGEST_TOKEN on sast, or send an API token with the editor role.");
      if (!req.headers.authorization?.startsWith("Bearer oa_"))
        throw new SastError(401, "invalid-token", "Send SAST_INGEST_TOKEN or an API token as a bearer token.");
    }
    const p = auth.authorize(req, access === "ingest" ? "editor" : access);
    return p.kind === "session" ? p.user.name : `API token ${p.name}`;
  }

  async function route(req: IncomingMessage, res: ServerResponse): Promise<string> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;

    if (path === "/healthz") return (json(res, 200, { status: "ok" }), "/healthz");

    if (path === "/readyz") {
      // Ready to take scans as long as the database answers.
      try {
        db.prepare("SELECT 1").get();
        json(res, 200, { status: "ready" });
      } catch {
        json(res, 503, { status: "database unavailable" });
      }
      return "/readyz";
    }

    if (path === "/metrics") {
      // Not even the web UI's fallback answers here when metrics have their own port.
      if (serveMetrics) send(res, 200, metricsText(sast, version), "text/plain; version=0.0.4");
      else problem(res, 404, "not-found");
      return "/metrics";
    }

    if (path === "/api/openapi.json" && spec) return (send(res, 200, spec), "/api/openapi.json");

    if (docsDir && (path === "/api/docs" || path.startsWith("/api/docs/"))) {
      if (path === "/api/docs") {
        res.writeHead(301, { ...SECURITY_HEADERS, location: "/api/docs/" }).end();
        return "/api/docs";
      }
      const relative = path.slice("/api/docs/".length) || "index.html";
      if (!(await serveFile(res, docsDir, relative))) problem(res, 404, "not-found");
      return "/api/docs";
    }

    if (await auth.handle(req, res)) return auth.routeName(req) ?? "/api/v1/auth/*";

    for (const r of compiled) {
      const m = path.match(r.re);
      if (!m || r.method !== req.method) continue;
      try {
        const who = authorize(req, r.auth);
        const params = m.slice(1).map(decodeURIComponent);
        const result = await r.handle({ req, res, url, params, body: () => readJson(req), actor: () => who ?? "unknown", agent: who ?? "" });
        if (!res.headersSent && result !== undefined) json(res, 200, result);
      } catch (err) {
        if (err instanceof AuthError) {
          sendProblem(res, err);
          if (!req.complete) req.resume();
          return r.path;
        }
        if (!(err instanceof SastError)) throw err;
        problem(res, err.status, err.code, err.message);
        // Unread request bodies would otherwise hold the connection.
        if (!req.complete) req.resume();
      }
      return r.path;
    }

    if (path.startsWith("/api/")) return (problem(res, 404, "not-found"), "/api/*");

    if (webDir && (req.method === "GET" || req.method === "HEAD")) {
      // Unknown paths fall back to the single-page app.
      if (!(await serveFile(res, webDir, path === "/" ? "index.html" : path))) send(res, 200, await readFile(join(webDir, "index.html")), TYPES[".html"]);
      return "/web";
    }

    problem(res, 404, "not-found");
    return "unmatched";
  }

  return async (req: IncomingMessage, res: ServerResponse) => {
    const started = performance.now();
    let routeName = "error";
    try {
      routeName = await route(req, res);
    } catch (err) {
      log("error", "request failed", { error: String(err), path: req.url });
      if (!res.headersSent) problem(res, 500, "internal-error");
    }
    countRequest(req.method ?? "GET", routeName, res.statusCode);
    if (routeName !== "/healthz" && routeName !== "/metrics") {
      log("info", "request", { method: req.method, path: url(req), status: res.statusCode, ms: Math.round(performance.now() - started) });
    }
  };
}

/** The path without the query string, which may name hosts and images. */
const url = (req: IncomingMessage) => (req.url ?? "/").split("?")[0];
