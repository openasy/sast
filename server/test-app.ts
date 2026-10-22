// Starts the app on a random port for tests.
import { createServer, type RequestListener, type Server } from "node:http";
import { createAuth } from "@openasy/auth";
import type { AddressInfo } from "node:net";
import { createApp, type AppOptions } from "./app.ts";
import { openDb } from "./db.ts";
import { createSast } from "./sast.ts";

export const INGEST_TOKEN = "test-ingest-token";
export const ADMIN_TOKEN = "test-admin-token";

export interface TestResult {
  rule: string;
  /** SARIF level. */
  level?: "error" | "warning" | "note";
  score?: number;
  path: string;
  line?: number;
  code?: string;
  message?: string;
  suppressed?: boolean;
}

/** A SARIF 2.1.0 log such as `opengrep scan --sarif` writes. */
export function sarif(...results: TestResult[]) {
  return JSON.stringify({
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: "opengrep", rules: [] } },
        results: results.map((r) => ({
          ruleId: r.rule,
          level: r.level ?? "warning",
          message: { text: r.message ?? `${r.rule} matched` },
          ...(r.score !== undefined && { properties: { "security-severity": String(r.score) } }),
          ...(r.suppressed && { suppressions: [{ kind: "inSource" }] }),
          locations: [{ physicalLocation: { artifactLocation: { uri: r.path }, region: { startLine: r.line ?? 1, ...(r.code && { snippet: { text: r.code } }) } } }],
        })),
      },
    ],
  });
}

export async function startApp(opts: Partial<AppOptions> & { version: string }) {
  const db = openDb(":memory:");
  const sast = createSast(db);
  // The origin is known once the port is, so the handler is set after listening.
  let handler: RequestListener = (_req, res) => res.writeHead(503).end();
  const server: Server = createServer((req, res) => handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  const auth = createAuth({ db, product: "sast", productName: "OpenAsy SAST", origin: base });
  handler = createApp({ db, sast, auth, ingestToken: INGEST_TOKEN, adminToken: ADMIN_TOKEN, ...opts });
  const as = (token: string) => (path: string, init: RequestInit = {}) => fetch(base + path, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...init.headers } });
  const admin = as(ADMIN_TOKEN);
  const ingest = as(INGEST_TOKEN);
  /** Sends a scan the way CI does. */
  const scan = (query: Record<string, string>, body: string) => ingest(`/api/v1/scans?${new URLSearchParams(query)}`, { method: "POST", body });
  const close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return { db, sast, auth, base, admin, ingest, scan, close };
}
