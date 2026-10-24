import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { createAuth, oidcFromEnv, readSecretsKey } from "@openasy/auth";
import { createApp, createMetricsHandler } from "./app.ts";
import { openDb } from "./db.ts";
import { log } from "./log.ts";
import { parseProducts } from "./products.ts";
import { createForge } from "./forge.ts";
import { createKeyring } from "./kek.ts";
import { createSast } from "./sast.ts";

const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
const port = Number(process.env.PORT ?? 8080);
const dbPath = process.env.SAST_DB ?? "/data/sast.db";
const retentionDays = Number(process.env.SAST_RETENTION_DAYS ?? 365);
const webDir = new URL("../dist/web", import.meta.url).pathname;
const docsDir = new URL("../dist/docs", import.meta.url).pathname;
const openapi = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Record<string, unknown>;
const headless = process.env.SAST_HEADLESS === "true";
// Set it to keep /metrics off the port that is published or behind an ingress (ADR 0026).
const metricsPort = process.env.SAST_METRICS_PORT ? Number(process.env.SAST_METRICS_PORT) : undefined;

if (!Number.isFinite(retentionDays) || retentionDays < 1) throw new Error("SAST_RETENTION_DAYS must be a number of days, 1 or more");

const db = openDb(dbPath);
// The address people open sast at, behind the TLS proxy (ADR 0026). Cookies, passkeys and OIDC redirects use it.
const publicUrl = (process.env.SAST_PUBLIC_URL ?? `http://localhost:${port}`).replace(/\/$/, "");
const secretsKeyFile = process.env.SAST_SECRETS_KEY_FILE ?? "/run/secrets/openasy-kek";
const secretsKey = readSecretsKey(secretsKeyFile);
const pollMinutes = Number(process.env.SAST_POLL_MINUTES ?? 5);
if (!Number.isFinite(pollMinutes) || pollMinutes < 1) throw new Error("SAST_POLL_MINUTES must be a number of minutes, 1 or more");
const auth = createAuth({
  db,
  product: "sast",
  productName: "OpenAsy SAST",
  origin: publicUrl,
  // Locally the same sast is often opened as 127.0.0.1 too.
  trustedOrigins: publicUrl.startsWith("http://localhost:") ? [publicUrl.replace("localhost", "127.0.0.1")] : [],
  passwords: process.env.SAST_PASSWORD_SIGN_IN !== "false",
  oidc: oidcFromEnv(process.env, "SAST_"),
  secretsKey,
  // Audit log (ADR 0013): every sign-in, failure and change to members and tokens.
  onEvent: (event) => log(event.type === "sign-in-failed" ? "warn" : "info", "auth", { event }),
});
const sast = createSast(db, { retentionDays });
// Forge connections and their scan jobs (ADR 0036): tokens sealed with openasy-kek, never kept without it.
const forge = createForge({
  db,
  keyring: secretsKey ? createKeyring(secretsKey) : undefined,
  ingest: (params, raw) => sast.ingest(params, raw),
  githubApi: process.env.SAST_GITHUB_API,
  log,
});
const products = parseProducts(process.env.OPENASY_PRODUCTS);
if (products.invalid.length) log("warn", "OPENASY_PRODUCTS: left out entries that are not id=https://address", { entries: products.invalid });
const server = createServer(
  createApp({
    db,
    sast,
    forge,
    version,
    auth,
    ingestToken: process.env.SAST_INGEST_TOKEN,
    webDir: !headless && existsSync(webDir) ? webDir : undefined,
    docsDir: existsSync(docsDir) ? docsDir : undefined,
    openapi,
    serveMetrics: metricsPort === undefined,
    products: products.products,
  }),
);
const metricsServer = metricsPort !== undefined ? createServer(createMetricsHandler(sast, version)) : undefined;
metricsServer?.listen(metricsPort, () => log("info", "metrics on their own port", { port: metricsPort }));

server.listen(port, () => log("info", "sast started", { version, port, db: dbPath, headless, retentionDays }));
if (!process.env.SAST_INGEST_TOKEN)
  log("warn", "SAST_INGEST_TOKEN is not set; CI needs an API token with the editor role (Settings, API tokens) to send scans");
if (!publicUrl.startsWith("https://") && !/^http:\/\/(localhost|127\.0\.0\.1)(:|$)/.test(publicUrl)) {
  log("warn", "SAST_PUBLIC_URL is not https: browsers will not keep secure cookies or allow passkeys. Put sast behind TLS (ADR 0026)", { url: publicUrl });
}
if (auth.secretsInClear)
  log("warn", "no secrets key: TOTP secrets are stored unencrypted. Mount a 32-byte key (openssl rand -hex 32)", { file: secretsKeyFile });
const setup = auth.setupLink();
// No default password (ADR 0013): the first person to open this link becomes the owner.
if (setup) log("info", "no owner yet: open this link once to create the owner account", { url: setup });

sast.purge();
const timers: NodeJS.Timeout[] = [
  setInterval(() => auth.purge(), 5 * 60_000),
  setInterval(() => sast.purge(), 24 * 3_600_000),
  // Each connected account's repositories, and a scan for every default branch that moved.
  setInterval(() => void forge.poll(), pollMinutes * 60_000),
];
void forge.poll();

function shutdown(signal: string) {
  log("info", "shutting down", { signal });
  for (const t of timers) clearInterval(t);
  metricsServer?.close();
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
