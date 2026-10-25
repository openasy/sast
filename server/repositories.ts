// The install's forge accounts from a file, like its servers and endpoints (ADR 0052): which GitHub organizations and
// GitLab groups SAST reads, and settings of single repositories. A token is never in the file, only the name of the
// environment variable that holds it, kept in secrets/sast.env as DAST's secrets are in secrets/dast.env, so the YAML
// can be kept in git and reviewed like code. The file is the only way in: there is no form for connections. A change
// is applied within a minute; a changed token needs a restart, as any environment variable does.
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { parse } from "yaml";

export interface ForgeEntry {
  /** Unique in the file, and how the entry is found again when the file changes. */
  name: string;
  forge: "github" | "gitlab";
  /** A GitHub organization or user, or a GitLab group or user by its path. */
  account: string;
  /** GitLab only: the https address of a GitLab of the install's own; GitLab.com or SAST_GITLAB_URL without it. */
  url: string | null;
  /** The name of the environment variable that holds the token, such as SAST_ACME_TOKEN. */
  token: string;
}

export interface RepositoryEntry {
  /** The repository's path on the forge, such as acme/web or acme/platform/api. */
  name: string;
  /** false: listed and kept, never scanned. */
  scan: boolean;
}

export interface RepositoriesFile {
  forges: ForgeEntry[];
  repositories: RepositoryEntry[];
}

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
// The name of an environment variable, as DAST's login secrets are named (ADR 0052).
const TOKEN_VAR = /^[A-Z_][A-Z0-9_]{0,63}$/;
const GITHUB_ACCOUNT = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const GITLAB_ACCOUNT = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}(?:\/[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}){0,19}$/;
const REPO = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}(?:\/[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}){1,20}$/;
const FORGE_KEYS = ["name", "forge", "account", "url", "token"];
const REPO_KEYS = ["name", "scan"];
const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

/** Reads the file's text. Throws with the entry and field at fault, so one message says what to fix. */
export function parseRepositories(text: string): RepositoriesFile {
  let doc: unknown;
  try {
    doc = parse(text);
  } catch (err) {
    throw new Error(`Not valid YAML: ${(err as Error).message.split("\n")[0]}`);
  }
  if (doc === null || doc === undefined) return { forges: [], repositories: [] };
  if (!isObj(doc) || Object.keys(doc).some((k) => k !== "forges" && k !== "repositories"))
    throw new Error("The file holds two lists, forges: and repositories:, and nothing else.");
  const forgeList = doc.forges ?? [];
  const repoList = doc.repositories ?? [];
  if (!Array.isArray(forgeList)) throw new Error("forges must be a list.");
  if (!Array.isArray(repoList)) throw new Error("repositories must be a list.");
  if (forgeList.length > 100) throw new Error("forges holds at most 100 entries.");
  if (repoList.length > 5000) throw new Error("repositories holds at most 5000 entries.");

  const names = new Set<string>();
  const accounts = new Set<string>();
  const forges = forgeList.map((f, i): ForgeEntry => {
    const at = `forges[${i}]`;
    if (!isObj(f)) throw new Error(`${at} must be a map with name, forge, account and token.`);
    const extra = Object.keys(f).filter((k) => !FORGE_KEYS.includes(k));
    if (extra.length) throw new Error(`${at}: unknown ${extra.join(", ")}; an entry takes ${FORGE_KEYS.join(", ")}.`);
    if (typeof f.name !== "string" || !NAME.test(f.name)) throw new Error(`${at}: name is up to 63 letters, digits and . _ -, such as acme.`);
    const name = f.name;
    if (names.has(name.toLowerCase())) throw new Error(`${at}: ${name} is in the file twice.`);
    names.add(name.toLowerCase());
    if (f.forge !== "github" && f.forge !== "gitlab") throw new Error(`${name}: forge is github or gitlab.`);
    const account = typeof f.account === "string" ? f.account.trim().replace(/^\/+|\/+$/g, "") : "";
    if (f.forge === "github" && !GITHUB_ACCOUNT.test(account)) throw new Error(`${name}: account is a GitHub organization or user, such as acme.`);
    if (f.forge === "gitlab" && !GITLAB_ACCOUNT.test(account))
      throw new Error(`${name}: account is a GitLab group or user by its path, such as acme or acme/platform.`);
    let url: string | null = null;
    if (f.url !== undefined && f.url !== null) {
      if (f.forge === "github") throw new Error(`${name}: url is for GitLab; GitHub's address is the install's SAST_GITHUB_API.`);
      let u: URL;
      try {
        u = new URL(String(f.url));
      } catch {
        throw new Error(`${name}: url is the https address of a GitLab, such as https://gitlab.example.com.`);
      }
      if (u.protocol !== "https:" || u.username || u.password || u.search || u.hash)
        throw new Error(`${name}: url is the https address of a GitLab, such as https://gitlab.example.com.`);
      url = u.href.replace(/\/$/, "");
    }
    const key = `${f.forge}|${url ?? ""}|${account.toLowerCase()}`;
    if (accounts.has(key)) throw new Error(`${name}: the same account is in the file twice.`);
    accounts.add(key);
    if (typeof f.token !== "string" || !TOKEN_VAR.test(f.token))
      throw new Error(
        `${name}: token is the name of the environment variable that holds the token, such as SAST_${name.toUpperCase().replace(/[^A-Z0-9]/g, "_")}_TOKEN; never the token itself.`,
      );
    return { name, forge: f.forge, account, url, token: f.token };
  });

  const repoNames = new Set<string>();
  const repositories = repoList.map((r, i): RepositoryEntry => {
    const at = `repositories[${i}]`;
    if (!isObj(r)) throw new Error(`${at} must be a map with name and scan.`);
    const extra = Object.keys(r).filter((k) => !REPO_KEYS.includes(k));
    if (extra.length) throw new Error(`${at}: unknown ${extra.join(", ")}; an entry takes ${REPO_KEYS.join(", ")}.`);
    if (typeof r.name !== "string" || !REPO.test(r.name)) throw new Error(`${at}: name is the repository's path on its forge, such as acme/web.`);
    if (repoNames.has(r.name.toLowerCase())) throw new Error(`${at}: ${r.name} is in the file twice.`);
    repoNames.add(r.name.toLowerCase());
    if (typeof r.scan !== "boolean") throw new Error(`${r.name}: scan is true or false.`);
    return { name: r.name, scan: r.scan };
  });
  return { forges, repositories };
}

/** A token from the environment variable an entry names. Throws a message that names the variable and where it goes. */
export function readToken(env: NodeJS.ProcessEnv, name: string): string {
  const token = env[name]?.trim() ?? "";
  if (!token) throw new Error(`${name} is not set: put it in secrets/sast.env, then restart sast.`);
  if (token.length < 20 || token.length > 400 || /\s/.test(token)) throw new Error(`${name} does not hold a token.`);
  return token;
}

export interface RepositoriesFileState {
  path: string;
  /** When the file was last read and applied, or null if it never was. */
  appliedAt: string | null;
  forges: number;
  repositories: number;
  /** Why the file on disk is not what is applied; the last good list stays until it is fixed. */
  error: string | null;
  /** Things to fix that did not stop the file from being applied, such as a token that is not set. */
  warnings: string[];
}

/**
 * Reads the file now and whenever it changes (checked every `everyMs`), and hands each new list to `apply`, which
 * returns warnings or throws to refuse it. While the last apply had warnings, the same list is applied again at every
 * check. A file that cannot be read or applied leaves the
 * last good list in place. `stop()` ends the polling.
 */
export function watchRepositories(
  path: string,
  apply: (file: RepositoriesFile) => string[],
  { everyMs = 60_000, onChange }: { everyMs?: number; onChange?: (state: RepositoriesFileState) => void } = {},
) {
  const state: RepositoriesFileState = { path, appliedAt: null, forges: 0, repositories: 0, error: null, warnings: [] };
  let seen = "";
  const read = () => {
    let text: string;
    let stamp: string;
    try {
      const st = statSync(path);
      text = readFileSync(path, "utf8");
      stamp = `${st.size}:${st.mtimeMs}:${createHash("sha256").update(text).digest("hex")}`;
    } catch (err) {
      const error = `Cannot read ${path}: ${(err as NodeJS.ErrnoException).code ?? (err as Error).message}`;
      if (state.error !== error) ((state.error = error), onChange?.(state));
      return;
    }
    if (stamp === seen && !state.warnings.length) return;
    const changed = stamp !== seen;
    seen = stamp;
    try {
      const file = parseRepositories(text);
      const before = state.warnings.join("\n");
      state.warnings = apply(file);
      Object.assign(state, { appliedAt: new Date().toISOString(), forges: file.forges.length, repositories: file.repositories.length, error: null });
      if (changed || before !== state.warnings.join("\n")) onChange?.(state);
    } catch (err) {
      state.error = (err as Error).message;
      onChange?.(state);
    }
  };
  read();
  const timer = setInterval(read, everyMs);
  timer.unref();
  return { state, read, stop: () => clearInterval(timer) };
}
