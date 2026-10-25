// What the search window (Cmd+K) finds in SAST: repositories by name, and open findings by rule, file or message, from the API.
import type { SearchFn, SearchResult } from "@openasy/ui";
import { Bug, FolderGit2 } from "lucide-react";
import type { Finding, Repository } from "./api.ts";
import type { T } from "./i18n.ts";

type Call = <R>(path: string, init?: RequestInit) => Promise<R>;

export function search(call: Call, t: T): SearchFn {
  return async (q, signal) => {
    const [list, found] = await Promise.all([
      call<{ repositories: Repository[] }>("/api/v1/repositories?limit=500", { signal }),
      call<{ findings: Finding[] }>(`/api/v1/findings?${new URLSearchParams({ q, limit: "8" })}`, { signal }),
    ]);
    const named: SearchResult[] = list.repositories
      .filter((e) => e.name.toLowerCase().includes(q))
      .slice(0, 6)
      .map((e) => ({
        id: `repository:${e.id}`,
        label: e.name,
        detail: t("search.open", { open: Object.values(e.open).reduce((n, c) => n + c, 0) }),
        kind: t("search.repository"),
        icon: FolderGit2,
        mono: true,
        href: `/repositories/${encodeURIComponent(e.id)}`,
      }));
    const findings: SearchResult[] = found.findings.map((f) => ({
      id: `finding:${f.repository.id}:${f.fingerprint}`,
      label: `${f.path}${f.line ? `:${f.line}` : ""}`,
      detail: `${f.message} · ${f.repository.name}`,
      kind: t("search.finding"),
      icon: Bug,
      severity: f.severity,
      mono: true,
      href: `/repositories/${encodeURIComponent(f.repository.id)}`,
    }));
    return [...named, ...findings];
  };
}
