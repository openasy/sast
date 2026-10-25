import {
  AppShell,
  Badge,
  BrandProvider,
  Button,
  Callout,
  DataTable,
  Dialog,
  EmptyState,
  FacetFilter,
  FilterBar,
  IconButton,
  KpiCard,
  KpiGrid,
  navigate,
  PageHeader,
  Panel,
  PRODUCT_IDS,
  SearchInput,
  SelectField,
  SeverityBadge,
  StatusBadge,
  Switch,
  Tabs,
  TextField,
  TimeSeriesChart,
  usePath,
  type Column,
  type ProductId,
  useThemePreference,
  useAgo,
  toLocale,
  useLocalePreference,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAccountMenu, useAuth, useInstallBrand } from "@openasy/auth/react";
import colophon from "virtual:openasy-colophon";
import { Bug, CircleSlash, FolderGit2, GitBranch, KeyRound, LogIn, LogOut, Play, Plus, RefreshCw, ScrollText, Trash2, UserRound, Users, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  MfaSetupRequired,
  type Agent,
  type Connection,
  type Job,
  type OwnRule,
  type RuleList,
  Unauthorized,
  type FailOn,
  type Finding,
  type ProductLink,
  type Repository,
  type Scan,
  type ScanDetail,
  type Severity,
  type Summary,
} from "./api.ts";
import { useT, type T } from "./i18n.ts";
import { search } from "./search.ts";

const PAGES = ["repositories", "github", "rules", "setup", "account", "members", "signin", "tokens", "about"] as const;
type Route = { page: "findings" | (typeof PAGES)[number] } | { page: "repository" | "scan"; id: string };
/** The first path segments that are pages of this UI, for followLinks. */
export const PATHS = ["findings", "repositories", "scans", ...PAGES];
function parseRoute(path: string): Route {
  const [page, id] = path.replace(/^\//, "").split("/");
  if (page === "repositories" && id) return { page: "repository", id: decodeURIComponent(id) };
  if (page === "scans" && id) return { page: "scan", id: decodeURIComponent(id) };
  if ((PAGES as readonly string[]).includes(page ?? "")) return { page: page as (typeof PAGES)[number] };
  return { page: "findings" };
}

/** Data loading with the session; when it ends, the sign-in screen comes back. */
function useApi() {
  const { expired, refresh } = useAuth();
  return useCallback(
    async <T,>(path: string, init?: RequestInit): Promise<T> => {
      try {
        return await api<T>(path, init);
      } catch (err) {
        if (err instanceof Unauthorized) expired();
        if (err instanceof MfaSetupRequired) void refresh();
        throw err;
      }
    },
    [expired, refresh],
  );
}
type Call = ReturnType<typeof useApi>;

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const FAIL_ON = (t: T): Array<{ value: FailOn; label: string }> => [
  { value: "critical", label: t("failOn.critical") },
  { value: "high", label: t("failOn.highOrWorse") },
  { value: "medium", label: t("failOn.mediumOrWorse") },
  { value: "low", label: t("failOn.anyFinding") },
  { value: "none", label: t("failOn.neverFail") },
];

/** Compact severity counts; each badge carries the full name for screen readers. */
function SevCounts({ counts }: { counts: Record<Severity, number> }) {
  const t = useT();
  const shown = SEVERITIES.filter((s) => counts[s] > 0);
  if (!shown.length) return <span className="text-xs text-fg-muted">{t("sevCounts.none")}</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {shown.map((s) => (
        <Badge key={s} tone={s === "low" ? "neutral" : s === "medium" ? "warning" : "danger"}>
          <span className="sr-only">{s} </span>
          {counts[s]}
        </Badge>
      ))}
    </span>
  );
}

function Code({ children }: { children: ReactNode }) {
  return <pre className="m-0 overflow-x-auto rounded-md bg-subtle px-2.5 py-2 font-mono text-xs text-fg">{children}</pre>;
}

/** What a panel needs to show and triage one finding, from a repository's list or from a scan. */
interface Detail {
  repository: { id: string; name: string };
  fingerprint: string;
  rule: string;
  severity: Severity;
  path: string;
  line: number | null;
  message: string;
  snippet: string | null;
  triage: Finding["triage"];
}

function FindingPanel({ finding, call, onClose, onChanged }: { finding: Detail; call: Call; onClose: () => void; onChanged: () => void }) {
  const ago = useAgo();
  const msg = useT();
  const { can } = useAuth();
  const [deciding, setDeciding] = useState(false);
  const [state, setState] = useState<"false-positive" | "accepted">("false-positive");
  const [days, setDays] = useState("90");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string>();
  const close = () => (setDeciding(false), setReason(""), setError(undefined));
  const url = `/api/v1/repositories/${finding.repository.id}/findings/${finding.fingerprint}`;

  const decide = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await call(url, {
        method: "PUT",
        body: JSON.stringify({ state, reason, ...(state === "accepted" && { expiresAt: new Date(Date.now() + Number(days) * 86_400_000).toISOString() }) }),
      });
      close();
      onChanged();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  const reopen = () => call(url, { method: "PUT", body: JSON.stringify({ state: "open" }) }).then(onChanged, () => {});
  const [switchedOff, setSwitchedOff] = useState(false);
  // Agent scans stop reporting this rule; scans CI sends use CI's own rules.
  const switchOff = async () => {
    const { disabled } = await call<RuleList>("/api/v1/rules");
    await call("/api/v1/rules/disabled", { method: "PUT", body: JSON.stringify({ disabled: [...disabled, finding.rule] }) });
    setSwitchedOff(true);
  };
  const t = finding.triage;

  return (
    <Panel
      aria-label={msg("findingPanel.details", { rule: finding.rule })}
      title={<span className="sast-wrap font-mono text-sm">{finding.rule}</span>}
      description={`${finding.repository.name}`}
      actions={
        <IconButton label={msg("findingPanel.closeDetails")} size="sm" onClick={onClose}>
          <X />
        </IconButton>
      }
    >
      <div className="flex flex-col gap-3 text-sm">
        <div className="flex flex-wrap items-center gap-1.5">
          <SeverityBadge severity={finding.severity} />
          <Badge mono>
            {finding.path}
            {finding.line ? `:${finding.line}` : ""}
          </Badge>
        </div>
        <p className="m-0 text-fg-muted">{finding.message}</p>
        {finding.snippet && <Code>{finding.snippet}</Code>}
        {t && (
          <div className="flex flex-col gap-1 rounded-md border border-line p-2.5 text-xs">
            <span>
              <StatusBadge tone={t.active ? "success" : "neutral"}>
                {t.state === "false-positive"
                  ? msg("findingPanel.falsePositive")
                  : t.active
                    ? msg("findingPanel.acceptedRisk")
                    : msg("findingPanel.acceptanceExpired")}
              </StatusBadge>
            </span>
            <span>{t.reason}</span>
            <span className="text-fg-muted">
              {t.by ? `${t.by}, ` : ""}
              {ago(t.at)}
              {t.expiresAt ? msg("findingPanel.until", { value: new Date(t.expiresAt).toLocaleDateString() }) : ""}
            </span>
          </div>
        )}
        {can("editor") && (
          <div className="flex gap-2 border-t border-line pt-3">
            <Button size="sm" icon={<CircleSlash />} onClick={() => setDeciding(true)}>
              {t ? msg("findingPanel.changeDecision") : msg("findingPanel.triage")}
            </Button>
            {t && (
              <Button size="sm" onClick={() => void reopen()}>
                {msg("findingPanel.openAgain")}
              </Button>
            )}
            {can("admin") && (
              <Button size="sm" onClick={() => void switchOff()} disabled={switchedOff}>
                {switchedOff ? msg("findingPanel.ruleOff") : msg("findingPanel.switchRuleOff")}
              </Button>
            )}
          </div>
        )}
        <Dialog
          open={deciding}
          onOpenChange={(open) => !open && close()}
          title={msg("findingPanel.triage2", { rule: finding.rule })}
          description={msg("findingPanel.theDecisionFollowsThisFinding")}
          onSubmit={decide}
          footer={
            <>
              <Button type="button" onClick={close}>
                {msg("findingPanel.cancel")}
              </Button>
              <Button type="submit" variant="primary" disabled={reason.trim().length < 3}>
                {msg("findingPanel.saveDecision")}
              </Button>
            </>
          }
        >
          <SelectField
            label={msg("findingPanel.decision")}
            value={state}
            onChange={(e) => setState(e.target.value as typeof state)}
            options={[
              { value: "false-positive", label: msg("findingPanel.falsePositive") },
              { value: "accepted", label: msg("findingPanel.acceptedRisk") },
            ]}
          />
          <TextField
            label={msg("findingPanel.reason")}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            hint={msg("findingPanel.whyForTheNextReview")}
            error={error}
          />
          {state === "accepted" && (
            <SelectField
              label={msg("findingPanel.for")}
              value={days}
              onChange={(e) => setDays(e.target.value)}
              options={[
                { value: "30", label: msg("findingPanel.n30Days") },
                { value: "90", label: msg("findingPanel.n90Days") },
                { value: "180", label: msg("findingPanel.n180Days") },
                { value: "365", label: msg("findingPanel.n1Year") },
              ]}
            />
          )}
        </Dialog>
      </div>
    </Panel>
  );
}

type Tab = "open" | "suppressed" | "resolved";

/** Findings of every repository, or of one when repoId is given. */
function FindingsTable({ call, repoId, summary, reload }: { call: Call; repoId?: string; summary?: { open: Record<Severity, number> }; reload: () => void }) {
  const ago = useAgo();
  const t = useT();
  const [tab, setTab] = useState<Tab>("open");
  const [sev, setSev] = useState<string[]>([]);
  const [q, setQ] = useState("");
  const [rows, setRows] = useState<Finding[]>();
  const [more, setMore] = useState<string>();
  const [open, setOpen] = useState<Finding | null>(null);
  const base = repoId ? `/api/v1/repositories/${repoId}/findings` : "/api/v1/findings";

  const query = useCallback(
    (cursor?: string) => {
      const p = new URLSearchParams({ status: tab, limit: "200" });
      if (sev.length) p.set("severity", sev.join(","));
      if (q.trim()) p.set("q", q.trim());
      if (cursor) p.set("cursor", cursor);
      return call<{ findings: Finding[]; nextCursor?: string }>(`${base}?${p}`);
    },
    [call, base, tab, sev, q],
  );
  const load = useCallback(() => {
    query().then(
      (r) => (setRows(r.findings), setMore(r.nextCursor)),
      () => setRows([]),
    );
  }, [query]);
  useEffect(load, [load]);
  const loadMore = () => more && query(more).then((r) => (setRows((x) => [...(x ?? []), ...r.findings]), setMore(r.nextCursor)));

  const columns: Column<Finding>[] = [
    { id: "sev", header: t("findingsTable.severity"), width: "104px", cell: (f) => <SeverityBadge severity={f.severity} /> },
    {
      id: "rule",
      header: t("findingsTable.rule"),
      width: "32%",
      cell: (f) => (
        <span className="flex min-w-0 flex-col">
          <button type="button" onClick={() => setOpen(f)} className="sast-wrap self-start text-left font-mono text-xs font-medium text-fg hover:underline">
            {f.rule}
          </button>
          <span className="sast-clamp text-xs text-fg-muted" title={f.message}>
            {f.message}
          </span>
        </span>
      ),
    },
    {
      id: "where",
      header: t("findingsTable.where"),
      width: "30%",
      cell: (f) => (
        <span className="sast-wrap font-mono text-xs">
          {f.path}
          {f.line ? `:${f.line}` : ""}
        </span>
      ),
    },
    ...(repoId
      ? []
      : [
          {
            id: "repo",
            header: t("findingsTable.repository"),
            cell: (f: Finding) => <span className="text-xs">{f.repository.name}</span>,
          } satisfies Column<Finding>,
        ]),
    {
      id: "seen",
      header: t("findingsTable.firstSeen"),
      sortValue: (f) => f.firstSeen,
      cell: (f) => <span className="text-xs whitespace-nowrap">{ago(f.firstSeen)}</span>,
    },
  ];

  return (
    <>
      <Tabs<Tab>
        label={t("findingsTable.findingViews")}
        value={tab}
        onChange={setTab}
        items={[
          { value: "open", label: t("findingsTable.open") },
          { value: "suppressed", label: t("findingsTable.triaged") },
          { value: "resolved", label: t("findingsTable.fixed") },
        ]}
      />
      <FilterBar onClear={() => (setSev([]), setQ(""))}>
        <FacetFilter
          label={t("findingsTable.severity")}
          selected={sev}
          onChange={setSev}
          options={SEVERITIES.map((s) => ({ value: s, label: s.charAt(0).toUpperCase() + s.slice(1), count: tab === "open" ? summary?.open[s] : undefined }))}
        />
        <SearchInput label={t("findingsTable.searchRulePathOrMessage")} className="w-64" value={q} onChange={(e) => setQ(e.target.value)} />
      </FilterBar>
      <div className={open ? "grid gap-2.5 xl:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]" : "grid gap-2.5"}>
        <Panel
          title={tab === "open" ? t("findingsTable.open") : tab === "suppressed" ? t("findingsTable.falsePositivesAndAcceptedRisk") : t("findingsTable.fixed")}
          description={t("findingsTable.findingsOfTheDefaultBranch")}
          flush
          footer={
            more ? (
              <Button size="sm" onClick={loadMore}>
                {t("findingsTable.loadMore")}
              </Button>
            ) : undefined
          }
        >
          <DataTable
            label={t("findingsTable.findings")}
            columns={columns}
            rows={rows ?? []}
            loading={!rows}
            getRowId={(f) => `${f.repository.id}/${f.fingerprint}`}
            onRowClick={(f) => setOpen(f)}
            activeRowId={open ? `${open.repository.id}/${open.fingerprint}` : undefined}
            minWidth={860}
            pageSize={50}
            empty={
              <EmptyState
                title={
                  tab === "open"
                    ? t("findingsTable.noOpenFindings")
                    : tab === "suppressed"
                      ? t("findingsTable.nothingTriaged")
                      : t("findingsTable.nothingFixedYet")
                }
              >
                {tab === "open" && summary && !Object.values(summary.open).some(Boolean) ? (
                  <>
                    {t("findingsTable.sendAScanFromCi")} <a href="/setup">{t("findingsTable.setup")}</a>.
                  </>
                ) : (
                  t("findingsTable.nothingMatchesTheseFilters")
                )}
              </EmptyState>
            }
          />
        </Panel>
        {open && (
          <FindingPanel
            finding={open}
            call={call}
            onClose={() => setOpen(null)}
            onChanged={() => {
              setOpen(null);
              load();
              reload();
            }}
          />
        )}
      </div>
    </>
  );
}

function FindingsPage({ call, summary, reload }: { call: Call; summary?: Summary; reload: () => void }) {
  const ago = useAgo();
  const t = useT();
  const s = summary;
  return (
    <>
      <PageHeader
        title={t("findingsPage.findings")}
        description={s ? t("findingsPage.lastScan", { plural: t("plurals.repository", { count: s.repositories }), ago: ago(s.lastScanAt) }) : undefined}
      />
      {s && (
        <KpiGrid minWidth={150}>
          <KpiCard label={t("findingsPage.critical")} value={s.open.critical} footer={<SeverityBadge severity="critical" />} />
          <KpiCard label={t("findingsPage.high")} value={s.open.high} footer={<SeverityBadge severity="high" />} />
          <KpiCard label={t("findingsPage.medium")} value={s.open.medium} footer={<SeverityBadge severity="medium" />} />
          <KpiCard label={t("findingsPage.low")} value={s.open.low} footer={<SeverityBadge severity="low" />} />
          <KpiCard label={t("findingsPage.failedChecks7Days")} value={s.failingChecks} tone={s.failingChecks ? "warning" : "success"} />
          <KpiCard label={t("findingsPage.triaged")} value={s.suppressed} tone="info" />
        </KpiGrid>
      )}
      <FindingsTable call={call} summary={s} reload={reload} />
    </>
  );
}

function ScanStatus({ s }: { s: Pick<Scan, "passed" | "kind"> }) {
  const t = useT();
  return s.passed ? <StatusBadge tone="success">{t("scanStatus.passed")}</StatusBadge> : <StatusBadge tone="danger">{t("scanStatus.failed")}</StatusBadge>;
}

function RepositoriesPage({ call }: { call: Call }) {
  const ago = useAgo();
  const t = useT();
  const [rows, setRows] = useState<Repository[]>();
  useEffect(
    () =>
      void call<{ repositories: Repository[] }>("/api/v1/repositories?limit=500").then(
        (r) => setRows(r.repositories),
        () => setRows([]),
      ),
    [call],
  );
  const columns: Column<Repository>[] = [
    {
      id: "name",
      header: t("repositoriesPage.repository"),
      width: "28%",
      sortValue: (r) => r.name,
      cell: (r) => (
        <a href={`/repositories/${r.id}`} className="font-medium">
          {r.name}
        </a>
      ),
    },
    { id: "branch", header: t("repositoriesPage.defaultBranch"), mono: true, cell: (r) => r.defaultBranch },
    {
      id: "source",
      header: t("repositoriesPage.source"),
      cell: (r) =>
        r.source === "github" ? (
          <Badge tone={r.scanEnabled ? "info" : "neutral"}>{r.scanEnabled ? t("repositoriesPage.github") : t("repositoriesPage.githubOff")}</Badge>
        ) : (
          <Badge>{t("repositoriesPage.ci")}</Badge>
        ),
    },
    { id: "open", header: t("repositoriesPage.open"), cell: (r) => <SevCounts counts={r.open} /> },
    {
      id: "last",
      header: t("repositoriesPage.lastScan"),
      cell: (r) =>
        r.lastScan ? (
          <span className="text-xs">
            {ago(r.lastScan.at)}, {r.lastScan.kind === "baseline" ? t("repositoriesPage.defaultBranch2") : r.lastScan.branch}
          </span>
        ) : (
          "–"
        ),
    },
    {
      id: "check",
      header: t("repositoriesPage.check"),
      cell: (r) => (r.lastScan ? <ScanStatus s={{ passed: r.lastScan.passed, kind: r.lastScan.kind }} /> : "–"),
    },
  ];
  return (
    <>
      <PageHeader title={t("repositoriesPage.repositories")} description={t("repositoriesPage.aRepositoryAppearsWithIts")} />
      <Panel flush>
        <DataTable
          label={t("repositoriesPage.repositories")}
          columns={columns}
          rows={rows ?? []}
          loading={!rows}
          getRowId={(r) => r.id}
          minWidth={760}
          empty={
            <EmptyState title={t("repositoriesPage.noRepositoriesYet")}>
              {t("repositoriesPage.connectGithubOrCi")} <a href="/github">{t("repositoriesPage.github")}</a>, <a href="/setup">{t("repositoriesPage.setup")}</a>
              .
            </EmptyState>
          }
        />
      </Panel>
    </>
  );
}

function RepositoryPage({ call, id, reload }: { call: Call; id: string; reload: () => void }) {
  const ago = useAgo();
  const t = useT();
  const { can } = useAuth();
  const [repo, setRepo] = useState<Repository | null>();
  const [scans, setScans] = useState<Scan[]>();
  const [failOn, setFailOn] = useState<FailOn>("high");
  const [branch, setBranch] = useState("");
  const [error, setError] = useState<string>();
  const [removing, setRemoving] = useState(false);

  const load = useCallback(() => {
    call<Repository>(`/api/v1/repositories/${id}`).then(
      (r) => (setRepo(r), setFailOn(r.failOn), setBranch(r.defaultBranch)),
      () => setRepo(null),
    );
    call<{ scans: Scan[] }>(`/api/v1/repositories/${id}/scans?limit=50`).then(
      (r) => setScans(r.scans),
      () => setScans([]),
    );
  }, [call, id]);
  useEffect(load, [load]);

  const save = async () => {
    try {
      await call(`/api/v1/repositories/${id}`, { method: "PATCH", body: JSON.stringify({ failOn, defaultBranch: branch }) });
      setError(undefined);
      load();
      reload();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  const [queued, setQueued] = useState(false);
  const setScanning = (on: boolean) =>
    call(`/api/v1/repositories/${id}`, { method: "PATCH", body: JSON.stringify({ scanEnabled: on }) }).then(load, (err: Error) => setError(err.message));
  const scanNow = () =>
    call(`/api/v1/repositories/${id}/scan`, { method: "POST" }).then(
      () => setQueued(true),
      (err: Error) => setError(err.message),
    );
  const remove = () =>
    call(`/api/v1/repositories/${id}`, { method: "DELETE" }).then(
      () => {
        reload();
        navigate("/repositories");
      },
      (err: Error) => setError(err.message),
    );

  if (repo === null)
    return (
      <EmptyState title={t("repositoryPage.repositoryNotFound")}>
        {t("repositoryPage.itMayHaveBeenDeleted")} <a href="/repositories">{t("repositoryPage.backToRepositories")}</a>.
      </EmptyState>
    );

  // The default branch's scans, oldest first; a change scan reports a pull request, not the repository.
  const baselines = (scans ?? []).filter((s) => s.kind === "baseline").reverse();
  const columns: Column<Scan>[] = [
    {
      id: "when",
      header: t("repositoryPage.scan"),
      sortValue: (s) => s.createdAt,
      cell: (s) => (
        <a href={`/scans/${s.id}`} className="text-xs whitespace-nowrap">
          {ago(s.createdAt)}
        </a>
      ),
    },
    {
      id: "branch",
      header: t("repositoryPage.branch"),
      cell: (s) => <span className="sast-wrap font-mono text-xs">{s.pullRequest ? `#${s.pullRequest} ${s.branch}` : s.branch}</span>,
    },
    {
      id: "kind",
      header: t("repositoryPage.kind"),
      cell: (s) => (s.kind === "baseline" ? <Badge>{t("repositoryPage.baseline")}</Badge> : <Badge tone="info">{t("repositoryPage.change")}</Badge>),
    },
    { id: "total", header: t("repositoryPage.reported"), align: "right", cell: (s) => s.total },
    { id: "new", header: t("repositoryPage.new"), align: "right", cell: (s) => s.new },
    { id: "check", header: t("repositoryPage.check"), cell: (s) => <ScanStatus s={s} /> },
  ];
  return (
    <>
      <PageHeader
        title={repo?.name ?? t("repositoryPage.repository")}
        description={
          repo
            ? t("repositoryPage.defaultBranch", {
                defaultBranch: repo.defaultBranch,
                plural: t("plurals.openFinding", { count: Object.values(repo.open).reduce((a, b) => a + b, 0) }),
              })
            : undefined
        }
      />
      {repo?.source === "github" && (
        <Panel title={t("repositoryPage.scanning")} description={t("repositoryPage.scanningDescription")}>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <Switch
              checked={repo.scanEnabled}
              onCheckedChange={(on) => void setScanning(on)}
              disabled={!can("editor")}
              label={t("repositoryPage.scanThisRepository")}
              description={
                repo.scannedCommit
                  ? repo.scannedCommit === repo.headCommit
                    ? t("repositoryPage.headScanned", { commit: repo.scannedCommit.slice(0, 8) })
                    : t("repositoryPage.headNotScanned", { commit: (repo.headCommit ?? "").slice(0, 8) })
                  : t("repositoryPage.notScannedYet")
              }
            />
            {can("editor") && (
              <Button icon={<Play />} onClick={() => void scanNow()} disabled={!repo.scanEnabled || queued}>
                {queued ? t("repositoryPage.queued") : t("repositoryPage.scanNow")}
              </Button>
            )}
          </div>
        </Panel>
      )}
      {can("admin") && repo && (
        <Panel title={t("repositoryPage.policy")} description={t("repositoryPage.whatACheckTreatsAs")}>
          <div className="grid gap-2 sm:grid-cols-2">
            <SelectField
              label={t("repositoryPage.failTheCheckFor")}
              value={failOn}
              onChange={(e) => setFailOn(e.target.value as FailOn)}
              options={FAIL_ON(t)}
            />
            <TextField
              label={t("repositoryPage.defaultBranch2")}
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
              hint={t("repositoryPage.itsScansAreTheBaseline")}
              error={error}
            />
          </div>
          <div className="mt-3 flex gap-2">
            <Button variant="primary" onClick={() => void save()} disabled={failOn === repo.failOn && branch === repo.defaultBranch}>
              {t("repositoryPage.savePolicy")}
            </Button>
            <Button icon={<Trash2 />} onClick={() => setRemoving(true)}>
              {t("repositoryPage.deleteRepository")}
            </Button>
          </div>
          <Dialog
            open={removing}
            onOpenChange={setRemoving}
            title={t("repositoryPage.delete", { name: repo.name })}
            description={t("repositoryPage.itsScansFindingsAndDecisions")}
            footer={
              <>
                <Button type="button" onClick={() => setRemoving(false)}>
                  {t("repositoryPage.cancel")}
                </Button>
                <Button type="button" variant="primary" onClick={() => void remove()}>
                  {t("repositoryPage.delete2")}
                </Button>
              </>
            }
          >
            <></>
          </Dialog>
        </Panel>
      )}
      <FindingsTable call={call} repoId={id} summary={repo ?? undefined} reload={() => (load(), reload())} />
      {baselines.length > 1 && (
        <Panel title={t("repositoryPage.findingsOverTime")} description={t("repositoryPage.whatEachScanOfThe")}>
          <TimeSeriesChart
            label={t("repositoryPage.findingsInEachScanOf", { name: repo?.name ?? t("repositoryPage.repository") })}
            series={[
              { id: "total", name: t("repositoryPage.reported"), data: baselines.map((s) => s.total) },
              { id: "new", name: t("repositoryPage.new"), data: baselines.map((s) => s.new) },
            ]}
            labels={baselines.map((s) => new Date(s.createdAt).toLocaleDateString())}
            area={false}
            height={160}
          />
        </Panel>
      )}
      <Panel title={t("repositoryPage.scans")} flush>
        <DataTable
          label={t("repositoryPage.scans")}
          columns={columns}
          rows={scans ?? []}
          loading={!scans}
          getRowId={(s) => s.id}
          minWidth={640}
          empty={<EmptyState title={t("repositoryPage.noScans")}>{t("repositoryPage.nothingHasBeenSentFor")}</EmptyState>}
        />
      </Panel>
    </>
  );
}

function ScanPage({ call, id, reload }: { call: Call; id: string; reload: () => void }) {
  const ago = useAgo();
  const t = useT();
  const [scan, setScan] = useState<ScanDetail | null>();
  const [open, setOpen] = useState<ScanDetail["findings"][number] | null>(null);
  const load = useCallback(() => void call<ScanDetail>(`/api/v1/scans/${id}`).then(setScan, () => setScan(null)), [call, id]);
  useEffect(load, [load]);
  if (scan === null) return <EmptyState title={t("scanPage.scanNotFound")}>{t("scanPage.itMayBeOlderThan")}</EmptyState>;

  const columns: Column<ScanDetail["findings"][number]>[] = [
    { id: "sev", header: t("scanPage.severity"), width: "104px", cell: (f) => <SeverityBadge severity={f.severity} /> },
    { id: "rule", header: t("scanPage.rule"), cell: (f) => <span className="sast-wrap font-mono text-xs">{f.rule}</span> },
    {
      id: "where",
      header: t("scanPage.where"),
      cell: (f) => (
        <span className="sast-wrap font-mono text-xs">
          {f.path}
          {f.line ? `:${f.line}` : ""}
        </span>
      ),
    },
    {
      id: "state",
      header: t("scanPage.state"),
      cell: (f) => (f.suppressed ? <Badge>{t("scanPage.triaged")}</Badge> : <Badge tone="danger">{t("scanPage.new")}</Badge>),
    },
  ];
  return (
    <>
      <PageHeader
        title={
          scan
            ? scan.pullRequest
              ? t("scanPage.pullRequest", { pullRequest: scan.pullRequest })
              : t("scanPage.scanOf", { branch: scan.branch })
            : t("scanPage.scan")
        }
        description={
          scan
            ? `${scan.repository.name} · ${scan.branch}${scan.commit ? ` · ${scan.commit.slice(0, 8)}` : ""} · ${scan.tool} · ${ago(scan.createdAt)}`
            : undefined
        }
        actions={scan && <ScanStatus s={scan} />}
      />
      {scan && (
        <KpiGrid minWidth={150}>
          <KpiCard label={t("scanPage.reported")} value={scan.total} />
          <KpiCard label={t("scanPage.new")} value={scan.new} tone={scan.new ? "warning" : "success"} />
          <KpiCard
            label={t("scanPage.blocking")}
            value={scan.blocking}
            tone={scan.blocking ? "danger" : "success"}
            footer={<span className="text-xs text-fg-muted">{FAIL_ON(t).find((f) => f.value === scan.failOn)?.label}</span>}
          />
          <KpiCard label={t("scanPage.triaged")} value={scan.suppressed} tone="info" />
        </KpiGrid>
      )}
      <div className={open ? "grid gap-2.5 xl:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]" : "grid gap-2.5"}>
        <Panel
          title={t("scanPage.whatThisScanAdded")}
          description={scan?.kind === "baseline" ? t("scanPage.aScanOfTheDefault") : t("scanPage.findingsTheDefaultBranchDoes")}
          flush
        >
          <DataTable
            label={t("scanPage.newFindings")}
            columns={columns}
            rows={scan?.findings ?? []}
            loading={scan === undefined}
            getRowId={(f) => f.fingerprint}
            onRowClick={(f) => setOpen(f)}
            activeRowId={open?.fingerprint}
            minWidth={640}
            empty={<EmptyState title={t("scanPage.nothingNew")}>{t("scanPage.thisScanAddedNoFindings")}</EmptyState>}
          />
        </Panel>
        {open && scan && (
          <FindingPanel
            finding={{ ...open, repository: scan.repository, triage: null }}
            call={call}
            onClose={() => setOpen(null)}
            onChanged={() => {
              setOpen(null);
              load();
              reload();
            }}
          />
        )}
      </div>
    </>
  );
}

// ---------------------------------------------------------------- Rules

const RULE_TEMPLATE = `rules:
  - id: acme.no-console-log
    message: Remove console.log before it ships.
    severity: WARNING
    languages: [javascript, typescript]
    pattern: console.log(...)
`;

/** Rules the install writes for sast-agent's scans, and rules switched off (ADR 0036). */
function RulesPage({ call }: { call: Call }) {
  const t = useT();
  const [rules, setRules] = useState<RuleList>();
  const [editing, setEditing] = useState<{ id?: string; name: string; yaml: string }>();
  const [ruleId, setRuleId] = useState("");
  const [error, setError] = useState<string>();
  const load = useCallback(
    () =>
      void call<RuleList>("/api/v1/rules").then(
        (r) => setRules(r),
        () => setRules({ own: [], disabled: [] }),
      ),
    [call],
  );
  useEffect(load, [load]);
  const save = async (e: FormEvent) => {
    e.preventDefault();
    if (!editing) return;
    try {
      if (editing.id) await call(`/api/v1/rules/${editing.id}`, { method: "PUT", body: JSON.stringify({ yaml: editing.yaml }) });
      else await call("/api/v1/rules", { method: "POST", body: JSON.stringify({ name: editing.name.trim(), yaml: editing.yaml }) });
      setEditing(undefined);
      setError(undefined);
      load();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  const remove = (r: OwnRule) => call(`/api/v1/rules/${r.id}`, { method: "DELETE" }).then(load, () => {});
  const setDisabled = async (disabled: string[]) => {
    try {
      await call("/api/v1/rules/disabled", { method: "PUT", body: JSON.stringify({ disabled }) });
      setRuleId("");
      setError(undefined);
      load();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  const columns: Column<OwnRule>[] = [
    {
      id: "name",
      header: t("rulesPage.name"),
      cell: (r) => (
        <button
          type="button"
          className="font-mono text-xs font-medium text-fg hover:underline"
          onClick={() => setEditing({ id: r.id, name: r.name, yaml: r.yaml })}
        >
          {r.name}
        </button>
      ),
    },
    { id: "ids", header: t("rulesPage.rules"), cell: (r) => <span className="sast-wrap font-mono text-xs">{ruleIds(r.yaml).join(", ") || "–"}</span> },
    {
      id: "remove",
      header: <span className="sr-only">{t("rulesPage.actions")}</span>,
      width: "56px",
      cell: (r) => (
        <IconButton label={t("rulesPage.remove", { name: r.name })} size="sm" onClick={() => void remove(r)}>
          <Trash2 />
        </IconButton>
      ),
    },
  ];
  return (
    <>
      <PageHeader
        title={t("rulesPage.title")}
        description={t("rulesPage.description")}
        actions={
          <Button variant="primary" icon={<Plus />} onClick={() => setEditing({ name: "", yaml: RULE_TEMPLATE })}>
            {t("rulesPage.add")}
          </Button>
        }
      />
      <Panel title={t("rulesPage.own")} description={t("rulesPage.ownDescription")} flush>
        <DataTable
          label={t("rulesPage.own")}
          columns={columns}
          rows={rules?.own ?? []}
          loading={!rules}
          getRowId={(r) => r.id}
          minWidth={520}
          empty={<EmptyState title={t("rulesPage.noOwn")}>{t("rulesPage.noOwnDetail")}</EmptyState>}
        />
      </Panel>
      <Panel title={t("rulesPage.disabled")} description={t("rulesPage.disabledDescription")}>
        <div className="flex flex-col gap-2">
          {rules && rules.disabled.length === 0 && <p className="m-0 text-sm text-fg-muted">{t("rulesPage.noneDisabled")}</p>}
          {rules?.disabled.map((id) => (
            <div key={id} className="flex items-center gap-2">
              <Badge mono>{id}</Badge>
              <IconButton label={t("rulesPage.enable", { id })} size="sm" onClick={() => void setDisabled(rules.disabled.filter((x) => x !== id))}>
                <X />
              </IconButton>
            </div>
          ))}
          <form
            className="flex flex-wrap items-end gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              void setDisabled([...(rules?.disabled ?? []), ruleId.trim()]);
            }}
          >
            <TextField
              label={t("rulesPage.ruleId")}
              value={ruleId}
              onChange={(e) => setRuleId(e.target.value)}
              placeholder="openasy.javascript.eval"
              mono
              error={editing ? undefined : error}
            />
            <Button type="submit" icon={<CircleSlash />} disabled={!ruleId.trim()}>
              {t("rulesPage.switchOff")}
            </Button>
          </form>
        </div>
      </Panel>
      <Dialog
        open={!!editing}
        onOpenChange={(open) => !open && (setEditing(undefined), setError(undefined))}
        title={editing?.id ? editing.name : t("rulesPage.add")}
        description={t("rulesPage.editDescription")}
        onSubmit={save}
        footer={
          <>
            <Button type="button" onClick={() => (setEditing(undefined), setError(undefined))}>
              {t("rulesPage.cancel")}
            </Button>
            <Button type="submit" variant="primary">
              {t("rulesPage.save")}
            </Button>
          </>
        }
      >
        {!editing?.id && (
          <TextField
            label={t("rulesPage.name")}
            value={editing?.name ?? ""}
            onChange={(e) => setEditing((x) => x && { ...x, name: e.target.value })}
            hint={t("rulesPage.nameHint")}
            mono
          />
        )}
        <label className="flex flex-col gap-1 text-sm">
          <span>{t("rulesPage.yaml")}</span>
          <textarea
            className="sast-editor"
            rows={16}
            spellCheck={false}
            value={editing?.yaml ?? ""}
            onChange={(e) => setEditing((x) => x && { ...x, yaml: e.target.value })}
          />
        </label>
        {error && <span className="text-xs text-danger">{error}</span>}
      </Dialog>
    </>
  );
}

/** The ids a rule file declares, for the list; Opengrep reads the file itself. */
const ruleIds = (yaml: string) => [...yaml.matchAll(/^\s*-\s*id:\s*([^\s#]+)/gm)].map((m) => m[1]!);

// ---------------------------------------------------------------- GitHub

const JOB_TONE = { queued: "neutral", running: "info", done: "success", failed: "danger" } as const;
const AGENT_TONE = { "waiting-to-enrol": "warning", online: "success", offline: "danger" } as const;

/** GitHub accounts sast follows, the agents that scan them, extra rule sources and the scan queue (ADR 0036). */
function GithubPage({ call, reload }: { call: Call; reload: () => void }) {
  const ago = useAgo();
  const t = useT();
  const { can } = useAuth();
  const [connections, setConnections] = useState<Connection[]>();
  const [agents, setAgents] = useState<Agent[]>();
  const [jobs, setJobs] = useState<Job[]>();
  const [sources, setSources] = useState<string[]>([]);
  const [newSource, setNewSource] = useState("");
  const [sourceError, setSourceError] = useState<string>();
  const [adding, setAdding] = useState(false);
  const [account, setAccount] = useState("");
  const [token, setToken] = useState("");
  const [connectError, setConnectError] = useState<string>();
  const [agentName, setAgentName] = useState("");
  const [agentError, setAgentError] = useState<string>();
  const [enrolment, setEnrolment] = useState<{ name: string; token: string }>();
  const [syncing, setSyncing] = useState(false);

  const load = useCallback(() => {
    call<{ connections: Connection[] }>("/api/v1/connections").then(
      (r) => setConnections(r.connections),
      () => setConnections([]),
    );
    call<{ agents: Agent[] }>("/api/v1/agents").then(
      (r) => setAgents(r.agents),
      () => setAgents([]),
    );
    call<{ jobs: Job[] }>("/api/v1/jobs").then(
      (r) => setJobs(r.jobs),
      () => setJobs([]),
    );
    call<{ ruleSources: string[] }>("/api/v1/rule-sources").then(
      (r) => setSources(r.ruleSources),
      () => {},
    );
  }, [call]);
  useEffect(() => {
    load();
    const timer = setInterval(load, 10_000);
    return () => clearInterval(timer);
  }, [load]);

  const closeConnect = () => (setAdding(false), setAccount(""), setToken(""), setConnectError(undefined));
  const connect = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await call("/api/v1/connections", { method: "POST", body: JSON.stringify({ kind: "github", account, token }) });
      closeConnect();
      load();
      reload();
    } catch (err) {
      setConnectError((err as Error).message);
    }
  };
  const disconnect = (c: Connection) => call(`/api/v1/connections/${c.id}`, { method: "DELETE" }).then(load, () => {});
  const sync = () => {
    setSyncing(true);
    call("/api/v1/connections/sync", { method: "POST" })
      .then(
        () => (load(), reload()),
        () => {},
      )
      .finally(() => setSyncing(false));
  };
  const addAgent = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const r = await call<{ agent: Agent; enrollToken: string }>("/api/v1/agents", { method: "POST", body: JSON.stringify({ name: agentName.trim() }) });
      setEnrolment({ name: r.agent.name, token: r.enrollToken });
      setAgentName("");
      setAgentError(undefined);
      load();
    } catch (err) {
      setAgentError((err as Error).message);
    }
  };
  const removeAgent = (a: Agent) => call(`/api/v1/agents/${a.id}`, { method: "DELETE" }).then(load, () => {});
  const saveSources = async (next: string[]) => {
    try {
      const r = await call<{ ruleSources: string[] }>("/api/v1/rule-sources", { method: "PUT", body: JSON.stringify({ ruleSources: next }) });
      setSources(r.ruleSources);
      setNewSource("");
      setSourceError(undefined);
    } catch (err) {
      setSourceError((err as Error).message);
    }
  };

  const connectionColumns: Column<Connection>[] = [
    { id: "account", header: t("githubPage.account"), cell: (c) => <span className="font-medium">{c.account}</span> },
    { id: "repos", header: t("githubPage.repositories"), align: "right", cell: (c) => c.repositories },
    {
      id: "synced",
      header: t("githubPage.lastLook"),
      cell: (c) =>
        c.error ? <StatusBadge tone="danger">{c.error}</StatusBadge> : <span className="text-xs">{c.syncedAt ? ago(c.syncedAt) : t("githubPage.notYet")}</span>,
    },
    ...(can("owner")
      ? [
          {
            id: "remove",
            header: <span className="sr-only">{t("githubPage.actions")}</span>,
            width: "56px",
            cell: (c: Connection) => (
              <IconButton label={t("githubPage.disconnect", { account: c.account })} size="sm" onClick={() => void disconnect(c)}>
                <Trash2 />
              </IconButton>
            ),
          } satisfies Column<Connection>,
        ]
      : []),
  ];
  const agentColumns: Column<Agent>[] = [
    { id: "name", header: t("githubPage.name"), mono: true, cell: (a) => a.name },
    { id: "status", header: t("githubPage.status"), cell: (a) => <StatusBadge tone={AGENT_TONE[a.status]}>{t(`githubPage.agent.${a.status}`)}</StatusBadge> },
    { id: "version", header: t("githubPage.version"), mono: true, cell: (a) => a.version ?? "–" },
    { id: "seen", header: t("githubPage.lastSeen"), cell: (a) => <span className="text-xs">{a.lastSeen ? ago(a.lastSeen) : "–"}</span> },
    {
      id: "remove",
      header: <span className="sr-only">{t("githubPage.actions")}</span>,
      width: "56px",
      cell: (a) => (
        <IconButton label={t("githubPage.removeAgent", { name: a.name })} size="sm" onClick={() => void removeAgent(a)}>
          <Trash2 />
        </IconButton>
      ),
    },
  ];
  const jobColumns: Column<Job>[] = [
    { id: "repo", header: t("githubPage.repository"), cell: (j) => <span className="text-xs">{j.repository}</span> },
    {
      id: "commit",
      header: t("githubPage.commit"),
      cell: (j) => (
        <span className="font-mono text-xs">
          {j.pullRequest ? `#${j.pullRequest} ` : ""}
          {j.branch} {j.commit.slice(0, 8)}
        </span>
      ),
    },
    {
      id: "status",
      header: t("githubPage.status"),
      cell: (j) =>
        j.status === "done" && j.scanId ? (
          <a href={`/scans/${j.scanId}`}>
            <StatusBadge tone="success">{t("githubPage.job.done")}</StatusBadge>
          </a>
        ) : (
          <span className="flex min-w-0 flex-col gap-0.5">
            <span>
              <StatusBadge tone={JOB_TONE[j.status]}>{t(`githubPage.job.${j.status}`)}</StatusBadge>
            </span>
            {j.error && <span className="sast-clamp text-xs text-fg-muted">{j.error}</span>}
            {j.checkError && <span className="sast-clamp text-xs text-fg-muted">{j.checkError}</span>}
          </span>
        ),
    },
    {
      id: "when",
      header: t("githubPage.queued"),
      sortValue: (j) => j.createdAt,
      cell: (j) => <span className="text-xs whitespace-nowrap">{ago(j.createdAt)}</span>,
    },
  ];

  const origin = window.location.origin;
  const noAgent = agents !== undefined && !agents.some((a) => a.status === "online");
  return (
    <>
      <PageHeader
        title={t("githubPage.title")}
        description={t("githubPage.description")}
        actions={
          <>
            <Button icon={<RefreshCw />} onClick={sync} disabled={syncing || !connections?.length}>
              {t("githubPage.lookNow")}
            </Button>
            {can("owner") && (
              <Button variant="primary" icon={<Plus />} onClick={() => setAdding(true)}>
                {t("githubPage.connectAccount")}
              </Button>
            )}
          </>
        }
      />
      {noAgent && !!connections?.length && (
        <Callout tone="warning" title={t("githubPage.noAgentOnline")}>
          {t("githubPage.noAgentOnlineDetail")}
        </Callout>
      )}
      <Panel title={t("githubPage.accounts")} description={t("githubPage.accountsDescription")} flush>
        <DataTable
          label={t("githubPage.accounts")}
          columns={connectionColumns}
          rows={connections ?? []}
          loading={!connections}
          getRowId={(c) => c.id}
          minWidth={560}
          empty={<EmptyState title={t("githubPage.noAccounts")}>{t("githubPage.noAccountsDetail")}</EmptyState>}
        />
      </Panel>
      <Panel title={t("githubPage.agents")} description={t("githubPage.agentsDescription")} flush>
        <DataTable
          label={t("githubPage.agents")}
          columns={agentColumns}
          rows={agents ?? []}
          loading={!agents}
          getRowId={(a) => a.id}
          minWidth={560}
          empty={<EmptyState title={t("githubPage.noAgents")}>{t("githubPage.noAgentsDetail")}</EmptyState>}
        />
        <form className="flex flex-wrap items-end gap-2 border-t border-line p-3" onSubmit={(e) => void addAgent(e)}>
          <TextField
            label={t("githubPage.agentName")}
            value={agentName}
            onChange={(e) => setAgentName(e.target.value)}
            hint={t("githubPage.agentNameHint")}
            error={agentError}
            mono
          />
          <Button type="submit" icon={<Plus />} disabled={!agentName.trim()}>
            {t("githubPage.addAgent")}
          </Button>
        </form>
      </Panel>
      <Panel title={t("githubPage.ruleSources")} description={t("githubPage.ruleSourcesDescription")}>
        <div className="flex flex-col gap-2">
          {sources.length === 0 && <p className="m-0 text-sm text-fg-muted">{t("githubPage.onlyShippedRules")}</p>}
          {sources.map((s) => (
            <div key={s} className="flex items-center gap-2">
              <Badge mono>{s}</Badge>
              <IconButton label={t("githubPage.removeSource", { url: s })} size="sm" onClick={() => void saveSources(sources.filter((x) => x !== s))}>
                <X />
              </IconButton>
            </div>
          ))}
          <form
            className="flex flex-wrap items-end gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              void saveSources([...sources, newSource.trim()]);
            }}
          >
            <TextField
              label={t("githubPage.ruleSourceUrl")}
              value={newSource}
              onChange={(e) => setNewSource(e.target.value)}
              placeholder="https://github.com/acme/opengrep-rules"
              hint={t("githubPage.ruleSourceHint")}
              error={sourceError}
              className="w-96"
              mono
            />
            <Button type="submit" icon={<Plus />} disabled={!newSource.trim()}>
              {t("githubPage.addSource")}
            </Button>
          </form>
        </div>
      </Panel>
      <Panel title={t("githubPage.scanJobs")} description={t("githubPage.scanJobsDescription")} flush>
        <DataTable
          label={t("githubPage.scanJobs")}
          columns={jobColumns}
          rows={jobs ?? []}
          loading={!jobs}
          getRowId={(j) => j.id}
          minWidth={640}
          pageSize={25}
          empty={<EmptyState title={t("githubPage.noJobs")}>{t("githubPage.noJobsDetail")}</EmptyState>}
        />
      </Panel>

      <Dialog
        open={adding}
        onOpenChange={(open) => !open && closeConnect()}
        title={t("githubPage.connectAccount")}
        description={t("githubPage.connectDescription")}
        onSubmit={connect}
        footer={
          <>
            <Button type="button" onClick={closeConnect}>
              {t("githubPage.cancel")}
            </Button>
            <Button type="submit" variant="primary" disabled={!account.trim() || token.trim().length < 20}>
              {t("githubPage.connect")}
            </Button>
          </>
        }
      >
        <TextField label={t("githubPage.account")} value={account} onChange={(e) => setAccount(e.target.value)} hint={t("githubPage.accountHint")} />
        <TextField
          label={t("githubPage.token")}
          type="password"
          autoComplete="off"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          hint={t("githubPage.tokenHint")}
          error={connectError}
          mono
        />
      </Dialog>
      <Dialog
        open={!!enrolment}
        onOpenChange={(open) => !open && setEnrolment(undefined)}
        title={t("githubPage.startAgent", { name: enrolment?.name ?? "" })}
        description={t("githubPage.startAgentDescription")}
        footer={
          <Button type="button" variant="primary" onClick={() => setEnrolment(undefined)}>
            {t("githubPage.done")}
          </Button>
        }
      >
        <Code>{`openssl rand -hex 32 > openasy-agent-kek
docker run -d --name sast-agent --restart unless-stopped --read-only --tmpfs /scan:size=2g \\
  --cap-drop ALL --security-opt no-new-privileges --memory 3g \\
  -v sast-agent-data:/data -v "$PWD/openasy-agent-kek:/run/secrets/openasy-agent-kek:ro" \\
  -e SAST_URL=${origin} -e SAST_ENROLL_TOKEN=${enrolment?.token ?? ""} \\
  ghcr.io/openasy/sast-agent:${__APP_VERSION__}`}</Code>
      </Dialog>
    </>
  );
}

// ---------------------------------------------------------------- Setup

function SetupPage() {
  const t = useT();
  const origin = window.location.origin;
  return (
    <>
      <PageHeader title={t("setupPage.setup")} description={t("setupPage.runAnyAnalyserThatWrites")} />
      <Panel title={t("setupPage.sendAScan")} description={t("setupPage.useSastIngestTokenSet")}>
        <Code>{`opengrep scan --sarif-output=results.sarif .
curl -sf -X POST -H "Authorization: Bearer $SAST_INGEST_TOKEN" -H 'content-type: application/json' \\
  --data-binary @results.sarif \\
  "${origin}/api/v1/scans?repository=acme/web&branch=$BRANCH&commit=$SHA&pullRequest=$PR" > scan.json
jq -e '.passed' scan.json   # fail the pipeline`}</Code>
      </Panel>
      <Panel title={t("setupPage.howAScanIsCompared")} description={t("setupPage.scansOfTheDefaultBranch")}>
        <ul className="sast-list flex flex-col gap-1 text-sm text-fg-muted">
          <li>{t("setupPage.aFindingKeepsItsIdentity")}</li>
          <li>{t("setupPage.aFalsePositiveOrAccepted")}</li>
          <li>{t("setupPage.underRepositoriesYouChooseWhich")}</li>
        </ul>
      </Panel>
    </>
  );
}

/** The first screen, until the first scan arrives. The summary is polled, so it gives way by itself. */
function WelcomePage() {
  const t = useT();
  return (
    <>
      <PageHeader
        title={t("welcomePage.getStarted")}
        description={t("welcomePage.findingsShowHereAsSoon")}
        actions={<StatusBadge tone="info">{t("welcomePage.waitingForTheFirstScan")}</StatusBadge>}
      />
      <SetupPage />
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const t = useT();
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title={t("settingsPage.adminsOnly")}>{t("settingsPage.askAnAdminOfThis")}</EmptyState>;
  const titles = {
    account: ["Account", "Your profile, password, two-step verification and where you are signed in."],
    members: [
      "Members",
      "Who can sign in to this sast, and with which role. Viewers see everything; editors also triage findings; admins also change policies, delete repositories, and manage members and tokens.",
    ],
    signin: [
      "Sign-in",
      "Identity providers people can sign in with, such as OpenAsy Identity, Keycloak or Microsoft Entra ID, and which of their groups give which role.",
    ],
    tokens: ["API tokens", "For scripts and CI. Each token has one role and an expiry; the secret is shown once."],
  } as const;
  return (
    <>
      <PageHeader
        title={titles[page][0]}
        description={titles[page][1]}
        actions={
          page === "account" && (
            <Button icon={<LogOut />} onClick={() => void signOut()}>
              {t("settingsPage.signOut")}
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product() {
  const msg = useT();
  const [theme, setTheme] = useThemePreference();
  const [, setLocale] = useLocalePreference();
  const { me, can } = useAuth();
  const account = useAccountMenu();
  const route = parseRoute(usePath());
  const [summary, setSummary] = useState<Summary>();
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);
  const call = useApi();
  const onSearch = useMemo(() => search(call, msg), [call, msg]);

  // The install's other products (OPENASY_PRODUCTS), for the switcher; ids this UI does not know are left out.
  useEffect(() => {
    void call<{ products: ProductLink[] }>("/api/v1/products").then(
      (r) => setProducts(r.products.filter((p): p is ProductLink & { id: ProductId } => p.id !== "sast" && (PRODUCT_IDS as readonly string[]).includes(p.id))),
      () => {},
    );
  }, [call]);

  const reload = useCallback(() => void call<Summary>("/api/v1/summary").then(setSummary, () => {}), [call]);
  useEffect(() => {
    reload();
    const t = setInterval(reload, 15_000);
    return () => clearInterval(t);
  }, [reload]);

  const nav = [
    { id: "findings", label: msg("product.findings"), icon: Bug },
    { id: "repositories", label: msg("product.repositories"), icon: FolderGit2, count: summary?.repositories },
  ];
  const footerNav = [
    ...(can("admin")
      ? [
          { id: "github", label: msg("product.github"), icon: GitBranch },
          { id: "rules", label: msg("product.rules"), icon: ScrollText },
          { id: "members", label: msg("product.members"), icon: Users },
          { id: "signin", label: msg("product.signIn"), icon: LogIn },
          { id: "tokens", label: msg("product.apiTokens"), icon: KeyRound },
        ]
      : []),
    { id: "account", label: msg("product.account"), icon: UserRound },
  ];
  const active = route.page === "repository" || route.page === "scan" ? "repositories" : route.page;
  const roleName = me.user.role.charAt(0).toUpperCase() + me.user.role.slice(1);

  return (
    <AppShell
      product="sast"
      onSearch={onSearch}
      about={colophon}
      nav={nav}
      activeNav={active}
      onNavigate={(id) => navigate(`/${id}`)}
      connectedProducts={products.map((p) => p.id)}
      onSwitchProduct={(id) => {
        const to = products.find((p) => p.id === id);
        if (to) window.location.assign(to.url);
      }}
      footerNav={account.settings(footerNav)}
      setup
      user={{ name: me.user.name, role: roleName, ...account.user }}
      theme={theme}
      onThemeChange={setTheme}
      onLanguageChange={(code) => setLocale(toLocale(code))}
    >
      {route.page === "findings" && summary && summary.repositories === 0 ? (
        <WelcomePage />
      ) : route.page === "findings" ? (
        <FindingsPage call={call} summary={summary} reload={reload} />
      ) : route.page === "repositories" ? (
        <RepositoriesPage call={call} />
      ) : route.page === "rules" ? (
        can("admin") ? (
          <RulesPage call={call} />
        ) : (
          <EmptyState title={msg("settingsPage.adminsOnly")}>{msg("settingsPage.askAnAdminOfThis")}</EmptyState>
        )
      ) : route.page === "github" ? (
        can("admin") ? (
          <GithubPage call={call} reload={reload} />
        ) : (
          <EmptyState title={msg("settingsPage.adminsOnly")}>{msg("settingsPage.askAnAdminOfThis")}</EmptyState>
        )
      ) : route.page === "repository" ? (
        <RepositoryPage key={route.id} call={call} id={route.id} reload={reload} />
      ) : route.page === "scan" ? (
        <ScanPage key={route.id} call={call} id={route.id} reload={reload} />
      ) : route.page === "account" || route.page === "members" || route.page === "signin" || route.page === "tokens" ? (
        <SettingsPage page={route.page} />
      ) : (
        <SetupPage />
      )}
    </AppShell>
  );
}

export function App() {
  const installBrand = useInstallBrand();
  const [theme] = useThemePreference();
  const [locale] = useLocalePreference();
  return (
    // The install's brand from config/brand.env (ADR 0053); OpenAsy's own look where it sets none.
    <BrandProvider theme={theme} locale={locale} brand={{ name: "OpenAsy", organization: undefined, ...installBrand }} className="min-h-screen">
      <AuthGate product="OpenAsy SAST">
        <Product />
      </AuthGate>
    </BrandProvider>
  );
}
