import {
  AppShell,
  Badge,
  BrandProvider,
  Button,
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
  Tabs,
  TextField,
  usePath,
  type Column,
  type ProductId,
  useThemePreference,
  useAgo,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAuth } from "@openasy/auth/react";
import { Bug, CircleSlash, FolderGit2, KeyRound, LogIn, LogOut, Settings2, Trash2, UserRound, Users, X } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  MfaSetupRequired,
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

const PAGES = ["repositories", "setup", "account", "members", "signin", "tokens"] as const;
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
              {t("repositoriesPage.sendAScanFromCi")} <a href="/setup">{t("repositoriesPage.setup")}</a>.
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
  const { me, can } = useAuth();
  const route = parseRoute(usePath());
  const [summary, setSummary] = useState<Summary>();
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);
  const call = useApi();

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
    { id: "setup", label: msg("product.setup"), icon: Settings2 },
    ...(can("admin")
      ? [
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
      nav={nav}
      activeNav={active}
      onNavigate={(id) => navigate(`/${id}`)}
      connectedProducts={products.map((p) => p.id)}
      onSwitchProduct={(id) => {
        const to = products.find((p) => p.id === id);
        if (to) window.location.assign(to.url);
      }}
      footerNav={footerNav}
      user={{ name: me.user.name, role: roleName }}
      theme={theme}
      onThemeChange={setTheme}
    >
      {route.page === "findings" && summary && summary.repositories === 0 ? (
        <WelcomePage />
      ) : route.page === "findings" ? (
        <FindingsPage call={call} summary={summary} reload={reload} />
      ) : route.page === "repositories" ? (
        <RepositoriesPage call={call} />
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
  const [theme] = useThemePreference();
  return (
    // No organization until branding is configurable (ADR 0004); the library's default is a placeholder.
    <BrandProvider theme={theme} brand={{ name: "OpenAsy", organization: undefined }} className="min-h-screen">
      <AuthGate product="OpenAsy SAST">
        <Product />
      </AuthGate>
    </BrandProvider>
  );
}
