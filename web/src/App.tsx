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
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAuth } from "@openasy/auth/react";
import { Bug, CircleSlash, FolderGit2, KeyRound, LogIn, LogOut, Settings2, Trash2, UserRound, Users, X } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { api, MfaSetupRequired, Unauthorized, type FailOn, type Finding, type ProductLink, type Repository, type Scan, type ScanDetail, type Severity, type Summary } from "./api.ts";

function ago(iso: string | null | undefined): string {
  if (!iso) return "never";
  const s = Math.round((Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86_400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86_400)} d ago`;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

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
const FAIL_ON: Array<{ value: FailOn; label: string }> = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High or worse" },
  { value: "medium", label: "Medium or worse" },
  { value: "low", label: "Any finding" },
  { value: "none", label: "Never fail" },
];

/** Compact severity counts; each badge carries the full name for screen readers. */
function SevCounts({ counts }: { counts: Record<Severity, number> }) {
  const shown = SEVERITIES.filter((s) => counts[s] > 0);
  if (!shown.length) return <span className="text-xs text-fg-muted">None</span>;
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
      await call(url, { method: "PUT", body: JSON.stringify({ state, reason, ...(state === "accepted" && { expiresAt: new Date(Date.now() + Number(days) * 86_400_000).toISOString() }) }) });
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
      aria-label={`${finding.rule} details`}
      title={<span className="sast-wrap font-mono text-sm">{finding.rule}</span>}
      description={`${finding.repository.name}`}
      actions={
        <IconButton label="Close details" size="sm" onClick={onClose}>
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
              <StatusBadge tone={t.active ? "success" : "neutral"}>{t.state === "false-positive" ? "False positive" : t.active ? "Accepted risk" : "Acceptance expired"}</StatusBadge>
            </span>
            <span>{t.reason}</span>
            <span className="text-fg-muted">
              {t.by ? `${t.by}, ` : ""}
              {ago(t.at)}
              {t.expiresAt ? `, until ${new Date(t.expiresAt).toLocaleDateString()}` : ""}
            </span>
          </div>
        )}
        {can("editor") && (
          <div className="flex gap-2 border-t border-line pt-3">
            <Button size="sm" icon={<CircleSlash />} onClick={() => setDeciding(true)}>
              {t ? "Change decision" : "Triage"}
            </Button>
            {t && (
              <Button size="sm" onClick={() => void reopen()}>
                Open again
              </Button>
            )}
          </div>
        )}
        <Dialog
          open={deciding}
          onOpenChange={(open) => !open && close()}
          title={`Triage ${finding.rule}`}
          description="The decision follows this finding to every branch, so a pull request that adds it does not fail. Say why, for the next review."
          onSubmit={decide}
          footer={
            <>
              <Button type="button" onClick={close}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" disabled={reason.trim().length < 3}>
                Save decision
              </Button>
            </>
          }
        >
          <SelectField
            label="Decision"
            value={state}
            onChange={(e) => setState(e.target.value as typeof state)}
            options={[
              { value: "false-positive", label: "False positive" },
              { value: "accepted", label: "Accepted risk" },
            ]}
          />
          <TextField label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} hint="Why, for the next review." error={error} />
          {state === "accepted" && (
            <SelectField
              label="For"
              value={days}
              onChange={(e) => setDays(e.target.value)}
              options={[
                { value: "30", label: "30 days" },
                { value: "90", label: "90 days" },
                { value: "180", label: "180 days" },
                { value: "365", label: "1 year" },
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
    query().then((r) => (setRows(r.findings), setMore(r.nextCursor)), () => setRows([]));
  }, [query]);
  useEffect(load, [load]);
  const loadMore = () => more && query(more).then((r) => (setRows((x) => [...(x ?? []), ...r.findings]), setMore(r.nextCursor)));

  const columns: Column<Finding>[] = [
    { id: "sev", header: "Severity", width: "104px", cell: (f) => <SeverityBadge severity={f.severity} /> },
    {
      id: "rule",
      header: "Rule",
      width: "32%",
      cell: (f) => (
        <span className="flex min-w-0 flex-col">
          <button type="button" className="sast-wrap self-start text-left font-mono text-xs font-medium text-fg hover:underline">
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
      header: "Where",
      width: "30%",
      cell: (f) => (
        <span className="sast-wrap font-mono text-xs">
          {f.path}
          {f.line ? `:${f.line}` : ""}
        </span>
      ),
    },
    ...(repoId ? [] : [{ id: "repo", header: "Repository", cell: (f: Finding) => <span className="text-xs">{f.repository.name}</span> } satisfies Column<Finding>]),
    { id: "seen", header: "First seen", sortValue: (f) => f.firstSeen, cell: (f) => <span className="text-xs whitespace-nowrap">{ago(f.firstSeen)}</span> },
  ];

  return (
    <>
      <Tabs<Tab>
        label="Finding views"
        value={tab}
        onChange={setTab}
        items={[
          { value: "open", label: "Open" },
          { value: "suppressed", label: "Triaged" },
          { value: "resolved", label: "Fixed" },
        ]}
      />
      <FilterBar onClear={() => (setSev([]), setQ(""))}>
        <FacetFilter label="Severity" selected={sev} onChange={setSev} options={SEVERITIES.map((s) => ({ value: s, label: s.charAt(0).toUpperCase() + s.slice(1), count: tab === "open" ? summary?.open[s] : undefined }))} />
        <SearchInput label="Search rule, path or message" className="w-64" value={q} onChange={(e) => setQ(e.target.value)} />
      </FilterBar>
      <div className={open ? "grid gap-2.5 xl:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]" : "grid gap-2.5"}>
        <Panel
          title={tab === "open" ? "Open" : tab === "suppressed" ? "False positives and accepted risk" : "Fixed"}
          description="Findings of the default branch, most severe first"
          flush
          footer={
            more ? (
              <Button size="sm" onClick={loadMore}>
                Load more
              </Button>
            ) : undefined
          }
        >
          <DataTable
            label="Findings"
            columns={columns}
            rows={rows ?? []}
            loading={!rows}
            getRowId={(f) => `${f.repository.id}/${f.fingerprint}`}
            onRowClick={(f) => setOpen(f)}
            activeRowId={open ? `${open.repository.id}/${open.fingerprint}` : undefined}
            minWidth={860}
            pageSize={50}
            empty={
              <EmptyState title={tab === "open" ? "No open findings" : tab === "suppressed" ? "Nothing triaged" : "Nothing fixed yet"}>
                {tab === "open" && summary && !Object.values(summary.open).some(Boolean) ? (
                  <>
                    Send a scan from CI to see findings. See <a href="/setup">Setup</a>.
                  </>
                ) : (
                  "Nothing matches these filters."
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
  const s = summary;
  return (
    <>
      <PageHeader title="Findings" description={s ? `${plural(s.repositories, "repository", "repositories")} · last scan ${ago(s.lastScanAt)}` : undefined} />
      {s && (
        <KpiGrid minWidth={150}>
          <KpiCard label="Critical" value={s.open.critical} footer={<SeverityBadge severity="critical" />} />
          <KpiCard label="High" value={s.open.high} footer={<SeverityBadge severity="high" />} />
          <KpiCard label="Medium" value={s.open.medium} footer={<SeverityBadge severity="medium" />} />
          <KpiCard label="Low" value={s.open.low} footer={<SeverityBadge severity="low" />} />
          <KpiCard label="Failed checks, 7 days" value={s.failingChecks} tone={s.failingChecks ? "warning" : "success"} />
          <KpiCard label="Triaged" value={s.suppressed} tone="info" />
        </KpiGrid>
      )}
      <FindingsTable call={call} summary={s} reload={reload} />
    </>
  );
}

function ScanStatus({ s }: { s: Pick<Scan, "passed" | "kind"> }) {
  return s.passed ? <StatusBadge tone="success">Passed</StatusBadge> : <StatusBadge tone="danger">Failed</StatusBadge>;
}

function RepositoriesPage({ call }: { call: Call }) {
  const [rows, setRows] = useState<Repository[]>();
  useEffect(() => void call<{ repositories: Repository[] }>("/api/v1/repositories?limit=500").then((r) => setRows(r.repositories), () => setRows([])), [call]);
  const columns: Column<Repository>[] = [
    {
      id: "name",
      header: "Repository",
      width: "28%",
      sortValue: (r) => r.name,
      cell: (r) => (
        <a href={`/repositories/${r.id}`} className="font-medium">
          {r.name}
        </a>
      ),
    },
    { id: "branch", header: "Default branch", mono: true, cell: (r) => r.defaultBranch },
    { id: "open", header: "Open", cell: (r) => <SevCounts counts={r.open} /> },
    { id: "last", header: "Last scan", cell: (r) => (r.lastScan ? <span className="text-xs">{ago(r.lastScan.at)}, {r.lastScan.kind === "baseline" ? "default branch" : r.lastScan.branch}</span> : "–") },
    { id: "check", header: "Check", cell: (r) => (r.lastScan ? <ScanStatus s={{ passed: r.lastScan.passed, kind: r.lastScan.kind }} /> : "–") },
  ];
  return (
    <>
      <PageHeader title="Repositories" description="A repository appears with its first scan. Its default branch is the baseline; other branches are compared with it." />
      <Panel flush>
        <DataTable
          label="Repositories"
          columns={columns}
          rows={rows ?? []}
          loading={!rows}
          getRowId={(r) => r.id}
          minWidth={760}
          empty={
            <EmptyState title="No repositories yet">
              Send a scan from CI. See <a href="/setup">Setup</a>.
            </EmptyState>
          }
        />
      </Panel>
    </>
  );
}

function RepositoryPage({ call, id, reload }: { call: Call; id: string; reload: () => void }) {
  const { can } = useAuth();
  const [repo, setRepo] = useState<Repository | null>();
  const [scans, setScans] = useState<Scan[]>();
  const [failOn, setFailOn] = useState<FailOn>("high");
  const [branch, setBranch] = useState("");
  const [error, setError] = useState<string>();
  const [removing, setRemoving] = useState(false);

  const load = useCallback(() => {
    call<Repository>(`/api/v1/repositories/${id}`).then((r) => (setRepo(r), setFailOn(r.failOn), setBranch(r.defaultBranch)), () => setRepo(null));
    call<{ scans: Scan[] }>(`/api/v1/repositories/${id}/scans?limit=50`).then((r) => setScans(r.scans), () => setScans([]));
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
    call(`/api/v1/repositories/${id}`, { method: "DELETE" }).then(() => {
      reload();
      navigate("/repositories");
    }, (err: Error) => setError(err.message));

  if (repo === null) return <EmptyState title="Repository not found">It may have been deleted. <a href="/repositories">Back to repositories</a>.</EmptyState>;

  const columns: Column<Scan>[] = [
    {
      id: "when",
      header: "Scan",
      sortValue: (s) => s.createdAt,
      cell: (s) => (
        <a href={`/scans/${s.id}`} className="text-xs whitespace-nowrap">
          {ago(s.createdAt)}
        </a>
      ),
    },
    { id: "branch", header: "Branch", cell: (s) => <span className="sast-wrap font-mono text-xs">{s.pullRequest ? `#${s.pullRequest} ${s.branch}` : s.branch}</span> },
    { id: "kind", header: "Kind", cell: (s) => (s.kind === "baseline" ? <Badge>Baseline</Badge> : <Badge tone="info">Change</Badge>) },
    { id: "total", header: "Reported", align: "right", cell: (s) => s.total },
    { id: "new", header: "New", align: "right", cell: (s) => s.new },
    { id: "check", header: "Check", cell: (s) => <ScanStatus s={s} /> },
  ];
  return (
    <>
      <PageHeader title={repo?.name ?? "Repository"} description={repo ? `Default branch ${repo.defaultBranch} · ${plural(Object.values(repo.open).reduce((a, b) => a + b, 0), "open finding")}` : undefined} />
      {can("admin") && repo && (
        <Panel title="Policy" description="What a check treats as a failure. Only findings the default branch does not have, and nobody has triaged, can fail it.">
          <div className="grid gap-2 sm:grid-cols-2">
            <SelectField label="Fail the check for" value={failOn} onChange={(e) => setFailOn(e.target.value as FailOn)} options={FAIL_ON} />
            <TextField label="Default branch" value={branch} onChange={(e) => setBranch(e.target.value)} hint="Its scans are the baseline." error={error} />
          </div>
          <div className="mt-3 flex gap-2">
            <Button variant="primary" onClick={() => void save()} disabled={failOn === repo.failOn && branch === repo.defaultBranch}>
              Save policy
            </Button>
            <Button icon={<Trash2 />} onClick={() => setRemoving(true)}>
              Delete repository
            </Button>
          </div>
          <Dialog
            open={removing}
            onOpenChange={setRemoving}
            title={`Delete ${repo.name}?`}
            description="Its scans, findings and decisions are deleted. A later scan creates it again, without them."
            footer={
              <>
                <Button type="button" onClick={() => setRemoving(false)}>
                  Cancel
                </Button>
                <Button type="button" variant="primary" onClick={() => void remove()}>
                  Delete
                </Button>
              </>
            }
          >
            <></>
          </Dialog>
        </Panel>
      )}
      <FindingsTable call={call} repoId={id} summary={repo ?? undefined} reload={() => (load(), reload())} />
      <Panel title="Scans" flush>
        <DataTable label="Scans" columns={columns} rows={scans ?? []} loading={!scans} getRowId={(s) => s.id} minWidth={640} empty={<EmptyState title="No scans">Nothing has been sent for this repository.</EmptyState>} />
      </Panel>
    </>
  );
}

function ScanPage({ call, id, reload }: { call: Call; id: string; reload: () => void }) {
  const [scan, setScan] = useState<ScanDetail | null>();
  const [open, setOpen] = useState<ScanDetail["findings"][number] | null>(null);
  const load = useCallback(() => void call<ScanDetail>(`/api/v1/scans/${id}`).then(setScan, () => setScan(null)), [call, id]);
  useEffect(load, [load]);
  if (scan === null) return <EmptyState title="Scan not found">It may be older than the retention period.</EmptyState>;

  const columns: Column<ScanDetail["findings"][number]>[] = [
    { id: "sev", header: "Severity", width: "104px", cell: (f) => <SeverityBadge severity={f.severity} /> },
    { id: "rule", header: "Rule", cell: (f) => <span className="sast-wrap font-mono text-xs">{f.rule}</span> },
    {
      id: "where",
      header: "Where",
      cell: (f) => (
        <span className="sast-wrap font-mono text-xs">
          {f.path}
          {f.line ? `:${f.line}` : ""}
        </span>
      ),
    },
    { id: "state", header: "State", cell: (f) => (f.suppressed ? <Badge>Triaged</Badge> : <Badge tone="danger">New</Badge>) },
  ];
  return (
    <>
      <PageHeader
        title={scan ? (scan.pullRequest ? `Pull request ${scan.pullRequest}` : `Scan of ${scan.branch}`) : "Scan"}
        description={scan ? `${scan.repository.name} · ${scan.branch}${scan.commit ? ` · ${scan.commit.slice(0, 8)}` : ""} · ${scan.tool} · ${ago(scan.createdAt)}` : undefined}
        actions={scan && <ScanStatus s={scan} />}
      />
      {scan && (
        <KpiGrid minWidth={150}>
          <KpiCard label="Reported" value={scan.total} />
          <KpiCard label="New" value={scan.new} tone={scan.new ? "warning" : "success"} />
          <KpiCard label="Blocking" value={scan.blocking} tone={scan.blocking ? "danger" : "success"} footer={<span className="text-xs text-fg-muted">{FAIL_ON.find((f) => f.value === scan.failOn)?.label}</span>} />
          <KpiCard label="Triaged" value={scan.suppressed} tone="info" />
        </KpiGrid>
      )}
      <div className={open ? "grid gap-2.5 xl:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]" : "grid gap-2.5"}>
        <Panel title="What this scan added" description={scan?.kind === "baseline" ? "A scan of the default branch is the baseline; everything it reports is new the first time." : "Findings the default branch does not have."} flush>
          <DataTable
            label="New findings"
            columns={columns}
            rows={scan?.findings ?? []}
            loading={scan === undefined}
            getRowId={(f) => f.fingerprint}
            onRowClick={(f) => setOpen(f)}
            activeRowId={open?.fingerprint}
            minWidth={640}
            empty={<EmptyState title="Nothing new">This scan added no findings.</EmptyState>}
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
  const origin = window.location.origin;
  return (
    <>
      <PageHeader title="Setup" description="Run any analyser that writes SARIF in CI and send the result here. The answer says whether the check passes." />
      <Panel title="Send a scan" description="Use SAST_INGEST_TOKEN, set where sast runs, or an API token with the editor role from API tokens.">
        <Code>{`opengrep scan --sarif-output=results.sarif .
curl -sf -X POST -H "Authorization: Bearer $SAST_INGEST_TOKEN" -H 'content-type: application/json' \\
  --data-binary @results.sarif \\
  "${origin}/api/v1/scans?repository=acme/web&branch=$BRANCH&commit=$SHA&pullRequest=$PR" > scan.json
jq -e '.passed' scan.json   # fail the pipeline`}</Code>
      </Panel>
      <Panel title="How a scan is compared" description="Scans of the default branch are the baseline. Any other branch, or any scan with pullRequest, reports only what the baseline does not have and nobody has triaged.">
        <ul className="sast-list flex flex-col gap-1 text-sm text-fg-muted">
          <li>A finding keeps its identity when its line moves: it is found by rule, file and the code it matched.</li>
          <li>A false positive or accepted risk follows the finding to every branch, so it does not fail the next pull request.</li>
          <li>Under Repositories you choose which severity fails a check, and which branch is the default.</li>
        </ul>
      </Panel>
    </>
  );
}

/** The first screen, until the first scan arrives. The summary is polled, so it gives way by itself. */
function WelcomePage() {
  return (
    <>
      <PageHeader title="Get started" description="Findings show here as soon as the first scan of a default branch arrives." actions={<StatusBadge tone="info">Waiting for the first scan</StatusBadge>} />
      <SetupPage />
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title="Admins only">Ask an admin of this sast for access.</EmptyState>;
  const titles = {
    account: ["Account", "Your profile, password, two-step verification and where you are signed in."],
    members: ["Members", "Who can sign in to this sast, and with which role. Viewers see everything; editors also triage findings; admins also change policies, delete repositories, and manage members and tokens."],
    signin: ["Sign-in", "Identity providers people can sign in with, such as OpenAsy Identity, Keycloak or Microsoft Entra ID, and which of their groups give which role."],
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
              Sign out
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product() {
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
    { id: "findings", label: "Findings", icon: Bug },
    { id: "repositories", label: "Repositories", icon: FolderGit2, count: summary?.repositories },
  ];
  const footerNav = [
    { id: "setup", label: "Setup", icon: Settings2 },
    ...(can("admin")
      ? [
          { id: "members", label: "Members", icon: Users },
          { id: "signin", label: "Sign-in", icon: LogIn },
          { id: "tokens", label: "API tokens", icon: KeyRound },
        ]
      : []),
    { id: "account", label: "Account", icon: UserRound },
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
