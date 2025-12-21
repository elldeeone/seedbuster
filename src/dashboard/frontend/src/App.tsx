import { useEffect, useMemo, useState, useCallback } from "react";
import type { FormEvent } from "react";
import "./index.css";
import {
  cleanupEvidence,
  fetchCluster,
  fetchClusters,
  fetchDomainDetail,
  fetchDomains,
  fetchStats,
  markFalsePositive,
  reportDomain,
  rescanDomain,
  submitTarget,
} from "./api";
import type { Cluster, Domain, DomainDetailResponse, PendingReport, Stats } from "./types";

type Route =
  | { name: "dashboard" }
  | { name: "domain"; id: number }
  | { name: "clusters" }
  | { name: "cluster"; id: string };

const STATUS_OPTIONS = ["", "pending", "analyzing", "analyzed", "reported", "failed", "deferred", "allowlisted", "false_positive"];
const VERDICT_OPTIONS = ["", "high", "medium", "low", "benign", "unknown", "false_positive"];
const LIMIT_OPTIONS = [25, 50, 100, 200, 500];

const parseHash = (): Route => {
  const raw = window.location.hash.replace(/^#/, "");
  const parts = raw.split("/").filter(Boolean);
  if (parts[0] === "domains" && parts[1]) {
    const id = Number(parts[1]);
    if (!Number.isNaN(id)) return { name: "domain", id };
  }
  if (parts[0] === "clusters" && parts[1]) {
    return { name: "cluster", id: parts[1] };
  }
  if (parts[0] === "clusters") return { name: "clusters" };
  return { name: "dashboard" };
};

const formatBytes = (num?: number | null) => {
  if (!num) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"] as const;
  let n = num;
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i += 1;
  }
  return `${n.toFixed(n >= 10 || n < 1 ? 1 : 2)} ${units[i]}`;
};

const formatDate = (value?: string | null) => {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
};

const timeAgo = (value?: string | null) => {
  if (!value) return "—";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  const diff = Date.now() - d.getTime();
  const mins = Math.floor(diff / (1000 * 60));
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
};

const badgeClass = (value: string | null | undefined, kind: "status" | "verdict" | "report") => {
  const v = (value || "unknown").toLowerCase();
  if (kind === "report") return `sb-badge sb-badge-${v}`;
  return `sb-badge sb-badge-${v}`;
};

const Toast = ({ message, tone }: { message: string; tone?: "success" | "error" | "info" }) => (
  <div className={`sb-toast ${tone || "info"}`}>{message}</div>
);

const Breakdown = ({ items }: { items: Record<string, number> }) => {
  const keys = Object.keys(items || {}).sort();
  if (!keys.length) return <div className="sb-muted">No data</div>;
  return (
    <div className="sb-breakdown">
      {keys.map((k) => (
        <div key={k} className="sb-breakdown-item">
          <span className="sb-breakdown-key">{k}</span>
          <span className="sb-breakdown-val">{items[k]}</span>
        </div>
      ))}
    </div>
  );
};

const DomainTable = ({
  domains,
  loading,
  error,
  filters,
  onFiltersChange,
  onPage,
  onView,
  onRescan,
  onReport,
  onFalsePositive,
  actionBusy,
}: {
  domains: Domain[];
  loading: boolean;
  error: string | null;
  filters: { status: string; verdict: string; q: string; limit: number; page: number };
  onFiltersChange: (next: Partial<{ status: string; verdict: string; q: string; limit: number; page: number }>) => void;
  onPage: (next: number) => void;
  onView: (id: number) => void;
  onRescan: (d: Domain) => void;
  onReport: (d: Domain) => void;
  onFalsePositive: (d: Domain) => void;
  actionBusy: Record<number, string | null>;
}) => (
  <div className="sb-panel">
    <div className="sb-panel-header">
      <span className="sb-panel-title">Tracked Domains</span>
      <span className="sb-muted">{domains.length} results</span>
    </div>

    <div className="sb-grid" style={{ marginBottom: 12 }}>
      <div className="col-3">
        <label className="sb-label">Status</label>
        <select
          className="sb-select"
          value={filters.status}
          onChange={(e) => onFiltersChange({ status: e.target.value, page: 1 })}
        >
          {STATUS_OPTIONS.map((s) => (
            <option key={s || "any"} value={s}>
              {s ? s.toUpperCase() : "All Statuses"}
            </option>
          ))}
        </select>
      </div>
      <div className="col-3">
        <label className="sb-label">Verdict</label>
        <select
          className="sb-select"
          value={filters.verdict}
          onChange={(e) => onFiltersChange({ verdict: e.target.value, page: 1 })}
        >
          {VERDICT_OPTIONS.map((v) => (
            <option key={v || "any"} value={v}>
              {v ? v.toUpperCase() : "All Verdicts"}
            </option>
          ))}
        </select>
      </div>
      <div className="col-3">
        <label className="sb-label">Search</label>
        <input
          className="sb-input"
          placeholder="domain contains..."
          value={filters.q}
          onChange={(e) => onFiltersChange({ q: e.target.value, page: 1 })}
        />
      </div>
      <div className="col-3">
        <label className="sb-label">Results / Page</label>
        <div className="sb-row" style={{ justifyContent: "space-between" }}>
          <select
            className="sb-select"
            value={filters.limit}
            onChange={(e) => onFiltersChange({ limit: Number(e.target.value) || 100, page: 1 })}
          >
            {LIMIT_OPTIONS.map((n) => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
          <input
            className="sb-input"
            style={{ width: 70 }}
            value={filters.page}
            onChange={(e) => onFiltersChange({ page: Number(e.target.value) || 1 })}
          />
        </div>
      </div>
    </div>

    <div className="sb-table-wrap">
      <table className="sb-table">
        <thead>
          <tr>
            <th>Domain</th>
            <th>Status</th>
            <th>Verdict</th>
            <th>D-Score</th>
            <th>A-Score</th>
            <th>Source</th>
            <th>First Seen</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {loading && (
            <tr><td colSpan={8}><div className="skeleton" style={{ height: 14 }} /></td></tr>
          )}
          {!loading && domains.length === 0 && (
            <tr><td colSpan={8} className="sb-muted" style={{ textAlign: "center", padding: 20 }}>No domains match these filters.</td></tr>
          )}
          {!loading && domains.map((d) => {
            const busy = d.id ? actionBusy[d.id] : null;
            const dScore = (d as any).domain_score ?? (d as any).score ?? "—";
            const aScore = (d as any).analysis_score ?? "—";
            return (
              <tr key={d.id ?? d.domain}>
                <td className="domain-cell" title={d.domain}>
                  {d.id ? (
                    <a className="domain-link" onClick={() => onView(d.id!)} href={`#/domains/${d.id}`}>
                      {d.domain}
                    </a>
                  ) : (
                    <span>{d.domain}</span>
                  )}
                  <div className="sb-muted" style={{ fontSize: 12 }}>{timeAgo(d.created_at)}</div>
                </td>
                <td><span className={badgeClass(d.status, "status")}>{(d.status || "unknown").toUpperCase()}</span></td>
                <td><span className={badgeClass(d.verdict, "verdict")}>{(d.verdict || "unknown").toUpperCase()}</span></td>
                <td><span className="sb-score">{dScore}</span></td>
                <td><span className="sb-score">{aScore}</span></td>
                <td className="sb-muted">{d.source || "—"}</td>
                <td className="sb-muted">{d.first_seen || "—"}</td>
                <td>
                  <div className="sb-row" style={{ flexWrap: "wrap" }}>
                    <button className="sb-btn sb-btn-primary" disabled={!d.id} onClick={() => d.id && onView(d.id)}>View</button>
                    <button className="sb-btn" disabled={!d.id || !!busy} onClick={() => onRescan(d)}>
                      {busy === "rescan" ? "Rescanning…" : "Rescan"}
                    </button>
                    <button className="sb-btn" disabled={!d.id || !!busy} onClick={() => onReport(d)}>
                      {busy === "report" ? "Reporting…" : "Report"}
                    </button>
                    <button className="sb-btn sb-btn-danger" disabled={!d.id || !!busy} onClick={() => onFalsePositive(d)}>
                      {busy === "false_positive" ? "Marking…" : "False +"}
                    </button>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>

    <div className="sb-pagination">
      <div className="sb-page-info">Page {filters.page}</div>
      <div className="sb-row">
        {filters.page > 1 && <button className="sb-btn" onClick={() => onPage(filters.page - 1)}>&larr; Previous</button>}
        {domains.length >= filters.limit && <button className="sb-btn" onClick={() => onPage(filters.page + 1)}>Next &rarr;</button>}
      </div>
    </div>

    {error && <div className="sb-notice" style={{ marginTop: 8 }}>{error}</div>}
  </div>
);

const EvidenceSection = ({ data }: { data: DomainDetailResponse | null }) => {
  if (!data) return null;
  const evidence = data.evidence || {};
  const shots = evidence.screenshots || [];
  const files = [
    evidence.html ? { label: "HTML", href: evidence.html } : null,
    evidence.analysis ? { label: "Analysis JSON", href: evidence.analysis } : null,
    ...(data.instruction_files || []).map((href) => ({ label: "Instructions", href })),
  ].filter(Boolean) as { label: string; href: string }[];

  return (
    <div className="sb-grid" style={{ gap: 12 }}>
      <div className="col-6">
        <div className="sb-panel">
          <div className="sb-panel-header">
            <span className="sb-panel-title">Evidence Files</span>
            <span className="sb-muted">{files.length || "No files"}</span>
          </div>
          <div className="sb-row" style={{ flexWrap: "wrap" }}>
            {files.length === 0 && <span className="sb-muted">No evidence files yet.</span>}
            {files.map((f) => (
              <a key={f.href} className="sb-btn" href={f.href} target="_blank" rel="noreferrer">{f.label}</a>
            ))}
          </div>
        </div>
      </div>
      <div className="col-6">
        <div className="sb-panel">
          <div className="sb-panel-header">
            <span className="sb-panel-title">Screenshots</span>
            <span className="sb-muted">{shots.length} captured</span>
          </div>
          <div className="sb-evidence-grid">
            {shots.length === 0 && <div className="sb-muted">No screenshots available.</div>}
            {shots.map((s) => (
              <div key={s} className="sb-screenshot">
                <a href={s} target="_blank" rel="noreferrer"><img src={s} alt={s} /></a>
                <div className="sb-screenshot-label">{s.split("/").pop()}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};

const ReportsTable = ({ data }: { data: DomainDetailResponse | null }) => {
  if (!data) return null;
  const rows = data.reports || [];
  return (
    <div className="sb-panel">
      <div className="sb-panel-header">
        <span className="sb-panel-title">Report History</span>
        <span className="sb-muted">{rows.length} records</span>
      </div>
      <div className="sb-table-wrap">
        <table className="sb-table">
          <thead>
            <tr>
              <th>Platform</th>
              <th>Status</th>
              <th>Attempted</th>
              <th>Submitted</th>
              <th>Next Attempt</th>
              <th>Response</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr><td colSpan={6} className="sb-muted" style={{ textAlign: "center", padding: 18 }}>No reports yet.</td></tr>
            )}
            {rows.map((r) => (
              <tr key={`${r.platform}-${r.created_at || r.id || Math.random()}`}>
                <td>{r.platform}</td>
                <td><span className={badgeClass(r.status, "report")}>{(r.status || "").toUpperCase()}</span></td>
                <td className="sb-muted">{formatDate(r.created_at)}</td>
                <td className="sb-muted">{formatDate(r.submitted_at as any)}</td>
                <td className="sb-muted">{formatDate((r as any).next_attempt_at)}</td>
                <td className="sb-muted" style={{ maxWidth: 260, overflow: "hidden", textOverflow: "ellipsis" }}>{(r as any).response || r.result || ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const ClusterCard = ({ cluster, related }: { cluster: Cluster | null | undefined; related: Domain[] }) => {
  if (!cluster) return null;
  const indicators = [
    { label: "Backends", values: cluster.shared_backends || [] },
    { label: "Kits", values: cluster.shared_kits || [] },
    { label: "Nameservers", values: cluster.shared_nameservers || [] },
  ];
  return (
    <div className="sb-panel" style={{ borderColor: "rgba(163, 113, 247, 0.3)" }}>
      <div className="sb-panel-header" style={{ borderColor: "rgba(163, 113, 247, 0.2)" }}>
        <div>
          <span className="sb-panel-title" style={{ color: "var(--accent-purple)" }}>Threat Campaign</span>
          <span className="sb-muted" style={{ marginLeft: 8 }}>ID: {cluster.cluster_id}</span>
        </div>
        <a className="sb-btn" href="#/clusters">View all</a>
      </div>
      <div className="sb-grid">
        <div className="col-6">
          <div className="sb-label">Campaign Name</div>
          <div style={{ fontSize: 16, fontWeight: 600 }}>{cluster.name || cluster.cluster_id}</div>
        </div>
        <div className="col-6">
          <div className="sb-label">Members</div>
          <div className="sb-muted">{cluster.members?.length ?? 0}</div>
        </div>
      </div>
      <div style={{ marginTop: 12 }}>
        <div className="sb-label">Related Domains</div>
        <div className="sb-breakdown">
          {(related || []).map((rd) => (
            <div key={rd.id || rd.domain} className="sb-breakdown-item" style={{ cursor: rd.id ? "pointer" : "default" }}
              onClick={() => rd.id && (window.location.hash = `#/domains/${rd.id}`)}>
              <span className="sb-breakdown-key">{rd.domain}</span>
              <span className="sb-score">{(rd as any).score ?? ""}</span>
            </div>
          ))}
          {(!related || related.length === 0) && <div className="sb-muted">No other domains yet.</div>}
        </div>
      </div>
      <div style={{ marginTop: 12 }}>
        <div className="sb-label">Shared Indicators</div>
        <div className="sb-row" style={{ flexWrap: "wrap", alignItems: "flex-start" }}>
          {indicators.map((ind) => ind.values && ind.values.length ? (
            <div key={ind.label} style={{ marginRight: 12 }}>
              <div className="sb-muted" style={{ fontSize: 12 }}>{ind.label}</div>
              <div style={{ marginTop: 4 }}>
                {ind.values.slice(0, 4).map((v) => (
                  <code key={v} className="sb-code" style={{ display: "inline-block", margin: "2px 4px 2px 0" }}>{v}</code>
                ))}
              </div>
            </div>
          ) : null)}
          {indicators.every((i) => !i.values || i.values.length === 0) && <div className="sb-muted">No shared indicators.</div>}
        </div>
      </div>
    </div>
  );
};

export default function App() {
  const [route, setRoute] = useState<Route>(parseHash());
  const [stats, setStats] = useState<Stats | null>(null);
  const [pendingReports, setPendingReports] = useState<PendingReport[]>([]);
  const [health, setHealth] = useState<unknown>(null);
  const [statsLoading, setStatsLoading] = useState(true);

  const [filters, setFilters] = useState({ status: "", verdict: "", q: "", limit: 100, page: 1 });
  const [domains, setDomains] = useState<Domain[]>([]);
  const [domainsLoading, setDomainsLoading] = useState(true);
  const [domainsError, setDomainsError] = useState<string | null>(null);

  const [domainDetail, setDomainDetail] = useState<DomainDetailResponse | null>(null);
  const [domainDetailLoading, setDomainDetailLoading] = useState(false);

  const [clusters, setClusters] = useState<Cluster[]>([]);
  const [clusterDetail, setClusterDetail] = useState<{ cluster: Cluster; domains: Domain[] } | null>(null);
  const [clusterLoading, setClusterLoading] = useState(false);

  const [toast, setToast] = useState<{ message: string; tone?: "success" | "error" | "info" } | null>(null);
  const [submitValue, setSubmitValue] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [cleanupDays, setCleanupDays] = useState(30);
  const [cleanupBusy, setCleanupBusy] = useState(false);
  const [cleanupResult, setCleanupResult] = useState<string | null>(null);
  const [actionBusy, setActionBusy] = useState<Record<number, string | null>>({});

  useEffect(() => {
    const onHash = () => setRoute(parseHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  useEffect(() => {
    if (!toast) return;
    const id = setTimeout(() => setToast(null), 3200);
    return () => clearTimeout(id);
  }, [toast]);

  const showToast = (message: string, tone?: "success" | "error" | "info") => setToast({ message, tone });

  const loadStats = useCallback(async () => {
    setStatsLoading(true);
    try {
      const data = await fetchStats();
      setStats(data.stats);
      setPendingReports(data.pending_reports || []);
      setHealth(data.health || null);
    } catch (err) {
      showToast((err as Error).message || "Failed to load stats", "error");
    } finally {
      setStatsLoading(false);
    }
  }, []);

  const loadDomains = useCallback(async () => {
    setDomainsLoading(true);
    setDomainsError(null);
    try {
      const res = await fetchDomains(filters);
      setDomains(res.domains);
    } catch (err) {
      setDomainsError((err as Error).message || "Failed to load domains");
    } finally {
      setDomainsLoading(false);
    }
  }, [filters]);

  const loadDomainDetail = useCallback(async (id: number) => {
    setDomainDetailLoading(true);
    try {
      const detail = await fetchDomainDetail(id);
      setDomainDetail(detail);
    } catch (err) {
      showToast((err as Error).message || "Failed to load domain", "error");
      setDomainDetail(null);
    } finally {
      setDomainDetailLoading(false);
    }
  }, []);

  const loadClusters = useCallback(async () => {
    setClusterLoading(true);
    try {
      const res = await fetchClusters();
      setClusters(res.clusters || []);
    } catch (err) {
      showToast((err as Error).message || "Failed to load clusters", "error");
    } finally {
      setClusterLoading(false);
    }
  }, []);

  const loadClusterDetail = useCallback(async (id: string) => {
    setClusterLoading(true);
    try {
      const res = await fetchCluster(id);
      setClusterDetail(res);
    } catch (err) {
      showToast((err as Error).message || "Failed to load cluster", "error");
      setClusterDetail(null);
    } finally {
      setClusterLoading(false);
    }
  }, []);

  useEffect(() => {
    loadStats();
    const id = setInterval(loadStats, 30000);
    return () => clearInterval(id);
  }, [loadStats]);

  useEffect(() => {
    loadDomains();
  }, [loadDomains]);

  useEffect(() => {
    if (route.name === "domain") {
      loadDomainDetail(route.id);
    } else {
      setDomainDetail(null);
    }
    if (route.name === "clusters") {
      loadClusters();
    }
    if (route.name === "cluster") {
      loadClusterDetail(route.id);
    }
  }, [route, loadDomainDetail, loadClusters, loadClusterDetail]);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (!submitValue.trim()) return;
    setSubmitting(true);
    try {
      const res = await submitTarget(submitValue.trim());
      showToast(`Submitted ${res.domain}`, "success");
      setSubmitValue("");
      loadDomains();
    } catch (err) {
      showToast((err as Error).message || "Submit failed", "error");
    } finally {
      setSubmitting(false);
    }
  };

  const handleCleanup = async (e: FormEvent) => {
    e.preventDefault();
    setCleanupBusy(true);
    try {
      const res = await cleanupEvidence(cleanupDays || 30);
      const msg = `Removed ${res.removed_dirs} evidence directories older than ${cleanupDays} days.`;
      setCleanupResult(msg);
      showToast(msg, "success");
    } catch (err) {
      showToast((err as Error).message || "Cleanup failed", "error");
    } finally {
      setCleanupBusy(false);
    }
  };

  const triggerAction = async (domain: Domain, type: "rescan" | "report" | "false_positive") => {
    const id = domain.id;
    if (!id) {
      showToast("Domain id is missing for this record", "error");
      return;
    }
    setActionBusy((prev) => ({ ...prev, [id]: type }));
    try {
      if (type === "rescan") {
        await rescanDomain(id, domain.domain);
        showToast(`Rescan queued for ${domain.domain}`, "success");
      } else if (type === "report") {
        await reportDomain(id, domain.domain);
        showToast(`Report enqueued for ${domain.domain}`, "success");
      } else {
        await markFalsePositive(id);
        showToast(`Marked ${domain.domain} as false positive`, "success");
      }
      loadDomains();
      if (route.name === "domain") loadDomainDetail(id);
    } catch (err) {
      showToast((err as Error).message || `${type} failed`, "error");
    } finally {
      setActionBusy((prev) => ({ ...prev, [id]: null }));
    }
  };

  const healthLabel = useMemo(() => {
    if (!health || typeof health !== "object") return "Unknown";
    if ((health as any).ok) return "Healthy";
    return "Unhealthy";
  }, [health]);

  const statsBlocks = useMemo(() => {
    if (!stats) return null;
    return (
      <div className="sb-grid" style={{ marginBottom: 12 }}>
        <div className="col-4">
          <div className="sb-stat">
            <div className="sb-stat-label">Total Domains</div>
            <div className="sb-stat-value">{stats.total}</div>
            <div className="sb-stat-meta">Last 24h: <b>{stats.last_24h}</b></div>
          </div>
        </div>
        <div className="col-4"><div className="sb-stat"><div className="sb-stat-label">By Status</div><Breakdown items={stats.by_status || {}} /></div></div>
        <div className="col-4"><div className="sb-stat"><div className="sb-stat-label">By Verdict</div><Breakdown items={stats.by_verdict || {}} /></div></div>
        <div className="col-4"><div className="sb-stat"><div className="sb-stat-label">Reports</div><Breakdown items={stats.reports || {}} /></div></div>
        <div className="col-4"><div className="sb-stat"><div className="sb-stat-label">Dashboard Actions</div><Breakdown items={stats.dashboard_actions || {}} /></div></div>
        <div className="col-4"><div className="sb-stat"><div className="sb-stat-label">Evidence Storage</div><div className="sb-stat-value">{formatBytes(stats.evidence_bytes)}</div><div className="sb-stat-meta">Approximate evidence size</div></div></div>
      </div>
    );
  }, [stats]);

  const healthPanel = (stats?.evidence_bytes !== undefined || stats?.total !== undefined) && (
    <div className="sb-panel" id="health-panel" style={{ borderColor: "rgba(88, 166, 255, 0.2)" }}>
      <div className="sb-panel-header">
        <span className="sb-panel-title">Health</span>
        <span className="sb-muted">Pipeline status</span>
      </div>
      <div className="sb-row" style={{ alignItems: "center", gap: 8 }}>
        <span className={`sb-badge sb-badge-${healthLabel.toLowerCase()}`}>{healthLabel}</span>
        <span className="sb-muted">{(health as any)?.status || (health as any)?.error || "Best-effort check"}</span>
      </div>
    </div>
  );

  const dashboardView = (
    <>
      {statsBlocks}
      <div className="sb-grid">
        <div className="col-8">
          {healthPanel}
          <DomainTable
            domains={domains}
            loading={domainsLoading}
            error={domainsError}
            filters={filters}
            onFiltersChange={(next) => setFilters((prev) => ({ ...prev, ...next }))}
            onPage={(nextPage) => setFilters((prev) => ({ ...prev, page: nextPage }))}
            onView={(id) => { window.location.hash = `#/domains/${id}`; }}
            onRescan={(d) => triggerAction(d, "rescan")}
            onReport={(d) => triggerAction(d, "report")}
            onFalsePositive={(d) => triggerAction(d, "false_positive")}
            actionBusy={actionBusy}
          />
        </div>
        <div className="col-4">
          <div className="sb-panel" style={{ borderColor: "rgba(88, 166, 255, 0.3)" }}>
            <div className="sb-panel-header" style={{ borderColor: "rgba(88, 166, 255, 0.2)" }}>
              <span className="sb-panel-title" style={{ color: "var(--accent-blue)" }}>Manual Submission</span>
              <span className="sb-muted">Submit or rescan</span>
            </div>
            <form onSubmit={handleSubmit} className="sb-grid" style={{ gap: 10 }}>
              <div className="col-12">
                <input className="sb-input" placeholder="example.com or https://target" value={submitValue} onChange={(e) => setSubmitValue(e.target.value)} />
              </div>
              <div className="col-12" style={{ display: "flex", justifyContent: "flex-end" }}>
                <button className="sb-btn sb-btn-primary" type="submit" disabled={submitting}>{submitting ? "Submitting…" : "Submit / Rescan"}</button>
              </div>
            </form>
          </div>

          <div className="sb-panel" style={{ borderColor: "rgba(63, 185, 80, 0.3)" }}>
            <div className="sb-panel-header" style={{ borderColor: "rgba(63, 185, 80, 0.2)" }}>
              <span className="sb-panel-title" style={{ color: "var(--accent-green)" }}>Evidence Cleanup</span>
              <span className="sb-muted">Remove older evidence</span>
            </div>
            <form onSubmit={handleCleanup} className="sb-row">
              <input className="sb-input" type="number" min={1} value={cleanupDays} onChange={(e) => setCleanupDays(Number(e.target.value) || 1)} style={{ width: 120 }} />
              <button className="sb-btn" type="submit" disabled={cleanupBusy}>{cleanupBusy ? "Cleaning…" : "Cleanup"}</button>
            </form>
            {cleanupResult && <div className="sb-muted" style={{ marginTop: 8 }}>{cleanupResult}</div>}
          </div>

          {pendingReports.length > 0 && (
            <div className="sb-panel" style={{ borderColor: "rgba(240, 136, 62, 0.3)" }}>
              <div className="sb-panel-header" style={{ borderColor: "rgba(240, 136, 62, 0.2)" }}>
                <span className="sb-panel-title" style={{ color: "var(--accent-orange)" }}>Reports Needing Attention</span>
                <span className="sb-muted">showing up to 50</span>
              </div>
              <div className="sb-table-wrap">
                <table className="sb-table">
                  <thead>
                    <tr><th>Domain</th><th>Platform</th><th>Status</th><th>Next Attempt</th></tr>
                  </thead>
                  <tbody>
                    {pendingReports.slice(0, 50).map((r) => (
                      <tr key={`${r.domain}-${r.platform}`}>
                        <td><a className="domain-link" href={r.domain_id ? `#/domains/${r.domain_id}` : undefined}>{r.domain}</a></td>
                        <td>{r.platform}</td>
                        <td><span className={badgeClass(r.status, "report")}>{(r.status || "").toUpperCase()}</span></td>
                        <td className="sb-muted">{(r as any).next_attempt_at || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );

  const clustersView = (
    <div className="sb-panel">
      <div className="sb-panel-header">
        <span className="sb-panel-title">Threat Clusters</span>
        <span className="sb-muted">{clusters.length} clusters</span>
      </div>
      {clusterLoading && <div className="sb-muted">Loading clusters…</div>}
      {!clusterLoading && clusters.length === 0 && <div className="sb-muted">No clusters yet.</div>}
      {!clusterLoading && clusters.length > 0 && (
        <div className="sb-grid" style={{ gap: 12 }}>
          {clusters.map((c) => (
            <div key={c.cluster_id} className="sb-panel" style={{ borderColor: "rgba(163, 113, 247, 0.3)" }}>
              <div className="sb-panel-header" style={{ borderColor: "rgba(163, 113, 247, 0.2)" }}>
                <div>
                  <div className="sb-panel-title" style={{ color: "var(--accent-purple)" }}>{c.name || c.cluster_id}</div>
                  <div className="sb-muted">Members: {c.members?.length ?? 0}</div>
                </div>
                <a className="sb-btn" href={`#/clusters/${c.cluster_id}`}>View</a>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );

  const clusterDetailView = (
    <div className="sb-grid" style={{ gap: 12 }}>
      <div className="sb-row"><a className="sb-btn" href="#/clusters">&larr; Back</a></div>
      {clusterLoading && <div className="sb-muted">Loading cluster…</div>}
      {!clusterLoading && <ClusterCard cluster={clusterDetail?.cluster} related={clusterDetail?.domains || []} />}
    </div>
  );

  const domainDetailView = (
    <div className="sb-grid" style={{ gap: 12 }}>
      <div className="sb-row"><a className="sb-btn" href="#/">&larr; Back</a></div>
      {domainDetailLoading && (
        <div className="sb-panel"><div className="skeleton" style={{ height: 24, marginBottom: 10 }} /><div className="skeleton" style={{ height: 12 }} /></div>
      )}
      {!domainDetailLoading && domainDetail && (
        <>
          <div className="sb-panel">
            <div className="sb-row sb-space-between" style={{ alignItems: "flex-start" }}>
              <div>
                <div style={{ fontSize: 22, fontWeight: 700 }}>{domainDetail.domain.domain}</div>
                <div className="sb-row" style={{ gap: 8, flexWrap: "wrap" }}>
                  <span className={badgeClass(domainDetail.domain.status, "status")}>{(domainDetail.domain.status || "unknown").toUpperCase()}</span>
                  <span className={badgeClass(domainDetail.domain.verdict, "verdict")}>{(domainDetail.domain.verdict || "unknown").toUpperCase()}</span>
                  <span className="sb-muted">ID: {domainDetail.domain.id ?? "N/A"}</span>
                </div>
              </div>
              <div className="sb-row" style={{ flexWrap: "wrap" }}>
                <button className="sb-btn sb-btn-primary" disabled={!domainDetail.domain.id || !!actionBusy[domainDetail.domain.id!]} onClick={() => triggerAction(domainDetail.domain, "rescan")}>
                  {actionBusy[domainDetail.domain.id || 0] === "rescan" ? "Rescanning…" : "Rescan"}
                </button>
                <button className="sb-btn" disabled={!domainDetail.domain.id || !!actionBusy[domainDetail.domain.id!]} onClick={() => triggerAction(domainDetail.domain, "report")}>
                  {actionBusy[domainDetail.domain.id || 0] === "report" ? "Reporting…" : "Report"}
                </button>
                <button className="sb-btn sb-btn-danger" disabled={!domainDetail.domain.id || !!actionBusy[domainDetail.domain.id!]} onClick={() => triggerAction(domainDetail.domain, "false_positive")}>
                  {actionBusy[domainDetail.domain.id || 0] === "false_positive" ? "Marking…" : "False Positive"}
                </button>
              </div>
            </div>
            <div className="sb-grid" style={{ marginTop: 12 }}>
              {[
                ["Domain score", (domainDetail.domain as any).domain_score ?? (domainDetail.domain as any).score ?? "—"],
                ["Analysis score", (domainDetail.domain as any).analysis_score ?? "—"],
                ["Source", domainDetail.domain.source || "—"],
                ["First seen", domainDetail.domain.first_seen || "—"],
                ["Analyzed at", domainDetail.domain.analyzed_at || "—"],
                ["Reported at", (domainDetail.domain as any).reported_at || "—"],
                ["Updated", domainDetail.domain.updated_at || "—"],
              ].map(([label, value]) => (
                <div key={label as string} className="col-4">
                  <div className="sb-label">{label as string}</div>
                  <div className="sb-muted">{value as string}</div>
                </div>
              ))}
            </div>
          </div>

          <EvidenceSection data={domainDetail} />
          <ReportsTable data={domainDetail} />

          <div className="sb-grid">
            <div className="col-6">
              <div className="sb-panel">
                <div className="sb-panel-header"><span className="sb-panel-title">Verdict Reasons</span></div>
                {domainDetail.domain.verdict_reasons ? (
                  <pre className="sb-pre">{domainDetail.domain.verdict_reasons as any}</pre>
                ) : (
                  <div className="sb-muted">—</div>
                )}
              </div>
            </div>
            <div className="col-6">
              <div className="sb-panel">
                <div className="sb-panel-header"><span className="sb-panel-title">Operator Notes</span></div>
                {domainDetail.domain.operator_notes ? (
                  <pre className="sb-pre">{domainDetail.domain.operator_notes as any}</pre>
                ) : (
                  <div className="sb-muted">—</div>
                )}
              </div>
            </div>
          </div>

          <ClusterCard cluster={domainDetail.cluster} related={domainDetail.related_domains || []} />
        </>
      )}
    </div>
  );

  const content = (() => {
    if (route.name === "domain") return domainDetailView;
    if (route.name === "clusters") return clustersView;
    if (route.name === "cluster") return clusterDetailView;
    return dashboardView;
  })();

  return (
    <div className="sb-container">
      <header className="sb-header">
        <div className="sb-brand">
          <a className="sb-logo" href="#/">
            <div className="sb-logo-icon">SB</div>
            <span className="sb-logo-text">SeedBuster</span>
          </a>
          <span className="sb-mode mode-admin">ADMIN</span>
        </div>
        <nav className="sb-nav">
          <a className="sb-btn" href="#/">Dashboard</a>
          <a className="sb-btn" href="#/clusters">Clusters</a>
        </nav>
      </header>

      {statsLoading && <div className="sb-muted" style={{ marginBottom: 12 }}>Loading stats…</div>}
      {content}

      <footer className="sb-footer">
        <span>SeedBuster Phishing Detection Pipeline</span>
        <span>Admin view</span>
      </footer>

      <div id="sb-toast-container" className="sb-toast-container" aria-live="polite">
        {toast && <Toast message={toast.message} tone={toast.tone} />}
      </div>
    </div>
  );
}
