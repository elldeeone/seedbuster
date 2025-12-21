import { useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
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
import type {
  Cluster,
  Domain,
  DomainDetailResponse,
  PendingReport,
  Stats,
} from "./types";

const STATUS_OPTIONS = ["", "pending", "analyzing", "analyzed", "reported", "failed", "deferred"];
const VERDICT_OPTIONS = ["", "high", "medium", "low", "benign", "unknown", "false_positive"];

type Route =
  | { name: "dashboard" }
  | { name: "domain"; id: number }
  | { name: "clusters" }
  | { name: "cluster"; id: string };

const normalizeKey = (value: string | null | undefined) =>
  (value || "unknown").toLowerCase().replace(/[^a-z0-9]+/g, "_");

const formatBytes = (num: number | undefined) => {
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
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
};

const timeAgo = (value?: string | null) => {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const diff = Date.now() - date.getTime();
  const mins = Math.floor(diff / (1000 * 60));
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
};

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
  if (parts[0] === "clusters") {
    return { name: "clusters" };
  }
  return { name: "dashboard" };
};

const Badge = ({ label, tone, kind }: { label: string; tone: string; kind: "status" | "verdict" }) => {
  const cls = `badge ${kind === "status" ? `status-${tone}` : `verdict-${tone}`}`;
  return <span className={cls}>{label}</span>;
};

const Toast = ({ message, tone }: { message: string; tone?: "success" | "error" | "info" }) => (
  <div className={`toast ${tone || "info"}`}>{message}</div>
);

interface DomainTableProps {
  domains: Domain[];
  loading: boolean;
  error: string | null;
  filters: { status: string; verdict: string; q: string };
  onFiltersChange: (next: { status?: string; verdict?: string; q?: string }) => void;
  onView: (domainId: number) => void;
  onRescan: (domain: Domain) => void;
  onReport: (domain: Domain) => void;
  actionBusy: Record<number, string | null>;
}

const DomainTable = ({
  domains,
  loading,
  error,
  filters,
  onFiltersChange,
  onView,
  onRescan,
  onReport,
  actionBusy,
}: DomainTableProps) => {
  return (
    <div className="card">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, marginBottom: 12 }}>
        <h3>Domains</h3>
        {loading && <div className="small-label">Refreshing…</div>}
      </div>
      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10, marginBottom: 12 }}>
        <input
          className="input"
          placeholder="Search domain or keyword"
          value={filters.q}
          onChange={(e) => onFiltersChange({ q: e.target.value })}
        />
        <select
          className="select"
          value={filters.status}
          onChange={(e) => onFiltersChange({ status: e.target.value })}
        >
          {STATUS_OPTIONS.map((s) => (
            <option key={s || "any"} value={s}>
              {s ? s.toUpperCase() : "Any status"}
            </option>
          ))}
        </select>
        <select
          className="select"
          value={filters.verdict}
          onChange={(e) => onFiltersChange({ verdict: e.target.value })}
        >
          {VERDICT_OPTIONS.map((v) => (
            <option key={v || "any"} value={v}>
              {v ? v.toUpperCase() : "Any verdict"}
            </option>
          ))}
        </select>
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Domain</th>
              <th>Status</th>
              <th>Verdict</th>
              <th>Score</th>
              <th>Added</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={6}>
                  <div className="skeleton" style={{ height: 12 }} />
                </td>
              </tr>
            )}
            {!loading && domains.length === 0 && (
              <tr>
                <td colSpan={6} className="muted">
                  No domains match this filter.
                </td>
              </tr>
            )}
            {!loading &&
              domains.map((d) => {
                const busy = d.id ? actionBusy[d.id] : null;
                return (
                  <tr key={d.id ?? d.domain}>
                    <td>
                      <div style={{ fontWeight: 600 }}>{d.domain}</div>
                      <div className="muted" style={{ fontSize: 12 }}>{timeAgo(d.created_at)}</div>
                    </td>
                    <td>
                      <Badge label={(d.status || "unknown").toUpperCase()} tone={normalizeKey(d.status)} kind="status" />
                    </td>
                    <td>
                      <Badge label={(d.verdict || "unknown").toUpperCase()} tone={normalizeKey(d.verdict)} kind="verdict" />
                    </td>
                    <td>{d.score ?? "-"}</td>
                    <td>{formatDate(d.created_at)}</td>
                    <td>
                      <div className="actions">
                        <button className="btn btn-primary" onClick={() => d.id && onView(d.id)} disabled={!d.id}>
                          View
                        </button>
                        <button
                          className="btn"
                          onClick={() => onRescan(d)}
                          disabled={!d.id || !!busy}
                        >
                          {busy === "rescan" ? "Rescanning…" : "Rescan"}
                        </button>
                        <button
                          className="btn"
                          onClick={() => onReport(d)}
                          disabled={!d.id || !!busy}
                        >
                          {busy === "report" ? "Reporting…" : "Report"}
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
          </tbody>
        </table>
      </div>
      {error && <div className="notice" style={{ marginTop: 12 }}>{error}</div>}
    </div>
  );
};

const PendingReportsCard = ({ items }: { items: PendingReport[] }) => (
  <div className="card">
    <h3>Pending Reports</h3>
    {items.length === 0 ? (
      <div className="muted">No pending reports.</div>
    ) : (
      <div className="grid" style={{ gap: 8 }}>
        {items.map((r) => (
          <div key={`${r.domain}-${r.platform}`} className="notice" style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
            <div>
              <div style={{ fontWeight: 600 }}>{r.domain}</div>
              <div className="muted" style={{ fontSize: 12 }}>{r.platform} • {r.status}</div>
            </div>
            {r.domain_id && (
              <button className="btn" onClick={() => { window.location.hash = `#/domains/${r.domain_id}`; }}>
                Open
              </button>
            )}
          </div>
        ))}
      </div>
    )}
  </div>
);

interface DomainDetailProps {
  data: DomainDetailResponse | null;
  loading: boolean;
  onRescan: (domain: Domain) => void;
  onReport: (domain: Domain) => void;
  onFalsePositive: (domain: Domain) => void;
  actionBusy: Record<number, string | null>;
}

const DomainDetail = ({ data, loading, onRescan, onReport, onFalsePositive, actionBusy }: DomainDetailProps) => {
  if (loading || !data) {
    return (
      <div className="card">
        <div className="skeleton" style={{ height: 24, marginBottom: 10 }} />
        <div className="skeleton" style={{ height: 12 }} />
      </div>
    );
  }

  const domain = data.domain;
  const evidence = data.evidence || {};
  const busy = domain.id ? actionBusy[domain.id] : null;

  return (
    <div className="grid" style={{ gap: 16 }}>
      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <div style={{ fontSize: 22, fontWeight: 700 }}>{domain.domain}</div>
            <div className="muted" style={{ fontSize: 13 }}>ID: {domain.id ?? "N/A"}</div>
          </div>
          <div className="tag-grid">
            <Badge label={(domain.status || "unknown").toUpperCase()} tone={normalizeKey(domain.status)} kind="status" />
            <Badge label={(domain.verdict || "unknown").toUpperCase()} tone={normalizeKey(domain.verdict)} kind="verdict" />
          </div>
        </div>
        <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", marginTop: 14, gap: 10 }}>
          <div>
            <div className="small-label">Score</div>
            <div style={{ fontSize: 18, fontWeight: 700 }}>{domain.score ?? "-"}</div>
          </div>
          <div>
            <div className="small-label">First seen</div>
            <div>{formatDate(domain.created_at)}</div>
            <div className="muted">{timeAgo(domain.created_at)}</div>
          </div>
          <div>
            <div className="small-label">Updated</div>
            <div>{formatDate(domain.updated_at)}</div>
            <div className="muted">{timeAgo(domain.updated_at)}</div>
          </div>
        </div>
        <div style={{ display: "flex", gap: 10, marginTop: 14, flexWrap: "wrap" }}>
          <button className="btn btn-primary" onClick={() => onRescan(domain)} disabled={!domain.id || !!busy}>
            {busy === "rescan" ? "Rescanning…" : "Rescan"}
          </button>
          <button className="btn" onClick={() => onReport(domain)} disabled={!domain.id || !!busy}>
            {busy === "report" ? "Reporting…" : "Report"}
          </button>
          <button className="btn btn-danger" onClick={() => onFalsePositive(domain)} disabled={!domain.id || !!busy}>
            {busy === "false_positive" ? "Marking…" : "False Positive"}
          </button>
        </div>
      </div>

      <div className="card">
        <h3>Evidence</h3>
        <div className="tag-grid">
          {evidence.html && (
            <a className="btn" href={evidence.html} target="_blank" rel="noreferrer">
              HTML Snapshot
            </a>
          )}
          {evidence.analysis && (
            <a className="btn" href={evidence.analysis} target="_blank" rel="noreferrer">
              Analysis JSON
            </a>
          )}
          {(evidence.screenshots || []).map((shot) => (
            <a key={shot} className="btn" href={shot} target="_blank" rel="noreferrer">
              Screenshot
            </a>
          ))}
          {(data.instruction_files || []).map((file) => (
            <a key={file} className="btn" href={file} target="_blank" rel="noreferrer">
              Manual Instructions
            </a>
          ))}
          {!evidence.html && !evidence.analysis && (!evidence.screenshots || evidence.screenshots.length === 0) && (
            <div className="muted">No evidence saved yet.</div>
          )}
        </div>
      </div>

      <div className="card">
        <h3>Reports</h3>
        {(!data.reports || data.reports.length === 0) && <div className="muted">No reports yet.</div>}
        {data.reports && data.reports.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Platform</th>
                  <th>Status</th>
                  <th>Result</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {data.reports.map((r) => (
                  <tr key={`${r.platform}-${r.created_at}-${r.id}`}>
                    <td>{r.platform}</td>
                    <td><Badge label={r.status.toUpperCase()} tone={normalizeKey(r.status)} kind="status" /></td>
                    <td className="muted">{r.result || ""}</td>
                    <td>{formatDate(r.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {(() => {
        const cluster = data.cluster;
        if (!cluster) return null;
        return (
          <div className="card">
            <h3>Cluster</h3>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div style={{ fontWeight: 700 }}>{cluster.name || cluster.cluster_id}</div>
                <div className="muted">Cluster ID: {cluster.cluster_id}</div>
              </div>
              <button className="btn" onClick={() => { window.location.hash = `#/clusters/${cluster.cluster_id}`; }}>
                Open Cluster
              </button>
            </div>
            <div className="tag-grid" style={{ marginTop: 10 }}>
              {(data.related_domains || []).map((rd) => (
                <button key={rd.id || rd.domain} className="btn" onClick={() => {
                  if (rd.id) {
                    window.location.hash = `#/domains/${rd.id}`;
                  }
                }}>
                  {rd.domain}
                </button>
              ))}
            </div>
          </div>
        );
      })()}
    </div>
  );
};

const ClusterList = ({ clusters, loading }: { clusters: Cluster[]; loading: boolean }) => (
  <div className="card">
    <h3>Clusters</h3>
    {loading && <div className="muted">Loading clusters…</div>}
    {!loading && clusters.length === 0 && <div className="muted">No clusters yet.</div>}
    {!loading && clusters.length > 0 && (
      <div className="grid" style={{ gap: 10 }}>
        {clusters.map((c) => (
          <div key={c.cluster_id} className="notice" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div style={{ fontWeight: 700 }}>{c.name || c.cluster_id}</div>
              <div className="muted">Members: {c.members?.length ?? 0}</div>
            </div>
            <button className="btn" onClick={() => { window.location.hash = `#/clusters/${c.cluster_id}`; }}>
              View
            </button>
          </div>
        ))}
      </div>
    )}
  </div>
);

const ClusterDetail = ({ data, loading }: { data: { cluster: Cluster; domains: Domain[] } | null; loading: boolean }) => {
  if (loading) return <div className="card"><div className="muted">Loading cluster…</div></div>;
  if (!data) return <div className="card"><div className="muted">Cluster not found.</div></div>;
  const { cluster, domains } = data;
  return (
    <div className="card">
      <h3>Cluster Detail</h3>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <div style={{ fontSize: 20, fontWeight: 700 }}>{cluster.name || cluster.cluster_id}</div>
          <div className="muted">ID: {cluster.cluster_id}</div>
        </div>
        <button className="btn" onClick={() => { window.location.hash = "#/clusters"; }}>Back to clusters</button>
      </div>
      <div className="grid" style={{ gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", marginTop: 12, gap: 10 }}>
        <div>
          <div className="small-label">Members</div>
          <div>{cluster.members?.length ?? 0}</div>
        </div>
        <div>
          <div className="small-label">Backends</div>
          <div className="muted">{(cluster.shared_backends || []).join(", ") || "-"}</div>
        </div>
        <div>
          <div className="small-label">Kits</div>
          <div className="muted">{(cluster.shared_kits || []).join(", ") || "-"}</div>
        </div>
      </div>
      <div className="table-wrap" style={{ marginTop: 14 }}>
        <table className="table">
          <thead>
            <tr>
              <th>Domain</th>
              <th>Score</th>
              <th>Added</th>
            </tr>
          </thead>
          <tbody>
            {domains.map((d) => (
              <tr key={d.domain}>
                <td>
                  <button className="btn btn-ghost" onClick={() => { if (d.id) window.location.hash = `#/domains/${d.id}`; }}>
                    {d.domain}
                  </button>
                </td>
                <td>{d.score ?? "-"}</td>
                <td>{formatDate(d.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default function App() {
  const [route, setRoute] = useState<Route>(parseHash());
  const [stats, setStats] = useState<Stats | null>(null);
  const [health, setHealth] = useState<unknown>(null);
  const [pendingReports, setPendingReports] = useState<PendingReport[]>([]);
  const [statsLoading, setStatsLoading] = useState(true);

  const [domains, setDomains] = useState<Domain[]>([]);
  const [domainsLoading, setDomainsLoading] = useState(true);
  const [domainsError, setDomainsError] = useState<string | null>(null);
  const [filters, setFilters] = useState({ status: "", verdict: "", q: "", page: 1 });

  const [domainDetail, setDomainDetail] = useState<DomainDetailResponse | null>(null);
  const [domainDetailLoading, setDomainDetailLoading] = useState(false);

  const [clusters, setClusters] = useState<Cluster[]>([]);
  const [clusterDetail, setClusterDetail] = useState<{ cluster: Cluster; domains: Domain[] } | null>(null);
  const [clusterLoading, setClusterLoading] = useState(false);

  const [toast, setToast] = useState<{ message: string; tone?: "success" | "error" | "info" } | null>(null);
  const [submitValue, setSubmitValue] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [cleanupDays, setCleanupDays] = useState(30);
  const [cleanupResult, setCleanupResult] = useState<string | null>(null);
  const [cleanupBusy, setCleanupBusy] = useState(false);
  const [actionBusy, setActionBusy] = useState<Record<number, string | null>>({});

  useEffect(() => {
    const onHash = () => setRoute(parseHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const showToast = (message: string, tone?: "success" | "error" | "info") => setToast({ message, tone });

  useEffect(() => {
    if (!toast) return;
    const id = setTimeout(() => setToast(null), 3200);
    return () => clearTimeout(id);
  }, [toast]);

  const loadStats = async () => {
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
  };

  const loadDomains = async () => {
    setDomainsLoading(true);
    setDomainsError(null);
    try {
      const res = await fetchDomains({
        status: filters.status,
        verdict: filters.verdict,
        q: filters.q,
        page: filters.page,
        limit: 100,
      });
      setDomains(res.domains);
    } catch (err) {
      setDomainsError((err as Error).message || "Failed to load domains");
    } finally {
      setDomainsLoading(false);
    }
  };

  const loadDomainDetail = async (id: number) => {
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
  };

  const loadClusters = async () => {
    setClusterLoading(true);
    try {
      const res = await fetchClusters();
      setClusters(res.clusters || []);
    } catch (err) {
      showToast((err as Error).message || "Failed to load clusters", "error");
    } finally {
      setClusterLoading(false);
    }
  };

  const loadClusterDetail = async (id: string) => {
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
  };

  useEffect(() => {
    loadStats();
    const id = setInterval(loadStats, 30000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    loadDomains();
  }, [filters.status, filters.verdict, filters.q, filters.page]);

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
  }, [route]);

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

  const triggerAction = async (
    domain: Domain,
    type: "rescan" | "report" | "false_positive",
  ) => {
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
      if (route.name === "domain") {
        loadDomainDetail(id);
      }
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

  const dashboardView = (
    <div className="grid" style={{ gap: 16 }}>
      <div className="grid two">
        <div className="grid" style={{ gap: 16 }}>
          <div className="card">
            <h3>System</h3>
            <div className="stat-grid">
              <div className="stat-card">
                <div className="stat-label">Domains</div>
                <div className="stat-value">{stats?.total ?? "-"}</div>
                <div className="muted">+{stats?.last_24h ?? 0} in last 24h</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Evidence</div>
                <div className="stat-value">{formatBytes(stats?.evidence_bytes)}</div>
                <div className="muted">Health: {healthLabel}</div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Reports</div>
                <div className="stat-value">{Object.values(stats?.reports || {}).reduce((a, b) => a + (b || 0), 0)}</div>
                <div className="muted">Pending: {(stats?.reports || {}).pending || 0}</div>
              </div>
            </div>
          </div>

          <DomainTable
            domains={domains}
            loading={domainsLoading}
            error={domainsError}
            filters={filters}
            onFiltersChange={(next) => setFilters((prev) => ({ ...prev, ...next, page: 1 }))}
            onView={(id) => { window.location.hash = `#/domains/${id}`; }}
            onRescan={(d) => triggerAction(d, "rescan")}
            onReport={(d) => triggerAction(d, "report")}
            actionBusy={actionBusy}
          />
        </div>

        <div className="grid" style={{ gap: 16 }}>
          <div className="card">
            <h3>Manual Submission</h3>
            <form onSubmit={handleSubmit} className="grid" style={{ gap: 10 }}>
              <input
                className="input"
                placeholder="example.com or https://target"
                value={submitValue}
                onChange={(e) => setSubmitValue(e.target.value)}
              />
              <div className="form-row" style={{ justifyContent: "flex-end" }}>
                <button className="btn btn-primary" type="submit" disabled={submitting}>
                  {submitting ? "Submitting…" : "Submit / Rescan"}
                </button>
              </div>
            </form>
          </div>

          <div className="card">
            <h3>Evidence Cleanup</h3>
            <form onSubmit={handleCleanup} className="form-row">
              <input
                className="input"
                type="number"
                min={1}
                value={cleanupDays}
                onChange={(e) => setCleanupDays(Number(e.target.value) || 1)}
              />
              <button className="btn" type="submit" disabled={cleanupBusy}>
                {cleanupBusy ? "Cleaning…" : "Cleanup"}
              </button>
            </form>
            {cleanupResult && <div className="muted" style={{ marginTop: 8 }}>{cleanupResult}</div>}
          </div>

          <PendingReportsCard items={pendingReports} />
        </div>
      </div>
    </div>
  );

  const content = (() => {
    if (route.name === "domain") {
      return (
        <div className="grid" style={{ gap: 12 }}>
          <button className="btn" onClick={() => { window.location.hash = ""; }}>← Back</button>
          <DomainDetail
            data={domainDetail}
            loading={domainDetailLoading}
            onRescan={(d) => triggerAction(d, "rescan")}
            onReport={(d) => triggerAction(d, "report")}
            onFalsePositive={(d) => triggerAction(d, "false_positive")}
            actionBusy={actionBusy}
          />
        </div>
      );
    }
    if (route.name === "clusters") {
      return (
        <div className="grid" style={{ gap: 12 }}>
          <button className="btn" onClick={() => { window.location.hash = ""; }}>← Back</button>
          <ClusterList clusters={clusters} loading={clusterLoading} />
        </div>
      );
    }
    if (route.name === "cluster") {
      return (
        <div className="grid" style={{ gap: 12 }}>
          <button className="btn" onClick={() => { window.location.hash = "#/clusters"; }}>← Back</button>
          <ClusterDetail data={clusterDetail} loading={clusterLoading} />
        </div>
      );
    }
    return dashboardView;
  })();

  return (
    <div className="app-shell">
      <header className="header">
        <div className="brand">
          <div className="brand-icon">SB</div>
          <div>
            <div className="brand-text">SeedBuster Dashboard</div>
            <div className="muted" style={{ fontSize: 13 }}>Hot-reload frontend • Admin mode</div>
          </div>
        </div>
        <div className="header-actions">
          <button
            className="btn"
            onClick={() => {
              loadStats();
              loadDomains();
              if (route.name === "domain") {
                loadDomainDetail(route.id);
              }
              if (route.name === "clusters") {
                loadClusters();
              }
              if (route.name === "cluster") {
                loadClusterDetail(route.id);
              }
            }}
          >
            Refresh
          </button>
          <button className="btn" onClick={() => { window.location.hash = "#/clusters"; }}>
            Clusters
          </button>
          <span className="badge status-analyzed">{healthLabel}</span>
        </div>
      </header>

      {statsLoading && <div className="muted" style={{ marginBottom: 8 }}>Loading stats…</div>}
      {content}

      {toast && <Toast message={toast.message} tone={toast.tone} />}
    </div>
  );
}
