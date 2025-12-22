import { useEffect, useMemo, useState, useCallback } from "react";
import type { FormEvent, MouseEvent } from "react";
import "./index.css";
import {
  cleanupEvidence,
  fetchCluster,
  fetchClusters,
  fetchDomainDetail,
  fetchDomains,
  fetchPlatformInfo,
  fetchStats,
  markFalsePositive,
  reportDomain,
  rescanDomain,
  submitTarget,
  updateDomainStatus,
} from "./api";
import type { PlatformInfo } from "./api";
import type { Cluster, Domain, DomainDetailResponse, PendingReport, Stats } from "./types";

type Route =
  | { name: "dashboard" }
  | { name: "domain"; id: number }
  | { name: "clusters" }
  | { name: "cluster"; id: string };

const STATUS_OPTIONS = ["", "pending", "analyzing", "analyzed", "reported", "failed", "watchlist", "allowlisted", "false_positive"];
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

const Breakdown = ({ items, onSelect }: { items: Record<string, number>; onSelect?: (key: string) => void }) => {
  const keys = Object.keys(items || {}).sort();
  if (!keys.length) return <div className="sb-muted">No data</div>;
  return (
    <div className="sb-breakdown">
      {keys.map((k) => {
        const clickable = Boolean(onSelect);
        return (
          <div
            key={k}
            className="sb-breakdown-item"
            style={clickable ? { cursor: "pointer" } : undefined}
            onClick={clickable ? () => onSelect && onSelect(k) : undefined}
          >
            <span className="sb-breakdown-key">{k}</span>
            <span className="sb-breakdown-val">{items[k]}</span>
          </div>
        );
      })}
    </div>
  );
};

// Category prefixes for verdict reasons
const REASON_CATEGORIES: Record<string, { label: string; color: string }> = {
  "INFRA:": { label: "Infrastructure", color: "var(--accent-blue)" },
  "CODE:": { label: "Code Analysis", color: "var(--accent-purple)" },
  "TEMPORAL:": { label: "Temporal", color: "var(--accent-orange)" },
  "EXTERNAL:": { label: "External Intel", color: "var(--accent-green)" },
  "EXPLORE:": { label: "Exploration", color: "var(--accent-red)" },
};

// Parse a single reason line and extract category + linkify URLs
const parseReasonLine = (line: string): { category: string | null; text: React.ReactNode } => {
  let category: string | null = null;
  let textContent = line;

  // Check for category prefix
  for (const prefix of Object.keys(REASON_CATEGORIES)) {
    if (line.startsWith(prefix)) {
      category = prefix;
      textContent = line.slice(prefix.length).trim();
      break;
    }
  }

  // Linkify URLs in the text
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  const parts: (string | React.ReactElement)[] = [];
  let lastIndex = 0;
  let match;

  while ((match = urlRegex.exec(textContent)) !== null) {
    if (match.index > lastIndex) {
      parts.push(textContent.substring(lastIndex, match.index));
    }
    const url = match[0];
    parts.push(
      <a key={match.index} href={url} target="_blank" rel="noreferrer" className="sb-verdict-link" style={{ wordBreak: "break-all" }}>
        {url}
      </a>
    );
    lastIndex = match.index + url.length;
  }

  if (lastIndex < textContent.length) {
    parts.push(textContent.substring(lastIndex));
  }

  const text = parts.length > 0 ? <>{parts}</> : textContent;
  return { category, text };
};

const VerdictReasons = ({ reasons }: { reasons: string | null | undefined }) => {
  if (!reasons) return <div className="sb-muted">—</div>;

  // Split into lines and deduplicate
  const lines = reasons.split("\n").map((l) => l.trim()).filter(Boolean);
  const uniqueLines = [...new Set(lines)];

  if (uniqueLines.length === 0) return <div className="sb-muted">—</div>;

  // Group by category
  const grouped: Record<string, React.ReactNode[]> = {
    "INFRA:": [],
    "CODE:": [],
    "TEMPORAL:": [],
    "EXTERNAL:": [],
    "EXPLORE:": [],
    other: [],
  };

  for (const line of uniqueLines) {
    const { category, text } = parseReasonLine(line);
    if (category && grouped[category]) {
      grouped[category].push(text);
    } else {
      grouped.other.push(text);
    }
  }

  // Render non-empty groups
  const categoryOrder = ["other", "INFRA:", "CODE:", "TEMPORAL:", "EXTERNAL:", "EXPLORE:"];

  return (
    <div className="sb-verdict-reasons">
      {categoryOrder.map((cat) => {
        const items = grouped[cat];
        if (!items || items.length === 0) return null;

        const catInfo = REASON_CATEGORIES[cat];
        const label = catInfo?.label || "General";
        const color = catInfo?.color || "var(--text-muted)";

        return (
          <div key={cat} style={{ marginBottom: 12 }}>
            {cat !== "other" && (
              <div
                className="sb-badge"
                style={{
                  backgroundColor: color,
                  color: "#fff",
                  marginBottom: 6,
                  display: "inline-block",
                  fontSize: 10,
                  padding: "2px 6px",
                }}
              >
                {label}
              </div>
            )}
            <ul style={{ margin: 0, paddingLeft: cat === "other" ? 0 : 16, listStyle: cat === "other" ? "none" : "disc" }}>
              {items.map((item, idx) => (
                <li key={idx} style={{ marginBottom: 4, fontSize: 13, color: "var(--text-secondary)" }}>
                  {item}
                </li>
              ))}
            </ul>
          </div>
        );
      })}
    </div>
  );
};

const DomainTable = ({
  domains,
  loading,
  error,
  total,
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
  total: number;
  filters: { status: string; verdict: string; q: string; limit: number; page: number };
  onFiltersChange: (next: Partial<{ status: string; verdict: string; q: string; limit: number; page: number }>) => void;
  onPage: (next: number) => void;
  onView: (id: number) => void;
  onRescan: (d: Domain) => void;
  onReport: (d: Domain) => void;
  onFalsePositive: (d: Domain) => void;
  actionBusy: Record<number, string | null>;
}) => {
  const totalPages = Math.max(1, Math.ceil((total || 0) / (filters.limit || 1)));
  const pageDisplay = Math.min(filters.page, totalPages);
  const canNext = pageDisplay < totalPages;
  const canPrev = pageDisplay > 1;
  const handlePageInput = (value: string) => {
    const parsed = Number(value) || 1;
    onPage(parsed);
  };
  return (
    <div className="sb-panel">
      <div className="sb-panel-header">
        <span className="sb-panel-title">Tracked Domains</span>
        <span className="sb-muted">
          Showing {domains.length} / {total || domains.length} (page {pageDisplay} of {totalPages})
        </span>
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
              onChange={(e) => handlePageInput(e.target.value)}
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
                    <div className="sb-muted" style={{ fontSize: 12 }}>{timeAgo(d.updated_at || d.created_at)}</div>
                  </td>
                  <td><span className={badgeClass(d.status, "status")}>{(d.status || "unknown").toUpperCase()}</span></td>
                  <td><span className={badgeClass(d.verdict, "verdict")}>{(d.verdict || "unknown").toUpperCase()}</span></td>
                  <td><span className="sb-score">{dScore}</span></td>
                  <td><span className="sb-score">{aScore}</span></td>
                  <td className="sb-muted">{d.source || "—"}</td>
                  <td className="sb-muted">{d.first_seen || "—"}</td>
                  <td>
                    <details className="sb-actions">
                      <summary className="sb-btn sb-btn-ghost">Actions ▾</summary>
                      <div className="sb-actions-menu">
                        <button className="sb-btn" disabled={!d.id || !!busy} onClick={() => d.id && onView(d.id)}>Open</button>
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
                    </details>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="sb-pagination">
        <div className="sb-page-info">Page {pageDisplay} of {totalPages}</div>
        <div className="sb-row">
          {canPrev && <button className="sb-btn" onClick={() => onPage(filters.page - 1)}>&larr; Previous</button>}
          {canNext && <button className="sb-btn" onClick={() => onPage(filters.page + 1)}>Next &rarr;</button>}
        </div>
      </div>

      {error && <div className="sb-notice" style={{ marginTop: 8 }}>{error}</div>}
    </div>
  );
};

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
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div className="sb-panel">
        <div className="sb-panel-header">
          <span className="sb-panel-title">Evidence Files</span>
          <span className="sb-muted">{files.length ? `${files.length} files` : "No files"}</span>
        </div>
        <div className="sb-row" style={{ flexWrap: "wrap", gap: 8 }}>
          {files.length === 0 && <span className="sb-muted">No evidence files yet.</span>}
          {files.map((f) => (
            <a key={f.href} className="sb-btn" href={f.href} target="_blank" rel="noreferrer">{f.label}</a>
          ))}
        </div>
      </div>
      {shots.length > 0 && (
        <div className="sb-panel">
          <div className="sb-panel-header">
            <span className="sb-panel-title">Screenshots</span>
            <span className="sb-muted">{shots.length} captured</span>
          </div>
          <div className="sb-evidence-grid">
            {shots.map((s) => (
              <div key={s} className="sb-screenshot">
                <a href={s} target="_blank" rel="noreferrer"><img src={s} alt={s} /></a>
                <div className="sb-screenshot-label">{s.split("/").pop()}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

const ReportsTable = ({ data }: { data: DomainDetailResponse | null }) => {
  if (!data) return null;
  const rows = data.reports || [];
  if (rows.length === 0) return null;
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
              <th style={{ minWidth: 200 }}>Response</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={`${r.platform}-${r.created_at || r.id || Math.random()}`}>
                <td>{r.platform}</td>
                <td><span className={badgeClass(r.status, "report")}>{(r.status || "").toUpperCase()}</span></td>
                <td className="sb-muted">{formatDate(r.created_at)}</td>
                <td className="sb-muted">{formatDate(r.submitted_at as any)}</td>
                <td className="sb-muted">{formatDate((r as any).next_attempt_at)}</td>
                <td className="sb-muted" style={{ maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{(r as any).response || r.result || "—"}</td>
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
  const [statsUpdatedAt, setStatsUpdatedAt] = useState<Date | null>(null);

  const [filters, setFilters] = useState({ status: "", verdict: "", q: "", limit: 100, page: 1 });
  const [domains, setDomains] = useState<Domain[]>([]);
  const [domainsTotal, setDomainsTotal] = useState(0);
  const [domainsLoading, setDomainsLoading] = useState(true);
  const [domainsError, setDomainsError] = useState<string | null>(null);

  const [domainDetail, setDomainDetail] = useState<DomainDetailResponse | null>(null);
  const [domainDetailLoading, setDomainDetailLoading] = useState(false);

  const [clusters, setClusters] = useState<Cluster[]>([]);
  const [clusterDetail, setClusterDetail] = useState<{ cluster: Cluster; domains: Domain[] } | null>(null);
  const [clusterLoading, setClusterLoading] = useState(false);
  const [clusterBulkWorking, setClusterBulkWorking] = useState<"rescan" | "report" | null>(null);
  const [clusterSearch, setClusterSearch] = useState("");

  const [toast, setToast] = useState<{ message: string; tone?: "success" | "error" | "info" } | null>(null);
  const [submitValue, setSubmitValue] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitResult, setSubmitResult] = useState<{ status: string; domain: string } | null>(null);
  const [cleanupDays, setCleanupDays] = useState(30);
  const [cleanupBusy, setCleanupBusy] = useState(false);
  const [cleanupResult, setCleanupResult] = useState<string | null>(null);
  const [cleanupPreview, setCleanupPreview] = useState<{ count: number; bytes: number } | null>(null);
  const [cleanupError, setCleanupError] = useState<string | null>(null);
  const [actionBusy, setActionBusy] = useState<Record<number, string | null>>({});
  const [reportFilters, setReportFilters] = useState<{ status: string; platform: string }>({ status: "", platform: "" });

  // Report Panel state
  const [reportPanelOpen, setReportPanelOpen] = useState(false);
  const [reportPanelDomain, setReportPanelDomain] = useState<Domain | null>(null);
  const [reportPanelPlatforms, setReportPanelPlatforms] = useState<string[]>([]);
  const [reportPanelInfo, setReportPanelInfo] = useState<Record<string, PlatformInfo>>({});
  const [reportPanelSelected, setReportPanelSelected] = useState<Set<string>>(new Set());
  const [reportPanelSubmitting, setReportPanelSubmitting] = useState(false);
  const [reportPanelManualMode, setReportPanelManualMode] = useState<string | null>(null);
  const [reportPanelManualQueue, setReportPanelManualQueue] = useState<string[]>([]);

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
      setStatsUpdatedAt(new Date());
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
      const total = res.total ?? res.count ?? res.domains.length;
      setDomainsTotal(total);
      const maxPage = Math.max(1, Math.ceil(total / (filters.limit || 1)));
      if (filters.page > maxPage) {
        setFilters((prev) => ({ ...prev, page: maxPage }));
      }
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

  const handleSubmit = async (e: FormEvent | MouseEvent, mode: "submit" | "rescan" = "submit") => {
    e.preventDefault();
    setSubmitError(null);
    setSubmitResult(null);
    if (!submitValue.trim()) {
      setSubmitError("Enter a domain or URL to submit.");
      return;
    }
    setSubmitting(true);
    try {
      const res = await submitTarget(submitValue.trim());
      const message =
        res.status === "rescan_queued"
          ? `Rescan queued for ${res.domain}`
          : `Submitted ${res.domain}`;
      showToast(message, "success");
      setSubmitResult(res);
      if (mode === "submit") {
        setSubmitValue("");
      }
      loadDomains();
    } catch (err) {
      const msg = (err as Error).message || "Submit failed";
      setSubmitError(msg);
      showToast(msg, "error");
    } finally {
      setSubmitting(false);
    }
  };

  const handleCleanup = async (e: FormEvent) => {
    e.preventDefault();
    setCleanupError(null);
    setCleanupBusy(true);
    try {
      const days = cleanupDays || 30;
      const confirm = window.confirm(`Remove evidence older than ${days} days? This cannot be undone.`);
      if (!confirm) {
        setCleanupBusy(false);
        return;
      }
      const res = await cleanupEvidence(days);
      const removedBytes = res.removed_bytes ? ` (~${formatBytes(res.removed_bytes)})` : "";
      const msg = `Removed ${res.removed_dirs} evidence directories older than ${days} days${removedBytes}.`;
      setCleanupResult(msg);
      setCleanupPreview(null);
      showToast(msg, "success");
    } catch (err) {
      const msg = (err as Error).message || "Cleanup failed";
      setCleanupError(msg);
      showToast(msg, "error");
    } finally {
      setCleanupBusy(false);
    }
  };

  const handleCleanupPreview = async () => {
    setCleanupError(null);
    setCleanupBusy(true);
    try {
      const res = await cleanupEvidence(cleanupDays || 30, { preview: true });
      setCleanupPreview({ count: res.would_remove || 0, bytes: res.would_bytes || 0 });
    } catch (err) {
      const msg = (err as Error).message || "Preview failed";
      setCleanupError(msg);
      showToast(msg, "error");
    } finally {
      setCleanupBusy(false);
    }
  };

  // Open the report panel for a domain
  const openReportPanel = async (domain: Domain) => {
    if (!domain.id) {
      showToast("Domain id is missing for this record", "error");
      return;
    }
    if (["reported", "false_positive", "allowlisted"].includes((domain.status || "").toLowerCase())) {
      showToast("Reporting is not applicable for this domain state", "error");
      return;
    }

    setReportPanelDomain(domain);
    setReportPanelOpen(true);
    setReportPanelManualMode(null);
    setReportPanelManualQueue([]);
    setReportPanelSelected(new Set());

    // Fetch available platforms
    try {
      const data = await fetchPlatformInfo();
      setReportPanelPlatforms(data.platforms || []);
      setReportPanelInfo(data.info || {});
      // Pre-select all platforms by default
      setReportPanelSelected(new Set(data.platforms || []));
    } catch (err) {
      showToast((err as Error).message || "Failed to load platforms", "error");
    }
  };

  const openReportPanelById = async (domainId: number, domainName: string) => {
    try {
      const detail = await fetchDomainDetail(domainId);
      await openReportPanel(detail.domain);
    } catch (err) {
      showToast((err as Error).message || `Failed to open report panel for ${domainName}`, "error");
    }
  };

  const triggerAction = async (domain: Domain, type: "rescan" | "report" | "false_positive") => {
    const id = domain.id;
    if (!id) {
      showToast("Domain id is missing for this record", "error");
      return;
    }

    // For report, open the panel instead of direct API call
    if (type === "report") {
      openReportPanel(domain);
      return;
    }

    if (type === "false_positive" && (domain.status || "").toLowerCase() === "false_positive") {
      showToast("Already marked as false positive", "info");
      return;
    }
    if (type === "false_positive") {
      const ok = window.confirm(`Mark ${domain.domain} as false positive? This will affect reporting and stats.`);
      if (!ok) return;
    }
    setActionBusy((prev) => ({ ...prev, [id]: type }));
    try {
      if (type === "rescan") {
        await rescanDomain(id, domain.domain);
        showToast(`Rescan queued for ${domain.domain}`, "success");
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

  const changeStatus = async (domain: Domain, newStatus: string) => {
    const id = domain.id;
    if (!id) {
      showToast("Domain id is missing for this record", "error");
      return;
    }

    const statusLabels: Record<string, string> = {
      watchlist: "Watchlist",
      allowlisted: "Allowlist",
      false_positive: "False Positive",
      analyzed: "Analyzed",
    };

    const label = statusLabels[newStatus] || newStatus;
    const ok = window.confirm(`Change status of ${domain.domain} to ${label}?`);
    if (!ok) return;

    setActionBusy((prev) => ({ ...prev, [id]: "status_change" }));
    try {
      await updateDomainStatus(id, newStatus);
      showToast(`Changed ${domain.domain} to ${label}`, "success");
      loadDomains();
      if (route.name === "domain") loadDomainDetail(id);
    } catch (err) {
      showToast((err as Error).message || "Status change failed", "error");
    } finally {
      setActionBusy((prev) => ({ ...prev, [id]: null }));
    }
  };

  const bulkTriggerCluster = async (type: "rescan" | "report") => {
    if (!clusterDetail) return;
    const domains = (clusterDetail.domains || []).filter((d) => d.id) as Domain[];
    if (!domains.length) {
      showToast("No domains with IDs to process in this cluster", "error");
      return;
    }
    const ok = window.confirm(`Queue ${type} for ${domains.length} domains in this cluster?`);
    if (!ok) return;
    setClusterBulkWorking(type);
    try {
      for (const d of domains) {
        await triggerAction(d, type);
      }
      showToast(`Queued ${type} for ${domains.length} domains`, "success");
    } finally {
      setClusterBulkWorking(null);
    }
  };

  const healthLabel = useMemo(() => {
    if (!health || typeof health !== "object") return "Unknown";
    if ((health as any).ok) return "Healthy";
    return "Unhealthy";
  }, [health]);

  const pendingPlatforms = useMemo(
    () => Array.from(new Set(pendingReports.map((p) => p.platform).filter(Boolean))),
    [pendingReports],
  );

  const filteredPendingReports = useMemo(() => {
    const list = pendingReports.filter((r) => {
      const statusOk = !reportFilters.status || (r.status || "").toLowerCase() === reportFilters.status;
      const platformOk = !reportFilters.platform || r.platform === reportFilters.platform;
      return statusOk && platformOk;
    });
    return [...list].sort((a, b) => {
      const aDate = new Date(a.next_attempt_at || a.created_at || 0).getTime();
      const bDate = new Date(b.next_attempt_at || b.created_at || 0).getTime();
      return aDate - bDate;
    });
  }, [pendingReports, reportFilters]);

  const filteredClusters = useMemo(() => {
    const term = clusterSearch.trim().toLowerCase();
    if (!term) return clusters;
    return clusters.filter((c) => {
      const haystack = `${c.name || ""} ${c.cluster_id || ""} ${(c.members || []).map((m) => m.domain).join(" ")}`.toLowerCase();
      return haystack.includes(term);
    });
  }, [clusters, clusterSearch]);

  const nextReportAttempt = useMemo(() => {
    if (!domainDetail?.reports) return null;
    const times = domainDetail.reports
      .map((r) => r.next_attempt_at)
      .filter(Boolean) as string[];
    if (!times.length) return null;
    return times.sort()[0];
  }, [domainDetail]);

  const statsBlocks = useMemo(() => {
    if (!stats) return null;
    const refreshed = statsUpdatedAt ? `Refreshed ${timeAgo(statsUpdatedAt.toISOString())}` : "Awaiting data";
    return (
      <>
        <div className="sb-grid" style={{ marginBottom: 12 }}>
          <div className="col-4">
            <div className="sb-stat">
              <div className="sb-stat-label">Total Domains</div>
              <div className="sb-stat-value">{stats.total}</div>
              <div className="sb-stat-meta">Last 24h: <b>{stats.last_24h}</b></div>
            </div>
          </div>
          <div className="col-4"><div className="sb-stat"><div className="sb-stat-label">By Status</div><Breakdown items={stats.by_status || {}} onSelect={(key) => setFilters((prev) => ({ ...prev, status: key === "all" ? "" : key, page: 1 }))} /></div></div>
          <div className="col-4"><div className="sb-stat"><div className="sb-stat-label">By Verdict</div><Breakdown items={stats.by_verdict || {}} onSelect={(key) => setFilters((prev) => ({ ...prev, verdict: key === "all" ? "" : key, page: 1 }))} /></div></div>
          <div className="col-4"><div className="sb-stat"><div className="sb-stat-label">Reports</div><Breakdown items={stats.reports || {}} /></div></div>
          <div className="col-4"><div className="sb-stat"><div className="sb-stat-label">Dashboard Actions</div><Breakdown items={stats.dashboard_actions || {}} /></div></div>
          <div className="col-4"><div className="sb-stat"><div className="sb-stat-label">Evidence Storage</div><div className="sb-stat-value">{formatBytes(stats.evidence_bytes)}</div><div className="sb-stat-meta">Approximate evidence size</div></div></div>
        </div>
        <div className="sb-muted" style={{ marginTop: -8, marginBottom: 12, fontSize: 12 }}>{refreshed}</div>
      </>
    );
  }, [stats, statsUpdatedAt, setFilters]);

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

      {/* Action panels row - full width, side by side */}
      <div className="sb-grid" style={{ marginBottom: 16 }}>
        <div className="col-4">
          {healthPanel}
        </div>
        <div className="col-4">
          <div className="sb-panel" style={{ borderColor: "rgba(88, 166, 255, 0.3)", height: "100%" }}>
            <div className="sb-panel-header" style={{ borderColor: "rgba(88, 166, 255, 0.2)" }}>
              <span className="sb-panel-title" style={{ color: "var(--accent-blue)" }}>Manual Submission</span>
            </div>
            <form onSubmit={(e) => handleSubmit(e, "submit")}>
              <input className="sb-input" placeholder="example.com or https://target" value={submitValue} onChange={(e) => setSubmitValue(e.target.value)} style={{ marginBottom: 10 }} />
              <div className="sb-row" style={{ justifyContent: "flex-end", gap: 8 }}>
                <button className="sb-btn" type="button" disabled={submitting} onClick={(e) => handleSubmit(e, "rescan")}>
                  {submitting ? "Working…" : "Force Rescan"}
                </button>
                <button className="sb-btn sb-btn-primary" type="submit" disabled={submitting}>{submitting ? "Submitting…" : "Submit New"}</button>
              </div>
              {submitError && <div className="sb-notice" style={{ color: "var(--accent-red)", marginTop: 8 }}>{submitError}</div>}
              {submitResult && (
                <div className="sb-flash sb-flash-success" style={{ marginTop: 8 }}>
                  {submitResult.status === "rescan_queued" ? "Rescan queued" : "Submitted"} for <b>{submitResult.domain}</b>
                </div>
              )}
            </form>
          </div>
        </div>
        <div className="col-4">
          <div className="sb-panel" style={{ borderColor: "rgba(63, 185, 80, 0.3)", height: "100%" }}>
            <div className="sb-panel-header" style={{ borderColor: "rgba(63, 185, 80, 0.2)" }}>
              <span className="sb-panel-title" style={{ color: "var(--accent-green)" }}>Evidence Cleanup</span>
            </div>
            <div className="sb-row" style={{ alignItems: "flex-start", gap: 8, flexWrap: "wrap" }}>
              <input className="sb-input" type="number" min={1} value={cleanupDays} onChange={(e) => setCleanupDays(Number(e.target.value) || 1)} style={{ width: 80 }} />
              <span className="sb-muted">days old</span>
              <button className="sb-btn" type="button" disabled={cleanupBusy} onClick={handleCleanupPreview}>{cleanupBusy ? "Working…" : "Preview"}</button>
              <button className="sb-btn sb-btn-danger" type="button" disabled={cleanupBusy} onClick={handleCleanup}>{cleanupBusy ? "Cleaning…" : "Cleanup"}</button>
            </div>
            {cleanupPreview && (
              <div className="sb-notice" style={{ marginTop: 8 }}>
                Would remove <b>{cleanupPreview.count}</b> directories (~{formatBytes(cleanupPreview.bytes)})
              </div>
            )}
            {cleanupResult && <div className="sb-muted" style={{ marginTop: 8 }}>{cleanupResult}</div>}
            {cleanupError && <div className="sb-notice" style={{ color: "var(--accent-red)", marginTop: 8 }}>{cleanupError}</div>}
          </div>
        </div>
      </div>

      {/* Reports Needing Attention - full width when present */}
      {pendingReports.length > 0 && (
        <div className="sb-panel" style={{ borderColor: "rgba(240, 136, 62, 0.3)", marginBottom: 16 }}>
          <div className="sb-panel-header" style={{ borderColor: "rgba(240, 136, 62, 0.2)" }}>
            <span className="sb-panel-title" style={{ color: "var(--accent-orange)" }}>Reports Needing Attention ({filteredPendingReports.length})</span>
            <div className="sb-row" style={{ gap: 8 }}>
              <select
                className="sb-select"
                value={reportFilters.status}
                onChange={(e) => setReportFilters((prev) => ({ ...prev, status: e.target.value }))}
              >
                <option value="">All Statuses</option>
                <option value="pending">Pending</option>
                <option value="manual_required">Manual</option>
                <option value="rate_limited">Rate Limited</option>
              </select>
              <select
                className="sb-select"
                value={reportFilters.platform}
                onChange={(e) => setReportFilters((prev) => ({ ...prev, platform: e.target.value }))}
              >
                <option value="">All Platforms</option>
                {pendingPlatforms.map((p) => <option key={p} value={p}>{p}</option>)}
              </select>
            </div>
          </div>
          <div className="sb-table-wrap">
            <table className="sb-table">
              <thead>
                <tr><th>Domain</th><th>Platform</th><th>Status</th><th>Attempts</th><th>Next Attempt</th><th>Last Response</th></tr>
              </thead>
              <tbody>
                {filteredPendingReports.slice(0, 20).map((r) => (
                  <tr key={`${r.domain}-${r.platform}`}>
                    <td>
                      <a
                        className="domain-link"
                        href="#"
                        onClick={(e) => {
                          e.preventDefault();
                          if (!r.domain_id) {
                            showToast("Domain ID missing for this report", "error");
                            return;
                          }
                          openReportPanelById(r.domain_id, r.domain);
                        }}
                      >
                        {r.domain}
                      </a>
                    </td>
                    <td>{r.platform}</td>
                    <td><span className={badgeClass(r.status, "report")}>{(r.status || "").toUpperCase()}</span></td>
                    <td className="sb-muted">{r.attempts ?? "—"}</td>
                    <td className="sb-muted">{r.next_attempt_at ? timeAgo(r.next_attempt_at) : "—"}</td>
                    <td className="sb-muted" style={{ maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{r.response || ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Domain table - full width */}
      <DomainTable
        domains={domains}
        loading={domainsLoading}
        error={domainsError}
        total={domainsTotal}
        filters={filters}
        onFiltersChange={(next) => setFilters((prev) => ({ ...prev, ...next }))}
        onPage={(nextPage) => {
          setFilters((prev) => {
            const maxPage = Math.max(1, Math.ceil((domainsTotal || 0) / (prev.limit || 1)) || 1);
            const clamped = Math.min(Math.max(1, nextPage), maxPage);
            return { ...prev, page: clamped };
          });
        }}
        onView={(id) => { window.location.hash = `#/domains/${id}`; }}
        onRescan={(d) => triggerAction(d, "rescan")}
        onReport={(d) => triggerAction(d, "report")}
        onFalsePositive={(d) => triggerAction(d, "false_positive")}
        actionBusy={actionBusy}
      />
    </>
  );

  const clustersView = (
    <div className="sb-panel">
      <div className="sb-panel-header">
        <span className="sb-panel-title">Threat Clusters</span>
        <div className="sb-row" style={{ gap: 12 }}>
          <input
            className="sb-input"
            placeholder="Search clusters or domains"
            value={clusterSearch}
            onChange={(e) => setClusterSearch(e.target.value)}
            style={{ width: 280 }}
          />
          <span className="sb-muted">{filteredClusters.length} clusters</span>
        </div>
      </div>
      {clusterLoading && <div className="sb-muted">Loading clusters…</div>}
      {!clusterLoading && filteredClusters.length === 0 && <div className="sb-muted">No clusters yet.</div>}
      {!clusterLoading && filteredClusters.length > 0 && (
        <div className="sb-grid" style={{ gap: 16 }}>
          {filteredClusters.map((c) => {
            const indicators = [
              ...(c.shared_backends || []),
              ...(c.shared_nameservers || []),
              ...(c.shared_kits || []),
            ].slice(0, 3);
            return (
              <div key={c.cluster_id} className="col-6">
                <div className="sb-panel" style={{ borderColor: "rgba(163, 113, 247, 0.3)", margin: 0 }}>
                  <div className="sb-panel-header" style={{ borderColor: "rgba(163, 113, 247, 0.2)" }}>
                    <div>
                      <div className="sb-panel-title" style={{ color: "var(--accent-purple)" }}>{c.name || c.cluster_id}</div>
                      <div className="sb-muted">Members: {c.members?.length ?? 0}</div>
                    </div>
                    <a className="sb-btn" href={`#/clusters/${c.cluster_id}`}>View</a>
                  </div>
                  <div className="sb-breakdown">
                    {(c.members || []).slice(0, 3).map((m) => (
                      <div key={m.domain} className="sb-breakdown-item">
                        <span className="sb-breakdown-key">{m.domain}</span>
                        <span className="sb-muted">{m.added_at || ""}</span>
                      </div>
                    ))}
                  </div>
                  {indicators.length > 0 && (
                    <div className="sb-row" style={{ flexWrap: "wrap", gap: 6, marginTop: 8 }}>
                      {indicators.map((ind) => <code key={ind as string} className="sb-code">{ind as string}</code>)}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );

  const clusterDetailView = (
    <div className="sb-grid" style={{ gap: 12 }}>
      <div className="sb-row"><a className="sb-btn" href="#/clusters">&larr; Back</a></div>
      {clusterDetail?.cluster && (
        <div className="sb-row" style={{ flexWrap: "wrap", gap: 8 }}>
          <button className="sb-btn" disabled={clusterBulkWorking === "rescan"} onClick={() => bulkTriggerCluster("rescan")}>
            {clusterBulkWorking === "rescan" ? "Queuing…" : "Bulk Rescan"}
          </button>
          <button className="sb-btn" disabled={clusterBulkWorking === "report"} onClick={() => bulkTriggerCluster("report")}>
            {clusterBulkWorking === "report" ? "Queuing…" : "Bulk Report"}
          </button>
          <a className="sb-btn" href={`/admin/clusters/${clusterDetail.cluster.cluster_id}/pdf`} target="_blank" rel="noreferrer">Cluster PDF</a>
          <a className="sb-btn" href={`/admin/clusters/${clusterDetail.cluster.cluster_id}/package`} target="_blank" rel="noreferrer">Cluster Package</a>
        </div>
      )}
      {clusterLoading && <div className="sb-muted">Loading cluster…</div>}
      {!clusterLoading && <ClusterCard cluster={clusterDetail?.cluster} related={clusterDetail?.domains || []} />}
    </div>
  );

  const domainDetailView = (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div className="sb-row"><a className="sb-btn" href="#/">&larr; Back</a></div>
      {domainDetailLoading && (
        <div className="sb-panel"><div className="skeleton" style={{ height: 24, marginBottom: 10 }} /><div className="skeleton" style={{ height: 12 }} /></div>
      )}
      {!domainDetailLoading && domainDetail && (
        <>
          {(domainDetail.domain.action_required || domainDetail.domain.operator_notes) && (
            <div className={`sb-flash ${domainDetail.domain.action_required ? "sb-flash-error" : "sb-flash-success"}`}>
              {domainDetail.domain.action_required || domainDetail.domain.operator_notes}
            </div>
          )}

          {/* Main domain info panel */}
          <div className="sb-panel">
            <div className="sb-row sb-space-between" style={{ alignItems: "flex-start", flexWrap: "wrap", gap: 16 }}>
              <div style={{ flex: 1, minWidth: 280 }}>
                <div style={{ fontSize: 22, fontWeight: 700, marginBottom: 8 }}>{domainDetail.domain.domain}</div>
                <div className="sb-row" style={{ gap: 8, flexWrap: "wrap" }}>
                  <span className={badgeClass(domainDetail.domain.status, "status")}>{(domainDetail.domain.status || "unknown").toUpperCase()}</span>
                  <span className={badgeClass(domainDetail.domain.verdict, "verdict")}>{(domainDetail.domain.verdict || "unknown").toUpperCase()}</span>
                  <span className="sb-muted">ID: {domainDetail.domain.id ?? "N/A"}</span>
                  {domainDetail.domain.last_checked_at && <span className="sb-muted">Last checked {timeAgo(domainDetail.domain.last_checked_at)}</span>}
                </div>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 12, alignItems: "flex-end" }}>
                {/* Primary action buttons */}
                <div className="sb-row" style={{ flexWrap: "wrap", gap: 8 }}>
                  <button className="sb-btn sb-btn-primary" disabled={!domainDetail.domain.id || !!actionBusy[domainDetail.domain.id!]} onClick={() => triggerAction(domainDetail.domain, "rescan")}>
                    {actionBusy[domainDetail.domain.id || 0] === "rescan" ? "Rescanning…" : "Rescan"}
                  </button>
                  <button className="sb-btn" disabled={!domainDetail.domain.id || !!actionBusy[domainDetail.domain.id!]} onClick={() => triggerAction(domainDetail.domain, "report")}>
                    {actionBusy[domainDetail.domain.id || 0] === "report" ? "Reporting…" : "Report"}
                  </button>
                </div>
                {/* Status action buttons */}
                {(() => {
                  const currentStatus = (domainDetail.domain.status || "").toLowerCase();
                  const isTerminal = ["false_positive", "allowlisted"].includes(currentStatus);
                  const isBusy = !!actionBusy[domainDetail.domain.id || 0];

                  if (isTerminal) {
                    return (
                      <button className="sb-btn" disabled={!domainDetail.domain.id || isBusy} onClick={() => changeStatus(domainDetail.domain, "analyzed")}>
                        {isBusy ? "Reactivating…" : "↻ Reactivate"}
                      </button>
                    );
                  }

                  return (
                    <div className="sb-row" style={{ flexWrap: "wrap", gap: 8 }}>
                      {currentStatus !== "watchlist" && (
                        <button className="sb-btn" disabled={!domainDetail.domain.id || isBusy} onClick={() => changeStatus(domainDetail.domain, "watchlist")}>
                          {isBusy ? "Working…" : "👁 Watch"}
                        </button>
                      )}
                      {currentStatus !== "false_positive" && (
                        <button className="sb-btn sb-btn-danger" disabled={!domainDetail.domain.id || isBusy} onClick={() => changeStatus(domainDetail.domain, "false_positive")}>
                          {isBusy ? "Marking…" : "✕ False Positive"}
                        </button>
                      )}
                      {currentStatus !== "allowlisted" && (
                        <button className="sb-btn" disabled={!domainDetail.domain.id || isBusy} onClick={() => changeStatus(domainDetail.domain, "allowlisted")}>
                          {isBusy ? "Adding…" : "✓ Allowlist"}
                        </button>
                      )}
                    </div>
                  );
                })()}
              </div>
            </div>

            {/* Metadata grid */}
            <div className="sb-grid" style={{ marginTop: 16, gap: 12 }}>
              {[
                ["Domain score", (domainDetail.domain as any).domain_score ?? (domainDetail.domain as any).score ?? "\u2014"],
                ["Analysis score", (domainDetail.domain as any).analysis_score ?? "\u2014"],
                ["Source", domainDetail.domain.source || "\u2014"],
                ["First seen", domainDetail.domain.first_seen || "\u2014"],
                ["Analyzed at", domainDetail.domain.analyzed_at || "\u2014"],
                ["Reported at", (domainDetail.domain as any).reported_at || "\u2014"],
                ["Updated", domainDetail.domain.updated_at || "\u2014"],
              ].map(([label, value]) => (
                <div key={label as string} className="col-3">
                  <div className="sb-label">{label as string}</div>
                  <div className="sb-muted">{value as string}</div>
                </div>
              ))}
            </div>

            {/* Watchlist baseline section */}
            {(() => {
              const currentStatus = (domainDetail.domain.status || "").toLowerCase();
              if (currentStatus !== "watchlist") return null;

              const isBusy = !!actionBusy[domainDetail.domain.id || 0];

              return (
                <div className="sb-section" style={{ marginTop: 16, padding: 12, background: "var(--accent-orange-subtle)", borderRadius: 8 }}>
                  <div className="sb-row" style={{ justifyContent: "space-between", alignItems: "center" }}>
                    <div>
                      <div className="sb-label" style={{ color: "var(--accent-orange)" }}>Watchlist Baseline</div>
                      <div className="sb-muted" style={{ fontSize: "0.875rem", marginTop: 4 }}>
                        {(domainDetail.domain as any).watchlist_baseline_timestamp || "Not set"}
                      </div>
                    </div>
                    <button
                      className="sb-btn"
                      disabled={isBusy}
                      onClick={async () => {
                        if (!domainDetail.domain.id) return;
                        setActionBusy(prev => ({ ...prev, [domainDetail.domain.id!]: "baseline" }));
                        try {
                          const response = await fetch(
                            `/admin/api/domains/${domainDetail.domain.id}/baseline`,
                            { method: "POST" }
                          );
                          if (response.ok) {
                            const data = await response.json();
                            showToast(`Baseline updated to ${data.baseline_timestamp}`, "success");
                            // Refresh domain detail
                            await loadDomainDetail(domainDetail.domain.id);
                          } else {
                            const error = await response.text();
                            showToast(`Failed to update baseline: ${error}`, "error");
                          }
                        } catch (err) {
                          showToast(`Error updating baseline: ${err}`, "error");
                        } finally {
                          setActionBusy(prev => ({ ...prev, [domainDetail.domain.id!]: null }));
                        }
                      }}
                    >
                      {isBusy ? "Updating…" : "Update Baseline"}
                    </button>
                  </div>
                </div>
              );
            })()}

            {/* Download links */}
            <div className="sb-row" style={{ flexWrap: "wrap", marginTop: 16, gap: 8 }}>
              {domainDetail.domain.id && (
                <>
                  <a className="sb-btn" href={`/admin/domains/${domainDetail.domain.id}/pdf`} target="_blank" rel="noreferrer">Download PDF</a>
                  <a className="sb-btn" href={`/admin/domains/${domainDetail.domain.id}/package`} target="_blank" rel="noreferrer">Download Package</a>
                </>
              )}
              {domainDetail.reports && domainDetail.reports.length > 0 && (
                <span className="sb-muted">
                  Next report attempt: {nextReportAttempt || "\u2014"}
                </span>
              )}
            </div>
          </div>

          <EvidenceSection data={domainDetail} />
          <ReportsTable data={domainDetail} />

          {/* Verdict and Notes panels */}
          <div className="sb-grid" style={{ gap: 16 }}>
            <div className="col-6">
              <div className="sb-panel" style={{ margin: 0 }}>
                <div className="sb-panel-header"><span className="sb-panel-title">Verdict Reasons</span></div>
                <VerdictReasons reasons={domainDetail.domain.verdict_reasons as any} />
              </div>
            </div>
            <div className="col-6">
              <div className="sb-panel" style={{ margin: 0 }}>
                <div className="sb-panel-header"><span className="sb-panel-title">Operator Notes</span></div>
                {domainDetail.domain.operator_notes ? (
                  <pre className="sb-pre">{domainDetail.domain.operator_notes as any}</pre>
                ) : (
                  <div className="sb-muted">\u2014</div>
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

      {/* Report Panel Slide-out */}
      <div className={`sb-slideout-overlay ${reportPanelOpen ? "open" : ""}`} onClick={() => { setReportPanelOpen(false); setReportPanelManualMode(null); }} />
      <div className={`sb-slideout-panel ${reportPanelOpen ? "open" : ""}`}>
        {reportPanelOpen && reportPanelDomain && (
          <>
            <div className="sb-slideout-header">
              <span className="sb-slideout-title">
                {reportPanelManualMode ? `${reportPanelManualMode.toUpperCase()} Manual Submission` : `Report ${reportPanelDomain.domain}`}
              </span>
              <button className="sb-slideout-close" onClick={() => { setReportPanelOpen(false); setReportPanelManualMode(null); }}>×</button>
            </div>
            <div className="sb-slideout-body">
              {reportPanelManualMode ? (
                <>
                  {/* Progress indicator */}
                  {reportPanelManualQueue.length > 1 && (
                    <div style={{ marginBottom: 16, padding: "8px 12px", background: "var(--bg-elevated)", borderRadius: "var(--radius-md)", border: "1px solid var(--border-default)" }}>
                      <div style={{ fontSize: 12, color: "var(--text-secondary)", marginBottom: 4 }}>
                        Platform {reportPanelManualQueue.indexOf(reportPanelManualMode) + 1} of {reportPanelManualQueue.length}
                      </div>
                      <div style={{ height: 4, background: "var(--border-default)", borderRadius: 2 }}>
                        <div style={{ height: "100%", background: "var(--accent-blue)", borderRadius: 2, width: `${((reportPanelManualQueue.indexOf(reportPanelManualMode) + 1) / reportPanelManualQueue.length) * 100}%` }} />
                      </div>
                    </div>
                  )}

                  {reportPanelInfo[reportPanelManualMode]?.url && (
                    <div className="sb-manual-cta">
                      <a className="sb-manual-cta-btn" href={reportPanelInfo[reportPanelManualMode].url} target="_blank" rel="noopener noreferrer">
                        ↗ Open {reportPanelManualMode.charAt(0).toUpperCase() + reportPanelManualMode.slice(1)} Abuse Form
                      </a>
                    </div>
                  )}
                  <div className="sb-copy-field">
                    <div className="sb-copy-field-label">Full URL</div>
                    <div className="sb-copy-field-value" style={{ position: "relative" }}>
                      {`https://${reportPanelDomain.domain}`}
                      <button className="sb-copy-btn" onClick={(e) => {
                        navigator.clipboard.writeText(`https://${reportPanelDomain.domain}`);
                        const btn = e.currentTarget;
                        btn.textContent = "Copied!";
                        btn.classList.add("copied");
                        setTimeout(() => { btn.textContent = "Copy"; btn.classList.remove("copied"); }, 1500);
                      }}>Copy</button>
                    </div>
                  </div>
                  <div className="sb-copy-field">
                    <div className="sb-copy-field-label">Additional Details Template</div>
                    <div className="sb-copy-field-value multiline" style={{ position: "relative", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
                      {(() => {
                        const verdict = domainDetail?.domain?.verdict || reportPanelDomain.verdict || "malicious";
                        const verdictReasons = domainDetail?.domain?.verdict_reasons || "";

                        let template = `Reporting ${verdict} phishing/scam site.\n\n`;

                        if (verdictReasons) {
                          const reasons = verdictReasons.split("\n").map((line: string) => line.trim()).filter(Boolean);
                          // Deduplicate reasons
                          const uniqueReasons = Array.from(new Set(reasons));
                          if (uniqueReasons.length > 0) {
                            template += "Evidence:\n";
                            uniqueReasons.slice(0, 5).forEach((reason: string) => {
                              template += `- ${reason}\n`;
                            });
                            template += "\n";
                          }
                        }

                        template += "This site poses a security risk to users.";

                        return template;
                      })()}
                      <button className="sb-copy-btn" onClick={(e) => {
                        const verdict = domainDetail?.domain?.verdict || reportPanelDomain.verdict || "malicious";
                        const verdictReasons = domainDetail?.domain?.verdict_reasons || "";

                        let template = `Reporting ${verdict} phishing/scam site.\n\n`;

                        if (verdictReasons) {
                          const reasons = verdictReasons.split("\n").map((line: string) => line.trim()).filter(Boolean);
                          // Deduplicate reasons
                          const uniqueReasons = Array.from(new Set(reasons));
                          if (uniqueReasons.length > 0) {
                            template += "Evidence:\n";
                            uniqueReasons.slice(0, 5).forEach((reason: string) => {
                              template += `- ${reason}\n`;
                            });
                            template += "\n";
                          }
                        }

                        template += "This site poses a security risk to users.";

                        navigator.clipboard.writeText(template);
                        const btn = e.currentTarget;
                        btn.textContent = "Copied!";
                        btn.classList.add("copied");
                        setTimeout(() => { btn.textContent = "Copy"; btn.classList.remove("copied"); }, 1500);
                      }}>Copy</button>
                    </div>
                  </div>
                  <div className="sb-manual-notes">
                    <div className="sb-manual-notes-title">Tips</div>
                    <ul>
                      <li>Copy the URL and paste into "URL to report" field</li>
                      <li>Copy the Additional Details template and paste into the form's description field</li>
                      <li>Review and edit the template if needed before submitting</li>
                    </ul>
                  </div>
                  <div style={{ marginTop: 20, display: "flex", gap: 8, flexWrap: "wrap" }}>
                    {(() => {
                      const currentIndex = reportPanelManualQueue.indexOf(reportPanelManualMode);
                      const hasNext = currentIndex < reportPanelManualQueue.length - 1;
                      const nextPlatform = hasNext ? reportPanelManualQueue[currentIndex + 1] : null;

                      return (
                        <>
                          {hasNext ? (
                            <button
                              className="sb-btn sb-btn-primary"
                              onClick={() => setReportPanelManualMode(nextPlatform!)}
                            >
                              ✓ Done — Next: {nextPlatform!.charAt(0).toUpperCase() + nextPlatform!.slice(1)}
                            </button>
                          ) : (
                            <button
                              className="sb-btn sb-btn-primary"
                              onClick={() => {
                                setReportPanelOpen(false);
                                setReportPanelManualMode(null);
                                setReportPanelManualQueue([]);
                                loadDomains();
                                if (route.name === "domain" && reportPanelDomain.id) {
                                  loadDomainDetail(reportPanelDomain.id);
                                }
                                showToast("All manual submissions complete!", "success");
                              }}
                            >
                              ✓ Done — Close
                            </button>
                          )}
                          <button className="sb-btn" onClick={() => {
                            setReportPanelManualMode(null);
                            setReportPanelManualQueue([]);
                          }}>← Back to Platforms</button>
                        </>
                      );
                    })()}
                  </div>
                </>
              ) : (
                <>
                  <div className="sb-copy-field-label" style={{ marginBottom: 12 }}>Select platforms to report to:</div>
                  {reportPanelPlatforms.length === 0 ? (
                    <div className="sb-muted">Loading platforms...</div>
                  ) : (
                    <>
                      <div className="sb-report-platform-list">
                        {reportPanelPlatforms.map((platform) => {
                          const info = reportPanelInfo[platform] || {};
                          const isManual = info.manual_only;
                          const isSelected = reportPanelSelected.has(platform);
                          return (
                            <label key={platform} className="sb-report-platform-item">
                              <input
                                type="checkbox"
                                checked={isSelected}
                                onChange={(e) => {
                                  const next = new Set(reportPanelSelected);
                                  if (e.target.checked) {
                                    next.add(platform);
                                  } else {
                                    next.delete(platform);
                                  }
                                  setReportPanelSelected(next);
                                }}
                              />
                              <span className="sb-report-platform-name">{platform.charAt(0).toUpperCase() + platform.slice(1)}</span>
                              <span className={`sb-badge ${isManual ? "sb-badge-manual" : "sb-badge-auto"}`}>
                                {isManual ? "Manual" : "Auto"}
                              </span>
                            </label>
                          );
                        })}
                      </div>
                      <div className="sb-row" style={{ marginTop: 16, gap: 8 }}>
                        <button className="sb-btn" onClick={() => setReportPanelSelected(new Set(reportPanelPlatforms))}>Select All</button>
                        <button className="sb-btn" onClick={() => setReportPanelSelected(new Set())}>Clear</button>
                      </div>
                      <div style={{ marginTop: 20, borderTop: "1px solid var(--border-default)", paddingTop: 16 }}>
                        <button
                          className="sb-btn sb-btn-primary"
                          disabled={reportPanelSubmitting || reportPanelSelected.size === 0}
                          onClick={async () => {
                            if (!reportPanelDomain?.id) return;
                            const selectedList = Array.from(reportPanelSelected);
                            const autoPlatforms = selectedList.filter(p => !reportPanelInfo[p]?.manual_only);
                            const manualPlatforms = selectedList.filter(p => reportPanelInfo[p]?.manual_only);

                            setReportPanelSubmitting(true);
                            try {
                              if (autoPlatforms.length > 0) {
                                await reportDomain(reportPanelDomain.id, reportPanelDomain.domain, autoPlatforms);
                                showToast(`Report queued for: ${autoPlatforms.join(", ")}`, "success");
                              }

                              if (manualPlatforms.length > 0) {
                                setReportPanelManualQueue(manualPlatforms);
                                setReportPanelManualMode(manualPlatforms[0]);
                              } else {
                                setReportPanelOpen(false);
                                loadDomains();
                                if (route.name === "domain" && reportPanelDomain.id) {
                                  loadDomainDetail(reportPanelDomain.id);
                                }
                              }
                            } catch (err) {
                              showToast((err as Error).message || "Report failed", "error");
                            } finally {
                              setReportPanelSubmitting(false);
                            }
                          }}
                        >
                          {reportPanelSubmitting ? "Submitting..." : `Submit ${reportPanelSelected.size} Platform${reportPanelSelected.size !== 1 ? "s" : ""}`}
                        </button>
                      </div>
                      <div className="sb-manual-notes" style={{ marginTop: 16 }}>
                        <div className="sb-manual-notes-title">How it works</div>
                        <ul>
                          <li><strong>Auto</strong> platforms are submitted automatically via API</li>
                          <li><strong>Manual</strong> platforms will show a form with copy-paste fields</li>
                        </ul>
                      </div>
                    </>
                  )}
                </>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
