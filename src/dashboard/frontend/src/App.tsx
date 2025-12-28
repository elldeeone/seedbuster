import { useEffect, useMemo, useState, useCallback } from "react";
import type { FormEvent, MouseEvent } from "react";
import "./index.css";
import {
  cleanupEvidence,
  fetchCampaign,
  fetchCampaigns,
  fetchDomainDetail,
  fetchDomains,
  fetchPublicSubmissions,
  fetchStats,
  isAdminMode,
  markFalsePositive,
  approvePublicSubmission,
  rejectPublicSubmission,
  recordReportEngagement,
  reportDomain,
  rescanDomain,
  submitPublicTarget,
  submitTarget,
  updateDomainStatus,
  updateOperatorNotes,
  updateCampaignName,
  fetchReportOptions,
  fetchAnalytics,
  updateWatchlistBaseline,
} from "./api";
import type { PlatformInfo } from "./api";
import type {
  Campaign,
  Domain,
  DomainDetailResponse,
  ManualSubmissionData,
  PendingReport,
  PublicSubmission,
  AnalyticsResponse,
  ReportOptionsResponse,
  Stats,
} from "./types";

type Route =
  | { name: "dashboard" }
  | { name: "domain"; id: number }
  | { name: "campaigns" }
  | { name: "campaign"; id: string };

const STATUS_OPTIONS = ["dangerous", "", "pending", "analyzing", "analyzed", "reported", "failed", "watchlist", "allowlisted", "false_positive"];
const VERDICT_OPTIONS = ["", "high", "medium", "low", "benign", "unknown", "false_positive"];
const LIMIT_OPTIONS = [25, 50, 100, 200, 500];

// Statuses to exclude when using "dangerous" filter mode
const EXCLUDED_STATUSES = ["watchlist", "false_positive", "allowlisted"];

const isPublicReportEligible = (domain?: Domain | null) => {
  if (!domain) return false;
  const status = (domain.status || "").toLowerCase();
  const verdict = (domain.verdict || "").toLowerCase();
  if (["allowlisted", "false_positive", "watchlist"].includes(status)) return false;
  if (verdict === "benign") return false;
  return true;
};

const parseHash = (): Route => {
  const rawHash = window.location.hash.replace(/^#/, "");
  const hashParts = rawHash.split("/").filter(Boolean);
  const pathParts = window.location.pathname.split("/").filter(Boolean);
  const parts = hashParts.length ? hashParts : pathParts;

  if (parts[0] === "domains" && parts[1]) {
    const id = Number(parts[1]);
    if (!Number.isNaN(id)) return { name: "domain", id };
  }

  if (parts[0] === "campaigns") {
    if (parts[1]) {
      return { name: "campaign", id: parts[1] };
    }
    return { name: "campaigns" };
  }

  // Default view: both modes land on dashboard (read-only for public)
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

const renderInfraList = (items?: string[] | null) => {
  if (!items || items.length === 0) return <div className="sb-muted">—</div>;
  return (
    <div className="sb-muted">
      {items.slice(0, 3).join(", ")}
      {items.length > 3 ? " …" : ""}
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
  canEdit,
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
  canEdit: boolean;
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
                {s === "dangerous" ? "Dangerous Only" : s ? s.toUpperCase() : "All Statuses"}
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
              <th>{canEdit ? "Actions" : "View"}</th>
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
                    {canEdit ? (
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
                    ) : (
                      <button className="sb-btn" disabled={!d.id} onClick={() => d.id && onView(d.id)}>Open</button>
                    )}
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

const CampaignCard = ({ campaign, related }: { campaign: Campaign | null | undefined; related: Domain[] }) => {
  if (!campaign) return null;
  const indicators = [
    { label: "Backends", values: campaign.shared_backends || [] },
    { label: "Kits", values: campaign.shared_kits || [] },
    { label: "Nameservers", values: campaign.shared_nameservers || [] },
  ];
  return (
    <div className="sb-panel" style={{ borderColor: "rgba(163, 113, 247, 0.3)" }}>
      <div className="sb-panel-header" style={{ borderColor: "rgba(163, 113, 247, 0.2)" }}>
        <div>
          <span className="sb-panel-title" style={{ color: "var(--accent-purple)" }}>Threat Campaign</span>
          <span className="sb-muted" style={{ marginLeft: 8 }}>Campaign ID: {campaign.campaign_id}</span>
        </div>
        <a className="sb-btn" href="#/campaigns">View all</a>
      </div>
      <div className="sb-grid">
        <div className="col-6">
          <div className="sb-label">Campaign Name</div>
          <div style={{ fontSize: 16, fontWeight: 600 }}>{campaign.name || campaign.campaign_id}</div>
        </div>
        <div className="col-6">
          <div className="sb-label">Members</div>
          <div className="sb-muted">{campaign.members?.length ?? 0}</div>
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

  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [campaignDetail, setCampaignDetail] = useState<{ campaign: Campaign; domains: Domain[] } | null>(null);
  const [campaignLoading, setCampaignLoading] = useState(false);
  const [campaignBulkWorking, setCampaignBulkWorking] = useState<"rescan" | "report" | null>(null);
  const [campaignSearch, setCampaignSearch] = useState("");

  const [toast, setToast] = useState<{ message: string; tone?: "success" | "error" | "info" } | null>(null);
  const [submitValue, setSubmitValue] = useState("");
  const [submitSource, setSubmitSource] = useState("");
  const [submitNotes, setSubmitNotes] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [submitResult, setSubmitResult] = useState<{ status: string; domain: string; duplicate?: boolean; message?: string } | null>(null);
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
  const [reportPanelInstructions, setReportPanelInstructions] = useState<Record<string, ManualSubmissionData | undefined>>({});
  const [reportPanelSelected, setReportPanelSelected] = useState<Set<string>>(new Set());
  const [reportPanelSubmitting, setReportPanelSubmitting] = useState(false);
  const [reportPanelManualMode, setReportPanelManualMode] = useState<string | null>(null);
  const [reportPanelManualQueue, setReportPanelManualQueue] = useState<string[]>([]);

  // Visit Website Warning Modal
  const [visitWarningOpen, setVisitWarningOpen] = useState(false);
  const [visitWarningUrl, setVisitWarningUrl] = useState("");

  // Operator Notes
  const [noteInput, setNoteInput] = useState("");
  const [noteSaving, setNoteSaving] = useState(false);

  // Campaign Name Editing
  const [campaignNameEditing, setCampaignNameEditing] = useState(false);
  const [campaignNameInput, setCampaignNameInput] = useState("");
  const [campaignNameSaving, setCampaignNameSaving] = useState(false);

  // Settings Popup
  const [settingsOpen, setSettingsOpen] = useState(false);

  // Public submissions (admin only)
  const [publicSubmissions, setPublicSubmissions] = useState<PublicSubmission[]>([]);
  const [publicSubmissionsLoading, setPublicSubmissionsLoading] = useState(false);
  const [publicSubmissionsError, setPublicSubmissionsError] = useState<string | null>(null);
  const [submissionActionBusy, setSubmissionActionBusy] = useState<Record<number, string | null>>({});

  // Public report options (public mode)
  const [reportOptions, setReportOptions] = useState<ReportOptionsResponse | null>(null);
  const [reportOptionsLoading, setReportOptionsLoading] = useState(false);
  const [reportOptionsError, setReportOptionsError] = useState<string | null>(null);
  const [reportEngagementBusy, setReportEngagementBusy] = useState<Record<string, boolean>>({});
  const [openReportPlatforms, setOpenReportPlatforms] = useState<Set<string>>(new Set());

  // Analytics (admin)
  const [analytics, setAnalytics] = useState<AnalyticsResponse | null>(null);
  const [analyticsError, setAnalyticsError] = useState<string | null>(null);

  // Detect admin mode for conditional rendering
  const isAdmin = isAdminMode();
  const canEdit = isAdmin;

  useEffect(() => {
    const onHash = () => {
      setRoute(parseHash());
    };
    onHash();
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
      // Handle special "dangerous" filter mode
      const apiParams = {
        ...filters,
        status: filters.status === "dangerous" ? "" : filters.status,
        excludeStatuses: filters.status === "dangerous" ? EXCLUDED_STATUSES : undefined,
      };
      const res = await fetchDomains(apiParams);
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

  const loadCampaigns = useCallback(async () => {
    setCampaignLoading(true);
    try {
      const res = await fetchCampaigns();
      setCampaigns(res.campaigns || []);
    } catch (err) {
      showToast((err as Error).message || "Failed to load campaigns", "error");
    } finally {
      setCampaignLoading(false);
    }
  }, []);

  const loadCampaignDetail = useCallback(async (id: string) => {
    setCampaignLoading(true);
    try {
      const res = await fetchCampaign(id);
      setCampaignDetail(res);
    } catch (err) {
      showToast((err as Error).message || "Failed to load campaign", "error");
      setCampaignDetail(null);
    } finally {
      setCampaignLoading(false);
    }
  }, []);

  const loadPublicSubmissions = useCallback(async () => {
    if (!canEdit) return;
    setPublicSubmissionsLoading(true);
    setPublicSubmissionsError(null);
    try {
      const res = await fetchPublicSubmissions("pending_review", 1, 200);
      setPublicSubmissions(res.submissions || []);
    } catch (err) {
      setPublicSubmissionsError((err as Error).message || "Failed to load submissions");
    } finally {
      setPublicSubmissionsLoading(false);
    }
  }, [canEdit]);

  const loadReportOptions = useCallback(async (domainId: number) => {
    if (canEdit) return;
    setReportOptionsLoading(true);
    setReportOptionsError(null);
    try {
      const res = await fetchReportOptions(domainId);
      setReportOptions(res);
    } catch (err) {
      setReportOptions(null);
      setReportOptionsError((err as Error).message || "Failed to load report options");
    } finally {
      setReportOptionsLoading(false);
    }
  }, [canEdit]);

  const loadAnalytics = useCallback(async () => {
    if (!canEdit) return;
    try {
      const res = await fetchAnalytics();
      setAnalytics(res);
      setAnalyticsError(null);
    } catch (err) {
      setAnalytics(null);
      setAnalyticsError((err as Error).message || "Failed to load analytics");
    }
  }, [canEdit]);

  useEffect(() => {
    loadStats();
    const id = setInterval(loadStats, 30000);
    return () => clearInterval(id);
  }, [loadStats]);

  useEffect(() => {
    loadDomains();
  }, [loadDomains]);

  useEffect(() => {
    if (canEdit) {
      loadPublicSubmissions();
      loadAnalytics();
    } else {
      setPublicSubmissions([]);
      setAnalytics(null);
    }
  }, [canEdit, loadPublicSubmissions, loadAnalytics]);

  useEffect(() => {
    if (route.name === "domain") {
      loadDomainDetail(route.id);
    } else {
      setDomainDetail(null);
    }
    if (route.name === "campaigns") {
      loadCampaigns();
    }
    if (route.name === "campaign") {
      loadCampaignDetail(route.id);
    }
  }, [route, loadDomainDetail, loadCampaigns, loadCampaignDetail]);

  useEffect(() => {
    if (!canEdit && domainDetail?.domain.id) {
      loadReportOptions(domainDetail.domain.id);
    } else {
      setReportOptions(null);
      setReportOptionsError(null);
    }
  }, [canEdit, domainDetail?.domain.id, loadReportOptions]);

  const handleSubmit = async (e: FormEvent | MouseEvent, mode: "submit" | "rescan" = "submit") => {
    e.preventDefault();
    if (mode === "rescan" && !canEdit) {
      showToast("Rescan is only available to admins.", "info");
      return;
    }
    setSubmitError(null);
    setSubmitResult(null);
    if (!submitValue.trim()) {
      setSubmitError("Enter a domain or URL to submit.");
      return;
    }
    setSubmitting(true);
    try {
      if (canEdit) {
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
      } else {
        const res = await submitPublicTarget(submitValue.trim(), {
          sourceUrl: submitSource.trim() || undefined,
          notes: submitNotes.trim() || undefined,
        });
        const message = res.message || (res.duplicate ? "Already submitted by someone else" : "Submitted for review");
        showToast(message, res.duplicate ? "info" : "success");
        setSubmitResult(res);
        setSubmitValue("");
        setSubmitSource("");
        setSubmitNotes("");
      }
    } catch (err) {
      const msg = (err as Error).message || "Submit failed";
      setSubmitError(msg);
      showToast(msg, "error");
    } finally {
      setSubmitting(false);
    }
  };

  const handleSubmissionAction = async (submissionId: number, action: "approve" | "reject") => {
    if (!canEdit) return;
    setSubmissionActionBusy((prev) => ({ ...prev, [submissionId]: action }));
    try {
      if (action === "approve") {
        await approvePublicSubmission(submissionId);
        showToast("Submission approved and queued", "success");
      } else {
        const reasonInput = window.prompt("Reason for rejection? (legitimate_site / insufficient_info / already_tracked / other)", "legitimate_site");
        if (reasonInput === null) {
          setSubmissionActionBusy((prev) => ({ ...prev, [submissionId]: null }));
          return;
        }
        const notesInput = window.prompt("Notes (optional)", "") || undefined;
        await rejectPublicSubmission(submissionId, reasonInput || "rejected", notesInput);
        showToast("Submission rejected", "info");
      }
      setPublicSubmissions((prev) => prev.filter((s) => s.id !== submissionId));
      loadStats();
    } catch (err) {
      showToast((err as Error).message || "Failed to process submission", "error");
    } finally {
      setSubmissionActionBusy((prev) => ({ ...prev, [submissionId]: null }));
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

  const toggleReportPlatform = (platformId: string) => {
    setOpenReportPlatforms((prev) => {
      const next = new Set(prev);
      if (next.has(platformId)) next.delete(platformId);
      else next.add(platformId);
      return next;
    });
  };

  const handleReportEngagement = async (platformId: string) => {
    if (!domainDetail?.domain.id) return;
    setReportEngagementBusy((prev) => ({ ...prev, [platformId]: true }));
    try {
      const res = await recordReportEngagement(domainDetail.domain.id, platformId);
      setReportOptions((prev) => {
        if (!prev) return prev;
        const nextPlatforms = prev.platforms.map((p) =>
          p.id === platformId ? { ...p, engagement_count: res.new_count } : p
        );
        const nextTotal = nextPlatforms.reduce((sum, p) => sum + (p.engagement_count || 0), 0);
        return { ...prev, platforms: nextPlatforms, total_engagements: nextTotal };
      });
      showToast(res.message || (res.status === "cooldown" ? "You've already reported recently." : "Thanks for reporting!"), res.status === "cooldown" ? "info" : "success");
    } catch (err) {
      showToast((err as Error).message || "Failed to record engagement", "error");
    } finally {
      setReportEngagementBusy((prev) => ({ ...prev, [platformId]: false }));
    }
  };

  const copyValue = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      showToast("Copied to clipboard", "success");
    } catch (err) {
      showToast("Copy failed", "error");
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
    if (!canEdit) {
      showToast("Read-only mode: reporting is disabled.", "info");
      return;
    }
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
    setReportPanelInstructions({});

    // Fetch available platforms
    try {
      const data = await fetchReportOptions(domain.id);
      const platforms = (data.platforms || []).map((p) => p.id);
      const info: Record<string, PlatformInfo> = {};
      const instructions: Record<string, ManualSubmissionData> = {};
      for (const p of data.platforms || []) {
        info[p.id] = { manual_only: p.manual_only, url: p.url || "", name: p.name };
        if (p.instructions) {
          instructions[p.id] = p.instructions;
        }
      }
      setReportPanelPlatforms(platforms);
      setReportPanelInfo(info);
      setReportPanelInstructions(instructions);
      // Pre-select all applicable platforms by default
      setReportPanelSelected(new Set(platforms));
    } catch (err) {
      showToast((err as Error).message || "Failed to load platform options", "error");
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
    if (!canEdit) {
      showToast("Read-only mode: actions are disabled.", "info");
      return;
    }
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
    if (!canEdit) {
      showToast("Read-only mode: status changes are disabled.", "info");
      return;
    }
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

  const bulkTriggerCampaign = async (type: "rescan" | "report") => {
    if (!canEdit) {
      showToast("Read-only mode: actions are disabled.", "info");
      return;
    }
    if (!campaignDetail) return;
    const domains = (campaignDetail.domains || []).filter((d) => d.id) as Domain[];
    if (!domains.length) {
      showToast("No domains with IDs to process in this campaign", "error");
      return;
    }
    const ok = window.confirm(`Queue ${type} for ${domains.length} domains in this campaign?`);
    if (!ok) return;
    setCampaignBulkWorking(type);
    try {
      for (const d of domains) {
        await triggerAction(d, type);
      }
      showToast(`Queued ${type} for ${domains.length} domains`, "success");
    } finally {
      setCampaignBulkWorking(null);
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

  const filteredCampaigns = useMemo(() => {
    const term = campaignSearch.trim().toLowerCase();
    if (!term) return campaigns;
    return campaigns.filter((c) => {
      const haystack = `${c.name || ""} ${c.campaign_id || ""} ${(c.members || []).map((m) => m.domain).join(" ")}`.toLowerCase();
      return haystack.includes(term);
    });
  }, [campaigns, campaignSearch]);

  const nextReportAttempt = useMemo(() => {
    if (!domainDetail?.reports) return null;
    const times = domainDetail.reports
      .map((r) => r.next_attempt_at)
      .filter(Boolean) as string[];
    if (!times.length) return null;
    return times.sort()[0];
  }, [domainDetail]);

  const reportPanelManualInstructions = reportPanelManualMode
    ? reportPanelInstructions[reportPanelManualMode]
    : undefined;
  const reportPanelManualFormUrl = reportPanelManualMode
    ? reportPanelManualInstructions?.form_url || reportPanelInfo[reportPanelManualMode]?.url || ""
    : "";

  const domainDownloadBase = canEdit ? "/admin/domains" : "/domains";
  const campaignDownloadBase = canEdit ? "/admin/campaigns" : "/campaigns";

  const statsBlocks = useMemo(() => {
    if (!stats) return null;
    const refreshed = statsUpdatedAt ? `Refreshed ${timeAgo(statsUpdatedAt.toISOString())}` : "Awaiting data";
    return (
      <>
        <div className="sb-grid" style={{ marginBottom: 12 }}>
          <div className="col-3">
            <div className="sb-stat">
              <div className="sb-stat-label">Total Domains</div>
              <div className="sb-stat-value">{stats.total}</div>
              <div className="sb-stat-meta">Last 24h: <b>{stats.last_24h}</b></div>
            </div>
          </div>
          <div className="col-3"><div className="sb-stat"><div className="sb-stat-label">By Verdict</div><Breakdown items={stats.by_verdict || {}} onSelect={(key) => setFilters((prev) => ({ ...prev, verdict: key === "all" ? "" : key, page: 1 }))} /></div></div>
          <div className="col-3"><div className="sb-stat"><div className="sb-stat-label">Reports</div><Breakdown items={stats.reports || {}} /></div></div>
          <div className="col-3">
            <div className="sb-stat">
              <div className="sb-stat-label">Public Submissions</div>
              <div className="sb-stat-value">{stats.public_submissions_pending ?? 0}</div>
              <div className="sb-stat-meta">Pending review</div>
            </div>
          </div>
        </div>
        <div className="sb-muted" style={{ marginTop: -8, marginBottom: 12, fontSize: 12 }}>{refreshed}</div>
      </>
    );
  }, [stats, statsUpdatedAt, setFilters]);



  const dashboardView = (
    <>
      {statsBlocks}

      {/* Manual Submission - admin only */}
      <div className="sb-panel" style={{ borderColor: "rgba(88, 166, 255, 0.3)", marginBottom: 16 }}>
        <div className="sb-panel-header" style={{ borderColor: "rgba(88, 166, 255, 0.2)" }}>
          <span className="sb-panel-title" style={{ color: "var(--accent-blue)" }}>
            {canEdit ? "Manual Submission" : "Report a Suspicious Site"}
          </span>
          {canEdit && (stats?.public_submissions_pending ?? 0) > 0 && (
            <span className="sb-badge sb-badge-pending">Pending: {stats?.public_submissions_pending}</span>
          )}
        </div>
        <form onSubmit={(e) => handleSubmit(e, "submit")}>
          <div className="sb-row" style={{ gap: 12, flexWrap: "wrap" }}>
            <input className="sb-input" placeholder="example.com or https://target" value={submitValue} onChange={(e) => setSubmitValue(e.target.value)} style={{ flex: 1, minWidth: 200 }} />
            {canEdit && (
              <button className="sb-btn" type="button" disabled={submitting} onClick={(e) => handleSubmit(e, "rescan")}>
                {submitting ? "Working…" : "Force Rescan"}
              </button>
            )}
            <button className="sb-btn sb-btn-primary" type="submit" disabled={submitting}>
              {submitting ? "Submitting…" : canEdit ? "Submit New" : "Submit for Review"}
            </button>
          </div>
          {!canEdit && (
            <>
              <div className="sb-row" style={{ marginTop: 10, gap: 12, flexWrap: "wrap" }}>
                <div style={{ flex: 1, minWidth: 260 }}>
                  <div className="sb-label">Where did you see this? (optional)</div>
                  <input
                    className="sb-input"
                    placeholder="Link to ad/post or the exact phishing URL"
                    value={submitSource}
                    onChange={(e) => setSubmitSource(e.target.value)}
                    style={{ width: "100%" }}
                  />
                  <div className="sb-muted" style={{ fontSize: 12, marginTop: 4 }}>
                    Example: https://x.com/... or https://phish.example.com/login
                  </div>
                </div>
              </div>
              <div className="sb-row" style={{ marginTop: 10 }}>
                <div style={{ width: "100%" }}>
                  <div className="sb-label">Why is this suspicious? (optional)</div>
                  <textarea
                    className="sb-input"
                    rows={3}
                    placeholder="Briefly describe what looked phishing (wallet prompt, seed phrase request, fake giveaway, etc.)"
                    value={submitNotes}
                    onChange={(e) => setSubmitNotes(e.target.value)}
                    style={{ width: "100%", resize: "vertical" }}
                  />
                </div>
              </div>
            </>
          )}
          {submitError && <div className="sb-notice" style={{ color: "var(--accent-red)", marginTop: 8 }}>{submitError}</div>}
          {submitResult && (
            <div className="sb-flash sb-flash-success" style={{ marginTop: 8 }}>
              {(submitResult.message || (submitResult.status === "rescan_queued" ? "Rescan queued" : submitResult.duplicate ? "Already submitted" : "Submitted"))}
              {" for "}
              <b>{submitResult.domain}</b>
            </div>
          )}
        </form>
      </div>

      {canEdit && (
        <div className="sb-panel" style={{ borderColor: "rgba(110, 220, 180, 0.4)", marginBottom: 16 }}>
          <div className="sb-panel-header" style={{ borderColor: "rgba(110, 220, 180, 0.3)" }}>
            <span className="sb-panel-title" style={{ color: "var(--accent-green)" }}>Engagement & Takedown Analytics</span>
            <div className="sb-row" style={{ gap: 8 }}>
              <button className="sb-btn" onClick={loadAnalytics}>Refresh</button>
            </div>
          </div>
          {analyticsError && <div className="sb-notice" style={{ color: "var(--accent-red)", marginBottom: 8 }}>{analyticsError}</div>}
          {!analytics && !analyticsError && <div className="sb-muted">Loading…</div>}
          {analytics && (
            <div className="sb-grid" style={{ gap: 12 }}>
              <div className="col-6">
                <div className="sb-label">Public report clicks (24h per session)</div>
                <div className="sb-muted" style={{ marginBottom: 6 }}>Total clicks: {analytics.engagement.total_engagements}</div>
                <div className="sb-breakdown">
                  {Object.entries(analytics.engagement.by_platform || {}).map(([p, c]) => (
                    <div key={p} className="sb-breakdown-item">
                      <span className="sb-breakdown-key">{p}</span>
                      <span className="sb-breakdown-val">{c}</span>
                    </div>
                  ))}
                  {Object.keys(analytics.engagement.by_platform || {}).length === 0 && <div className="sb-muted">No engagement yet.</div>}
                </div>
              </div>
              <div className="col-6">
                <div className="sb-label">Automated takedown status (DNS/HTTP/RDAP)</div>
                {analytics.takedown.avg_hours_to_detect != null && (
                  <div className="sb-muted" style={{ marginBottom: 6 }}>
                    Avg hours to first takedown signal: {analytics.takedown.avg_hours_to_detect.toFixed(1)}
                  </div>
                )}
                <div className="sb-breakdown">
                  {Object.entries(analytics.takedown.by_status || {}).map(([k, v]) => (
                    <div key={k} className="sb-breakdown-item">
                      <span className="sb-breakdown-key">{k}</span>
                      <span className="sb-breakdown-val">{v}</span>
                    </div>
                  ))}
                  {Object.keys(analytics.takedown.by_status || {}).length === 0 && <div className="sb-muted">No takedown data yet.</div>}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {canEdit && (
        <div className="sb-panel" style={{ borderColor: "rgba(255, 214, 102, 0.4)", marginBottom: 16 }}>
          <div className="sb-panel-header" style={{ borderColor: "rgba(255, 214, 102, 0.3)" }}>
            <span className="sb-panel-title" style={{ color: "var(--accent-orange)" }}>
              Public Submissions ({publicSubmissions.length})
            </span>
            <div className="sb-row" style={{ gap: 8 }}>
              <button className="sb-btn" onClick={loadPublicSubmissions} disabled={publicSubmissionsLoading}>
                {publicSubmissionsLoading ? "Loading…" : "Refresh"}
              </button>
            </div>
          </div>
          {publicSubmissionsError && (
            <div className="sb-notice" style={{ color: "var(--accent-red)", marginBottom: 8 }}>{publicSubmissionsError}</div>
          )}
          {publicSubmissionsLoading && <div className="skeleton" style={{ height: 12 }} />}
          {!publicSubmissionsLoading && publicSubmissions.length === 0 && (
            <div className="sb-muted">No pending submissions.</div>
          )}
          {!publicSubmissionsLoading && publicSubmissions.length > 0 && (
            <div className="sb-table-wrap">
              <table className="sb-table">
                <thead>
                  <tr>
                    <th>Domain</th>
                    <th>Count</th>
                    <th>Submitted</th>
                    <th>Source</th>
                    <th>Notes</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {publicSubmissions.map((s) => {
                    const busy = submissionActionBusy[s.id] || null;
                    return (
                      <tr key={s.id}>
                        <td><code className="sb-code">{s.domain}</code></td>
                        <td>{s.submission_count ?? 1}</td>
                        <td>
                          <div className="sb-muted" style={{ fontSize: 12 }}>First: {timeAgo(s.first_submitted_at)}</div>
                          <div className="sb-muted" style={{ fontSize: 12 }}>Last: {timeAgo(s.last_submitted_at)}</div>
                        </td>
                        <td>
                          {s.source_url ? <a href={s.source_url} target="_blank" rel="noreferrer">Link</a> : <span className="sb-muted">—</span>}
                        </td>
                        <td style={{ maxWidth: 240 }}>
                          {s.reporter_notes ? <div style={{ whiteSpace: "pre-wrap" }}>{s.reporter_notes}</div> : <span className="sb-muted">—</span>}
                        </td>
                        <td>
                          <div className="sb-row" style={{ gap: 6, flexWrap: "wrap" }}>
                            <button className="sb-btn sb-btn-primary" disabled={!!busy} onClick={() => handleSubmissionAction(s.id, "approve")}>
                              {busy === "approve" ? "Approving…" : "Approve"}
                            </button>
                            <button className="sb-btn sb-btn-danger" disabled={!!busy} onClick={() => handleSubmissionAction(s.id, "reject")}>
                              {busy === "reject" ? "Rejecting…" : "Reject"}
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Reports Needing Attention - full width when present */}
      {canEdit && pendingReports.length > 0 && (
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
                      {canEdit ? (
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
                      ) : (
                        <span>{r.domain}</span>
                      )}
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
        canEdit={isAdmin}
      />
    </>
  );

  const campaignsView = (
    <div className="sb-panel">
      <div className="sb-panel-header">
        <span className="sb-panel-title">Threat Campaigns</span>
        <div className="sb-row" style={{ gap: 12 }}>
          <input
            className="sb-input"
            placeholder="Search campaigns"
            value={campaignSearch}
            onChange={(e) => setCampaignSearch(e.target.value)}
            style={{ width: 280 }}
          />
          <span className="sb-muted">{filteredCampaigns.length} campaigns</span>
        </div>
      </div>
      {campaignLoading && <div className="sb-muted">Loading campaigns…</div>}
      {!campaignLoading && filteredCampaigns.length === 0 && <div className="sb-muted">No campaigns yet.</div>}
      {!campaignLoading && filteredCampaigns.length > 0 && (
        <div className="sb-grid" style={{ gap: 16 }}>
          {filteredCampaigns.map((c) => {
            const indicators = [
              ...(c.shared_backends || []),
              ...(c.shared_nameservers || []),
              ...(c.shared_kits || []),
            ].slice(0, 3);
            return (
              <div key={c.campaign_id} className="col-6">
                <div className="sb-panel" style={{ borderColor: "rgba(163, 113, 247, 0.3)", margin: 0 }}>
                  <div className="sb-panel-header" style={{ borderColor: "rgba(163, 113, 247, 0.2)" }}>
                    <div>
                      <div className="sb-panel-title" style={{ color: "var(--accent-purple)" }}>{c.name || c.campaign_id}</div>
                      <div className="sb-muted">Members: {c.members?.length ?? 0}</div>
                    </div>
                    <a className="sb-btn" href={`#/campaigns/${c.campaign_id}`}>View</a>
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

  const campaignDetailView = (() => {
    const campaign = campaignDetail?.campaign;
    const related = campaignDetail?.domains || [];

    if (campaignLoading) {
      return (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div className="sb-row"><a className="sb-btn" href="#/campaigns">&larr; Back to Campaigns</a></div>
          <div className="sb-muted">Loading campaign…</div>
        </div>
      );
    }

    if (!campaign) {
      return (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          <div className="sb-row"><a className="sb-btn" href="#/campaigns">&larr; Back to Campaigns</a></div>
          <div className="sb-muted">Campaign not found.</div>
        </div>
      );
    }

    const indicators = [
      { label: "Backends", values: campaign.shared_backends || [] },
      { label: "Kits", values: campaign.shared_kits || [] },
      { label: "Nameservers", values: campaign.shared_nameservers || [] },
    ];

    return (
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        <div className="sb-row"><a className="sb-btn" href="#/campaigns">&larr; Back to Campaigns</a></div>

        {/* Main Campaign Panel */}
        <div className="sb-panel" style={{ borderColor: "rgba(163, 113, 247, 0.3)" }}>
          <div className="sb-panel-header" style={{ borderColor: "rgba(163, 113, 247, 0.2)" }}>
            <div>
              <span className="sb-panel-title" style={{ color: "var(--accent-purple)" }}>Threat Campaign</span>
              <span className="sb-muted" style={{ marginLeft: 8 }}>ID: {campaign.campaign_id}</span>
            </div>
            <div className="sb-row" style={{ gap: 8 }}>
              <a className="sb-btn" href={`${campaignDownloadBase}/${campaign.campaign_id}/pdf`} target="_blank" rel="noreferrer">Campaign PDF</a>
              <a className="sb-btn" href={`${campaignDownloadBase}/${campaign.campaign_id}/package`} target="_blank" rel="noreferrer">Campaign Package</a>
            </div>
          </div>

          {/* Campaign Name with Edit */}
          <div className="sb-grid" style={{ marginBottom: 16 }}>
            <div className="col-8">
              <div className="sb-label">Campaign Name</div>
              {isAdmin && campaignNameEditing ? (
                <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 4 }}>
                  <input
                    className="sb-input"
                    value={campaignNameInput}
                    onChange={(e) => setCampaignNameInput(e.target.value)}
                    style={{ flex: 1, maxWidth: 400 }}
                  />
                  <button
                    className="sb-btn sb-btn-primary"
                    disabled={campaignNameSaving || !campaignNameInput.trim()}
                    onClick={async () => {
                      if (!campaign.campaign_id) return;
                      setCampaignNameSaving(true);
                      try {
                        await updateCampaignName(campaign.campaign_id, campaignNameInput.trim());
                        showToast("Campaign name updated", "success");
                        setCampaignNameEditing(false);
                        const res = await fetchCampaign(campaign.campaign_id);
                        setCampaignDetail(res);
                      } catch (err) {
                        showToast((err as Error).message || "Failed to update name", "error");
                      } finally {
                        setCampaignNameSaving(false);
                      }
                    }}
                  >
                    {campaignNameSaving ? "Saving..." : "Save"}
                  </button>
                  <button className="sb-btn" onClick={() => setCampaignNameEditing(false)}>Cancel</button>
                </div>
              ) : (
                <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 4 }}>
                  <div style={{ fontSize: 20, fontWeight: 600 }}>
                    {campaign.name || campaign.campaign_id}
                  </div>
                  {isAdmin && (
                    <button
                      className="sb-btn"
                      style={{ padding: "4px 10px", fontSize: 12 }}
                      onClick={() => {
                        setCampaignNameInput(campaign.name || "");
                        setCampaignNameEditing(true);
                      }}
                    >
                      ✏️ Edit
                    </button>
                  )}
                </div>
              )}
            </div>
            <div className="col-4">
              <div className="sb-label">Members</div>
              <div style={{ fontSize: 20, fontWeight: 600, marginTop: 4 }}>{campaign.members?.length ?? 0}</div>
            </div>
          </div>

          {/* Bulk Actions (admin only) */}
          {isAdmin && (
            <div className="sb-row" style={{ flexWrap: "wrap", gap: 8, marginBottom: 16 }}>
              <button className="sb-btn" disabled={campaignBulkWorking === "rescan"} onClick={() => bulkTriggerCampaign("rescan")}>
                {campaignBulkWorking === "rescan" ? "Queuing…" : "Bulk Rescan"}
              </button>
              <button className="sb-btn" disabled={campaignBulkWorking === "report"} onClick={() => bulkTriggerCampaign("report")}>
                {campaignBulkWorking === "report" ? "Queuing…" : "Bulk Report"}
              </button>
            </div>
          )}

          {/* Shared Indicators */}
          <div style={{ marginBottom: 16 }}>
            <div className="sb-label">Shared Indicators</div>
            <div className="sb-row" style={{ flexWrap: "wrap", alignItems: "flex-start", marginTop: 8 }}>
              {indicators.map((ind) => ind.values && ind.values.length ? (
                <div key={ind.label} style={{ marginRight: 16, marginBottom: 8 }}>
                  <div className="sb-muted" style={{ fontSize: 12, marginBottom: 4 }}>{ind.label}</div>
                  <div>
                    {ind.values.slice(0, 6).map((v) => (
                      <code key={v} className="sb-code" style={{ display: "inline-block", margin: "2px 4px 2px 0" }}>{v}</code>
                    ))}
                    {ind.values.length > 6 && <span className="sb-muted">+{ind.values.length - 6} more</span>}
                  </div>
                </div>
              ) : null)}
              {indicators.every((i) => !i.values || i.values.length === 0) && <div className="sb-muted">No shared indicators.</div>}
            </div>
          </div>

          {/* Related Domains */}
          <div>
            <div className="sb-label">Related Domains</div>
            <div className="sb-breakdown" style={{ marginTop: 8 }}>
              {(related || []).map((rd) => (
                <div key={rd.id || rd.domain} className="sb-breakdown-item" style={{ cursor: rd.id ? "pointer" : "default" }}
                  onClick={() => rd.id && (window.location.hash = `#/domains/${rd.id}`)}>
                  <span className="sb-breakdown-key">{rd.domain}</span>
                  <div className="sb-row" style={{ gap: 8 }}>
                    <span className={badgeClass(rd.status, "status")}>{(rd.status || "").toUpperCase()}</span>
                    <span className="sb-score">{(rd as any).score ?? ""}</span>
                  </div>
                </div>
              ))}
              {(!related || related.length === 0) && <div className="sb-muted">No related domains yet.</div>}
            </div>
          </div>
        </div>
      </div>
    );
  })();


  const domainDetailView = (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div className="sb-row"><a className="sb-btn" href="#/">&larr; Back</a></div>
      {domainDetailLoading && (
        <div className="sb-panel"><div className="skeleton" style={{ height: 24, marginBottom: 10 }} /><div className="skeleton" style={{ height: 12 }} /></div>
      )}
      {!domainDetailLoading && domainDetail && (
        <>
          {domainDetail.domain.action_required && (
            <div className="sb-flash sb-flash-error">
              {domainDetail.domain.action_required}
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
                {(((domainDetail.domain.takedown_status || "") as string).toLowerCase() !== "active") || domainDetail.domain.takedown_detected_at ? (
                  <div className="sb-row" style={{ gap: 8, flexWrap: "wrap", marginTop: 6 }}>
                    <span className={badgeClass(domainDetail.domain.takedown_status, "status")}>
                      TAKEDOWN: {(domainDetail.domain.takedown_status || "active").toUpperCase()}
                    </span>
                    {domainDetail.domain.takedown_detected_at && (
                      <span className="sb-muted">Detected {timeAgo(domainDetail.domain.takedown_detected_at)}</span>
                    )}
                    {domainDetail.domain.takedown_confirmed_at && (
                      <span className="sb-muted">Confirmed {timeAgo(domainDetail.domain.takedown_confirmed_at)}</span>
                    )}
                  </div>
                ) : null}
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 12, alignItems: "flex-end" }}>
                {/* Primary action buttons */}
                <div className="sb-row" style={{ flexWrap: "wrap", gap: 8 }}>
                  {canEdit && (
                    <>
                      <button className="sb-btn sb-btn-primary" disabled={!domainDetail.domain.id || !!actionBusy[domainDetail.domain.id!]} onClick={() => triggerAction(domainDetail.domain, "rescan")}>
                        {actionBusy[domainDetail.domain.id || 0] === "rescan" ? "Rescanning…" : "Rescan"}
                      </button>
                      <button className="sb-btn" disabled={!domainDetail.domain.id || !!actionBusy[domainDetail.domain.id!]} onClick={() => triggerAction(domainDetail.domain, "report")}>
                        {actionBusy[domainDetail.domain.id || 0] === "report" ? "Reporting…" : "Report"}
                      </button>
                    </>
                  )}
                  <button
                    className="sb-btn sb-btn-danger"
                    onClick={() => {
                      setVisitWarningUrl(`https://${domainDetail.domain.domain}`);
                      setVisitWarningOpen(true);
                    }}
                  >
                    ↗ Visit Site
                  </button>
                </div>
                {/* Status action buttons */}
                {canEdit && (() => {
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
                    {canEdit && (
                      <button
                        className="sb-btn"
                        disabled={isBusy}
                        onClick={async () => {
                          if (!canEdit) {
                            showToast("Read-only mode: baseline updates are disabled.", "info");
                            return;
                          }
                          if (!domainDetail.domain.id) return;
                          setActionBusy(prev => ({ ...prev, [domainDetail.domain.id!]: "baseline" }));
                          try {
                            const data = await updateWatchlistBaseline(domainDetail.domain.id);
                            showToast(`Baseline updated to ${data.baseline_timestamp}`, "success");
                            // Refresh domain detail
                            await loadDomainDetail(domainDetail.domain.id);
                          } catch (err) {
                            showToast(`Error updating baseline: ${err}`, "error");
                          } finally {
                            setActionBusy(prev => ({ ...prev, [domainDetail.domain.id!]: null }));
                          }
                        }}
                      >
                        {isBusy ? "Updating…" : "Update Baseline"}
                      </button>
                    )}
                  </div>
                </div>
              );
            })()}

              {/* Download links */}
              <div className="sb-row" style={{ flexWrap: "wrap", marginTop: 16, gap: 8 }}>
                {domainDetail.domain.id && (
                  <>
                  <a className="sb-btn" href={`${domainDownloadBase}/${domainDetail.domain.id}/pdf`} target="_blank" rel="noreferrer">Download PDF</a>
                  <a className="sb-btn" href={`${domainDownloadBase}/${domainDetail.domain.id}/package`} target="_blank" rel="noreferrer">Download Package</a>
                  </>
                )}
                {domainDetail.reports && domainDetail.reports.length > 0 && (
                  <span className="sb-muted">
                    Next report attempt: {nextReportAttempt || "\u2014"}
                </span>
              )}
            </div>
          </div>

          {!canEdit && isPublicReportEligible(domainDetail?.domain) && (
            <div className="sb-panel" style={{ marginTop: 8 }}>
              <div className="sb-panel-header">
                <span className="sb-panel-title">Help Take Down This Scam</span>
                <span className="sb-muted">Community reports: {reportOptions?.total_engagements ?? 0}</span>
              </div>
              {reportOptionsLoading && <div className="skeleton" style={{ height: 14, marginBottom: 8 }} />}
              {reportOptionsError && <div className="sb-notice" style={{ color: "var(--accent-red)", marginBottom: 8 }}>{reportOptionsError}</div>}
              {!reportOptionsLoading && !reportOptions && !reportOptionsError && (
                <div className="sb-muted">Reporting options will appear once this domain loads.</div>
              )}
              {reportOptions && reportOptions.platforms.map((opt) => {
                const open = openReportPlatforms.has(opt.id);
                return (
                  <div key={opt.id} className="sb-card" style={{ border: "1px solid var(--border-subtle)", borderRadius: 8, padding: 12, marginBottom: 10 }}>
                    <div className="sb-row sb-space-between" style={{ alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                      <div>
                        <div className="sb-label" style={{ fontSize: 14 }}>{opt.name}</div>
                        <div className="sb-muted" style={{ fontSize: 12 }}>{opt.engagement_count} reported</div>
                      </div>
                      <div className="sb-row" style={{ gap: 8, flexWrap: "wrap" }}>
                        <button className="sb-btn" type="button" onClick={() => toggleReportPlatform(opt.id)}>
                          {open ? "Hide Instructions" : "View Instructions"}
                        </button>
                        <button
                          className="sb-btn sb-btn-primary"
                          type="button"
                          disabled={reportEngagementBusy[opt.id]}
                          onClick={() => handleReportEngagement(opt.id)}
                        >
                          {reportEngagementBusy[opt.id] ? "Recording…" : "I Reported This"}
                        </button>
                      </div>
                    </div>
                    {open && (
                      <div style={{ marginTop: 12 }}>
                        <div className="sb-muted" style={{ marginBottom: 8 }}>
                          {opt.instructions?.reason || "Manual submission"}
                        </div>
                        <div style={{ marginBottom: 8 }}>
                          <div className="sb-label">Report URL</div>
                          {opt.instructions?.form_url ? (
                            <a href={opt.instructions.form_url} target="_blank" rel="noreferrer">{opt.instructions.form_url}</a>
                          ) : (
                            <span className="sb-muted">No form URL provided</span>
                          )}
                        </div>
                        {opt.instructions?.fields?.map((field) => (
                          <div key={field.name} style={{ marginBottom: 10 }}>
                            <div className="sb-label">{field.label}</div>
                            <div className="sb-row" style={{ gap: 8 }}>
                              <textarea
                                className="sb-input"
                                value={field.value}
                                readOnly
                                rows={field.multiline ? 3 : 1}
                                style={{ width: "100%", resize: "vertical" }}
                              />
                              <button className="sb-btn" type="button" onClick={() => copyValue(field.value)}>Copy</button>
                            </div>
                          </div>
                        ))}
                        {opt.instructions?.notes && opt.instructions.notes.length > 0 && (
                          <ul className="sb-muted" style={{ paddingLeft: 18, marginTop: 8 }}>
                            {opt.instructions.notes.map((n, idx) => <li key={idx}>{n}</li>)}
                          </ul>
                        )}
                        {!opt.instructions && opt.error && (
                          <div className="sb-notice" style={{ color: "var(--accent-red)" }}>{opt.error}</div>
                        )}
                        {!opt.instructions && !opt.error && <div className="sb-muted">Instructions not available for this platform.</div>}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* Infrastructure / Registrar info */}
          <div className="sb-panel" style={{ marginTop: 8 }}>
            <div className="sb-panel-header">
              <span className="sb-panel-title">Infrastructure</span>
            </div>
            {domainDetail.infrastructure ? (
              <div className="sb-grid" style={{ gap: 12 }}>
                <div className="col-4">
                  <div className="sb-label">Hosting Provider</div>
                  <div className="sb-muted" style={{ fontWeight: 600 }}>
                    {domainDetail.infrastructure.hosting_provider || "\u2014"}
                  </div>
                  <div style={{ marginTop: 4, fontSize: 13 }}>
                    <span className="sb-label" style={{ display: "inline-block", marginRight: 6 }}>IP</span>
                    {renderInfraList(domainDetail.infrastructure.ip_addresses)}
                  </div>
                </div>
                <div className="col-4">
                  <div className="sb-label">Registrar</div>
                  <div className="sb-muted">{domainDetail.infrastructure.registrar || "\u2014"}</div>
                </div>
                <div className="col-4">
                  <div className="sb-label">Nameservers</div>
                  {renderInfraList(domainDetail.infrastructure.nameservers)}
                </div>
              </div>
            ) : (
              <div className="sb-muted">No infrastructure data available.</div>
            )}
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
                  <pre className="sb-pre" style={{ marginBottom: 12 }}>{domainDetail.domain.operator_notes as any}</pre>
                ) : (
                  <div className="sb-muted" style={{ marginBottom: 12 }}>No notes yet.</div>
                )}
                {canEdit && (
                  <div style={{ borderTop: "1px solid var(--border-subtle)", paddingTop: 12 }}>
                    <div className="sb-label">Add Note</div>
                    <textarea
                      className="sb-input"
                      rows={2}
                      placeholder="Enter a note..."
                      value={noteInput}
                      onChange={(e) => setNoteInput(e.target.value)}
                      style={{ width: "100%", resize: "vertical", marginBottom: 8, minHeight: 60 }}
                    />
                    <button
                      className="sb-btn sb-btn-primary"
                      disabled={!noteInput.trim() || noteSaving}
                      onClick={async () => {
                        if (!canEdit) {
                          showToast("Read-only mode: notes are disabled.", "info");
                          return;
                        }
                        if (!domainDetail?.domain.id) return;
                        setNoteSaving(true);
                        try {
                          const timestamp = new Date().toISOString().slice(0, 16).replace("T", " ");
                          const existingNotes = (domainDetail.domain.operator_notes || "").trim();
                          const newNote = `[${timestamp}] ${noteInput.trim()}`;
                          const combined = existingNotes ? `${existingNotes}\n${newNote}` : newNote;
                          await updateOperatorNotes(domainDetail.domain.id, combined);
                          showToast("Note added", "success");
                          setNoteInput("");
                          loadDomainDetail(domainDetail.domain.id);
                        } catch (err) {
                          showToast((err as Error).message || "Failed to add note", "error");
                        } finally {
                          setNoteSaving(false);
                        }
                      }}
                    >
                      {noteSaving ? "Saving..." : "Add Note"}
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>

          <CampaignCard campaign={domainDetail.campaign} related={domainDetail.related_domains || []} />
        </>
      )}
    </div>
  );


  const content = (() => {
    if (route.name === "domain") return domainDetailView;
    if (route.name === "campaigns") return campaignsView;
    if (route.name === "campaign") return campaignDetailView;
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
          {isAdmin && (
            <span className={`sb-mode ${isAdmin ? "mode-admin" : "mode-public"}`}>
              ADMIN
            </span>
          )}
        </div>
        <nav className="sb-nav">
          <a className="sb-btn" href="#/">Dashboard</a>
          <a className="sb-btn" href="#/campaigns">Threat Campaigns</a>

          {/* Settings Cog */}
          {canEdit && (
            <div className="sb-settings-container">
              <button
                className={`sb-settings-btn ${settingsOpen ? "active" : ""}`}
                onClick={() => setSettingsOpen(!settingsOpen)}
                title="Settings"
              >
                ⚙
              </button>

              {settingsOpen && (
                <>
                  <div className="sb-settings-overlay" onClick={() => setSettingsOpen(false)} />
                  <div className="sb-settings-popup">
                    <div className="sb-settings-popup-header">
                      <span className="sb-settings-popup-title">System Settings</span>
                      <button className="sb-btn" onClick={() => setSettingsOpen(false)} style={{ padding: "4px 8px" }}>×</button>
                    </div>

                    {/* Health Status */}
                    <div className="sb-settings-section">
                      <div className="sb-settings-section-title">Health Status</div>
                      <div className="sb-row" style={{ alignItems: "center", gap: 8 }}>
                        <span className={`sb-badge sb-badge-${healthLabel.toLowerCase()}`}>{healthLabel}</span>
                        <span className="sb-muted" style={{ fontSize: 12 }}>{(health as any)?.status || (health as any)?.error || "Best-effort check"}</span>
                      </div>
                    </div>

                    {/* Evidence Storage */}
                    <div className="sb-settings-section">
                      <div className="sb-settings-section-title">Evidence Storage</div>
                      <div style={{ fontSize: 24, fontWeight: 700, fontFamily: "var(--font-mono)" }}>{formatBytes(stats?.evidence_bytes)}</div>
                      <div className="sb-muted" style={{ fontSize: 12 }}>Approximate evidence size</div>
                    </div>

                    {/* Evidence Cleanup */}
                    <div className="sb-settings-section">
                      <div className="sb-settings-section-title">Evidence Cleanup</div>
                      <div className="sb-row" style={{ alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                        <input
                          className="sb-input"
                          type="number"
                          min={1}
                          value={cleanupDays}
                          onChange={(e) => setCleanupDays(Number(e.target.value) || 1)}
                          style={{ width: 70 }}
                        />
                        <span className="sb-muted">days old</span>
                      </div>
                      <div className="sb-row" style={{ marginTop: 10, gap: 8 }}>
                        <button className="sb-btn" type="button" disabled={cleanupBusy} onClick={handleCleanupPreview}>
                          {cleanupBusy ? "Working…" : "Preview"}
                        </button>
                        <button className="sb-btn sb-btn-danger" type="button" disabled={cleanupBusy} onClick={handleCleanup}>
                          {cleanupBusy ? "Cleaning…" : "Cleanup"}
                        </button>
                      </div>
                      {cleanupPreview && (
                        <div className="sb-notice" style={{ marginTop: 8, fontSize: 12 }}>
                          Would remove <b>{cleanupPreview.count}</b> directories (~{formatBytes(cleanupPreview.bytes)})
                        </div>
                      )}
                      {cleanupResult && <div className="sb-muted" style={{ marginTop: 8, fontSize: 12 }}>{cleanupResult}</div>}
                      {cleanupError && <div className="sb-notice" style={{ color: "var(--accent-red)", marginTop: 8, fontSize: 12 }}>{cleanupError}</div>}
                    </div>
                  </div>
                </>
              )}
            </div>
          )}
        </nav>
      </header>

      {statsLoading && <div className="sb-muted" style={{ marginBottom: 12 }}>Loading stats…</div>}
      {content}

      <footer className="sb-footer">
        <span>SeedBuster Phishing Detection Pipeline</span>
        <span>{isAdmin ? "Admin view" : ""}</span>
      </footer>

      <div id="sb-toast-container" className="sb-toast-container" aria-live="polite">
        {toast && <Toast message={toast.message} tone={toast.tone} />}
      </div>

      {/* Report Panel Slide-out */}
      {canEdit && (
        <>
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

                      {reportPanelManualFormUrl && (
                        <div className="sb-manual-cta">
                          <a className="sb-manual-cta-btn" href={reportPanelManualFormUrl} target="_blank" rel="noopener noreferrer">
                            ↗ Open {((reportPanelInfo[reportPanelManualMode]?.name || reportPanelManualMode) as string).charAt(0).toUpperCase() + ((reportPanelInfo[reportPanelManualMode]?.name || reportPanelManualMode) as string).slice(1)} Abuse Form
                          </a>
                        </div>
                      )}
                      {reportPanelManualInstructions ? (
                        <>
                          <div className="sb-muted" style={{ marginBottom: 8 }}>
                            {reportPanelManualInstructions.reason || "Manual submission"}
                          </div>
                          <div style={{ marginBottom: 8 }}>
                            <div className="sb-label">Report URL</div>
                            {reportPanelManualInstructions.form_url ? (
                              <a href={reportPanelManualInstructions.form_url} target="_blank" rel="noreferrer">
                                {reportPanelManualInstructions.form_url}
                              </a>
                            ) : (
                              <span className="sb-muted">No form URL provided</span>
                            )}
                          </div>
                          {reportPanelManualInstructions.fields?.map((field) => (
                            <div key={field.name} style={{ marginBottom: 10 }}>
                              <div className="sb-label">{field.label}</div>
                              <div className="sb-row" style={{ gap: 8 }}>
                                <textarea
                                  className="sb-input"
                                  value={field.value}
                                  readOnly
                                  rows={field.multiline ? 3 : 1}
                                  style={{ width: "100%", resize: "vertical" }}
                                />
                                <button className="sb-btn" type="button" onClick={() => copyValue(field.value)}>Copy</button>
                              </div>
                            </div>
                          ))}
                          {reportPanelManualInstructions.notes && reportPanelManualInstructions.notes.length > 0 && (
                            <ul className="sb-muted" style={{ paddingLeft: 18, marginTop: 8 }}>
                              {reportPanelManualInstructions.notes.map((n, idx) => <li key={idx}>{n}</li>)}
                            </ul>
                          )}
                        </>
                      ) : (
                        <>
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
                        </>
                      )}
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
                              const displayName = info.name || platform.charAt(0).toUpperCase() + platform.slice(1);
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
                                  <span className="sb-report-platform-name">{displayName}</span>
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
        </>
      )}

      {/* Visit Website Warning Modal */}
      {visitWarningOpen && (
        <div className="sb-modal-overlay" onClick={() => setVisitWarningOpen(false)}>
          <div className="sb-modal" onClick={(e) => e.stopPropagation()}>
            <div className="sb-modal-header">⚠️ Security Warning</div>
            <div className="sb-modal-body">
              <p>You are about to visit a potentially malicious website:</p>
              <code className="sb-code">{visitWarningUrl}</code>
              <p style={{ marginTop: 12, color: "var(--accent-amber)" }}>
                This site may contain phishing content, malware, or other harmful material.
                Proceed only if you understand the risks.
              </p>
            </div>
            <div className="sb-modal-footer">
              <button className="sb-btn" onClick={() => setVisitWarningOpen(false)}>Cancel</button>
              <a
                className="sb-btn sb-btn-danger"
                href={visitWarningUrl}
                target="_blank"
                rel="noopener noreferrer"
                onClick={() => setVisitWarningOpen(false)}
              >
                I Understand — Open Website
              </a>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
