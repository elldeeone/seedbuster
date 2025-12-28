import type {
  Campaign,
  Domain,
  DomainDetailResponse,
  DomainsResponse,
  PendingReport,
  PublicSubmission,
  ReportOptionsResponse,
  Stats,
} from "./types";

// Detect admin vs public mode based solely on server-injected flag.
export function isAdminMode(): boolean {
  const flag = (window as any).__SB_MODE;
  if (flag === "admin") return true;
  return false;
}

// Use admin API for admin mode, public API for public mode (resolved per call so navigation can switch modes)
const getApiBase = () => (isAdminMode() ? "/admin/api" : "/api");
const BASIC_AUTH = import.meta.env.DEV ? import.meta.env.VITE_ADMIN_AUTH : "";
const AUTH_HEADER = BASIC_AUTH ? { Authorization: `Basic ${btoa(BASIC_AUTH)}` } : undefined;
const getCsrfHeader = (): Record<string, string> | undefined => {
  if (!isAdminMode()) return undefined;
  const token = (window as any).__SB_CSRF;
  if (!token) return undefined;
  return { "X-CSRF-Token": String(token) };
};

type RequestOptions = RequestInit & { skipJson?: boolean };

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const res = await fetch(`${getApiBase()}${path}`, {
    credentials: "include",
    cache: "no-store",
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(AUTH_HEADER || {}),
      ...(getCsrfHeader() || {}),
      ...(options.headers || {}),
    },
  });

  if (!res.ok) {
    let message = res.statusText;
    try {
      const data = await res.json();
      message = (data && (data.error || data.message)) || message;
    } catch (err) {
      try {
        message = await res.text();
      } catch (_err) {
        // ignore
      }
    }
    throw new Error(message || "Request failed");
  }

  if (options.skipJson) {
    // @ts-expect-error - caller knows this is intentional
    return undefined;
  }

  return (await res.json()) as T;
}

export async function fetchStats(): Promise<{
  stats: Stats;
  pending_reports: PendingReport[];
  health: unknown;
}> {
  return request<{
    stats: Stats;
    pending_reports: PendingReport[];
    health: unknown;
  }>("/stats");
}

export async function fetchDomains(params: {
  status?: string;
  verdict?: string;
  q?: string;
  page?: number;
  limit?: number;
  excludeStatuses?: string[];
}): Promise<DomainsResponse> {
  const qs = new URLSearchParams();
  if (params.status) qs.set("status", params.status);
  if (params.verdict) qs.set("verdict", params.verdict);
  if (params.q) qs.set("q", params.q);
  if (params.excludeStatuses && params.excludeStatuses.length > 0) {
    qs.set("exclude_statuses", params.excludeStatuses.join(","));
  }
  qs.set("page", String(params.page || 1));
  qs.set("limit", String(params.limit || 100));
  return request<DomainsResponse>(`/domains?${qs.toString()}`);
}


export async function fetchDomainDetail(domainId: number): Promise<DomainDetailResponse> {
  return request<DomainDetailResponse>(`/domains/${domainId}`);
}

export async function submitTarget(target: string): Promise<{ status: string; domain: string }> {
  return request("/submit", {
    method: "POST",
    body: JSON.stringify({ target }),
  });
}

export async function submitPublicTarget(
  target: string,
  opts: { sourceUrl?: string; notes?: string } = {},
): Promise<{ status: string; domain: string; duplicate?: boolean; submission_id?: number; message?: string }> {
  const res = await fetch("/api/public/submit", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      domain: target,
      source_url: opts.sourceUrl,
      notes: opts.notes,
    }),
  });
  if (!res.ok) {
    const msg = await res.text();
    throw new Error(msg || "Submit failed");
  }
  return res.json();
}

export async function rescanDomain(domainId: number, domain?: string): Promise<void> {
  await request(`/domains/${domainId}/rescan`, {
    method: "POST",
    body: JSON.stringify({ domain }),
    skipJson: true,
  });
}

export async function reportDomain(
  domainId: number,
  domain: string,
  platforms?: string[],
  force = false,
): Promise<void> {
  await request("/report", {
    method: "POST",
    body: JSON.stringify({ domain_id: domainId, domain, platforms, force }),
    skipJson: true,
  });
}

export async function markFalsePositive(domainId: number): Promise<void> {
  await request(`/domains/${domainId}/false_positive`, {
    method: "POST",
    skipJson: true,
  });
}

export async function cleanupEvidence(
  days: number,
  opts: { preview?: boolean } = {},
): Promise<{ status: string; removed_dirs?: number; removed_bytes?: number; would_remove?: number; would_bytes?: number; preview?: boolean }> {
  return request("/cleanup_evidence", {
    method: "POST",
    body: JSON.stringify({ days, preview: opts.preview }),
  });
}

export async function fetchReportOptions(domainId: number): Promise<ReportOptionsResponse> {
  return request<ReportOptionsResponse>(`/domains/${domainId}/report-options`);
}

export async function recordReportEngagement(domainId: number, platform: string): Promise<{ status: string; platform: string; new_count: number; message?: string }> {
  const res = await fetch(`/api/domains/${domainId}/report-engagement`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ platform }),
  });
  if (!res.ok) {
    const msg = await res.text();
    throw new Error(msg || "Failed to record engagement");
  }
  return res.json();
}

export async function requestRescan(domainId: number): Promise<{ status: string; count: number; threshold: number; remaining?: number; message?: string; window_hours?: number; cooldown_hours?: number }> {
  const res = await fetch(`/api/domains/${domainId}/rescan-request`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    const msg = await res.text();
    throw new Error(msg || "Failed to request rescan");
  }
  return res.json();
}

export async function fetchCampaigns(): Promise<{ campaigns: Campaign[] }> {
  return request("/campaigns");
}

export async function fetchCampaign(campaignId: string): Promise<{ campaign: Campaign; domains: Domain[] }> {
  return request(`/campaigns/${encodeURIComponent(campaignId)}`);
}

export async function updateDomainStatus(
  domainId: number,
  status: string,
): Promise<void> {
  await request(`/domains/${domainId}/status`, {
    method: "PATCH",
    body: JSON.stringify({ status }),
    skipJson: true,
  });
}

export async function updateWatchlistBaseline(domainId: number): Promise<any> {
  return await request(`/domains/${domainId}/baseline`, {
    method: "POST",
  });
}

export interface PlatformInfo {
  manual_only: boolean;
  url: string;
  name?: string;
}

export async function fetchPlatformInfo(): Promise<{
  platforms: string[];
  info: Record<string, PlatformInfo>;
}> {
  return request("/platforms");
}

export async function updateOperatorNotes(
  domainId: number,
  notes: string,
): Promise<void> {
  await request(`/domains/${domainId}/notes`, {
    method: "PATCH",
    body: JSON.stringify({ notes }),
    skipJson: true,
  });
}

export async function updateCampaignName(
  campaignId: string,
  name: string,
): Promise<void> {
  await request(`/campaigns/${encodeURIComponent(campaignId)}/name`, {
    method: "PATCH",
    body: JSON.stringify({ name }),
    skipJson: true,
  });
}

export async function fetchPublicSubmissions(
  status = "pending_review",
  page = 1,
  limit = 100,
): Promise<{ submissions: PublicSubmission[]; page: number; limit: number; count: number; total: number; total_pending?: number }> {
  const qs = new URLSearchParams({ status, page: String(page), limit: String(limit) });
  return request(`/submissions?${qs.toString()}`);
}

export async function fetchAnalytics(): Promise<{
  engagement: { total_engagements: number; by_platform: Record<string, number> };
  takedown: { by_status: Record<string, number>; avg_hours_to_detect?: number | null };
}> {
  return request("/analytics");
}

export async function approvePublicSubmission(
  submissionId: number,
  notes?: string,
): Promise<{ status: string; domain?: string; domain_id?: number }> {
  return request(`/submissions/${submissionId}/approve`, {
    method: "POST",
    body: JSON.stringify({ notes }),
  });
}

export async function rejectPublicSubmission(
  submissionId: number,
  reason = "rejected",
  notes?: string,
): Promise<{ status: string; reason?: string }> {
  return request(`/submissions/${submissionId}/reject`, {
    method: "POST",
    body: JSON.stringify({ reason, notes }),
  });
}
