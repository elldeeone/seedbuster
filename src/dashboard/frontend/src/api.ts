import type {
  Cluster,
  Domain,
  DomainDetailResponse,
  DomainsResponse,
  PendingReport,
  Stats,
} from "./types";

const API_BASE = "/admin/api";
const BASIC_AUTH = import.meta.env.VITE_ADMIN_AUTH;
const AUTH_HEADER = BASIC_AUTH ? { Authorization: `Basic ${btoa(BASIC_AUTH)}` } : undefined;

type RequestOptions = RequestInit & { skipJson?: boolean };

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    cache: "no-store",
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(AUTH_HEADER || {}),
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
}): Promise<DomainsResponse> {
  const qs = new URLSearchParams();
  if (params.status) qs.set("status", params.status);
  if (params.verdict) qs.set("verdict", params.verdict);
  if (params.q) qs.set("q", params.q);
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

export async function fetchClusters(): Promise<{ clusters: Cluster[] }> {
  return request("/clusters");
}

export async function fetchCluster(clusterId: string): Promise<{ cluster: Cluster; domains: Domain[] }> {
  return request(`/clusters/${encodeURIComponent(clusterId)}`);
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

export interface PlatformInfo {
  manual_only: boolean;
  url: string;
}

export async function fetchPlatformInfo(): Promise<{
  platforms: string[];
  info: Record<string, PlatformInfo>;
}> {
  return request("/platforms");
}
