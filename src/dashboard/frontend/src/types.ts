export interface Stats {
  total: number;
  last_24h: number;
  evidence_bytes?: number;
  public_submissions_pending?: number;
  active_threats?: number;
  tracked_domains?: number;
  by_status: Record<string, number>;
  by_verdict: Record<string, number>;
  reports?: Record<string, number>;
  dashboard_actions?: Record<string, number>;
}

export interface PendingReport {
  domain: string;
  platform: string;
  status: string;
  domain_id?: number;
  score?: number;
  created_at?: string;
   next_attempt_at?: string;
   attempts?: number;
   response?: string | null;
}

export interface Domain {
  id?: number;
  domain: string;
  status: string;
  verdict?: string | null;
  score?: number | null;
  domain_score?: number | null;
  analysis_score?: number | null;
  source?: string | null;
  first_seen?: string | null;
  analyzed_at?: string | null;
  reported_at?: string | null;
  created_at?: string;
  updated_at?: string;
  last_checked_at?: string;
  takedown_status?: string | null;
  takedown_detected_at?: string | null;
  takedown_confirmed_at?: string | null;
  action_required?: string | null;
  operator_notes?: string | null;
  verdict_reasons?: string | null;
  watchlist_baseline_timestamp?: string | null;
  [key: string]: unknown;
}

export interface DomainsResponse {
  domains: Domain[];
  page: number;
  limit: number;
  count: number;
  total?: number;
}

export interface Report {
  id?: number;
  platform: string;
  status: string;
  result?: string | null;
  created_at?: string;
  submitted_at?: string;
  next_attempt_at?: string;
  attempts?: number;
  response?: string;
}

export interface TakedownCheck {
  id?: number;
  domain_id?: number;
  domain?: string | null;
  checked_at?: string | null;
  http_status?: number | null;
  http_error?: string | null;
  dns_resolves?: boolean | null;
  dns_result?: string | null;
  is_sinkholed?: boolean | null;
  domain_status?: string | null;
  content_hash?: string | null;
  still_phishing?: boolean | null;
  takedown_status?: string | null;
  confidence?: number | null;
  provider_signal?: string | null;
  backend_status?: number | null;
  backend_error?: string | null;
  backend_target?: string | null;
}

export interface TakedownChecksResponse {
  checks: TakedownCheck[];
  count: number;
  limit: number;
  offset: number;
}

export interface EvidenceSummary {
  html?: string | null;
  analysis?: string | null;
  screenshots?: string[];
}

export interface SnapshotSummary {
  id: string;
  timestamp?: string | null;
  score?: number | null;
  verdict?: string | null;
  scan_reason?: string | null;
  is_latest?: boolean;
}

export interface SnapshotDetail extends SnapshotSummary {
  reasons?: string[] | string | null;
}

export interface RescanRequestInfo {
  count: number;
  threshold: number;
  window_hours?: number;
  cooldown_hours?: number;
}

export interface DomainDetailResponse {
  domain: Domain;
  reports: Report[];
  takedown_checks?: TakedownCheck[];
  evidence: EvidenceSummary;
  related_domains?: Domain[];
  campaign?: Campaign | null;
  instruction_files?: string[];
  rescan_request?: RescanRequestInfo | null;
  snapshots?: SnapshotSummary[];
  snapshot?: SnapshotDetail | null;
  infrastructure?: {
    hosting_provider?: string | null;
    edge_provider?: string | null;
    registrar?: string | null;
    nameservers?: string[] | null;
    ip_addresses?: string[] | null;
    tls_age_days?: number | null;
    domain_age_days?: number | null;
  };
}

export interface ManualSubmissionField {
  name: string;
  label: string;
  value: string;
  multiline?: boolean;
}

export interface ManualSubmissionData {
  form_url: string;
  reason: string;
  fields: ManualSubmissionField[];
  notes?: string[];
}

export interface ReportPlatformOption {
  id: string;
  name: string;
  manual_only: boolean;
  url?: string;
  engagement_count: number;
  instructions?: ManualSubmissionData;
  error?: string;
}

export interface ReportOptionsResponse {
  domain: string;
  domain_id: number;
  platforms: ReportPlatformOption[];
  total_engagements: number;
}

export interface BulkRescanStatus {
  total: number;
  pending?: number;
  processing?: number;
  done?: number;
  failed?: number;
}

export interface BulkRescanResponse {
  bulk_id: string;
  requested: number;
  found: number;
  missing: number;
  queued: number;
  skipped: number;
  status: BulkRescanStatus;
}

export interface PublicSubmission {
  id: number;
  domain: string;
  canonical_domain: string;
  source_url?: string | null;
  reporter_notes?: string | null;
  submission_count?: number;
  first_submitted_at?: string;
  last_submitted_at?: string;
  status: string;
  reviewed_at?: string | null;
  reviewer_notes?: string | null;
  promoted_domain_id?: number | null;
}

export interface AnalyticsResponse {
  engagement: { total_engagements: number; by_platform: Record<string, number> };
  takedown: { by_status: Record<string, number>; avg_hours_to_detect?: number | null };
}

export interface CampaignMember {
  domain: string;
  added_at?: string;
  score?: number;
  [key: string]: unknown;
}

export interface Campaign {
  campaign_id: string;
  name?: string;
  created_at?: string;
  updated_at?: string;
  members?: CampaignMember[];
  shared_backends?: string[];
  shared_nameservers?: string[];
  shared_kits?: string[];
  shared_asns?: string[];
  shared_visual_hashes?: string[];
  shared_domain_similarity?: Array<{ left: string; right: string; similarity: number }>;
  [key: string]: unknown;
}
