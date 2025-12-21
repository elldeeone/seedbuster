export interface Stats {
  total: number;
  last_24h: number;
  evidence_bytes?: number;
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
}

export interface Domain {
  id?: number;
  domain: string;
  status: string;
  verdict?: string | null;
  score?: number | null;
  created_at?: string;
  updated_at?: string;
  last_checked_at?: string;
  action_required?: string | null;
  operator_notes?: string | null;
  [key: string]: unknown;
}

export interface Report {
  id?: number;
  platform: string;
  status: string;
  result?: string | null;
  created_at?: string;
}

export interface EvidenceSummary {
  html?: string | null;
  analysis?: string | null;
  screenshots?: string[];
}

export interface DomainDetailResponse {
  domain: Domain;
  reports: Report[];
  evidence: EvidenceSummary;
  related_domains?: Domain[];
  cluster?: Cluster | null;
  instruction_files?: string[];
}

export interface ClusterMember {
  domain: string;
  added_at?: string;
  score?: number;
  [key: string]: unknown;
}

export interface Cluster {
  cluster_id: string;
  name?: string;
  created_at?: string;
  updated_at?: string;
  members?: ClusterMember[];
  shared_backends?: string[];
  shared_nameservers?: string[];
  shared_kits?: string[];
  shared_asns?: string[];
  [key: string]: unknown;
}
