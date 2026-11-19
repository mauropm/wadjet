// Mirror of internal/models/models.go JSON shapes + scanner manifest types.
// Field names here MUST stay aligned with the Go structs (contract binding).

export interface User {
  id: string;
  email: string;
  name: string;
  role: string;
  created_at: string;
}

export interface LoginResponse {
  user: User;
  token: string;
}

export interface ListResponse<T> {
  items: T[];
  total: number;
}

export interface Project {
  id: string;
  name: string;
  description: string;
  status: 'active' | 'archived' | string;
  tags: string[];
  settings: unknown; // jsonb
  created_by?: string | null;
  created_at: string;
  updated_at: string;
  last_activity_at?: string | null;
}

export interface ProjectTarget {
  id: string;
  project_id: string;
  target: string;
  target_type: string;
  excluded: boolean;
  note: string;
  created_at: string;
}

export interface Asset {
  id: string;
  project_id: string;
  identity: string;
  asset_type: string;
  ip?: string | null;
  ipv6?: string | null;
  hostname?: string | null;
  domain?: string | null;
  mac?: string | null;
  os_name?: string | null;
  os_accuracy?: number | null;
  status: string;
  discovery_source: string; // manual | scanner | import
  description: string;
  tags: string[];
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
}

export interface AssetObservation {
  id: string;
  asset_id: string;
  scan_session_id?: string | null;
  scanner_execution_id?: string | null;
  observation_type: string;
  observed_at: string;
  raw: unknown; // jsonb
  source: string;
  created_at: string;
}

export interface ScannerManifestOption {
  key: string;
  type: 'boolean' | 'multiselect' | 'select' | 'number' | 'string' | string;
  label?: string;
  description?: string;
  default?: unknown;
  options?: Array<string | { value: string; label?: string }>;
  min?: number;
  max?: number;
  placeholder?: string;
}

export interface ScannerManifest {
  name?: string;
  display_name?: string;
  description?: string;
  version_constraint?: string;
  adapter?: string;
  asset_types?: string[];
  capabilities?: string[];
  documentation?: string;
  configuration?: { options?: ScannerManifestOption[] };
  [k: string]: unknown;
}

export interface ScannerRecord {
  id: string;
  name: string;
  display_name: string;
  description: string;
  version: string;
  executable: string;
  adapter: string;
  enabled: boolean;
  asset_types: string[];
  capabilities: string[];
  manifest: ScannerManifest | null;
  status: string; // available | missing | disabled | ...
  status_detail: string;
  last_checked_at?: string | null;
  documentation: string;
  created_at: string;
  updated_at: string;
}

export interface ProfileScanner {
  id?: string;
  profile_id?: string;
  scanner_id: string;
  scanner: string; // denormalized scanner name
  config: unknown; // jsonb object
  sort_order: number;
}

export interface ScanProfile {
  id: string;
  project_id: string;
  name: string;
  description: string;
  target_selection: string[];
  excluded_targets: string[];
  timeout_seconds: number;
  report_prefs: unknown;
  created_at: string;
  updated_at: string;
  scanners?: ProfileScanner[];
}

export interface ScannerExecution {
  id: string;
  session_id: string;
  scanner_name: string;
  status: string; // queued|running|completed|failed|cancelled
  config: unknown;
  targets: string[];
  raw_output_path: string;
  raw_output_bytes: number;
  assets_observed: number;
  findings_found: number;
  error: string;
  log: string;
  started_at?: string | null;
  finished_at?: string | null;
  created_at: string;
}

export interface ScanSession {
  id: string;
  project_id: string;
  profile_id?: string | null;
  name: string;
  status: string; // draft|queued|running|completed|completed_with_errors|failed|cancelled
  targets: string[];
  scanner_names: string[];
  assets_processed: number;
  findings_created: number;
  findings_updated: number;
  error: string;
  started_at?: string | null;
  finished_at?: string | null;
  duration_ms?: number | null;
  created_by?: string | null;
  created_at: string;
  updated_at: string;
  executions?: ScannerExecution[];
}

export interface Finding {
  id: string;
  project_id: string;
  asset_id: string;
  title: string;
  description: string;
  technical_details: string;
  evidence: string;
  scanner: string;
  port?: number | null;
  protocol?: string | null;
  service?: string | null;
  cves: string[];
  cvss_score?: number | null;
  severity: string; // critical|high|medium|low|info
  status: string; // open|confirmed|remediated|accepted_risk|false_positive
  remediation: string;
  references: unknown; // jsonb — string[] or {url,label}[]
  fingerprint: string;
  first_detected: string;
  last_detected: string;
  created_at: string;
  updated_at: string;
}

export interface FindingObservation {
  id: string;
  finding_id: string;
  scan_session_id?: string | null;
  scanner_execution_id?: string | null;
  observed_at: string;
  status_at_detection: string;
  raw: unknown;
  created_at: string;
}

export interface FindingStatusHistory {
  id: string;
  finding_id: string;
  from_status: string;
  to_status: string;
  changed_by?: string | null;
  note: string;
  created_at: string;
}

export interface Report {
  id: string;
  project_id: string;
  session_id?: string | null;
  finding_id?: string | null;
  type: string; // scan|finding|findings_consolidated|findings_zip
  status: string; // pending|generating|completed|failed
  file_path: string;
  file_size: number;
  error: string;
  created_at: string;
  completed_at?: string | null;
}

export interface AuditLog {
  id: string;
  user_id?: string | null;
  action: string;
  resource_type: string;
  resource_id: string;
  details: unknown;
  ip: string;
  created_at: string;
}

// ── Request payload types (exact fields — server rejects unknown fields) ──

export interface ProjectCreateInput {
  name: string;
  description?: string;
  tags?: string[];
  settings?: unknown;
}

export interface ProjectUpdateInput {
  name?: string;
  description?: string;
  tags?: string[];
  status?: string;
  settings?: unknown;
}

export interface CloneInput {
  name?: string;
  copy_settings?: boolean;
  copy_targets?: boolean;
  copy_scanner_configs?: boolean;
  copy_profiles?: boolean;
  copy_tags?: boolean;
  copy_report_prefs?: boolean;
}

export interface TargetCreateInput {
  target: string;
  target_type?: string;
  excluded?: boolean;
  note?: string;
}

export interface TargetUpdateInput {
  target?: string;
  target_type?: string;
  excluded?: boolean;
  note?: string;
}

export interface AssetCreateInput {
  identity: string;
  asset_type: string;
  ip?: string;
  ipv6?: string;
  hostname?: string;
  domain?: string;
  os_name?: string;
  description?: string;
  tags?: string[];
}

export interface ProfileInput {
  name: string;
  description?: string;
  target_selection?: string[];
  excluded_targets?: string[];
  timeout_seconds?: number;
  report_prefs?: unknown;
  scanners?: ProfileScanner[];
}

export interface ScanCreateScanner {
  scanner: string;
  config?: unknown;
}

export interface ScanCreateInput {
  name: string;
  profile_id?: string;
  targets?: string[];
  scanner_names?: string[];
  scanners?: ScanCreateScanner[];
}

export interface FindingStatusInput {
  status: string;
  note?: string;
}
