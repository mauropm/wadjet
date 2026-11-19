// Centralized severity / status rendering (color + emoji + label maps).
// Every severity/status chip in the app goes through these maps.

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export interface SeverityMeta {
  label: string;
  emoji: string;
  hex: string;
  /** Tailwind classes for a small chip (bg/text/border). */
  chip: string;
  /** Tailwind text color. */
  text: string;
  /** Solid background for banners/dots. */
  solid: string;
  /** Higher = more severe, for sorting. */
  weight: number;
}

const SEVERITY_MAP: Record<Severity, SeverityMeta> = {
  critical: {
    label: 'Critical',
    emoji: '🔴',
    hex: '#EF4444',
    chip: 'bg-sev-critical/15 text-sev-critical border-sev-critical/30',
    text: 'text-sev-critical',
    solid: 'bg-sev-critical',
    weight: 5,
  },
  high: {
    label: 'High',
    emoji: '🟠',
    hex: '#F97316',
    chip: 'bg-sev-high/15 text-sev-high border-sev-high/30',
    text: 'text-sev-high',
    solid: 'bg-sev-high',
    weight: 4,
  },
  medium: {
    label: 'Medium',
    emoji: '🟡',
    hex: '#EAB308',
    chip: 'bg-sev-medium/15 text-sev-medium border-sev-medium/30',
    text: 'text-sev-medium',
    solid: 'bg-sev-medium',
    weight: 3,
  },
  low: {
    label: 'Low',
    emoji: '🔵',
    hex: '#3B82F6',
    chip: 'bg-sev-low/15 text-sev-low border-sev-low/30',
    text: 'text-sev-low',
    solid: 'bg-sev-low',
    weight: 2,
  },
  info: {
    label: 'Info',
    emoji: '⚪',
    hex: '#64748B',
    chip: 'bg-sev-info/15 text-sev-info border-sev-info/30',
    text: 'text-sev-info',
    solid: 'bg-sev-info',
    weight: 1,
  },
};

const SEVERITY_FALLBACK: SeverityMeta = {
  label: 'Unknown',
  emoji: '⚪',
  hex: '#64748B',
  chip: 'bg-sev-info/15 text-sev-info border-sev-info/30',
  text: 'text-mute',
  solid: 'bg-sev-info',
  weight: 0,
};

export function severityMeta(severity?: string | null): SeverityMeta {
  if (!severity) return SEVERITY_FALLBACK;
  return SEVERITY_MAP[severity.toLowerCase() as Severity] ?? {
    ...SEVERITY_FALLBACK,
    label: severity,
  };
}

export function severityWeight(severity?: string | null): number {
  return severityMeta(severity).weight;
}

export function isSeverity(v?: string | null): v is Severity {
  return !!v && (SEVERITIES as readonly string[]).includes(v.toLowerCase());
}

// ── Finding status ──────────────────────────────────────────────────────────

export const FINDING_STATUSES = [
  'open',
  'confirmed',
  'remediated',
  'accepted_risk',
  'false_positive',
] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export interface StatusMeta {
  label: string;
  emoji: string;
  chip: string;
}

const FINDING_STATUS_MAP: Record<string, StatusMeta> = {
  open: { label: 'Open', emoji: '🟥', chip: 'bg-sev-critical/10 text-sev-critical border-sev-critical/25' },
  confirmed: { label: 'Confirmed', emoji: '🧨', chip: 'bg-sev-high/10 text-sev-high border-sev-high/25' },
  remediated: { label: 'Remediated', emoji: '✅', chip: 'bg-accent/10 text-accent-soft border-accent/25' },
  accepted_risk: { label: 'Accepted Risk', emoji: '🤝', chip: 'bg-gold/10 text-gold border-gold/30' },
  false_positive: { label: 'False Positive', emoji: '🫥', chip: 'bg-sev-info/10 text-mute border-line' },
};

const STATUS_FALLBACK: StatusMeta = {
  label: 'Unknown',
  emoji: '•',
  chip: 'bg-raised text-mute border-line',
};

export function findingStatusMeta(status?: string | null): StatusMeta {
  if (!status) return STATUS_FALLBACK;
  return FINDING_STATUS_MAP[status.toLowerCase()] ?? { ...STATUS_FALLBACK, label: status };
}

// ── Scan session status ─────────────────────────────────────────────────────

const SCAN_STATUS_MAP: Record<string, StatusMeta> = {
  draft: { label: 'Draft', emoji: '📝', chip: 'bg-sev-info/10 text-mute border-line' },
  queued: { label: 'Queued', emoji: '🕐', chip: 'bg-sev-low/10 text-sev-low border-sev-low/25' },
  running: { label: 'Running', emoji: '👁️', chip: 'bg-accent/10 text-accent-soft border-accent/30' },
  completed: { label: 'Completed', emoji: '✅', chip: 'bg-accent/10 text-accent-soft border-accent/25' },
  completed_with_errors: { label: 'Completed w/ errors', emoji: '⚠️', chip: 'bg-sev-medium/10 text-sev-medium border-sev-medium/25' },
  failed: { label: 'Failed', emoji: '💥', chip: 'bg-sev-critical/10 text-sev-critical border-sev-critical/25' },
  cancelled: { label: 'Cancelled', emoji: '🚫', chip: 'bg-sev-info/10 text-mute border-line' },
};

export function scanStatusMeta(status?: string | null): StatusMeta {
  if (!status) return STATUS_FALLBACK;
  return SCAN_STATUS_MAP[status.toLowerCase()] ?? { ...STATUS_FALLBACK, label: status };
}

// ── Scanner execution status ────────────────────────────────────────────────

const EXEC_STATUS_MAP: Record<string, StatusMeta> = {
  queued: { label: 'Queued', emoji: '🕐', chip: 'bg-sev-low/10 text-sev-low border-sev-low/25' },
  running: { label: 'Running', emoji: '▶️', chip: 'bg-accent/10 text-accent-soft border-accent/30' },
  completed: { label: 'Completed', emoji: '✅', chip: 'bg-accent/10 text-accent-soft border-accent/25' },
  failed: { label: 'Failed', emoji: '💥', chip: 'bg-sev-critical/10 text-sev-critical border-sev-critical/25' },
  cancelled: { label: 'Cancelled', emoji: '🚫', chip: 'bg-sev-info/10 text-mute border-line' },
};

export function execStatusMeta(status?: string | null): StatusMeta {
  if (!status) return STATUS_FALLBACK;
  return EXEC_STATUS_MAP[status.toLowerCase()] ?? { ...STATUS_FALLBACK, label: status };
}

// ── Report status / type ────────────────────────────────────────────────────

const REPORT_STATUS_MAP: Record<string, StatusMeta> = {
  pending: { label: 'Pending', emoji: '🕐', chip: 'bg-sev-low/10 text-sev-low border-sev-low/25' },
  generating: { label: 'Generating', emoji: '⚙️', chip: 'bg-gold/10 text-gold border-gold/30' },
  completed: { label: 'Completed', emoji: '✅', chip: 'bg-accent/10 text-accent-soft border-accent/25' },
  failed: { label: 'Failed', emoji: '💥', chip: 'bg-sev-critical/10 text-sev-critical border-sev-critical/25' },
};

export function reportStatusMeta(status?: string | null): StatusMeta {
  if (!status) return STATUS_FALLBACK;
  return REPORT_STATUS_MAP[status.toLowerCase()] ?? { ...STATUS_FALLBACK, label: status };
}

export function reportTypeLabel(type?: string | null): string {
  switch (type?.toLowerCase()) {
    case 'scan':
      return '📄 Scan report';
    case 'finding':
      return '🔍 Finding report';
    case 'findings_consolidated':
      return '📚 Consolidated findings';
    case 'findings_zip':
      return '🗜️ Findings ZIP';
    default:
      return type ?? 'Report';
  }
}

// ── Misc labels ─────────────────────────────────────────────────────────────

const ASSET_TYPE_LABELS: Record<string, string> = {
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  hostname: 'Hostname',
  domain: 'Domain',
  server: 'Server',
  endpoint: 'Endpoint',
  web_app: 'Web App',
  container: 'Container',
  other: 'Other',
};

export function assetTypeLabel(t?: string | null): string {
  if (!t) return '—';
  return ASSET_TYPE_LABELS[t.toLowerCase()] ?? t;
}

const DISCOVERY_LABELS: Record<string, string> = {
  manual: '✍️ Manual',
  scanner: '📡 Scanner',
  import: '📦 Import',
};

export function discoveryLabel(src?: string | null): string {
  if (!src) return '—';
  return DISCOVERY_LABELS[src.toLowerCase()] ?? src;
}

const SCANNER_STATUS_META: Record<string, StatusMeta & { dot: string }> = {
  available: { label: 'Available', emoji: '', chip: '', dot: 'bg-accent' },
  missing: { label: 'Missing', emoji: '', chip: '', dot: 'bg-sev-critical' },
  disabled: { label: 'Disabled', emoji: '', chip: '', dot: 'bg-sev-info' },
};

export function scannerStatusMeta(status?: string | null, enabled?: boolean) {
  const key = enabled === false ? 'disabled' : (status ?? '').toLowerCase();
  return (
    SCANNER_STATUS_META[key] ?? {
      label: status ?? 'Unknown',
      emoji: '',
      chip: '',
      dot: 'bg-sev-info',
    }
  );
}
