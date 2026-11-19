import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, ExternalLink, FileDown } from 'lucide-react';
import { findingsApi, unwrap } from '@/api/client';
import { SeverityChip, StatusChip } from '@/components/chips';
import { EmptyState, ErrorState } from '@/components/empty-state';
import { Badge, Chip } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Field, Select, Textarea } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { Separator } from '@/components/ui/switch';
import { useToast } from '@/components/ui/toast';
import { useApi } from '@/lib/use-api';
import { useReportGen } from '@/lib/use-report';
import { FINDING_STATUSES, findingStatusMeta, severityMeta } from '@/lib/severity';
import { formatDateTime, timeAgo } from '@/lib/utils';
import type { Finding } from '@/lib/types';

/** Normalize references jsonb (string[] or {url,label}[]) into links. */
function referenceLinks(refs: unknown): Array<{ url: string; label: string }> {
  if (!refs) return [];
  let arr: unknown = refs;
  if (typeof refs === 'string') {
    try {
      arr = JSON.parse(refs);
    } catch {
      return refs.trim() ? [{ url: refs.trim(), label: refs.trim() }] : [];
    }
  }
  if (!Array.isArray(arr)) return [];
  return arr
    .map((item): { url: string; label: string } | null => {
      if (typeof item === 'string') return item ? { url: item, label: item } : null;
      if (item && typeof item === 'object') {
        const o = item as Record<string, unknown>;
        const url = String(o.url ?? o.href ?? o.link ?? '');
        if (!url) return null;
        return { url, label: String(o.label ?? o.title ?? url) };
      }
      return null;
    })
    .filter((x): x is { url: string; label: string } => !!x && /^https?:\/\//i.test(x.url));
}

/** Untrusted text rendered as escaped monospace blocks (React escapes). */
function TextBlock({ title, text, tone }: { title: string; text?: string; tone?: 'danger' }) {
  if (!text?.trim()) return null;
  return (
    <>
      <Separator className="my-4" />
      <div>
        <h3 className="mb-1.5 text-[12px] font-semibold uppercase tracking-wider text-mute/80">{title}</h3>
        <pre className={tone === 'danger' ? 'mono-block border-sev-critical/20' : 'mono-block'}>
          {text}
        </pre>
      </div>
    </>
  );
}

function StatusControl({ finding, onChanged }: { finding: Finding; onChanged: () => void }) {
  const toast = useToast();
  const [status, setStatus] = useState(finding.status);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);

  const dirty = status !== finding.status;

  const apply = async () => {
    setBusy(true);
    try {
      await findingsApi.setStatus(finding.id, { status, note: note.trim() || undefined });
      toast.success(`Status → ${findingStatusMeta(status).label}`);
      setNote('');
      onChanged();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Status change failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>🎛️ Status</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-center gap-2 text-[13px] text-mute">
          Current: <StatusChip status={finding.status} kind="finding" />
        </div>
        <Field label="New status">
          <Select value={status} onChange={(e) => setStatus(e.target.value)}>
            {FINDING_STATUSES.map((s) => (
              <option key={s} value={s}>
                {findingStatusMeta(s).emoji} {findingStatusMeta(s).label}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Note" hint="recorded in history">
          <Textarea
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Context for the auditor…"
            rows={2}
          />
        </Field>
        <Button variant="primary" size="sm" className="w-full" disabled={!dirty && !note.trim()} loading={busy} onClick={apply}>
          Update status
        </Button>
      </CardContent>
    </Card>
  );
}

export default function FindingDetailPage() {
  const { id = '' } = useParams();
  const state = useApi(() => findingsApi.get(id), [id]);
  const historyState = useApi(() => findingsApi.history(id).then(unwrap), [id]);
  const obsState = useApi(() => findingsApi.observations(id).then(unwrap).catch(() => []), [id]);
  const report = useReportGen();

  if (state.loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-16 w-full rounded-2xl" />
        <Skeleton className="h-72 rounded-2xl" />
      </div>
    );
  }
  if (state.error || !state.data) {
    return <ErrorState message={state.error ?? 'Finding not found'} onRetry={state.refetch} />;
  }
  const f = state.data;
  const sev = severityMeta(f.severity);
  const refs = referenceLinks(f.references);

  return (
    <div>
      <Link to={`/projects/${f.project_id}/findings`} className="mb-3 inline-flex items-center gap-1 text-[12.5px] text-mute hover:text-ink">
        <ArrowLeft className="h-3.5 w-3.5" /> Back to findings
      </Link>

      {/* severity banner */}
      <div
        className="mb-6 overflow-hidden rounded-2xl border bg-raised shadow-panel"
        style={{ borderColor: `${sev.hex}44` }}
      >
        <div className="h-1" style={{ backgroundColor: sev.hex }} aria-hidden />
        <div className="flex flex-wrap items-start justify-between gap-4 p-5">
          <div className="min-w-0">
            <div className="mb-1.5 flex flex-wrap items-center gap-2">
              <SeverityChip severity={f.severity} />
              <StatusChip status={f.status} kind="finding" />
              <Badge tone="outline" className="font-mono">
                🔧 {f.scanner}
              </Badge>
            </div>
            <h1 className="text-lg font-bold leading-snug text-ink">{f.title}</h1>
            <div className="mt-2 flex flex-wrap items-center gap-2 text-[12.5px] text-mute">
              <Link to={`/assets/${f.asset_id}`} className="font-mono text-accent-soft hover:underline">
                🖥️ asset →
              </Link>
              <span aria-hidden>·</span>
              <span className="font-mono">
                {[f.port, f.service, f.protocol].filter((v) => v != null && v !== '').join(' / ') || 'no port info'}
              </span>
              <span aria-hidden>·</span>
              <span title={f.first_detected}>first {timeAgo(f.first_detected)}</span>
              <span aria-hidden>·</span>
              <span title={f.last_detected}>last {timeAgo(f.last_detected)}</span>
            </div>
          </div>
          <div className="flex flex-col items-end gap-2">
            {f.cvss_score != null && (
              <div
                className="flex h-16 w-16 flex-col items-center justify-center rounded-2xl border"
                style={{ borderColor: `${sev.hex}55`, backgroundColor: `${sev.hex}14` }}
              >
                <span className="text-xl font-bold" style={{ color: sev.hex }}>
                  {f.cvss_score.toFixed(1)}
                </span>
                <span className="text-[9px] uppercase tracking-wider text-mute">CVSS</span>
              </div>
            )}
            <Button
              variant="secondary"
              size="sm"
              loading={report.busy}
              onClick={() => report.run(() => findingsApi.generateReport(f.id), `wadjet-finding.pdf`)}
            >
              <FileDown className="h-3.5 w-3.5" /> Download PDF
            </Button>
          </div>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        {/* main content */}
        <div className="space-y-6 lg:col-span-2">
          <Card>
            <CardContent className="p-5">
              <div className="flex flex-wrap gap-1.5">
                {(f.cves ?? []).map((cve) => (
                  <a
                    key={cve}
                    href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    title={`Open ${cve} on NVD`}
                  >
                    <Chip className="border-sev-high/30 text-sev-high hover:border-sev-high/60">
                      🛡️ {cve} <ExternalLink className="h-2.5 w-2.5" />
                    </Chip>
                  </a>
                ))}
                {(f.cves ?? []).length === 0 && (
                  <span className="text-[12.5px] text-mute/70">No CVEs attached.</span>
                )}
              </div>

              {f.description?.trim() ? (
                <div className="mt-4">
                  <h3 className="mb-1.5 text-[12px] font-semibold uppercase tracking-wider text-mute/80">
                    Description
                  </h3>
                  <pre className="mono-block font-sans leading-relaxed">{f.description}</pre>
                </div>
              ) : null}

              <TextBlock title="Technical details" text={f.technical_details} />
              <TextBlock title="Evidence (untrusted scanner output)" text={f.evidence} tone="danger" />
              {f.remediation?.trim() && (
                <div className="mt-4">
                  <h3 className="mb-1.5 text-[12px] font-semibold uppercase tracking-wider text-accent-soft">
                    🛠️ Remediation
                  </h3>
                  <pre className="mono-block border-accent/20 font-sans leading-relaxed">{f.remediation}</pre>
                </div>
              )}
            </CardContent>
          </Card>

          {refs.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>🔗 References</CardTitle>
              </CardHeader>
              <CardContent>
                <ul className="space-y-1.5">
                  {refs.map((r) => (
                    <li key={r.url}>
                      <a
                        href={r.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 text-[13px] text-accent-soft hover:underline"
                      >
                        <ExternalLink className="h-3.5 w-3.5 shrink-0" />
                        <span className="break-all">{r.label}</span>
                      </a>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          )}

          {/* detection timeline */}
          <Card>
            <CardHeader>
              <CardTitle>🕵️ Detection timeline</CardTitle>
            </CardHeader>
            <CardContent>
              {obsState.loading && <Skeleton className="h-20" />}
              {!obsState.loading && (obsState.data ?? []).length === 0 && (
                <p className="text-[13px] text-mute">
                  Detection events appear here once the observations endpoint exposes them. First detected{' '}
                  {formatDateTime(f.first_detected)}, most recent {formatDateTime(f.last_detected)}.
                </p>
              )}
              {(obsState.data ?? []).length > 0 && (
                <ol className="relative space-y-3 border-l border-line pl-5">
                  {(obsState.data ?? [])
                    .slice()
                    .sort((a, b) => new Date(b.observed_at).getTime() - new Date(a.observed_at).getTime())
                    .map((o) => (
                      <li key={o.id} className="relative">
                        <span className="absolute -left-[26px] top-1.5 h-2.5 w-2.5 rounded-full border border-accent/40 bg-accent/20" aria-hidden />
                        <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
                          <span className="text-mute">{formatDateTime(o.observed_at)}</span>
                          <StatusChip status={o.status_at_detection} kind="finding" />
                          {o.scan_session_id && (
                            <Link to={`/scans/${o.scan_session_id}`} className="text-accent-soft hover:underline">
                              scan →
                            </Link>
                          )}
                        </div>
                      </li>
                    ))}
                </ol>
              )}
            </CardContent>
          </Card>
        </div>

        {/* sidebar */}
        <div className="space-y-6">
          <StatusControl finding={f} onChanged={state.refetch} />

          <Card>
            <CardHeader>
              <CardTitle>📜 Status history</CardTitle>
            </CardHeader>
            <CardContent>
              {historyState.loading && <Skeleton className="h-20" />}
              {historyState.error && (
                <p className="text-[13px] text-mute">History unavailable: {historyState.error}</p>
              )}
              {!historyState.loading && !historyState.error && (historyState.data ?? []).length === 0 && (
                <EmptyState emoji="🗒️" title="No transitions yet" className="border-0 py-4" />
              )}
              <ol className="space-y-3">
                {(historyState.data ?? [])
                  .slice()
                  .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
                  .map((h) => (
                    <li key={h.id} className="rounded-xl border border-line/70 bg-panel/50 p-2.5 text-[12.5px]">
                      <div className="flex items-center gap-1.5">
                        <StatusChip status={h.from_status} kind="finding" />→
                        <StatusChip status={h.to_status} kind="finding" />
                        <span className="ml-auto text-mute" title={h.created_at}>
                          {timeAgo(h.created_at)}
                        </span>
                      </div>
                      {h.note && <p className="mt-1.5 text-mute">“{h.note}”</p>}
                    </li>
                  ))}
              </ol>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>🧬 Fingerprint</CardTitle>
            </CardHeader>
            <CardContent>
              <code className="block break-all rounded-lg border border-line bg-black/40 p-2 font-mono text-[11px] text-mute">
                {f.fingerprint}
              </code>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
