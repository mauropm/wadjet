import { useMemo } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { assetsApi, projectsApi, unwrap } from '@/api/client';
import { SeverityChip, StatusChip } from '@/components/chips';
import { ErrorState } from '@/components/empty-state';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { useApi } from '@/lib/use-api';
import { assetTypeLabel, discoveryLabel } from '@/lib/severity';
import { formatDateTime, timeAgo } from '@/lib/utils';
import type { AssetObservation } from '@/lib/types';

/** Pull interesting scalar fields out of an observation's raw JSON. */
function rawFields(raw: unknown): Array<[string, string]> {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return [];
  return Object.entries(raw as Record<string, unknown>)
    .filter(([, v]) => typeof v !== 'object' || v === null)
    .map(([k, v]) => [k, String(v)] as [string, string]);
}

/** Detect port/service arrays inside raw and flatten them to rows. */
function rawList(raw: unknown, keys: string[]): Array<Record<string, unknown>> {
  if (Array.isArray(raw)) return raw.filter((x) => x && typeof x === 'object') as Array<Record<string, unknown>>;
  if (raw && typeof raw === 'object') {
    for (const k of Object.keys(raw as Record<string, unknown>)) {
      if (keys.some((needle) => k.toLowerCase().includes(needle))) {
        const v = (raw as Record<string, unknown>)[k];
        if (Array.isArray(v)) return v.filter((x) => x && typeof x === 'object') as Array<Record<string, unknown>>;
      }
    }
  }
  return [];
}

const PORT_KEYS = ['port', 'service', 'protocol', 'state', 'version', 'name', 'product'];

function PortServiceTable({ observations }: { observations: AssetObservation[] }) {
  const rows = useMemo(() => {
    const seen = new Map<string, Record<string, unknown>>();
    // Newest first so later observations overwrite earlier ones.
    const sorted = observations.slice().sort((a, b) => new Date(a.observed_at).getTime() - new Date(b.observed_at).getTime());
    for (const obs of sorted) {
      const isPortish = /port|service/i.test(obs.observation_type);
      const list = isPortish ? rawList(obs.raw, ['port', 'service']) : [];
      for (const item of list) {
        const key = [item.port ?? item.protocol ?? '', item.service ?? item.name ?? ''].join('|');
        seen.set(key, item);
      }
    }
    return [...seen.values()];
  }, [observations]);

  if (rows.length === 0) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle>🔌 Latest ports & services</CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <Table>
          <THead>
            <TR>
              {PORT_KEYS.map((k) => (
                <TH key={k}>{k}</TH>
              ))}
            </TR>
          </THead>
          <TBody>
            {rows.map((row, i) => (
              <TR key={i}>
                {PORT_KEYS.map((k) => (
                  <TD key={k} className="font-mono text-[12.5px] text-ink/90">
                    {row[k] != null ? String(row[k]) : ''}
                  </TD>
                ))}
              </TR>
            ))}
          </TBody>
        </Table>
      </CardContent>
    </Card>
  );
}

export default function AssetDetailPage() {
  const { id = '' } = useParams();
  const assetState = useApi(() => assetsApi.get(id), [id]);
  const historyState = useApi(() => assetsApi.history(id).then(unwrap), [id]);

  const observations = historyState.data ?? [];
  const findingsState = useApi(async () => {
    if (!assetState.data) return [];
    const all = await projectsApi.listFindings(assetState.data.project_id, { limit: 1000 }).then(unwrap);
    return all.filter((f) => f.asset_id === id);
  }, [assetState.data?.project_id, id]);

  if (assetState.loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-72" />
        <Skeleton className="h-40 rounded-2xl" />
      </div>
    );
  }
  if (assetState.error || !assetState.data) {
    return <ErrorState message={assetState.error ?? 'Asset not found'} onRetry={assetState.refetch} />;
  }
  const a = assetState.data;

  return (
    <div>
      <Link
        to={`/projects/${a.project_id}/assets`}
        className="mb-3 inline-flex items-center gap-1 text-[12.5px] text-mute hover:text-ink"
      >
        <ArrowLeft className="h-3.5 w-3.5" /> Back to assets
      </Link>

      <div className="mb-6 flex flex-wrap items-center gap-2">
        <h1 className="font-mono text-xl font-bold text-ink">{a.identity}</h1>
        <Badge tone="accent">{assetTypeLabel(a.asset_type)}</Badge>
        <Badge tone="outline">{discoveryLabel(a.discovery_source)}</Badge>
        {a.os_name && <Badge tone="gold">💻 {a.os_name}</Badge>}
        {(a.tags ?? []).map((t) => (
          <Badge key={t} tone="outline">
            {t}
          </Badge>
        ))}
      </div>

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <PortServiceTable observations={observations} />

          <Card>
            <CardHeader>
              <CardTitle>🕰️ Observation history</CardTitle>
            </CardHeader>
            <CardContent>
              {historyState.loading && <Skeleton className="h-32" />}
              {historyState.error && <ErrorState message={historyState.error} onRetry={historyState.refetch} />}
              {!historyState.loading && !historyState.error && observations.length === 0 && (
                <p className="text-[13px] text-mute">
                  No observations yet — this asset was added manually and no scanner has seen it.
                </p>
              )}
              {!historyState.loading && !historyState.error && (
                <ol className="relative space-y-4 border-l border-line pl-5">
                  {observations
                    .slice()
                    .sort((x, y) => new Date(y.observed_at).getTime() - new Date(x.observed_at).getTime())
                    .map((obs) => {
                      const fields = rawFields(obs.raw);
                      return (
                        <li key={obs.id} className="relative">
                          <span className="absolute -left-[26px] top-1.5 h-2.5 w-2.5 rounded-full border border-accent/40 bg-accent/20" aria-hidden />
                          <div className="flex flex-wrap items-center gap-2">
                            <Badge tone="outline">📡 {obs.observation_type}</Badge>
                            <span className="text-[12px] text-mute" title={obs.observed_at}>
                              {formatDateTime(obs.observed_at)} · via {obs.source || 'unknown'}
                            </span>
                            {obs.scan_session_id && (
                              <Link
                                to={`/scans/${obs.scan_session_id}`}
                                className="text-[12px] text-accent-soft hover:underline"
                              >
                                scan →
                              </Link>
                            )}
                          </div>
                          {fields.length > 0 && (
                            <div className="mt-2 grid grid-cols-2 gap-x-6 gap-y-1 rounded-xl border border-line/70 bg-panel/50 p-3 sm:grid-cols-3">
                              {fields.slice(0, 12).map(([k, v]) => (
                                <div key={k} className="min-w-0">
                                  <p className="text-[10.5px] uppercase tracking-wide text-mute/60">{k}</p>
                                  <p className="truncate font-mono text-[12.5px] text-ink/90" title={v}>
                                    {v}
                                  </p>
                                </div>
                              ))}
                            </div>
                          )}
                          <details className="mt-1.5">
                            <summary className="cursor-pointer text-[11.5px] text-mute/70 hover:text-mute">
                              raw JSON
                            </summary>
                            <pre className="mono-block mt-1.5 max-h-56 overflow-y-auto text-[11.5px]">
                              {JSON.stringify(obs.raw, null, 2)}
                            </pre>
                          </details>
                        </li>
                      );
                    })}
                </ol>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>🪪 Identity</CardTitle>
            </CardHeader>
            <CardContent className="space-y-1.5 text-[13px]">
              {[
                ['IP', a.ip],
                ['IPv6', a.ipv6],
                ['Hostname', a.hostname],
                ['Domain', a.domain],
                ['MAC', a.mac],
                ['Status', a.status],
              ].map(([k, v]) => (
                <div key={String(k)} className="flex justify-between gap-3">
                  <span className="text-mute">{k}</span>
                  <span className="font-mono text-ink/90">{(v as string) || '—'}</span>
                </div>
              ))}
              <div className="flex justify-between gap-3 pt-1">
                <span className="text-mute">First seen</span>
                <span className="text-ink/90" title={a.first_seen}>{timeAgo(a.first_seen)}</span>
              </div>
              <div className="flex justify-between gap-3">
                <span className="text-mute">Last seen</span>
                <span className="text-ink/90" title={a.last_seen}>{timeAgo(a.last_seen)}</span>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex-row items-center justify-between">
              <CardTitle>🐛 Findings on this asset</CardTitle>
              {!findingsState.loading && (
                <Badge tone={(findingsState.data?.length ?? 0) > 0 ? 'danger' : 'accent'}>
                  {findingsState.data?.length ?? 0}
                </Badge>
              )}
            </CardHeader>
            <CardContent className="p-3">
              {findingsState.loading && <Skeleton className="mx-3 h-16" />}
              {!findingsState.loading && (findingsState.data ?? []).length === 0 && (
                <p className="px-3 py-4 text-center text-[13px] text-mute">✨ Nothing found here (yet).</p>
              )}
              {(findingsState.data ?? []).map((f) => (
                <Link
                  key={f.id}
                  to={`/findings/${f.id}`}
                  className="block rounded-xl px-3 py-2 transition-colors hover:bg-panel"
                >
                  <div className="flex items-center justify-between gap-2">
                    <SeverityChip severity={f.severity} />
                    <StatusChip status={f.status} kind="finding" />
                  </div>
                  <p className="mt-1 line-clamp-2 text-[13px] text-ink">{f.title}</p>
                  <p className="mt-0.5 text-[11.5px] text-mute">
                    {f.scanner} · last seen {timeAgo(f.last_detected)}
                  </p>
                </Link>
              ))}
            </CardContent>
          </Card>

          {a.description && (
            <Card>
              <CardHeader>
                <CardTitle>📝 Notes</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-[13px] leading-relaxed text-mute">{a.description}</p>
              </CardContent>
            </Card>
          )}

          <p className="px-1 text-[11.5px] text-mute/60">
            Asset id <code className="font-mono">{a.id}</code>
          </p>
        </div>
      </div>
    </div>
  );
}
