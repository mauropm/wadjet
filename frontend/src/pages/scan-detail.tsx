import { useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, FileDown, RefreshCw, Rocket, Square } from 'lucide-react';
import { projectsApi, scansApi } from '@/api/client';
import { subscribe } from '@/api/sse';
import { StatusChip } from '@/components/chips';
import { EmptyState, ErrorState } from '@/components/empty-state';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Skeleton } from '@/components/ui/skeleton';
import { useToast } from '@/components/ui/toast';
import { useApi } from '@/lib/use-api';
import { useReportGen } from '@/lib/use-report';
import { durationBetween, formatBytes, formatDateTime, timeAgo } from '@/lib/utils';
import type { ScannerExecution } from '@/lib/types';

export default function ScanDetailPage() {
  const { id = '' } = useParams();
  const toast = useToast();
  const state = useApi(() => scansApi.get(id), [id]);
  const report = useReportGen();
  const [busy, setBusy] = useState(false);
  const [liveTick, setLiveTick] = useState(0);

  const session = state.data;
  const isLive = session?.status === 'running' || session?.status === 'queued';

  // ── LIVE progress via SSE (scan.status / scan.progress / execution.status) ──
  useEffect(() => {
    if (!id) return;
    const sub = subscribe(['scan.status', 'scan.progress', 'execution.status'], (topic, data) => {
      if (data.session_id != null && data.session_id !== id) return;
      if (!state.data) return;
      if (topic === 'scan.status') {
        state.setData((prev) =>
          prev ? { ...prev, status: String(data.status ?? prev.status), error: String(data.error ?? prev.error ?? '') } : prev,
        );
        setLiveTick((t) => t + 1);
      } else if (topic === 'scan.progress') {
        state.setData((prev) =>
          prev
            ? {
                ...prev,
                assets_processed: Number(data.assets_processed ?? prev.assets_processed),
                findings_created: Number(data.findings_created ?? prev.findings_created),
                findings_updated: Number(data.findings_updated ?? prev.findings_updated),
              }
            : prev,
        );
        setLiveTick((t) => t + 1);
      } else if (topic === 'execution.status') {
        state.setData((prev) => {
          if (!prev) return prev;
          const execs = prev.executions ? [...prev.executions] : [];
          const idx = execs.findIndex((e) => e.id === data.execution_id || e.scanner_name === data.scanner);
          const patch: Partial<ScannerExecution> = {
            status: String(data.status ?? 'running'),
          };
          if (data.assets_observed != null) patch.assets_observed = Number(data.assets_observed);
          if (data.findings_found != null) patch.findings_found = Number(data.findings_found);
          if (data.error != null) patch.error = String(data.error);
          if (idx >= 0) execs[idx] = { ...execs[idx], ...patch };
          else if (data.scanner)
            execs.push({
              id: String(data.execution_id ?? crypto.randomUUID()),
              session_id: id,
              scanner_name: String(data.scanner),
              status: String(data.status ?? 'running'),
              config: null,
              targets: [],
              raw_output_path: '',
              raw_output_bytes: 0,
              assets_observed: Number(data.assets_observed ?? 0),
              findings_found: Number(data.findings_found ?? 0),
              error: String(data.error ?? ''),
              log: '',
              created_at: new Date().toISOString(),
            });
          return { ...prev, executions: execs };
        });
        setLiveTick((t) => t + 1);
      }
    });
    return () => sub.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, !!state.data]);

  // Gentle fallback refresh while live (in case an event slips through).
  useEffect(() => {
    if (!isLive) return;
    const t = setInterval(() => state.refetch(), 10_000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isLive]);

  const executions = useMemo(() => session?.executions ?? [], [session?.executions]);

  if (state.loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-24 rounded-2xl" />
        <Skeleton className="h-40 rounded-2xl" />
      </div>
    );
  }
  if (state.error || !session) {
    return <ErrorState message={state.error ?? 'Scan not found'} onRetry={state.refetch} />;
  }

  const done = executions.filter((e) => ['completed', 'failed', 'cancelled'].includes(e.status)).length;
  const pct = executions.length ? Math.round((done / executions.length) * 100) : 0;

  const act = async (action: 'start' | 'cancel') => {
    setBusy(true);
    try {
      if (action === 'start') await scansApi.start(session.id);
      else await scansApi.cancel(session.id);
      toast.success(action === 'start' ? 'Scan started 🚀' : 'Scan cancelled');
      state.refetch();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : `Failed to ${action}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <Link
        to={`/projects/${session.project_id}/scans`}
        className="mb-3 inline-flex items-center gap-1 text-[12.5px] text-mute hover:text-ink"
      >
        <ArrowLeft className="h-3.5 w-3.5" /> Scan sessions
      </Link>

      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2.5 text-xl font-bold tracking-tight text-ink">
            {session.name}
            <StatusChip status={session.status} kind="scan" />
            {isLive && (
              <span className="flex items-center gap-1.5 rounded-full border border-accent/30 bg-accent/10 px-2 py-0.5 text-[11px] font-medium text-accent-soft">
                <span className="h-1.5 w-1.5 animate-pulse-dot rounded-full bg-accent" /> live 👁️
                <span className="sr-only">(updated {liveTick} times)</span>
              </span>
            )}
          </h1>
          <p className="mt-1 text-[13px] text-mute">
            <Link to={`/projects/${session.project_id}`} className="hover:text-ink hover:underline">
              Project
            </Link>{' '}
            · created {timeAgo(session.created_at)} · started {formatDateTime(session.started_at)}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          {session.status === 'draft' && (
            <Button variant="primary" onClick={() => act('start')} loading={busy}>
              <Rocket className="h-4 w-4" /> Start scan
            </Button>
          )}
          {isLive && (
            <Button variant="danger" onClick={() => act('cancel')} loading={busy}>
              <Square className="h-4 w-4" /> Cancel
            </Button>
          )}
          <Button
            variant="secondary"
            onClick={() =>
              report.run(() => projectsApi.generateScanReport(session.project_id, session.id), `wadjet-scan-${session.name}.pdf`)
            }
            loading={report.busy}
          >
            <FileDown className="h-4 w-4" /> Download report
          </Button>
          <Button variant="ghost" size="icon" aria-label="Refresh" onClick={state.refetch}>
            <RefreshCw className="h-4 w-4" />
          </Button>
        </div>
      </div>

      {session.error && (
        <div className="mb-4 rounded-xl border border-sev-critical/30 bg-sev-critical/10 p-3 text-[13px] text-sev-critical">
          💥 {session.error}
        </div>
      )}

      {/* progress */}
      <Card className="mb-6">
        <CardContent className="space-y-4 p-5">
          <div className="flex flex-wrap items-center justify-between gap-2 text-[13px] text-mute">
            <span>
              {executions.length === 0
                ? 'Waiting for executions…'
                : `${done}/${executions.length} executions done`}
            </span>
            <span className="font-mono text-ink">
              👁 {session.assets_processed} assets · {session.findings_created} new ·{' '}
              {session.findings_updated} updated
            </span>
            <span>⏱ {durationBetween(session.started_at, session.finished_at, session.duration_ms)}</span>
          </div>
          <Progress
            value={pct}
            indeterminate={isLive && executions.length === 0}
            label="Scan progress"
            indicatorClassName={session.status === 'failed' ? 'bg-sev-critical' : undefined}
          />
          {session.targets?.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {session.targets.map((t) => (
                <Badge key={t} tone="outline" className="font-mono">
                  🎯 {t}
                </Badge>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* executions */}
      <h2 className="mb-3 text-[15px] font-semibold text-ink">🔧 Scanner executions</h2>
      {executions.length === 0 ? (
        <EmptyState emoji="🕐" title="No executions yet" description="They appear as soon as the scan starts." />
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          {executions.map((e) => (
            <Card key={e.id}>
              <CardHeader className="flex-row items-center justify-between py-3.5">
                <CardTitle className="font-mono text-[14px]">{e.scanner_name}</CardTitle>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-[11.5px] text-mute">
                    {e.assets_observed}a · {e.findings_found}f
                  </span>
                  <StatusChip status={e.status} kind="execution" />
                </div>
              </CardHeader>
              <CardContent className="space-y-3 text-[13px]">
                {e.error && (
                  <div className="mono-block border-sev-critical/30 text-sev-critical">{e.error}</div>
                )}
                {e.raw_output_path && (
                  <div>
                    <p className="mb-1 text-[11px] uppercase tracking-wider text-mute/70">
                      Raw output {e.raw_output_bytes ? `(${formatBytes(e.raw_output_bytes)})` : ''}
                    </p>
                    <code className="block truncate rounded-lg border border-line bg-black/40 px-2 py-1 font-mono text-[11.5px] text-mute" title={e.raw_output_path}>
                      {e.raw_output_path}
                    </code>
                  </div>
                )}
                {e.log && (
                  <details>
                    <summary className="cursor-pointer text-[12.5px] text-accent-soft">📜 View log</summary>
                    <pre className="mono-block mt-2 max-h-64 overflow-y-auto">{e.log}</pre>
                  </details>
                )}
                <p className="text-[12px] text-mute/70">
                  {e.started_at ? `started ${formatDateTime(e.started_at)}` : 'not started'}
                  {e.finished_at ? ` · finished ${formatDateTime(e.finished_at)}` : ''}
                </p>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
