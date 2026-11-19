import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { Eye, FileDown, Plus, Rocket, Square } from 'lucide-react';
import { projectsApi, scansApi, unwrap } from '@/api/client';
import { StatusChip } from '@/components/chips';
import { EmptyState, ErrorState } from '@/components/empty-state';
import { Button, buttonVariants } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { SkeletonRows } from '@/components/ui/skeleton';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { useToast } from '@/components/ui/toast';
import { useApi } from '@/lib/use-api';
import { useReportGen } from '@/lib/use-report';
import { cn, durationBetween, formatDateTime } from '@/lib/utils';
import type { ScanSession } from '@/lib/types';

export default function SessionsTab() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const state = useApi(() => projectsApi.listScans(id).then(unwrap), [id]);
  const toast = useToast();
  const report = useReportGen();
  const [busyId, setBusyId] = useState<string | null>(null);

  const act = async (s: ScanSession, action: 'start' | 'cancel') => {
    setBusyId(s.id);
    try {
      if (action === 'start') {
        await scansApi.start(s.id);
        toast.info(`Scan “${s.name}” launched 🚀`);
      } else {
        await scansApi.cancel(s.id);
        toast.info(`Scan “${s.name}” cancelled`);
      }
      state.refetch();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : `Failed to ${action} scan`);
    } finally {
      setBusyId(null);
    }
  };

  const rows = (state.data ?? []).slice();
  rows.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());

  return (
    <div>
      <div className="mb-4 flex justify-end">
        <Link to={`/projects/${id}/scans/new`} className={cn(buttonVariants({ variant: 'primary' }))}>
          <Plus className="h-4 w-4" /> New scan
        </Link>
      </div>

      {state.loading && (
        <Card>
          <SkeletonRows rows={5} cols={7} />
        </Card>
      )}
      {state.error && !state.loading && <ErrorState message={state.error} onRetry={state.refetch} />}

      {!state.loading && !state.error && rows.length === 0 && (
        <EmptyState
          emoji="🚀"
          title="No scan sessions yet"
          description="Launch the guided wizard to scan your scope."
          action={
            <Link to={`/projects/${id}/scans/new`} className={cn(buttonVariants({ variant: 'primary' }))}>
              <Rocket className="h-4 w-4" /> Start first scan
            </Link>
          }
        />
      )}

      {!state.loading && !state.error && rows.length > 0 && (
        <Card>
          <Table>
            <THead>
              <TR>
                <TH>Name</TH>
                <TH>Status</TH>
                <TH>Scanners</TH>
                <TH>Started</TH>
                <TH>Duration</TH>
                <TH>Assets</TH>
                <TH>Findings</TH>
                <TH className="text-right">Actions</TH>
              </TR>
            </THead>
            <TBody>
              {rows.map((s) => (
                <TR key={s.id} clickable onClick={() => navigate(`/scans/${s.id}`)}>
                  <TD>
                    <Link
                      to={`/scans/${s.id}`}
                      className="text-[13.5px] font-medium text-ink hover:text-accent-soft"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {s.name}
                    </Link>
                  </TD>
                  <TD>
                    <StatusChip status={s.status} kind="scan" />
                    {s.error && <span className="ml-1" title={s.error}>⚠️</span>}
                  </TD>
                  <TD className="max-w-[220px] truncate font-mono text-[12px] text-mute">
                    {s.scanner_names?.join(', ') || '—'}
                  </TD>
                  <TD className="text-[12.5px] text-mute" title={s.started_at ?? s.created_at}>
                    {formatDateTime(s.started_at ?? s.created_at)}
                  </TD>
                  <TD className="font-mono text-[12px] text-mute">
                    {durationBetween(s.started_at, s.finished_at, s.duration_ms)}
                  </TD>
                  <TD className="font-mono text-[13px] text-ink">{s.assets_processed}</TD>
                  <TD className="font-mono text-[13px] text-ink">
                    {s.findings_created}
                    <span className="text-mute">/+{s.findings_updated}</span>
                  </TD>
                  <TD>
                    <div
                      className="flex justify-end gap-1"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {s.status === 'draft' && (
                        <Button
                          variant="outline"
                          size="icon-sm"
                          title="Start scan"
                          aria-label="Start scan"
                          loading={busyId === s.id}
                          onClick={() => act(s, 'start')}
                        >
                          <Rocket className="h-3.5 w-3.5" />
                        </Button>
                      )}
                      {(s.status === 'running' || s.status === 'queued') && (
                        <Button
                          variant="danger"
                          size="icon-sm"
                          title="Cancel scan"
                          aria-label="Cancel scan"
                          loading={busyId === s.id}
                          onClick={() => act(s, 'cancel')}
                        >
                          <Square className="h-3.5 w-3.5" />
                        </Button>
                      )}
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        title="Generate & download scan report"
                        aria-label="Download scan report"
                        loading={report.busy}
                        onClick={() => report.run(() => projectsApi.generateScanReport(s.project_id, s.id), `wadjet-scan-${s.name}.pdf`)}
                      >
                        <FileDown className="h-3.5 w-3.5" />
                      </Button>
                      <Link
                        to={`/scans/${s.id}`}
                        className={cn(buttonVariants({ variant: 'ghost', size: 'icon-sm' }))}
                        title="Open details"
                        aria-label="Open scan details"
                      >
                        <Eye className="h-3.5 w-3.5" />
                      </Link>
                    </div>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </Card>
      )}
    </div>
  );
}
