import { useState } from 'react';
import { useParams } from 'react-router-dom';
import { Download, FileArchive, FileText, Library, RefreshCw } from 'lucide-react';
import { projectsApi, reportsApi, unwrap } from '@/api/client';
import { StatusChip } from '@/components/chips';
import { EmptyState, ErrorState } from '@/components/empty-state';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Select } from '@/components/ui/input';
import { SkeletonRows } from '@/components/ui/skeleton';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { useToast } from '@/components/ui/toast';
import { useApi } from '@/lib/use-api';
import { useReportGen } from '@/lib/use-report';
import { reportTypeLabel } from '@/lib/severity';
import { formatBytes, formatDateTime } from '@/lib/utils';

export default function ReportsTab() {
  const { id = '' } = useParams();
  const toast = useToast();
  const gen = useReportGen();
  const [sessionId, setSessionId] = useState('');

  const state = useApi(async () => {
    const [reports, scans] = await Promise.all([
      reportsApi.list(id).then(unwrap),
      projectsApi.listScans(id).then(unwrap),
    ]);
    const mine = reports.filter((r) => r.project_id === id);
    mine.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
    return { reports: mine, scans };
  }, [id]);

  const download = async (reportId: string) => {
    try {
      await reportsApi.download(reportId);
      toast.success('Download started 📄');
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Download failed');
    }
  };

  const generate = (kind: 'scan' | 'consolidated' | 'zip') => {
    if (kind === 'scan') {
      if (!sessionId) {
        toast.error('Pick a scan session first.');
        return;
      }
      void gen.run(() => projectsApi.generateScanReport(id, sessionId), 'wadjet-scan.pdf')
        .then(state.refetch);
    } else if (kind === 'consolidated') {
      void gen.run(() => projectsApi.generateFindingsReport(id, 'findings_consolidated'), 'wadjet-findings.pdf')
        .then(state.refetch);
    } else {
      void gen.run(() => projectsApi.generateFindingsReport(id, 'findings_zip'), 'wadjet-findings.zip')
        .then(state.refetch);
    }
  };

  const rows = state.data?.reports ?? [];
  const scans = state.data?.scans ?? [];

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>📄 Scan report</CardTitle>
            <CardDescription>A single scan session, formatted for humans.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Select
              value={sessionId}
              onChange={(e) => setSessionId(e.target.value)}
              aria-label="Pick scan session"
            >
              <option value="">Pick a session…</option>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} · {formatDateTime(s.started_at ?? s.created_at)}
                </option>
              ))}
            </Select>
            <Button variant="primary" size="sm" className="w-full" loading={gen.busy} onClick={() => generate('scan')}>
              <FileText className="h-4 w-4" /> Generate
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>📚 Consolidated findings</CardTitle>
            <CardDescription>All open findings in one executive-ready PDF.</CardDescription>
          </CardHeader>
          <CardContent>
            <Button variant="primary" size="sm" className="w-full" loading={gen.busy} onClick={() => generate('consolidated')}>
              <Library className="h-4 w-4" /> Generate
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>🗜️ Findings ZIP</CardTitle>
            <CardDescription>One PDF per finding, zipped for the team.</CardDescription>
          </CardHeader>
          <CardContent>
            <Button variant="secondary" size="sm" className="w-full" loading={gen.busy} onClick={() => generate('zip')}>
              <FileArchive className="h-4 w-4" /> Generate ZIP
            </Button>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle>🗂️ Report history</CardTitle>
          <Button variant="ghost" size="sm" onClick={state.refetch}>
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </Button>
        </CardHeader>
        {state.loading && <SkeletonRows rows={4} cols={5} />}
        {state.error && !state.loading && <ErrorState message={state.error} onRetry={state.refetch} className="m-5" />}
        {!state.loading && !state.error && rows.length === 0 && (
          <div className="p-5">
            <EmptyState
              emoji="📄"
              title="No reports yet"
              description="Generate one above — the eye also writes essays."
              className="py-8"
            />
          </div>
        )}
        {!state.loading && !state.error && rows.length > 0 && (
          <Table>
            <THead>
              <TR>
                <TH>Type</TH>
                <TH>Status</TH>
                <TH>Size</TH>
                <TH>Created</TH>
                <TH className="text-right">Download</TH>
              </TR>
            </THead>
            <TBody>
              {rows.map((r) => (
                <TR key={r.id}>
                  <TD className="text-[13px] text-ink">{reportTypeLabel(r.type)}</TD>
                  <TD>
                    <StatusChip status={r.status} kind="report" />
                    {r.status === 'failed' && r.error && (
                      <span className="ml-2 text-[12px] text-sev-critical" title={r.error}>
                        {r.error.slice(0, 60)}
                      </span>
                    )}
                  </TD>
                  <TD className="font-mono text-[12.5px] text-mute">{formatBytes(r.file_size)}</TD>
                  <TD className="text-[12.5px] text-mute">{formatDateTime(r.created_at)}</TD>
                  <TD className="text-right">
                    {r.status === 'completed' ? (
                      <Button variant="secondary" size="sm" onClick={() => download(r.id)}>
                        <Download className="h-3.5 w-3.5" /> Download
                      </Button>
                    ) : (
                      <span className="text-[12px] text-mute/60">—</span>
                    )}
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        )}
      </Card>
    </div>
  );
}
