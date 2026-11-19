import { Link } from 'react-router-dom';
import { ArrowRight, FolderPlus, Play, ScanSearch } from 'lucide-react';
import { projectsApi, unwrap } from '@/api/client';
import { PageHeader } from '@/components/app-shell';
import { SeverityDot } from '@/components/chips';
import { EmptyState, ErrorState } from '@/components/empty-state';
import { NewProjectDialog } from '@/components/project-dialogs';
import { Badge } from '@/components/ui/badge';
import { Button, buttonVariants } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { Skeleton, SkeletonCards } from '@/components/ui/skeleton';
import { StatusChip } from '@/components/chips';
import { SEVERITIES, severityMeta } from '@/lib/severity';
import { useApi } from '@/lib/use-api';
import { cn, timeAgo } from '@/lib/utils';
import type { Finding, ScanSession } from '@/lib/types';
import { useState } from 'react';

interface OverviewData {
  projects: import('@/lib/types').Project[];
  recentProjects: import('@/lib/types').Project[];
  recentScans: { scan: ScanSession; project: import('@/lib/types').Project }[];
  severityCounts: Record<string, number>;
  totalFindings: number;
  snapshotProjectCount: number;
}

export default function OverviewPage() {
  const [showNew, setShowNew] = useState(false);

  // All numbers here are aggregated client-side from real API data —
  // projects → their recent scans + findings snapshots.
  const state = useApi(async (): Promise<OverviewData> => {
    const projects = unwrap(await projectsApi.list()).slice();
    projects.sort(
      (a, b) =>
        new Date(b.last_activity_at ?? b.updated_at).getTime() -
        new Date(a.last_activity_at ?? a.updated_at).getTime(),
    );
    const recentProjects = projects.slice(0, 4);

    const perProject = await Promise.allSettled(
      recentProjects.map(async (p) => {
        const [scansR, findingsR] = await Promise.all([
          projectsApi.listScans(p.id),
          projectsApi.listFindings(p.id, { limit: 200 }),
        ]);
        return {
          project: p,
          scans: unwrap(scansR),
          findings: unwrap(findingsR) as Finding[],
        };
      }),
    );

    const ok = perProject.flatMap((r) => (r.status === 'fulfilled' ? [r.value] : []));

    const recentScans = ok
      .flatMap(({ project, scans }) => scans.map((s) => ({ scan: s, project })))
      .sort((a, b) => new Date(b.scan.created_at).getTime() - new Date(a.scan.created_at).getTime())
      .slice(0, 6);

    const severityCounts: Record<string, number> = {};
    let totalFindings = 0;
    for (const { findings } of ok) {
      for (const f of findings) {
        totalFindings += 1;
        severityCounts[f.severity] = (severityCounts[f.severity] ?? 0) + 1;
      }
    }

    return {
      projects,
      recentProjects,
      recentScans,
      severityCounts,
      totalFindings,
      snapshotProjectCount: recentProjects.length,
    };
  }, []);

  const { data, loading, error } = state;
  const maxSev = Math.max(1, ...Object.values(data?.severityCounts ?? {}));

  return (
    <div>
      <PageHeader
        emoji="👁️"
        title="Overview"
        description="The eye sees what your assets are hiding — live from the API."
        actions={
          <>
            <Button variant="primary" onClick={() => setShowNew(true)}>
              <FolderPlus className="h-4 w-4" /> New project
            </Button>
            <Link to="/scanners" className={cn(buttonVariants({ variant: 'secondary' }))}>
              <ScanSearch className="h-4 w-4" /> Scanners
            </Link>
          </>
        }
      />

      {error && !loading && <ErrorState message={error} onRetry={state.refetch} />}

      {loading && (
        <div className="space-y-6">
          <Skeleton className="h-40 rounded-2xl" />
          <SkeletonCards count={3} />
        </div>
      )}

      {data && !loading && data.projects.length === 0 && (
        <EmptyState
          emoji="👁️"
          title="Nothing in the eye yet"
          description="WADJET has no projects. Create one, add targets, and let the scanners look around."
          action={
            <Button variant="primary" onClick={() => setShowNew(true)}>
              <FolderPlus className="h-4 w-4" /> Create your first project
            </Button>
          }
        />
      )}

      {data && !loading && data.projects.length > 0 && (
        <div className="space-y-6">
          {/* Severity snapshot */}
          <Card>
            <CardHeader className="flex-row items-center justify-between">
              <CardTitle>🎨 Severity snapshot</CardTitle>
              <span className="text-[12px] text-mute">
                {data.totalFindings} finding{data.totalFindings === 1 ? '' : 's'} across your{' '}
                {data.snapshotProjectCount} most recent project{data.snapshotProjectCount === 1 ? '' : 's'}
              </span>
            </CardHeader>
            <CardContent>
              {data.totalFindings === 0 ? (
                <p className="py-2 text-[13.5px] text-mute">
                  ✨ No findings in recent projects — suspiciously clean, or no scans yet.
                </p>
              ) : (
                <div className="grid gap-x-8 gap-y-3 sm:grid-cols-2 lg:grid-cols-3">
                  {SEVERITIES.map((sev) => {
                    const m = severityMeta(sev);
                    const count = data.severityCounts[sev] ?? 0;
                    return (
                      <div key={sev} className="flex items-center gap-3">
                        <div className="flex w-24 shrink-0 items-center gap-1.5 text-[13px]">
                          <SeverityDot severity={sev} />
                          {m.label}
                        </div>
                        <div className="flex-1">
                          <Progress
                            value={(count / maxSev) * 100}
                            indicatorClassName={m.solid}
                            label={`${m.label}: ${count}`}
                          />
                        </div>
                        <span className="w-10 text-right font-mono text-[13px] text-ink">{count}</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>

          <div className="grid gap-6 lg:grid-cols-2">
            {/* Recent projects */}
            <Card>
              <CardHeader className="flex-row items-center justify-between">
                <CardTitle>📁 Recent projects</CardTitle>
                <Link to="/projects" className={cn(buttonVariants({ variant: 'ghost', size: 'sm' }))}>
                  All <ArrowRight className="h-3.5 w-3.5" />
                </Link>
              </CardHeader>
              <CardContent className="space-y-2 p-3">
                {data.recentProjects.map((p) => (
                  <Link
                    key={p.id}
                    to={`/projects/${p.id}`}
                    className="flex items-center justify-between gap-3 rounded-xl px-3 py-2.5 transition-colors hover:bg-panel"
                  >
                    <div className="min-w-0">
                      <p className="truncate text-[13.5px] font-medium text-ink">{p.name}</p>
                      <p className="truncate text-[12px] text-mute">
                        {p.status === 'archived' ? '🗄️ archived · ' : ''}
                        {timeAgo(p.last_activity_at ?? p.updated_at)}
                      </p>
                    </div>
                    <div className="flex shrink-0 gap-1">
                      {(p.tags ?? []).slice(0, 2).map((t) => (
                        <Badge key={t} tone="outline">
                          {t}
                        </Badge>
                      ))}
                    </div>
                  </Link>
                ))}
              </CardContent>
            </Card>

            {/* Recent scans */}
            <Card>
              <CardHeader>
                <CardTitle>🚀 Recent scans</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 p-3">
                {data.recentScans.length === 0 && (
                  <p className="px-3 py-6 text-center text-[13px] text-mute">
                    No scans yet — open a project and launch one.
                  </p>
                )}
                {data.recentScans.map(({ scan, project }) => (
                  <Link
                    key={scan.id}
                    to={`/scans/${scan.id}`}
                    className="flex items-center justify-between gap-3 rounded-xl px-3 py-2.5 transition-colors hover:bg-panel"
                  >
                    <div className="min-w-0">
                      <p className="truncate text-[13.5px] font-medium text-ink">{scan.name}</p>
                      <p className="truncate text-[12px] text-mute">
                        {project.name} · {scan.scanner_names?.length ?? 0} scanner
                        {(scan.scanner_names?.length ?? 0) === 1 ? '' : 's'} ·{' '}
                        {timeAgo(scan.started_at ?? scan.created_at)}
                      </p>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <span className="font-mono text-[11.5px] text-mute">
                        {scan.assets_processed}a · {scan.findings_created}f
                      </span>
                      <StatusChip status={scan.status} kind="scan" />
                    </div>
                  </Link>
                ))}
              </CardContent>
            </Card>
          </div>

          {/* Quick actions */}
          <Card>
            <CardHeader>
              <CardTitle>⚡ Quick actions</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-2">
              <Button variant="primary" onClick={() => setShowNew(true)}>
                <FolderPlus className="h-4 w-4" /> New project
              </Button>
              <Link to="/projects" className={cn(buttonVariants({ variant: 'secondary' }))}>
                <Play className="h-4 w-4" /> Start a scan (pick a project)
              </Link>
              <Link to="/scanners" className={cn(buttonVariants({ variant: 'secondary' }))}>
                <ScanSearch className="h-4 w-4" /> Check scanner health
              </Link>
              <Link to="/settings" className={cn(buttonVariants({ variant: 'ghost' }))}>
                ⚙️ Audit log
              </Link>
            </CardContent>
          </Card>
        </div>
      )}

      <NewProjectDialog open={showNew} onClose={() => setShowNew(false)} onCreated={state.refetch} />
    </div>
  );
}
