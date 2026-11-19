import { Link, useParams } from 'react-router-dom';
import { ArrowRight, Plus, Rocket } from 'lucide-react';
import { projectsApi, unwrap } from '@/api/client';
import { EmptyState, ErrorState } from '@/components/empty-state';
import { StatusChip } from '@/components/chips';
import { Badge } from '@/components/ui/badge';
import { buttonVariants } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';
import { useApi } from '@/lib/use-api';
import { cn, durationBetween, timeAgo } from '@/lib/utils';
import type { ProjectTarget } from '@/lib/types';

function ScopeChips({ title, targets, excluded }: { title: string; targets: ProjectTarget[]; excluded?: boolean }) {
  if (targets.length === 0) return null;
  return (
    <div>
      <p className="mb-2 text-[12px] font-semibold uppercase tracking-wider text-mute/80">{title}</p>
      <div className="flex flex-wrap gap-1.5">
        {targets.map((t) => (
          <span
            key={t.id}
            title={t.note || undefined}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-lg border px-2 py-1 font-mono text-[12px]',
              excluded
                ? 'border-sev-critical/25 bg-sev-critical/5 text-mute line-through decoration-sev-critical/60'
                : 'border-accent/25 bg-accent/5 text-ink/90',
            )}
          >
            {excluded ? '🚫' : '🎯'} {t.target}
            <span className="text-[10px] uppercase text-mute/70">{t.target_type}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

export default function ProjectOverviewTab() {
  const { id = '' } = useParams();
  const state = useApi(async () => {
    const [targets, profiles, sessions] = await Promise.all([
      projectsApi.listTargets(id).then(unwrap),
      projectsApi.listProfiles(id).then(unwrap),
      projectsApi.listScans(id).then(unwrap),
    ]);
    return { targets, profiles, sessions };
  }, [id]);

  if (state.loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-44 rounded-2xl" />
        <Skeleton className="h-44 rounded-2xl" />
      </div>
    );
  }
  if (state.error) return <ErrorState message={state.error} onRetry={state.refetch} />;

  const { targets, profiles, sessions } = state.data!;
  const included = targets.filter((t) => !t.excluded);
  const excluded = targets.filter((t) => t.excluded);
  const recent = sessions
    .slice()
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, 5);

  return (
    <div className="space-y-6">
      {/* quick stats — all from real API data */}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {[
          { label: 'Authorized targets', value: included.length, emoji: '🎯' },
          { label: 'Excluded', value: excluded.length, emoji: '🚫' },
          { label: 'Scan profiles', value: profiles.length, emoji: '📋' },
          { label: 'Scan sessions', value: sessions.length, emoji: '🚀' },
        ].map((s) => (
          <Card key={s.label} className="p-4">
            <p className="text-[12px] text-mute">
              <span aria-hidden>{s.emoji}</span> {s.label}
            </p>
            <p className="mt-1 text-2xl font-bold text-ink">{s.value}</p>
          </Card>
        ))}
      </div>

      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle>🗺️ Scope</CardTitle>
          <Link
            to={`/projects/${id}/settings`}
            className={cn(buttonVariants({ variant: 'ghost', size: 'sm' }))}
          >
            <Plus className="h-3.5 w-3.5" /> Manage targets
          </Link>
        </CardHeader>
        <CardContent className="space-y-5">
          {targets.length === 0 ? (
            <EmptyState
              emoji="🗺️"
              title="Scope is empty"
              description="Add authorized targets so the scanners know where they're welcome."
              action={
                <Link to={`/projects/${id}/settings`} className={cn(buttonVariants({ variant: 'primary', size: 'sm' }))}>
                  Add targets
                </Link>
              }
              className="py-8"
            />
          ) : (
            <>
              <ScopeChips title="Authorized" targets={included} />
              <ScopeChips title="Excluded" targets={excluded} excluded />
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle>🕘 Recent sessions</CardTitle>
          <div className="flex gap-2">
            <Link to={`/projects/${id}/scans`} className={cn(buttonVariants({ variant: 'ghost', size: 'sm' }))}>
              All <ArrowRight className="h-3.5 w-3.5" />
            </Link>
            <Link
              to={`/projects/${id}/scans/new`}
              className={cn(buttonVariants({ variant: 'primary', size: 'sm' }))}
            >
              <Rocket className="h-3.5 w-3.5" /> New scan
            </Link>
          </div>
        </CardHeader>
        <CardContent className="p-3">
          {recent.length === 0 ? (
            <p className="px-3 py-6 text-center text-[13px] text-mute">
              No scans yet. <Link className="text-accent-soft hover:underline" to={`/projects/${id}/scans/new`}>Launch the first one 🚀</Link>
            </p>
          ) : (
            <ul className="space-y-1">
              {recent.map((s) => (
                <li key={s.id}>
                  <Link
                    to={`/scans/${s.id}`}
                    className="flex flex-wrap items-center justify-between gap-2 rounded-xl px-3 py-2.5 transition-colors hover:bg-panel"
                  >
                    <div className="min-w-0">
                      <p className="truncate text-[13.5px] font-medium text-ink">{s.name}</p>
                      <p className="text-[12px] text-mute">
                        {s.scanner_names?.join(', ') || 'no scanners'} · {timeAgo(s.started_at ?? s.created_at)}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge tone="outline">
                        {s.assets_processed} assets · {s.findings_created + s.findings_updated} findings
                      </Badge>
                      <StatusChip status={s.status} kind="scan" />
                      {s.error && <span title={s.error}>⚠️</span>}
                      {s.duration_ms != null && (
                        <span className="font-mono text-[11px] text-mute/70">
                          {durationBetween(s.started_at, s.finished_at, s.duration_ms)}
                        </span>
                      )}
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <div className="flex justify-end">
        <Link
          to={`/projects/${id}/scans/new`}
          className={cn(buttonVariants({ variant: 'secondary', size: 'sm' }))}
        >
          <Rocket className="h-3.5 w-3.5" /> Start a guided scan
        </Link>
      </div>
    </div>
  );
}
