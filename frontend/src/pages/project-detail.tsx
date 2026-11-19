import { Link, NavLink, Outlet, useParams } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { projectsApi } from '@/api/client';
import { EmptyState, ErrorState } from '@/components/empty-state';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { useApi } from '@/lib/use-api';
import { cn } from '@/lib/utils';

const TABS = [
  { seg: '', label: '👁️ Overview' },
  { seg: 'assets', label: '🖥️ Assets' },
  { seg: 'profiles', label: '📋 Scan Profiles' },
  { seg: 'scans', label: '🚀 Scan Sessions' },
  { seg: 'findings', label: '🐛 Findings' },
  { seg: 'reports', label: '📄 Reports' },
  { seg: 'settings', label: '⚙️ Settings' },
];

export default function ProjectDetailPage() {
  const { id = '' } = useParams();
  const state = useApi(() => projectsApi.get(id), [id]);

  if (state.loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-72" />
        <Skeleton className="h-10 w-full max-w-2xl" />
      </div>
    );
  }

  if (state.error || !state.data) {
    return (
      <ErrorState message={state.error ?? 'Project not found'} onRetry={state.refetch} />
    );
  }

  const p = state.data;
  const archived = p.status === 'archived';

  return (
    <div>
      <Link
        to="/projects"
        className="mb-3 inline-flex items-center gap-1 text-[12.5px] text-mute hover:text-ink"
      >
        <ArrowLeft className="h-3.5 w-3.5" /> Projects
      </Link>

      <div className="mb-4 flex flex-wrap items-center gap-2">
        <h1 className="text-xl font-bold tracking-tight text-ink">{p.name}</h1>
        <Badge tone={archived ? 'neutral' : 'accent'}>{archived ? '🗄️ Archived' : '🟢 Active'}</Badge>
        {(p.tags ?? []).map((t) => (
          <Badge key={t} tone="outline">
            {t}
          </Badge>
        ))}
      </div>
      {p.description && <p className="mb-4 max-w-3xl text-[13.5px] text-mute">{p.description}</p>}

      <nav aria-label="Project sections" className="mb-6 flex gap-1 overflow-x-auto border-b border-line">
        {TABS.map((t) => (
          <NavLink
            key={t.seg}
            to={`/projects/${id}${t.seg ? `/${t.seg}` : ''}`}
            end={t.seg === ''}
            className={({ isActive }) =>
              cn(
                'relative whitespace-nowrap rounded-t-lg px-3.5 py-2 text-sm transition-colors',
                isActive
                  ? 'font-semibold text-ink after:absolute after:inset-x-2 after:-bottom-px after:h-0.5 after:rounded-full after:bg-accent'
                  : 'text-mute hover:text-ink',
              )
            }
          >
            {t.label}
          </NavLink>
        ))}
      </nav>

      <Outlet />
    </div>
  );
}

export function TabEmpty({ title, description }: { title: string; description?: string }) {
  return <EmptyState title={title} description={description} />;
}
