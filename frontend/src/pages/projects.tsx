import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Archive, Copy, FolderPlus, MoreHorizontal, Search, Trash2 } from 'lucide-react';
import { projectsApi, unwrap } from '@/api/client';
import { PageHeader } from '@/components/app-shell';
import { CloneProjectDialog, NewProjectDialog } from '@/components/project-dialogs';
import { EmptyState, ErrorState } from '@/components/empty-state';
import { Badge } from '@/components/ui/badge';
import { Button, buttonVariants } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownItem,
  DropdownSeparator,
} from '@/components/ui/dropdown-menu';
import { Input } from '@/components/ui/input';
import { SkeletonCards } from '@/components/ui/skeleton';
import { useToast } from '@/components/ui/toast';
import { useApi } from '@/lib/use-api';
import { cn, timeAgo } from '@/lib/utils';
import type { Project } from '@/lib/types';

function ProjectCard({
  project,
  onClone,
  onChanged,
}: {
  project: Project;
  onClone: () => void;
  onChanged: () => void;
}) {
  const toast = useToast();
  const archived = project.status === 'archived';

  const archive = async () => {
    try {
      await projectsApi.archive(project.id);
      toast.success(`“${project.name}” archived 🗄️`);
      onChanged();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Archive failed');
    }
  };

  const remove = async () => {
    if (!window.confirm(`Delete project “${project.name}”? This cannot be undone.`)) return;
    try {
      await projectsApi.remove(project.id);
      toast.success('Project deleted');
      onChanged();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Delete failed');
    }
  };

  return (
    <div
      className={cn(
        'group relative flex flex-col rounded-2xl border border-line bg-raised p-5 shadow-panel transition-colors hover:border-accent/30',
        archived && 'opacity-60',
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <Link to={`/projects/${project.id}`} className="min-w-0">
          <h3 className="truncate text-[15px] font-semibold text-ink group-hover:text-accent-soft">
            {project.name}
          </h3>
        </Link>
        <DropdownMenu
          trigger={({ toggle }) => (
            <Button
              variant="ghost"
              size="icon-sm"
              onClick={toggle}
              aria-label={`Actions for ${project.name}`}
            >
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          )}
        >
          {(close) => (
            <>
              <DropdownItem
                icon={<Copy className="h-3.5 w-3.5" />}
                onClick={() => {
                  close();
                  onClone();
                }}
              >
                Clone…
              </DropdownItem>
              {!archived && (
                <>
                  <DropdownSeparator />
                  <DropdownItem
                    icon={<Archive className="h-3.5 w-3.5" />}
                    onClick={() => {
                      close();
                      void archive();
                    }}
                  >
                    Archive
                  </DropdownItem>
                </>
              )}
              <DropdownItem
                danger
                icon={<Trash2 className="h-3.5 w-3.5" />}
                onClick={() => {
                  close();
                  void remove();
                }}
              >
                Delete
              </DropdownItem>
            </>
          )}
        </DropdownMenu>
      </div>

      <Link to={`/projects/${project.id}`} className="mt-1 min-w-0 flex-1">
        <p className="line-clamp-2 text-[13px] leading-relaxed text-mute">
          {project.description || 'No description — the eye is curious.'}
        </p>
      </Link>

      <div className="mt-3 flex flex-wrap items-center gap-1.5">
        <Badge tone={archived ? 'neutral' : 'accent'}>
          {archived ? '🗄️ Archived' : '🟢 Active'}
        </Badge>
        {(project.tags ?? []).slice(0, 4).map((t) => (
          <Badge key={t} tone="outline">
            {t}
          </Badge>
        ))}
        {project.tags?.length > 4 && <Badge tone="outline">+{project.tags.length - 4}</Badge>}
      </div>

      <p className="mt-3 text-[11.5px] text-mute/70">
        Last activity {timeAgo(project.last_activity_at ?? project.updated_at)}
      </p>
    </div>
  );
}

export default function ProjectsPage() {
  const state = useApi(() => projectsApi.list().then(unwrap), []);
  const [query, setQuery] = useState('');
  const [showNew, setShowNew] = useState(false);
  const [cloneSource, setCloneSource] = useState<Project | null>(null);

  const filtered = useMemo(() => {
    const items = (state.data ?? []).slice();
    items.sort(
      (a, b) =>
        new Date(b.last_activity_at ?? b.updated_at).getTime() -
        new Date(a.last_activity_at ?? a.updated_at).getTime(),
    );
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter(
      (p) =>
        p.name.toLowerCase().includes(q) ||
        (p.description ?? '').toLowerCase().includes(q) ||
        (p.tags ?? []).some((t) => t.toLowerCase().includes(q)),
    );
  }, [state.data, query]);

  return (
    <div>
      <PageHeader
        emoji="📁"
        title="Projects"
        description="Every assessment begins with a scope."
        actions={
          <Button variant="primary" onClick={() => setShowNew(true)}>
            <FolderPlus className="h-4 w-4" /> New project
          </Button>
        }
      />

      <div className="relative mb-5 max-w-sm">
        <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-mute" />
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search name, description, tags…"
          className="pl-9"
          aria-label="Search projects"
        />
      </div>

      {state.loading && <SkeletonCards count={6} />}
      {state.error && !state.loading && (
        <ErrorState message={state.error} onRetry={state.refetch} />
      )}
      {!state.loading && !state.error && filtered.length === 0 && (
        <EmptyState
          emoji={query ? '🔍' : '👁️'}
          title={query ? 'The eye found nothing' : 'No projects yet'}
          description={
            query
              ? `No project matches “${query}”. Try a different search.`
              : 'Create your first project and give the eye something to look at.'
          }
          action={
            !query && (
              <Button variant="primary" onClick={() => setShowNew(true)}>
                <FolderPlus className="h-4 w-4" /> Create first project
              </Button>
            )
          }
        />
      )}

      {!state.loading && !state.error && filtered.length > 0 && (
        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
          {filtered.map((p) => (
            <ProjectCard key={p.id} project={p} onClone={() => setCloneSource(p)} onChanged={state.refetch} />
          ))}
        </div>
      )}

      <NewProjectDialog open={showNew} onClose={() => setShowNew(false)} onCreated={state.refetch} />
      <CloneProjectDialog
        open={!!cloneSource}
        onClose={() => setCloneSource(null)}
        source={cloneSource}
        onCloned={state.refetch}
      />

      <div className="mt-8 text-center">
        <Link to="/scanners" className={cn(buttonVariants({ variant: 'ghost', size: 'sm' }))}>
          🔎 Browse scanners
        </Link>
      </div>
    </div>
  );
}
