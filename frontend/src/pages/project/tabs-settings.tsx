import { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { Archive, Plus, Trash2 } from 'lucide-react';
import { projectsApi, unwrap } from '@/api/client';
import { ErrorState } from '@/components/empty-state';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Field, Input, Select, Textarea } from '@/components/ui/input';
import { useToast } from '@/components/ui/toast';
import { useApi } from '@/lib/use-api';
import { parseTags } from '@/lib/utils';
import type { Project, ProjectTarget } from '@/lib/types';

const TARGET_TYPES = ['cidr', 'domain', 'hostname', 'ipv4', 'ipv6', 'url', 'range', 'other'];

function ScopeManager({ projectId }: { projectId: string }) {
  const state = useApi(() => projectsApi.listTargets(projectId).then(unwrap), [projectId]);
  const toast = useToast();
  const [rows, setRows] = useState<Array<{ target: string; target_type: string; excluded: boolean; note: string }>>([]);

  const add = async () => {
    const valid = rows.filter((r) => r.target.trim());
    if (!valid.length) {
      toast.error('Add at least one target value.');
      return;
    }
    try {
      for (const r of valid) {
        await projectsApi.createTarget(projectId, {
          target: r.target.trim(),
          target_type: r.target_type,
          excluded: r.excluded,
          note: r.note.trim() || undefined,
        });
      }
      toast.success(`${valid.length} target${valid.length === 1 ? '' : 's'} added 🎯`);
      setRows([]);
      state.refetch();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to add targets');
      state.refetch();
    }
  };

  const remove = async (t: ProjectTarget) => {
    try {
      await projectsApi.deleteTarget(t.id);
      toast.success('Target removed');
      state.refetch();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to remove target');
    }
  };

  const rowsData = state.data ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle>🗺️ Scope management</CardTitle>
        <CardDescription>
          Authorized targets are in-scope; excluded targets are subtracted from them. Scanners stay home otherwise.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-5">
        {state.error && <ErrorState message={state.error} onRetry={state.refetch} />}

        {rowsData.length === 0 && !state.loading && (
          <p className="text-[13px] text-mute">No targets yet — the project has no scope.</p>
        )}
        <ul className="divide-y divide-line/70 rounded-xl border border-line">
          {rowsData.map((t) => (
            <li key={t.id} className="flex items-center justify-between gap-3 px-3 py-2">
              <div className="flex min-w-0 flex-wrap items-center gap-2">
                <span className={t.excluded ? 'text-mute line-through' : 'text-ink'}>
                  {t.excluded ? '🚫' : '🎯'}
                </span>
                <code className="font-mono text-[13px] text-ink">{t.target}</code>
                <Badge tone="outline">{t.target_type}</Badge>
                {t.note && <span className="truncate text-[12px] text-mute">{t.note}</span>}
              </div>
              <Button
                variant="ghost"
                size="icon-sm"
                aria-label={`Remove ${t.target}`}
                className="text-sev-critical hover:bg-sev-critical/10"
                onClick={() => remove(t)}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </li>
          ))}
        </ul>

        <div className="rounded-xl border border-dashed border-line p-4">
          <p className="mb-3 text-[13px] font-medium text-ink">Add targets</p>
          <div className="space-y-2">
            {rows.map((row, i) => (
              <div key={i} className="flex flex-wrap gap-2">
                <Input
                  className="min-w-[160px] flex-1"
                  placeholder={row.excluded ? '10.0.0.0/24 excluded' : 'app.acme.com or 10.0.0.0/24'}
                  value={row.target}
                  onChange={(e) =>
                    setRows((rs) => rs.map((r, j) => (i === j ? { ...r, target: e.target.value } : r)))
                  }
                />
                <Select
                  className="w-auto"
                  value={row.target_type}
                  onChange={(e) =>
                    setRows((rs) => rs.map((r, j) => (i === j ? { ...r, target_type: e.target.value } : r)))
                  }
                  aria-label="Target type"
                >
                  {TARGET_TYPES.map((tt) => (
                    <option key={tt} value={tt}>
                      {tt}
                    </option>
                  ))}
                </Select>
                <label className="flex items-center gap-1.5 rounded-lg border border-line bg-panel px-2 text-[12.5px] text-mute">
                  <input
                    type="checkbox"
                    className="h-3.5 w-3.5 accent-accent"
                    checked={row.excluded}
                    onChange={(e) =>
                      setRows((rs) => rs.map((r, j) => (i === j ? { ...r, excluded: e.target.checked } : r)))
                    }
                  />
                  excluded
                </label>
                <Input
                  className="min-w-[120px] flex-1"
                  placeholder="note (optional)"
                  value={row.note}
                  onChange={(e) => setRows((rs) => rs.map((r, j) => (i === j ? { ...r, note: e.target.value } : r)))}
                />
                <Button
                  variant="ghost"
                  size="icon-sm"
                  aria-label="Remove row"
                  onClick={() => setRows((rs) => rs.filter((_, j) => j !== i))}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>
            ))}
          </div>
          <div className="mt-3 flex gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() =>
                setRows((rs) => [...rs, { target: '', target_type: 'hostname', excluded: false, note: '' }])
              }
            >
              <Plus className="h-3.5 w-3.5" /> Add row
            </Button>
            <Button variant="primary" size="sm" onClick={add} disabled={rows.length === 0}>
              Save targets
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function DangerZone({ project, onChanged }: { project: Project; onChanged: () => void }) {
  const toast = useToast();
  const navigate = useNavigate();
  const [confirmName, setConfirmName] = useState('');
  const [confirmDeleteName, setConfirmDeleteName] = useState('');
  const [busy, setBusy] = useState(false);

  const archive = async () => {
    setBusy(true);
    try {
      await projectsApi.archive(project.id);
      toast.success('Project archived 🗄️');
      onChanged();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Archive failed');
    } finally {
      setBusy(false);
    }
  };

  const destroy = async () => {
    if (confirmDeleteName !== project.name) {
      toast.error('Type the exact project name to delete it.');
      return;
    }
    setBusy(true);
    try {
      await projectsApi.remove(project.id);
      toast.success('Project deleted');
      navigate('/projects');
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Delete failed');
      setBusy(false);
    }
  };

  return (
    <Card className="border-sev-critical/30">
      <CardHeader>
        <CardTitle className="text-sev-critical">🔥 Danger zone</CardTitle>
        <CardDescription>These make the eye blink. Be careful.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <p className="text-[13.5px] font-medium text-ink">Archive project</p>
            <p className="text-[12.5px] text-mute">Hide it from the front page without losing data.</p>
            <div className="mt-2">
              <Field label={`Type “${project.name}” to confirm archive`} className="max-w-xs">
                <Input
                  value={confirmName}
                  onChange={(e) => setConfirmName(e.target.value)}
                  placeholder={project.name}
                />
              </Field>
            </div>
          </div>
          <Button
            variant="secondary"
            onClick={archive}
            loading={busy}
            disabled={confirmName !== project.name}
          >
            <Archive className="h-4 w-4" /> Archive
          </Button>
        </div>

        <div className="h-px bg-line" />

        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <p className="text-[13.5px] font-medium text-sev-critical">Delete project</p>
            <p className="text-[12.5px] text-mute">
              Erases the project, its assets, findings and scans. Forever.
            </p>
            <div className="mt-2">
              <Field label={`Type “${project.name}” to confirm deletion`} className="max-w-xs">
                <Input
                  value={confirmDeleteName}
                  onChange={(e) => setConfirmDeleteName(e.target.value)}
                  placeholder={project.name}
                  aria-invalid={confirmDeleteName !== '' && confirmDeleteName !== project.name}
                />
              </Field>
            </div>
          </div>
          <Button
            variant="danger"
            onClick={destroy}
            loading={busy}
            disabled={confirmDeleteName !== project.name}
          >
            <Trash2 className="h-4 w-4" /> Delete forever
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

export default function SettingsTab() {
  const { id = '' } = useParams();
  const toast = useToast();
  const state = useApi(() => projectsApi.get(id), [id]);
  const [name, setName] = useState<string | null>(null);
  const [description, setDescription] = useState<string | null>(null);
  const [tags, setTags] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (state.loading) return <Card className="p-8"><div className="h-4 w-1/2 animate-pulse rounded bg-panel" /></Card>;
  if (state.error || !state.data) return <ErrorState message={state.error ?? 'Not found'} onRetry={state.refetch} />;

  const project = state.data;
  const currentName = name ?? project.name;
  const currentDescription = description ?? project.description ?? '';
  const currentTags = tags ?? (project.tags ?? []).join(', ');

  const dirty =
    currentName !== project.name ||
    currentDescription !== (project.description ?? '') ||
    currentTags !== (project.tags ?? []).join(', ');

  const save = async () => {
    setBusy(true);
    try {
      await projectsApi.update(project.id, {
        name: currentName.trim(),
        description: currentDescription,
        tags: parseTags(currentTags),
      });
      toast.success('Project updated ⚙️');
      setName(null);
      setDescription(null);
      setTags(null);
      state.refetch();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Save failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>⚙️ Project details</CardTitle>
          <CardDescription>Name, description and tags.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Field label="Name" required className="max-w-md">
            <Input value={currentName} onChange={(e) => setName(e.target.value)} />
          </Field>
          <Field label="Description" className="max-w-2xl">
            <Textarea value={currentDescription} onChange={(e) => setDescription(e.target.value)} />
          </Field>
          <Field label="Tags" hint="comma separated" className="max-w-md">
            <Input value={currentTags} onChange={(e) => setTags(e.target.value)} />
          </Field>
          <div className="flex justify-end">
            <Button variant="primary" onClick={save} loading={busy} disabled={!dirty}>
              Save changes
            </Button>
          </div>
        </CardContent>
      </Card>

      <ScopeManager projectId={project.id} />

      <DangerZone project={project} onChanged={state.refetch} />
    </div>
  );
}
