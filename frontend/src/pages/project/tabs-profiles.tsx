import { useMemo, useState } from 'react';
import { useParams } from 'react-router-dom';
import { Pencil, Plus, Trash2 } from 'lucide-react';
import { projectsApi, scannersApi, unwrap } from '@/api/client';
import { ScannerConfigForm } from '@/components/scanner-config-form';
import { EmptyState, ErrorState } from '@/components/empty-state';
import { Badge, Chip } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Field, Input, Textarea } from '@/components/ui/input';
import { Sheet } from '@/components/ui/sheet';
import { SkeletonCards } from '@/components/ui/skeleton';
import { Switch } from '@/components/ui/switch';
import { useToast } from '@/components/ui/toast';
import { useApi } from '@/lib/use-api';
import { pluralize } from '@/lib/utils';
import type { ProfileScanner, ScanProfile, ScannerRecord } from '@/lib/types';

interface Draft {
  name: string;
  description: string;
  timeout_seconds: number;
  target_selection: string[];
  excluded_targets: string[];
  scanners: Array<{
    scanner_id: string;
    scanner: string;
    enabled: boolean;
    config: Record<string, unknown>;
  }>;
}

function emptyDraft(): Draft {
  return {
    name: '',
    description: '',
    timeout_seconds: 3600,
    target_selection: [],
    excluded_targets: [],
    scanners: [],
  };
}

function ProfileForm({
  projectId,
  profile,
  onClose,
  onSaved,
}: {
  projectId: string;
  profile: ScanProfile | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const toast = useToast();
  const targetsState = useApi(() => projectsApi.listTargets(projectId).then(unwrap), [projectId]);
  const scannersState = useApi(() => scannersApi.list().then(unwrap), []);
  const [busy, setBusy] = useState(false);

  const [draft, setDraft] = useState<Draft>(() => {
    if (profile) {
      return {
        name: profile.name,
        description: profile.description ?? '',
        timeout_seconds: profile.timeout_seconds || 3600,
        target_selection: profile.target_selection ?? [],
        excluded_targets: profile.excluded_targets ?? [],
        scanners: (profile.scanners ?? []).map((s) => ({
          scanner_id: s.scanner_id,
          scanner: s.scanner,
          enabled: true,
          config: (s.config && typeof s.config === 'object' ? s.config : {}) as Record<string, unknown>,
        })),
      };
    }
    return emptyDraft();
  });

  const scanners: ScannerRecord[] = useMemo(
    () => (scannersState.data ?? []).filter((s) => s.enabled),
    [scannersState.data],
  );

  const toggleScanner = (rec: ScannerRecord) => {
    setDraft((d) => {
      const existing = d.scanners.find((s) => s.scanner_id === rec.id);
      if (existing) {
        return { ...d, scanners: d.scanners.filter((s) => s.scanner_id !== rec.id) };
      }
      return {
        ...d,
        scanners: [...d.scanners, { scanner_id: rec.id, scanner: rec.name, enabled: true, config: {} }],
      };
    });
  };

  const toggleTarget = (target: string, excluded: boolean) => {
    setDraft((d) => {
      const list = excluded ? d.excluded_targets : d.target_selection;
      const next = list.includes(target) ? list.filter((t) => t !== target) : [...list, target];
      return excluded ? { ...d, excluded_targets: next } : { ...d, target_selection: next };
    });
  };

  const save = async () => {
    if (!draft.name.trim()) {
      toast.error('Profile needs a name.');
      return;
    }
    setBusy(true);
    try {
      const scannersPayload: ProfileScanner[] = draft.scanners
        .filter((s) => s.enabled)
        .map((s, i) => ({
          scanner_id: s.scanner_id,
          scanner: s.scanner,
          config: s.config,
          sort_order: i,
        }));
      const body = {
        name: draft.name.trim(),
        description: draft.description.trim() || undefined,
        target_selection: draft.target_selection,
        excluded_targets: draft.excluded_targets,
        timeout_seconds: Number(draft.timeout_seconds) || 3600,
        scanners: scannersPayload,
      };
      if (profile) await projectsApi.updateProfile(profile.id, body);
      else await projectsApi.createProfile(projectId, body);
      toast.success(profile ? 'Profile updated' : 'Profile created 📋');
      onSaved();
      onClose();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to save profile');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Sheet
      open
      onClose={onClose}
      title={profile ? `Edit “${profile.name}”` : '📋 New scan profile'}
      description="A profile bundles target selection, timeout and per-scanner configuration."
      width="max-w-xl"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" onClick={save} loading={busy}>
            {profile ? 'Save changes' : 'Create profile'}
          </Button>
        </>
      }
    >
      <div className="space-y-6">
        <Field label="Name" required>
          <Input
            value={draft.name}
            onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
            placeholder="Weekly external sweep"
          />
        </Field>
        <Field label="Description">
          <Textarea
            value={draft.description}
            onChange={(e) => setDraft((d) => ({ ...d, description: e.target.value }))}
          />
        </Field>
        <Field label="Timeout (seconds)" hint="per execution">
          <Input
            type="number"
            min={1}
            value={String(draft.timeout_seconds)}
            onChange={(e) => setDraft((d) => ({ ...d, timeout_seconds: Number(e.target.value) }))}
          />
        </Field>

        <div>
          <p className="mb-2 text-[13px] font-medium text-mute">
            Target selection <span className="text-mute/60">(from project scope)</span>
          </p>
          {targetsState.loading && <p className="text-[13px] text-mute">Loading targets…</p>}
          {!targetsState.loading && (targetsState.data ?? []).filter((t) => !t.excluded).length === 0 && (
            <p className="text-[13px] text-mute">No authorized targets in this project yet.</p>
          )}
          <div className="flex flex-wrap gap-1.5">
            {(targetsState.data ?? [])
              .filter((t) => !t.excluded)
              .map((t) => (
                <Chip
                  key={t.id}
                  as="button"
                  active={draft.target_selection.includes(t.target)}
                  onClick={() => toggleTarget(t.target, false)}
                >
                  🎯 {t.target}
                </Chip>
              ))}
          </div>
          {(targetsState.data ?? []).filter((t) => t.excluded).length > 0 && (
            <>
              <p className="mb-1.5 mt-3 text-[12px] font-medium text-mute/80">Excluded targets</p>
              <div className="flex flex-wrap gap-1.5">
                {(targetsState.data ?? [])
                  .filter((t) => t.excluded)
                  .map((t) => (
                    <Chip
                      key={t.id}
                      as="button"
                      active={draft.excluded_targets.includes(t.target)}
                      onClick={() => toggleTarget(t.target, true)}
                    >
                      🚫 {t.target}
                    </Chip>
                  ))}
              </div>
            </>
          )}
        </div>

        <div>
          <p className="mb-2 text-[13px] font-medium text-mute">
            Scanners <span className="text-mute/60">(only enabled scanners are selectable)</span>
          </p>
          {scannersState.loading && <p className="text-[13px] text-mute">Loading scanners…</p>}
          {!scannersState.loading && scanners.length === 0 && (
            <p className="text-[13px] text-sev-medium">
              No enabled scanners — enable one on the{' '}
              <a href="/scanners" className="text-accent-soft underline">
                Scanners
              </a>{' '}
              page.
            </p>
          )}
          <div className="space-y-3">
            {scanners.map((rec) => {
              const sel = draft.scanners.find((s) => s.scanner_id === rec.id);
              const included = !!sel;
              return (
                <div key={rec.id} className="rounded-xl border border-line bg-panel/50 p-3">
                  <div className="flex items-center justify-between gap-3">
                    <div className="min-w-0">
                      <p className="text-[13.5px] font-semibold text-ink">
                        {rec.display_name || rec.name}
                      </p>
                      <p className="truncate text-[12px] text-mute">{rec.description}</p>
                    </div>
                    <div className="flex shrink-0 items-center gap-2">
                      <Badge tone="outline">v{rec.version || '?'}</Badge>
                      <Switch checked={included} onChange={() => toggleScanner(rec)} label={`Include ${rec.name}`} />
                    </div>
                  </div>
                  {included && sel && (
                    <div className="mt-3 border-t border-line/60 pt-3">
                      <ScannerConfigForm
                        scanner={rec}
                        value={sel.config}
                        onChange={(config) =>
                          setDraft((d) => ({
                            ...d,
                            scanners: d.scanners.map((s) => (s.scanner_id === rec.id ? { ...s, config } : s)),
                          }))
                        }
                      />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </Sheet>
  );
}

export default function ProfilesTab() {
  const { id = '' } = useParams();
  const state = useApi(() => projectsApi.listProfiles(id).then(unwrap), [id]);
  const toast = useToast();
  const [editing, setEditing] = useState<ScanProfile | null>(null);
  const [creating, setCreating] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<ScanProfile | null>(null);

  const remove = async (p: ScanProfile) => {
    try {
      await projectsApi.deleteProfile(p.id);
      toast.success(`Profile “${p.name}” deleted`);
      setConfirmDelete(null);
      state.refetch();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Delete failed');
    }
  };

  return (
    <div>
      <div className="mb-4 flex justify-end">
        <Button variant="primary" onClick={() => setCreating(true)}>
          <Plus className="h-4 w-4" /> New profile
        </Button>
      </div>

      {state.loading && <SkeletonCards count={2} />}
      {state.error && !state.loading && <ErrorState message={state.error} onRetry={state.refetch} />}
      {!state.loading && !state.error && (state.data ?? []).length === 0 && (
        <EmptyState
          emoji="📋"
          title="No scan profiles yet"
          description="Profiles make repeat scans one-click — bundle targets, scanners and their configs."
          action={
            <Button variant="primary" onClick={() => setCreating(true)}>
              <Plus className="h-4 w-4" /> Create a profile
            </Button>
          }
        />
      )}

      {!state.loading && !state.error && (state.data ?? []).length > 0 && (
        <div className="grid gap-4 lg:grid-cols-2">
          {state.data!.map((p) => (
            <Card key={p.id}>
              <CardHeader>
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <CardTitle>{p.name}</CardTitle>
                    <CardDescription>{p.description || 'No description'}</CardDescription>
                  </div>
                  <div className="flex shrink-0 gap-1">
                    <Button variant="ghost" size="icon-sm" aria-label="Edit profile" onClick={() => setEditing(p)}>
                      <Pencil className="h-3.5 w-3.5" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      aria-label="Delete profile"
                      className="text-sev-critical hover:bg-sev-critical/10"
                      onClick={() => setConfirmDelete(p)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex flex-wrap items-center gap-1.5 text-[12.5px] text-mute">
                  <Badge tone="outline">⏱ {p.timeout_seconds}s timeout</Badge>
                  <Badge tone="outline">
                    🎯 {pluralize(p.target_selection?.length ?? 0, 'target')}
                  </Badge>
                  <Badge tone="outline">
                    🔧 {pluralize(p.scanners?.length ?? 0, 'scanner')}
                  </Badge>
                </div>
                {(p.scanners ?? []).length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {p.scanners!.map((s) => (
                      <Chip key={`${s.scanner}-${s.scanner_id}`}>🔧 {s.scanner}</Chip>
                    ))}
                  </div>
                )}
                {(p.target_selection ?? []).length > 0 && (
                  <div className="flex flex-wrap gap-1.5">
                    {p.target_selection.slice(0, 6).map((t) => (
                      <Chip key={t}>🎯 {t}</Chip>
                    ))}
                    {p.target_selection.length > 6 && <Chip>+{p.target_selection.length - 6} more</Chip>}
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      )}

      {(creating || editing) && (
        <ProfileForm
          projectId={id}
          profile={editing}
          onClose={() => {
            setCreating(false);
            setEditing(null);
          }}
          onSaved={state.refetch}
        />
      )}

      {confirmDelete && (
        <ConfirmDeleteDialog profile={confirmDelete} onCancel={() => setConfirmDelete(null)} onConfirm={() => remove(confirmDelete)} />
      )}
    </div>
  );
}

function ConfirmDeleteDialog({
  profile,
  onCancel,
  onConfirm,
}: {
  profile: ScanProfile;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  return (
    <Card className="fixed inset-x-4 top-1/2 z-50 mx-auto max-w-sm -translate-y-1/2 border-sev-critical/40 p-5 shadow-panel">
      <p className="text-sm font-semibold text-ink">Delete profile “{profile.name}”?</p>
      <p className="mt-1 text-[13px] text-mute">This cannot be undone.</p>
      <div className="mt-4 flex justify-end gap-2">
        <Button variant="ghost" onClick={onCancel}>
          Keep it
        </Button>
        <Button variant="danger" onClick={onConfirm}>
          <Trash2 className="h-3.5 w-3.5" /> Delete
        </Button>
      </div>
    </Card>
  );
}
