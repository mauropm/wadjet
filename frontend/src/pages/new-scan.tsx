import { useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, ArrowRight, Check, Plus, Rocket, Trash2 } from 'lucide-react';
import { projectsApi, scannersApi, scansApi, unwrap } from '@/api/client';
import { ScannerConfigForm } from '@/components/scanner-config-form';
import { ErrorState } from '@/components/empty-state';
import { Badge, Chip } from '@/components/ui/badge';
import { Button, buttonVariants } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Field, Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { Switch } from '@/components/ui/switch';
import { useToast } from '@/components/ui/toast';
import { useApi } from '@/lib/use-api';
import { cn } from '@/lib/utils';
import type { ScanProfile, ScannerRecord } from '@/lib/types';

const STEPS = ['Targets', 'Profile', 'Scanners', 'Review', 'Launch'] as const;

export default function NewScanWizard() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const toast = useToast();

  const targetsState = useApi(() => projectsApi.listTargets(id).then(unwrap), [id]);
  const profilesState = useApi(() => projectsApi.listProfiles(id).then(unwrap), [id]);
  const scannersState = useApi(() => scannersApi.list().then(unwrap), [id]);

  const [step, setStep] = useState(0);
  const [sessionName, setSessionName] = useState('');
  const [checkedTargets, setCheckedTargets] = useState<Set<string>>(new Set());
  const [adhoc, setAdhoc] = useState<string[]>([]);
  const [adhocInput, setAdhocInput] = useState('');
  const [profileId, setProfileId] = useState<string | null>(null); // null = custom
  const [scannerSel, setScannerSel] = useState<Record<string, { enabled: boolean; config: Record<string, unknown> }>>({});
  const [launching, setLaunching] = useState(false);

  const includedTargets = (targetsState.data ?? []).filter((t) => !t.excluded);
  const excludedTargets = (targetsState.data ?? []).filter((t) => t.excluded);
  const enabledScanners: ScannerRecord[] = useMemo(
    () => (scannersState.data ?? []).filter((s) => s.enabled),
    [scannersState.data],
  );
  const selectedProfile: ScanProfile | null = useMemo(
    () => (profilesState.data ?? []).find((p) => p.id === profileId) ?? null,
    [profilesState.data, profileId],
  );

  const chosenTargets = [
    ...includedTargets.filter((t) => checkedTargets.has(t.id)).map((t) => t.target),
    ...adhoc,
  ];

  const activeScanners = Object.entries(scannerSel).filter(([, v]) => v.enabled);

  const loading = targetsState.loading || profilesState.loading || scannersState.loading;

  const canNext = (): boolean => {
    if (step === 0) return chosenTargets.length > 0;
    if (step === 2) return profileId !== null || activeScanners.length > 0;
    return true;
  };

  const launch = async () => {
    setLaunching(true);
    try {
      const name = sessionName.trim() || `Scan ${new Date().toISOString().slice(0, 16).replace('T', ' ')}`;
      const body = selectedProfile
        ? { name, profile_id: selectedProfile.id, targets: chosenTargets.length ? chosenTargets : undefined }
        : {
            name,
            targets: chosenTargets,
            scanners: activeScanners.map(([scanner, v]) => ({ scanner, config: v.config })),
          };
      const session = await projectsApi.createScan(id, body);
      try {
        await scansApi.start(session.id);
        toast.success('Scan launched — the eye is open 👁️');
      } catch (e) {
        toast.info('Session created — start it manually if it doesn’t begin.');
        toast.error(e instanceof Error ? e.message : 'Start failed');
      }
      navigate(`/scans/${session.id}`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to create scan session');
      setLaunching(false);
    }
  };

  if (loading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-64 rounded-2xl" />
      </div>
    );
  }
  if (targetsState.error || profilesState.error || scannersState.error) {
    return (
      <ErrorState
        message={targetsState.error ?? profilesState.error ?? scannersState.error ?? 'Load failed'}
        onRetry={() => {
          targetsState.refetch();
          profilesState.refetch();
          scannersState.refetch();
        }}
      />
    );
  }

  return (
    <div>
      <Link
        to={`/projects/${id}`}
        className="mb-3 inline-flex items-center gap-1 text-[12.5px] text-mute hover:text-ink"
      >
        <ArrowLeft className="h-3.5 w-3.5" /> Project
      </Link>

      <h1 className="mb-5 text-xl font-bold tracking-tight text-ink">🚀 New scan</h1>

      {/* stepper */}
      <ol className="mb-6 flex flex-wrap items-center gap-2">
        {STEPS.map((s, i) => (
          <li key={s} className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => i < step && setStep(i)}
              disabled={i > step}
              className={cn(
                'flex items-center gap-1.5 rounded-full border px-3 py-1 text-[12.5px] transition-colors',
                i === step && 'border-accent/50 bg-accent/10 font-semibold text-accent-soft',
                i < step && 'border-line bg-panel text-mute hover:text-ink',
                i > step && 'border-line/50 text-mute/50',
              )}
            >
              <span
                className={cn(
                  'flex h-4.5 w-4.5 items-center justify-center rounded-full text-[10px] font-bold',
                  i === step ? 'bg-accent text-base' : i < step ? 'bg-accent/30 text-accent-soft' : 'bg-line text-mute',
                )}
              >
                {i < step ? <Check className="h-3 w-3" /> : i + 1}
              </span>
              {s}
            </button>
            {i < STEPS.length - 1 && <span className="text-mute/30" aria-hidden>—</span>}
          </li>
        ))}
      </ol>

      <Card className="min-h-[320px]">
        {/* ── STEP 1 · Targets ── */}
        {step === 0 && (
          <>
            <CardHeader>
              <CardTitle>1 · Choose targets</CardTitle>
            </CardHeader>
            <CardContent className="space-y-5">
              {includedTargets.length === 0 && (
                <p className="text-[13px] text-sev-medium">
                  No authorized targets in scope. Add some in{' '}
                  <Link className="text-accent-soft underline" to={`/projects/${id}/settings`}>
                    project settings
                  </Link>{' '}
                  or use ad-hoc entries below.
                </p>
              )}
              <div className="grid gap-2 sm:grid-cols-2">
                {includedTargets.map((t) => (
                  <label
                    key={t.id}
                    className={cn(
                      'flex cursor-pointer items-center gap-2.5 rounded-xl border px-3 py-2 text-[13.5px] transition-colors',
                      checkedTargets.has(t.id)
                        ? 'border-accent/40 bg-accent/5 text-ink'
                        : 'border-line bg-panel/50 text-mute hover:border-line',
                    )}
                  >
                    <input
                      type="checkbox"
                      className="h-4 w-4 accent-accent"
                      checked={checkedTargets.has(t.id)}
                      onChange={(e) =>
                        setCheckedTargets((s) => {
                          const next = new Set(s);
                          if (e.target.checked) next.add(t.id);
                          else next.delete(t.id);
                          return next;
                        })
                      }
                    />
                    <code className="font-mono">{t.target}</code>
                    <Badge tone="outline">{t.target_type}</Badge>
                  </label>
                ))}
              </div>

              {excludedTargets.length > 0 && (
                <div>
                  <p className="mb-1.5 text-[12px] font-semibold uppercase tracking-wider text-mute/70">
                    Exclusions (auto-subtracted)
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {excludedTargets.map((t) => (
                      <Chip key={t.id} title={t.note || undefined}>
                        🚫 {t.target}
                      </Chip>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <p className="mb-1.5 text-[12px] font-semibold uppercase tracking-wider text-mute/70">
                  Ad-hoc targets
                </p>
                <div className="flex gap-2">
                  <Input
                    value={adhocInput}
                    onChange={(e) => setAdhocInput(e.target.value)}
                    placeholder="extra.example.com or 10.10.0.0/24"
                    className="max-w-sm"
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' && adhocInput.trim()) {
                        e.preventDefault();
                        setAdhoc((a) => [...a, adhocInput.trim()]);
                        setAdhocInput('');
                      }
                    }}
                  />
                  <Button
                    variant="secondary"
                    size="sm"
                    disabled={!adhocInput.trim()}
                    onClick={() => {
                      setAdhoc((a) => [...a, adhocInput.trim()]);
                      setAdhocInput('');
                    }}
                  >
                    <Plus className="h-3.5 w-3.5" /> Add
                  </Button>
                </div>
                {adhoc.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {adhoc.map((t, i) => (
                      <button
                        key={`${t}-${i}`}
                        className="group"
                        onClick={() => setAdhoc((a) => a.filter((_, j) => j !== i))}
                        title="Remove"
                      >
                        <Chip className="group-hover:border-sev-critical/50 group-hover:text-sev-critical">
                          {t} <Trash2 className="h-2.5 w-2.5" />
                        </Chip>
                      </button>
                    ))}
                  </div>
                )}
              </div>

              <Field label="Session name" hint="optional">
                <Input
                  value={sessionName}
                  onChange={(e) => setSessionName(e.target.value)}
                  placeholder="Monday sweep"
                  className="max-w-sm"
                />
              </Field>
            </CardContent>
          </>
        )}

        {/* ── STEP 2 · Profile or custom ── */}
        {step === 1 && (
          <>
            <CardHeader>
              <CardTitle>2 · Profile or custom?</CardTitle>
            </CardHeader>
            <CardContent className="grid gap-3 sm:grid-cols-2">
              <button
                onClick={() => setProfileId(null)}
                className={cn(
                  'rounded-xl border p-4 text-left transition-colors',
                  profileId === null ? 'border-accent/50 bg-accent/5' : 'border-line hover:border-mute/40',
                )}
              >
                <p className="text-[14px] font-semibold text-ink">🛠️ Custom run</p>
                <p className="mt-1 text-[12.5px] text-mute">
                  Pick scanners and tune their config right now.
                </p>
              </button>
              {(profilesState.data ?? []).length === 0 && (
                <div className="rounded-xl border border-dashed border-line p-4 text-[13px] text-mute">
                  No profiles yet — create one on the{' '}
                  <Link className="text-accent-soft underline" to={`/projects/${id}/profiles`}>
                    Scan Profiles
                  </Link>{' '}
                  tab.
                </div>
              )}
              {(profilesState.data ?? []).map((p) => (
                <button
                  key={p.id}
                  onClick={() => setProfileId(p.id)}
                  className={cn(
                    'rounded-xl border p-4 text-left transition-colors',
                    profileId === p.id ? 'border-accent/50 bg-accent/5' : 'border-line hover:border-mute/40',
                  )}
                >
                  <p className="text-[14px] font-semibold text-ink">📋 {p.name}</p>
                  <p className="mt-1 line-clamp-2 text-[12.5px] text-mute">{p.description || 'No description'}</p>
                  <p className="mt-2 text-[11.5px] text-mute/70">
                    {p.scanners?.length ?? 0} scanners · {p.target_selection?.length ?? 0} targets ·{' '}
                    {p.timeout_seconds}s timeout
                  </p>
                </button>
              ))}
            </CardContent>
          </>
        )}

        {/* ── STEP 3 · Scanners + config ── */}
        {step === 2 && (
          <>
            <CardHeader>
              <CardTitle>
                3 · {selectedProfile ? 'Profile scanners (review)' : 'Pick scanners & tune config'}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {selectedProfile ? (
                <div className="rounded-xl border border-accent/25 bg-accent/5 p-4 text-[13.5px]">
                  Using profile <b className="text-ink">{selectedProfile.name}</b> — its scanners and configs
                  travel with the session. Next step shows the summary.
                  {(selectedProfile.scanners ?? []).length === 0 && (
                    <p className="mt-2 text-sev-medium">⚠️ This profile has no scanners.</p>
                  )}
                </div>
              ) : enabledScanners.length === 0 ? (
                <p className="text-[13px] text-sev-medium">
                  No enabled scanners. Enable one on the{' '}
                  <Link className="text-accent-soft underline" to="/scanners">
                    Scanners
                  </Link>{' '}
                  page first.
                </p>
              ) : (
                enabledScanners.map((rec) => {
                  const sel = scannerSel[rec.name];
                  return (
                    <div key={rec.id} className="rounded-xl border border-line bg-panel/50 p-3">
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <p className="text-[13.5px] font-semibold text-ink">
                            {rec.display_name || rec.name}
                          </p>
                          <p className="text-[12px] text-mute">{rec.description}</p>
                        </div>
                        <Switch
                          checked={!!sel?.enabled}
                          label={`Select ${rec.name}`}
                          onChange={(on) =>
                            setScannerSel((s) => ({
                              ...s,
                              [rec.name]: { enabled: on, config: s[rec.name]?.config ?? {} },
                            }))
                          }
                        />
                      </div>
                      {sel?.enabled && (
                        <div className="mt-3 border-t border-line/60 pt-3">
                          <ScannerConfigForm
                            scanner={rec}
                            value={sel.config}
                            onChange={(config) =>
                              setScannerSel((s) => ({ ...s, [rec.name]: { enabled: true, config } }))
                            }
                          />
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </CardContent>
          </>
        )}

        {/* ── STEP 4 · Review ── */}
        {step === 3 && (
          <>
            <CardHeader>
              <CardTitle>4 · Review before launch</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 text-[13.5px]">
              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <p className="mb-1.5 text-[12px] font-semibold uppercase tracking-wider text-mute/70">
                    Session
                  </p>
                  <p className="text-ink">{sessionName.trim() || '(auto-named)'}</p>
                  <p className="text-mute">
                    {selectedProfile ? `Profile: ${selectedProfile.name}` : 'Custom scanner selection'}
                  </p>
                </div>
                <div>
                  <p className="mb-1.5 text-[12px] font-semibold uppercase tracking-wider text-mute/70">
                    Targets ({chosenTargets.length})
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {chosenTargets.map((t) => (
                      <Chip key={t}>🎯 {t}</Chip>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="mb-1.5 text-[12px] font-semibold uppercase tracking-wider text-mute/70">
                    Scanners
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedProfile
                      ? (selectedProfile.scanners ?? []).map((s) => <Chip key={s.scanner}>🔧 {s.scanner}</Chip>)
                      : activeScanners.map(([name, v]) => (
                          <Chip key={name} title={JSON.stringify(v.config)}>
                            🔧 {name}
                            {Object.keys(v.config ?? {}).length > 0 && (
                              <span className="text-accent-soft"> · {Object.keys(v.config).length} opts</span>
                            )}
                          </Chip>
                        ))}
                  </div>
                </div>
              </div>
              <p className="rounded-xl border border-gold/25 bg-gold/5 p-3 text-[12.5px] text-gold">
                ⚖️ Only scan what you're authorized to scan. The eye judges silently.
              </p>
            </CardContent>
          </>
        )}

        {/* ── STEP 5 · Launch ── */}
        {step === 4 && (
          <CardContent className="flex flex-col items-center gap-4 py-16">
            <div className="text-5xl" aria-hidden>
              👁️
            </div>
            <p className="text-center text-[15px] text-ink">
              Everything looks good. Release the eye?
            </p>
            <Button variant="primary" size="lg" loading={launching} onClick={launch}>
              <Rocket className="h-4 w-4" /> Launch scan 🚀
            </Button>
          </CardContent>
        )}

        {/* nav */}
        <div className="flex items-center justify-between border-t border-line p-4">
          <Button
            variant="ghost"
            onClick={() => (step === 0 ? navigate(`/projects/${id}`) : setStep((s) => s - 1))}
          >
            <ArrowLeft className="h-4 w-4" /> Back
          </Button>
          {step < STEPS.length - 1 && (
            <Button variant="primary" onClick={() => setStep((s) => s + 1)} disabled={!canNext()}>
              Next <ArrowRight className="h-4 w-4" />
            </Button>
          )}
        </div>
      </Card>

      <div className="mt-4 text-center">
        <Link to={`/projects/${id}/scans`} className={cn(buttonVariants({ variant: 'ghost', size: 'sm' }))}>
          Cancel
        </Link>
      </div>
    </div>
  );
}
