import { useState } from 'react';
import { ChevronDown, RefreshCw } from 'lucide-react';
import { scannersApi, unwrap } from '@/api/client';
import { ConfigSchemaView, parseManifest } from '@/components/scanner-config-form';
import { ErrorState } from '@/components/empty-state';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { SkeletonCards } from '@/components/ui/skeleton';
import { Switch } from '@/components/ui/switch';
import { useToast } from '@/components/ui/toast';
import { useApi } from '@/lib/use-api';
import { assetTypeLabel, scannerStatusMeta } from '@/lib/severity';
import { timeAgo } from '@/lib/utils';

export default function ScannersPage() {
  const state = useApi(() => scannersApi.list().then(unwrap), []);
  const toast = useToast();
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const toggleEnabled = async (id: string, enabled: boolean, name: string) => {
    try {
      await scannersApi.setEnabled(id, enabled);
      toast.success(`${name} ${enabled ? 'enabled ✅' : 'disabled'}`);
      state.refetch();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Toggle failed');
    }
  };

  return (
    <div>
      <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold tracking-tight text-ink">
            🔎 Scanners
          </h1>
          <p className="mt-1 text-[13.5px] text-mute">
            Tooling the eye can call on. Enable, disable, and peek inside each adapter.
          </p>
        </div>
        <Button variant="ghost" size="sm" onClick={state.refetch}>
          <RefreshCw className="h-3.5 w-3.5" /> Re-check
        </Button>
      </div>

      {state.loading && <SkeletonCards count={3} />}
      {state.error && !state.loading && <ErrorState message={state.error} onRetry={state.refetch} />}
      {!state.loading && !state.error && (state.data ?? []).length === 0 && (
        <div className="rounded-2xl border border-dashed border-line bg-panel/40 px-6 py-12 text-center">
          <div className="text-3xl">🔎</div>
          <h3 className="mt-2 text-[15px] font-semibold text-ink">No scanners registered</h3>
          <p className="mx-auto mt-1 max-w-sm text-[13px] text-mute">
            Drop manifests into the scanner registry and they will show up here, blinking eagerly.
          </p>
        </div>
      )}

      {!state.loading && !state.error && (state.data ?? []).length > 0 && (
        <div className="grid gap-4 lg:grid-cols-2">
          {state.data!.map((sc) => {
            const st = scannerStatusMeta(sc.status, sc.enabled);
            const isOpen = expanded.has(sc.id);
            const manifest = parseManifest(sc);
            return (
              <Card key={sc.id} className={sc.enabled ? '' : 'opacity-75'}>
                <CardHeader>
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex min-w-0 items-start gap-2.5">
                      <span
                        className={`mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full ${st.dot} ${
                          sc.status === 'available' && sc.enabled ? 'animate-pulse-dot' : ''
                        }`}
                        title={st.label}
                        aria-label={`Status: ${st.label}`}
                      />
                      <div className="min-w-0">
                        <CardTitle>{sc.display_name || sc.name}</CardTitle>
                        <CardDescription>{sc.description || 'No description'}</CardDescription>
                      </div>
                    </div>
                    <div className="flex shrink-0 flex-col items-end gap-1.5">
                      <Switch
                        checked={sc.enabled}
                        onChange={(next) => toggleEnabled(sc.id, next, sc.name)}
                        label={`Enable ${sc.name}`}
                      />
                      <span className="text-[11px] text-mute">
                        {st.label}
                        {sc.version ? ` · v${sc.version}` : ''}
                      </span>
                    </div>
                  </div>
                  {sc.status_detail && sc.status !== 'available' && (
                    <p className="mt-1 rounded-lg border border-sev-medium/25 bg-sev-medium/5 px-2 py-1 text-[12px] text-sev-medium">
                      {sc.status_detail}
                    </p>
                  )}
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex flex-wrap gap-1.5">
                    {(sc.capabilities ?? []).map((c) => (
                      <Badge key={c} tone="gold">
                        ✨ {c}
                      </Badge>
                    ))}
                    {(sc.asset_types ?? []).map((t) => (
                      <Badge key={t} tone="outline">
                        {assetTypeLabel(t)}
                      </Badge>
                    ))}
                  </div>

                  <div className="flex items-center justify-between text-[11.5px] text-mute/70">
                    <span>
                      <code className="font-mono">{sc.executable}</code>
                      {sc.last_checked_at ? ` · checked ${timeAgo(sc.last_checked_at)}` : ''}
                    </span>
                    <button
                      className="inline-flex items-center gap-1 text-accent-soft hover:underline"
                      onClick={() =>
                        setExpanded((s) => {
                          const next = new Set(s);
                          if (next.has(sc.id)) next.delete(sc.id);
                          else next.add(sc.id);
                          return next;
                        })
                      }
                      aria-expanded={isOpen}
                    >
                      {isOpen ? 'Hide manifest' : 'Inspect manifest'}
                      <ChevronDown className={`h-3.5 w-3.5 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
                    </button>
                  </div>

                  {isOpen && (
                    <div className="space-y-4 animate-fade-in">
                      {(sc.documentation || manifest?.documentation) && (
                        <div>
                          <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-mute/70">
                            Documentation
                          </p>
                          <pre className="mono-block max-h-56 overflow-y-auto font-sans text-[12.5px] leading-relaxed">
                            {sc.documentation || manifest?.documentation}
                          </pre>
                        </div>
                      )}
                      <div>
                        <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-mute/70">
                          Configuration schema
                        </p>
                        <ConfigSchemaView scanner={sc} />
                      </div>
                      <details>
                        <summary className="cursor-pointer text-[12px] text-mute hover:text-ink">
                          Raw manifest JSON
                        </summary>
                        <pre className="mono-block mt-1.5 max-h-64 overflow-y-auto text-[11.5px]">
                          {JSON.stringify(sc.manifest, null, 2)}
                        </pre>
                      </details>
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
