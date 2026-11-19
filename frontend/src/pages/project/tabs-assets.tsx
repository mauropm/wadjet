import { useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { Plus, Search } from 'lucide-react';
import { projectsApi, unwrap } from '@/api/client';
import { EmptyState, ErrorState } from '@/components/empty-state';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Field, Input, Select, Textarea } from '@/components/ui/input';
import { SkeletonRows } from '@/components/ui/skeleton';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { useToast } from '@/components/ui/toast';
import { useApi } from '@/lib/use-api';
import { assetTypeLabel, discoveryLabel } from '@/lib/severity';
import { parseTags, timeAgo } from '@/lib/utils';

const ASSET_TYPES = [
  'ipv4',
  'ipv6',
  'hostname',
  'domain',
  'server',
  'endpoint',
  'web_app',
  'container',
  'other',
];

function AddAssetDialog({
  onClose,
  projectId,
  onAdded,
}: {
  onClose: () => void;
  projectId: string;
  onAdded: () => void;
}) {
  const toast = useToast();
  const [identity, setIdentity] = useState('');
  const [assetType, setAssetType] = useState('ipv4');
  const [ip, setIp] = useState('');
  const [hostname, setHostname] = useState('');
  const [osName, setOsName] = useState('');
  const [description, setDescription] = useState('');
  const [tags, setTags] = useState('');
  const [busy, setBusy] = useState(false);

  const add = async () => {
    if (!identity.trim()) {
      toast.error('Identity is required — it’s the dedup key.');
      return;
    }
    setBusy(true);
    try {
      await projectsApi.createAsset(projectId, {
        identity: identity.trim(),
        asset_type: assetType,
        ip: ip.trim() || undefined,
        hostname: hostname.trim() || undefined,
        os_name: osName.trim() || undefined,
        description: description.trim() || undefined,
        tags: parseTags(tags).length ? parseTags(tags) : undefined,
      });
      toast.success(`Asset ${identity.trim()} added ✍️`);
      setIdentity('');
      setIp('');
      setHostname('');
      setOsName('');
      setDescription('');
      setTags('');
      onAdded();
      onClose();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to add asset');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card className="mt-4 animate-fade-in">
      <div className="grid gap-4 p-5 md:grid-cols-2">
        <Field label="Identity" required hint="dedup key (IP or lowercased hostname)">
          <Input value={identity} onChange={(e) => setIdentity(e.target.value)} placeholder="10.0.5.12 or app.acme.com" />
        </Field>
        <Field label="Asset type" required>
          <Select value={assetType} onChange={(e) => setAssetType(e.target.value)}>
            {ASSET_TYPES.map((t) => (
              <option key={t} value={t}>
                {assetTypeLabel(t)}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="IP">
          <Input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="10.0.5.12" />
        </Field>
        <Field label="Hostname">
          <Input value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="web-01" />
        </Field>
        <Field label="OS name">
          <Input value={osName} onChange={(e) => setOsName(e.target.value)} placeholder="Ubuntu 22.04" />
        </Field>
        <Field label="Tags" hint="comma separated">
          <Input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="prod, dmz" />
        </Field>
        <Field label="Description" className="md:col-span-2">
          <Textarea value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
        <div className="flex justify-end gap-2 md:col-span-2">
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="primary" onClick={add} loading={busy}>
            Add asset
          </Button>
        </div>
      </div>
    </Card>
  );
}

export default function AssetsTab() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const state = useApi(() => projectsApi.listAssets(id).then(unwrap), [id]);
  const [query, setQuery] = useState('');
  const [adding, setAdding] = useState(false);

  const rows = useMemo(() => {
    const items = (state.data ?? []).slice();
    items.sort((a, b) => new Date(b.last_seen).getTime() - new Date(a.last_seen).getTime());
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter((a) =>
      [a.identity, a.ip, a.hostname, a.domain, a.os_name, ...a.tags]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(q)),
    );
  }, [state.data, query]);

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div className="relative max-w-sm flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-mute" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by identity, IP, hostname, OS, tag…"
            className="pl-9"
            aria-label="Filter assets"
          />
        </div>
        <Button variant="primary" onClick={() => setAdding((s) => !s)}>
          <Plus className="h-4 w-4" /> Add asset
        </Button>
      </div>

      {adding && (
        <AddAssetDialog onClose={() => setAdding(false)} projectId={id} onAdded={state.refetch} />
      )}

      {state.loading && (
        <Card>
          <SkeletonRows rows={6} cols={6} />
        </Card>
      )}
      {state.error && !state.loading && <ErrorState message={state.error} onRetry={state.refetch} />}

      {!state.loading && !state.error && rows.length === 0 && (
        <EmptyState
          emoji="🖥️"
          title={query ? 'The eye squints — nothing matches' : 'No assets yet'}
          description={
            query
              ? `No asset matches “${query}”.`
              : 'Assets appear here when scanners discover them — or add one manually.'
          }
        />
      )}

      {!state.loading && !state.error && rows.length > 0 && (
        <Card>
          <Table>
            <THead>
              <TR>
                <TH>Identity</TH>
                <TH>Type</TH>
                <TH>IP / Hostname</TH>
                <TH>OS</TH>
                <TH>Discovery</TH>
                <TH>First seen</TH>
                <TH>Last seen</TH>
              </TR>
            </THead>
            <TBody>
              {rows.map((a) => (
                <TR key={a.id} clickable onClick={() => navigate(`/assets/${a.id}`)}>
                  <TD>
                    <Link
                      to={`/assets/${a.id}`}
                      className="font-mono text-[13px] font-medium text-ink hover:text-accent-soft"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {a.identity}
                    </Link>
                    {(a.tags ?? []).length > 0 && (
                      <span className="ml-2 text-[11px] text-mute">{a.tags.join(', ')}</span>
                    )}
                  </TD>
                  <TD>
                    <Badge tone="outline">{assetTypeLabel(a.asset_type)}</Badge>
                  </TD>
                  <TD className="font-mono text-[12.5px] text-mute">
                    {[a.ip, a.hostname].filter(Boolean).join(' · ') || '—'}
                  </TD>
                  <TD className="text-[13px] text-mute">
                    {a.os_name ?? '—'}
                    {a.os_accuracy != null && (
                      <span className="ml-1 text-[11px] text-mute/60">{a.os_accuracy}%</span>
                    )}
                  </TD>
                  <TD className="text-[12.5px] text-mute">{discoveryLabel(a.discovery_source)}</TD>
                  <TD className="text-[12.5px] text-mute" title={a.first_seen}>
                    {timeAgo(a.first_seen)}
                  </TD>
                  <TD className="text-[12.5px] text-mute" title={a.last_seen}>
                    {timeAgo(a.last_seen)}
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
