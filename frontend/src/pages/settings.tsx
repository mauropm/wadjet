import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { LogOut, RefreshCw, ShieldCheck } from 'lucide-react';
import { auditApi, unwrap } from '@/api/client';
import { EmptyState, ErrorState } from '@/components/empty-state';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { SkeletonRows } from '@/components/ui/skeleton';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { useAuth } from '@/lib/auth';
import { useApi } from '@/lib/use-api';
import { formatDateTime, timeAgo } from '@/lib/utils';

export default function SettingsPage() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const auditState = useApi(() => auditApi.list().then(unwrap), []);
  const [busy, setBusy] = useState(false);

  const audit404 = auditState.error !== null && /404|not found/i.test(auditState.error);

  return (
    <div className="space-y-6">
      <h1 className="text-xl font-bold tracking-tight text-ink">⚙️ Settings</h1>

      <Card className="max-w-2xl">
        <CardHeader>
          <CardTitle>🪪 You</CardTitle>
          <CardDescription>Who the eye trusts.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-accent/15 text-lg font-bold text-accent-soft">
              {(user?.name || user?.email || '?').slice(0, 1).toUpperCase()}
            </div>
            <div>
              <p className="text-[15px] font-semibold text-ink">{user?.name || '—'}</p>
              <p className="text-[13px] text-mute">{user?.email}</p>
              <div className="mt-1 flex items-center gap-1.5">
                <Badge tone={user?.role === 'admin' ? 'gold' : 'accent'}>
                  <ShieldCheck className="h-3 w-3" /> {user?.role || 'user'}
                </Badge>
                {user?.created_at && (
                  <span className="text-[11.5px] text-mute/70">joined {timeAgo(user.created_at)}</span>
                )}
              </div>
            </div>
          </div>
          <Button
            variant="danger"
            loading={busy}
            onClick={async () => {
              setBusy(true);
              await logout();
              navigate('/login');
            }}
          >
            <LogOut className="h-4 w-4" /> Sign out
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <div>
            <CardTitle>🧾 Audit log</CardTitle>
            <CardDescription>Every blink is recorded. Tamper-evident trail of user actions.</CardDescription>
          </div>
          <Button variant="ghost" size="sm" onClick={auditState.refetch}>
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </Button>
        </CardHeader>

        {auditState.loading && <SkeletonRows rows={5} cols={4} />}

        {!auditState.loading && audit404 && (
          <div className="p-5">
            <EmptyState
              emoji="🧾"
              title="Audit log not exposed yet"
              description="The API doesn't serve /api/v1/audit (404). The moment it does, this table lights up."
              className="py-8"
            />
          </div>
        )}

        {!auditState.loading && !audit404 && auditState.error && (
          <div className="p-5">
            <ErrorState message={auditState.error} onRetry={auditState.refetch} className="py-6" />
          </div>
        )}

        {!auditState.loading && !auditState.error && (auditState.data ?? []).length === 0 && (
          <div className="p-5">
            <EmptyState emoji="🌙" title="Nothing to report" description="The logs are suspiciously quiet." className="py-8" />
          </div>
        )}

        {!auditState.loading && !auditState.error && (auditState.data ?? []).length > 0 && (
          <Table>
            <THead>
              <TR>
                <TH>Action</TH>
                <TH>Resource</TH>
                <TH>IP</TH>
                <TH>When</TH>
              </TR>
            </THead>
            <TBody>
              {auditState.data!.map((a) => (
                <TR key={a.id}>
                  <TD>
                    <code className="font-mono text-[12.5px] text-accent-soft">{a.action}</code>
                  </TD>
                  <TD className="text-[13px] text-mute">
                    {a.resource_type}
                    {a.resource_id ? (
                      <span className="ml-1 font-mono text-[11.5px] text-mute/70">
                        {String(a.resource_id).slice(0, 8)}…
                      </span>
                    ) : null}
                  </TD>
                  <TD className="font-mono text-[12.5px] text-mute">{a.ip || '—'}</TD>
                  <TD className="text-[12.5px] text-mute" title={formatDateTime(a.created_at)}>
                    {timeAgo(a.created_at)}
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
