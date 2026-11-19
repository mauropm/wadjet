import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ArrowUpDown, Search } from 'lucide-react';
import { findingsApi, projectsApi, unwrap } from '@/api/client';
import { SeverityChip, StatusChip } from '@/components/chips';
import { EmptyState, ErrorState } from '@/components/empty-state';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { Dialog } from '@/components/ui/dialog';
import { Input, Select, Textarea } from '@/components/ui/input';
import { SkeletonRows } from '@/components/ui/skeleton';
import { Table, TBody, TD, TH, THead, TR } from '@/components/ui/table';
import { useToast } from '@/components/ui/toast';
import { useApi } from '@/lib/use-api';
import { FINDING_STATUSES, SEVERITIES, findingStatusMeta, severityWeight } from '@/lib/severity';
import { timeAgo } from '@/lib/utils';
import type { Finding } from '@/lib/types';

const PAGE_SIZE = 25;
type SortKey = 'severity' | 'date';

export default function FindingsTab() {
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const state = useApi(() => projectsApi.listFindings(id, { limit: 1000 }).then(unwrap), [id]);

  const [severities, setSeverities] = useState<Set<string>>(new Set());
  const [status, setStatus] = useState('');
  const [scanner, setScanner] = useState('');
  const [query, setQuery] = useState('');
  const [sortKey, setSortKey] = useState<SortKey>('severity');
  const [sortDesc, setSortDesc] = useState(true);
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkOpen, setBulkOpen] = useState(false);
  const [bulkStatus, setBulkStatus] = useState('confirmed');
  const [bulkNote, setBulkNote] = useState('');
  const [bulkBusy, setBulkBusy] = useState(false);

  useEffect(() => setPage(0), [severities, status, scanner, query, sortKey, sortDesc]);

  const all = state.data ?? [];
  const scanners = useMemo(
    () => [...new Set(all.map((f) => f.scanner).filter(Boolean))].sort(),
    [all],
  );

  const filtered = useMemo(() => {
    let rows = all.slice();
    if (severities.size) rows = rows.filter((f) => severities.has(f.severity));
    if (status) rows = rows.filter((f) => f.status === status);
    if (scanner) rows = rows.filter((f) => f.scanner === scanner);
    const q = query.trim().toLowerCase();
    if (q) {
      rows = rows.filter((f) =>
        [f.title, f.description, f.scanner, f.fingerprint, ...f.cves]
          .filter(Boolean)
          .some((v) => String(v).toLowerCase().includes(q)),
      );
    }
    rows.sort((a, b) => {
      const dir = sortDesc ? -1 : 1;
      if (sortKey === 'severity') {
        const d = severityWeight(a.severity) - severityWeight(b.severity);
        if (d !== 0) return d * dir;
      }
      return (new Date(a.last_detected).getTime() - new Date(b.last_detected).getTime()) * dir;
    });
    return rows;
  }, [all, severities, status, scanner, query, sortKey, sortDesc]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const pageRows = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const pageIds = pageRows.map((f) => f.id);
  const allPageSelected = pageIds.length > 0 && pageIds.every((i) => selected.has(i));

  const applyServerFilters = status || scanner || query || severities.size
    ? {
        ...(status ? { status } : {}),
        ...(scanner ? { scanner } : {}),
        ...(query.trim() ? { q: query.trim() } : {}),
        ...(severities.size === 1 ? { severity: [...severities][0] } : {}),
      }
    : {};

  const bulkApply = async () => {
    setBulkBusy(true);
    let ok = 0;
    let fail = 0;
    for (const findingId of selected) {
      try {
        await findingsApi.setStatus(findingId, {
          status: bulkStatus,
          note: bulkNote.trim() || undefined,
        });
        ok += 1;
      } catch {
        fail += 1;
      }
    }
    setBulkBusy(false);
    setBulkOpen(false);
    setBulkNote('');
    setSelected(new Set());
    if (fail) toast.error(`${ok} updated, ${fail} failed`);
    else toast.success(`${ok} finding${ok === 1 ? '' : 's'} → ${findingStatusMeta(bulkStatus).label}`);
    state.refetch();
  };

  return (
    <div>
      {/* filter bar */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="flex gap-1">
          {SEVERITIES.map((sev) => {
            const active = severities.has(sev);
            return (
              <button
                key={sev}
                onClick={() =>
                  setSeverities((s) => {
                    const next = new Set(s);
                    if (next.has(sev)) next.delete(sev);
                    else next.add(sev);
                    return next;
                  })
                }
                className="transition-transform hover:scale-105"
                aria-pressed={active}
                title={`Filter ${sev}`}
              >
                <SeverityChip severity={sev} className={active ? 'ring-1 ring-accent/60' : 'opacity-60'} />
              </button>
            );
          })}
        </div>
        <Select
          value={status}
          onChange={(e) => setStatus(e.target.value)}
          className="w-auto"
          aria-label="Filter by status"
        >
          <option value="">All statuses</option>
          {FINDING_STATUSES.map((s) => (
            <option key={s} value={s}>
              {findingStatusMeta(s).label}
            </option>
          ))}
        </Select>
        <Select
          value={scanner}
          onChange={(e) => setScanner(e.target.value)}
          className="w-auto"
          aria-label="Filter by scanner"
        >
          <option value="">All scanners</option>
          {scanners.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </Select>
        <div className="relative min-w-[180px] flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-mute" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search title, description, CVE…"
            className="pl-9"
            aria-label="Search findings"
          />
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => {
            if (sortKey === 'severity') setSortKey('date');
            else {
              setSortKey('severity');
            }
          }}
          title="Toggle sort: severity ⇄ date"
        >
          <ArrowUpDown className="h-3.5 w-3.5" />
          {sortKey === 'severity' ? 'Severity' : 'Date'} · {sortDesc ? '↓' : '↑'}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setSortDesc((d) => !d)}
          title="Toggle sort direction"
        >
          {sortDesc ? 'desc' : 'asc'}
        </Button>
      </div>

      {state.loading && (
        <Card>
          <SkeletonRows rows={8} cols={7} />
        </Card>
      )}
      {state.error && !state.loading && <ErrorState message={state.error} onRetry={state.refetch} />}

      {!state.loading && !state.error && filtered.length === 0 && (
        <EmptyState
          emoji={all.length ? '🧹' : '✨'}
          title={all.length ? 'Nothing matches those filters' : 'No findings — suspiciously clean'}
          description={
            all.length
              ? 'Loosen the filters, or let the eye scan again.'
              : 'Once scans run, findings land here — deduplicated and severity-tagged.'
          }
        />
      )}

      {!state.loading && !state.error && filtered.length > 0 && (
        <>
          <Card>
            <Table>
              <THead>
                <TR>
                  <TH className="w-8">
                    <input
                      type="checkbox"
                      aria-label="Select all on page"
                      checked={allPageSelected}
                      onChange={(e) =>
                        setSelected((s) => {
                          const next = new Set(s);
                          if (e.target.checked) pageIds.forEach((i) => next.add(i));
                          else pageIds.forEach((i) => next.delete(i));
                          return next;
                        })
                      }
                      className="h-4 w-4 accent-accent"
                    />
                  </TH>
                  <TH>Severity</TH>
                  <TH>Title</TH>
                  <TH>Scanner</TH>
                  <TH>Port/Service</TH>
                  <TH>Status</TH>
                  <TH>Last detected</TH>
                </TR>
              </THead>
              <TBody>
                {pageRows.map((f: Finding) => (
                  <TR
                    key={f.id}
                    clickable
                    onClick={() => navigate(`/findings/${f.id}`)}
                  >
                    <TD onClick={(e) => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        aria-label={`Select ${f.title}`}
                        checked={selected.has(f.id)}
                        onChange={(e) =>
                          setSelected((s) => {
                            const next = new Set(s);
                            if (e.target.checked) next.add(f.id);
                            else next.delete(f.id);
                            return next;
                          })
                        }
                        className="h-4 w-4 accent-accent"
                      />
                    </TD>
                    <TD>
                      <SeverityChip severity={f.severity} showScore={f.cvss_score} />
                    </TD>
                    <TD>
                      <Link
                        to={`/findings/${f.id}`}
                        className="line-clamp-1 max-w-md text-[13.5px] font-medium text-ink hover:text-accent-soft"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {f.title}
                      </Link>
                      {f.cves?.length > 0 && (
                        <div className="mt-0.5 flex flex-wrap gap-1">
                          {f.cves.slice(0, 3).map((c) => (
                            <Badge key={c} tone="outline" className="font-mono">
                              {c}
                            </Badge>
                          ))}
                          {f.cves.length > 3 && <Badge tone="outline">+{f.cves.length - 3}</Badge>}
                        </div>
                      )}
                    </TD>
                    <TD className="font-mono text-[12px] text-mute">{f.scanner}</TD>
                    <TD className="font-mono text-[12px] text-mute">
                      {[f.port, f.service, f.protocol].filter((v) => v != null && v !== '').join('/') || '—'}
                    </TD>
                    <TD>
                      <StatusChip status={f.status} kind="finding" />
                    </TD>
                    <TD className="text-[12.5px] text-mute" title={f.last_detected}>
                      {timeAgo(f.last_detected)}
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          </Card>

          {/* pagination */}
          <div className="mt-3 flex items-center justify-between text-[13px] text-mute">
            <span>
              {filtered.length} finding{filtered.length === 1 ? '' : 's'}
              {Object.keys(applyServerFilters).length > 0 && ' (filtered)'} · page {page + 1}/{pageCount}
            </span>
            <div className="flex gap-1">
              <Button variant="secondary" size="sm" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
                ← Prev
              </Button>
              <Button
                variant="secondary"
                size="sm"
                disabled={page >= pageCount - 1}
                onClick={() => setPage((p) => p + 1)}
              >
                Next →
              </Button>
            </div>
          </div>
        </>
      )}

      {/* bulk action bar */}
      {selected.size > 0 && (
        <div className="fixed inset-x-0 bottom-6 z-40 mx-auto w-fit animate-fade-in rounded-2xl border border-line bg-raised/95 px-4 py-2.5 shadow-panel backdrop-blur">
          <div className="flex items-center gap-3 text-[13px]">
            <span className="font-medium text-ink">
              {selected.size} selected
            </span>
            <Button variant="primary" size="sm" onClick={() => setBulkOpen(true)}>
              Change status…
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setSelected(new Set())}>
              Clear
            </Button>
          </div>
        </div>
      )}

      <Dialog
        open={bulkOpen}
        onClose={() => setBulkOpen(false)}
        title={`Update ${selected.size} finding${selected.size === 1 ? '' : 's'}`}
        description="Status transitions are recorded in each finding's history."
        footer={
          <>
            <Button variant="ghost" onClick={() => setBulkOpen(false)}>
              Cancel
            </Button>
            <Button variant="primary" onClick={bulkApply} loading={bulkBusy}>
              Apply
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <div className="space-y-1.5">
            <label className="text-[13px] font-medium text-mute">New status</label>
            <Select value={bulkStatus} onChange={(e) => setBulkStatus(e.target.value)}>
              {FINDING_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {findingStatusMeta(s).emoji} {findingStatusMeta(s).label}
                </option>
              ))}
            </Select>
          </div>
          <div className="space-y-1.5">
            <label className="text-[13px] font-medium text-mute">Note (optional)</label>
            <Textarea
              value={bulkNote}
              onChange={(e) => setBulkNote(e.target.value)}
              placeholder="Why this change? Auditors love context."
            />
          </div>
        </div>
      </Dialog>
    </div>
  );
}
