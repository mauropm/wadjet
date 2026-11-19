import { cn } from '@/lib/utils';
import {
  execStatusMeta,
  findingStatusMeta,
  reportStatusMeta,
  scanStatusMeta,
  severityMeta,
} from '@/lib/severity';

export function SeverityChip({
  severity,
  className,
  showScore,
}: {
  severity?: string | null;
  className?: string;
  showScore?: number | null;
}) {
  const m = severityMeta(severity);
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11.5px] font-medium leading-4',
        m.chip,
        className,
      )}
    >
      <span aria-hidden>{m.emoji}</span>
      {m.label}
      {showScore != null && <span className="font-mono opacity-80">{showScore.toFixed(1)}</span>}
    </span>
  );
}

export function StatusChip({
  status,
  kind = 'finding',
  className,
}: {
  status?: string | null;
  kind?: 'finding' | 'scan' | 'execution' | 'report';
  className?: string;
}) {
  const m =
    kind === 'finding'
      ? findingStatusMeta(status)
      : kind === 'scan'
        ? scanStatusMeta(status)
        : kind === 'execution'
          ? execStatusMeta(status)
          : reportStatusMeta(status);
  const live = (status ?? '').toLowerCase() === 'running';
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11.5px] font-medium leading-4',
        m.chip,
        className,
      )}
    >
      <span aria-hidden className={live ? 'animate-pulse-dot' : undefined}>
        {m.emoji || '•'}
      </span>
      {m.label}
    </span>
  );
}

/** Small colored square used in severity snapshot bars/legends. */
export function SeverityDot({ severity, className }: { severity: string; className?: string }) {
  const m = severityMeta(severity);
  return (
    <span
      aria-hidden
      className={cn('inline-block h-2 w-2 rounded-full', m.solid, className)}
    />
  );
}
