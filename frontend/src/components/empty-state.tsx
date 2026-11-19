import { cn } from '@/lib/utils';

/** Empty states with a wink — every list page uses this. */
export function EmptyState({
  emoji = '👁️',
  title,
  description,
  action,
  className,
}: {
  emoji?: string;
  title: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center gap-2 rounded-2xl border border-dashed border-line/80 bg-panel/40 px-6 py-12 text-center',
        className,
      )}
    >
      <div className="text-3xl" aria-hidden>
        {emoji}
      </div>
      <h3 className="text-[15px] font-semibold text-ink">{title}</h3>
      {description && (
        <p className="max-w-sm text-[13px] leading-relaxed text-mute">{description}</p>
      )}
      {action && <div className="mt-3">{action}</div>}
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
  className,
}: {
  message: string;
  onRetry?: () => void;
  className?: string;
}) {
  return (
    <div
      className={cn(
        'flex flex-col items-center gap-2 rounded-2xl border border-sev-critical/25 bg-sev-critical/5 px-6 py-8 text-center',
        className,
      )}
    >
      <div className="text-2xl" aria-hidden>
        😵
      </div>
      <p className="text-sm font-medium text-sev-critical">Something went sideways</p>
      <p className="max-w-md text-[13px] text-mute">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="mt-1 rounded-lg border border-line px-3 py-1 text-[13px] text-ink hover:bg-panel"
        >
          Try again
        </button>
      )}
    </div>
  );
}
