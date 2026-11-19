import { cn } from '@/lib/utils';

export function Progress({
  value,
  className,
  indicatorClassName,
  indeterminate,
  label,
}: {
  value?: number; // 0..100
  className?: string;
  indicatorClassName?: string;
  indeterminate?: boolean;
  label?: string;
}) {
  const pct = Math.max(0, Math.min(100, value ?? 0));
  return (
    <div
      role="progressbar"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={indeterminate ? undefined : pct}
      aria-label={label ?? 'progress'}
      className={cn('h-1.5 w-full overflow-hidden rounded-full bg-panel', className)}
    >
      <div
        className={cn(
          'h-full rounded-full bg-accent transition-[width] duration-500',
          indeterminate &&
            'w-1/3 animate-[shimmer_1.2s_ease-in-out_infinite] bg-gradient-to-r from-accent/40 via-accent to-accent/40 bg-[length:300%_100%]',
          indicatorClassName,
        )}
        style={indeterminate ? undefined : { width: `${pct}%` }}
      />
    </div>
  );
}
