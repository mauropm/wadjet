import { cn } from '@/lib/utils';

export function Switch({
  checked,
  onChange,
  disabled,
  label,
  id,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  disabled?: boolean;
  label?: string;
  id?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      id={id}
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={cn(
        'relative inline-flex h-5.5 w-10 shrink-0 items-center rounded-full border transition-colors disabled:opacity-50',
        checked ? 'border-accent/50 bg-accent/80' : 'border-line bg-panel',
      )}
    >
      <span
        className={cn(
          'pointer-events-none inline-block h-4 w-4 translate-x-1 rounded-full bg-ink shadow transition-transform',
          checked && 'translate-x-[1.375rem] bg-base',
        )}
      />
    </button>
  );
}

export function Separator({
  className,
  vertical,
}: {
  className?: string;
  vertical?: boolean;
}) {
  return (
    <div
      role="separator"
      aria-orientation={vertical ? 'vertical' : 'horizontal'}
      className={cn(
        vertical ? 'h-full w-px bg-line' : 'h-px w-full bg-line',
        className,
      )}
    />
  );
}
