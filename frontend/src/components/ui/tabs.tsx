import { cn } from '@/lib/utils';

export interface TabDef {
  value: string;
  label: string;
  count?: number;
}

/** Presentational tab bar (controlled). Used standalone or with react-router NavLinks. */
export function Tabs({
  tabs,
  value,
  onChange,
  className,
}: {
  tabs: TabDef[];
  value: string;
  onChange: (value: string) => void;
  className?: string;
}) {
  return (
    <div role="tablist" className={cn('flex gap-1 overflow-x-auto border-b border-line', className)}>
      {tabs.map((t) => (
        <button
          key={t.value}
          role="tab"
          type="button"
          aria-selected={value === t.value}
          onClick={() => onChange(t.value)}
          className={cn(
            'relative whitespace-nowrap rounded-t-lg px-3.5 py-2 text-sm transition-colors',
            value === t.value
              ? 'font-semibold text-ink after:absolute after:inset-x-2 after:-bottom-px after:h-0.5 after:rounded-full after:bg-accent'
              : 'text-mute hover:text-ink',
          )}
        >
          {t.label}
          {t.count !== undefined && (
            <span className="ml-1.5 rounded-full bg-panel px-1.5 py-0.5 text-[11px] text-mute">
              {t.count}
            </span>
          )}
        </button>
      ))}
    </div>
  );
}
