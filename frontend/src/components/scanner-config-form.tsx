// Dynamic per-scanner configuration form.
// Controls are AUTO-RENDERED from the scanner manifest's
//   manifest.configuration.options[]
// boolean → toggle · multiselect → chip multi-select · select → dropdown ·
// number → input · string → input.

import { useMemo } from 'react';
import { Input } from '@/components/ui/input';
import { Select } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Chip } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import type { ScannerManifest, ScannerManifestOption, ScannerRecord } from '@/lib/types';

/** Manifest may arrive as an object or as a JSON string — be lenient. */
export function parseManifest(scanner: ScannerRecord | null | undefined): ScannerManifest | null {
  if (!scanner) return null;
  const m = scanner.manifest as unknown;
  if (m && typeof m === 'object') return m as ScannerManifest;
  if (typeof m === 'string') {
    try {
      const parsed = JSON.parse(m);
      if (parsed && typeof parsed === 'object') return parsed as ScannerManifest;
    } catch {
      /* fall through */
    }
  }
  return null;
}

export function manifestOptions(
  scanner: ScannerRecord | null | undefined,
): ScannerManifestOption[] {
  const manifest = parseManifest(scanner);
  const raw = manifest?.configuration?.options;
  if (!Array.isArray(raw)) return [];
  return raw.filter((o): o is ScannerManifestOption => !!o && typeof o.key === 'string');
}

type Choice = { value: string; label: string };

function normalizeChoices(opts?: ScannerManifestOption['options']): Choice[] {
  if (!Array.isArray(opts)) return [];
  return opts.map((o) =>
    typeof o === 'string' ? { value: o, label: o } : { value: o.value, label: o.label ?? o.value },
  );
}

/** Build the default config object from manifest option defaults. */
export function defaultConfig(
  scanner: ScannerRecord | null | undefined,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const o of manifestOptions(scanner)) {
    if (o.default === undefined) continue;
    out[o.key] = o.default;
  }
  return out;
}

function OptionLabel({ option }: { option: ScannerManifestOption }) {
  return (
    <div className="min-w-0">
      <p className="text-[13px] font-medium text-ink">{option.label ?? option.key}</p>
      {option.description && (
        <p className="mt-0.5 text-[12px] leading-snug text-mute">{option.description}</p>
      )}
      {option.description && (
        <p className="mt-0.5 font-mono text-[10.5px] text-mute/50">{option.key}</p>
      )}
    </div>
  );
}

export function ScannerConfigForm({
  scanner,
  value,
  onChange,
  className,
}: {
  scanner: ScannerRecord | null | undefined;
  value: Record<string, unknown>;
  onChange: (next: Record<string, unknown>) => void;
  className?: string;
}) {
  const options = useMemo(() => manifestOptions(scanner), [scanner]);

  if (options.length === 0) {
    return (
      <p className={cn('rounded-lg border border-dashed border-line/70 px-3 py-2 text-[12.5px] text-mute', className)}>
        No configurable options for this scanner.
      </p>
    );
  }

  const set = (key: string, v: unknown) => onChange({ ...value, [key]: v });

  return (
    <div className={cn('space-y-3', className)}>
      {options.map((option) => {
        const current = value[option.key];
        switch (option.type) {
          case 'boolean':
            return (
              <div
                key={option.key}
                className="flex items-center justify-between gap-4 rounded-lg border border-line/70 bg-panel/60 px-3 py-2"
              >
                <OptionLabel option={option} />
                <Switch
                  checked={current === true}
                  onChange={(next) => set(option.key, next)}
                  label={option.label ?? option.key}
                />
              </div>
            );
          case 'multiselect': {
            const choices = normalizeChoices(option.options);
            const selected = Array.isArray(current) ? (current as unknown[]).map(String) : [];
            return (
              <div key={option.key} className="rounded-lg border border-line/70 bg-panel/60 px-3 py-2.5">
                <OptionLabel option={option} />
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {choices.length === 0 && (
                    <span className="text-[12px] text-mute/70">No options declared.</span>
                  )}
                  {choices.map((c) => {
                    const active = selected.includes(c.value);
                    return (
                      <Chip
                        key={c.value}
                        as="button"
                        active={active}
                        title={active ? 'Remove' : 'Add'}
                        onClick={() =>
                          set(
                            option.key,
                            active ? selected.filter((v) => v !== c.value) : [...selected, c.value],
                          )
                        }
                      >
                        {c.label}
                      </Chip>
                    );
                  })}
                </div>
              </div>
            );
          }
          case 'select': {
            const choices = normalizeChoices(option.options);
            return (
              <div key={option.key} className="space-y-1.5">
                <OptionLabel option={option} />
                <Select
                  value={current == null ? '' : String(current)}
                  onChange={(e) => set(option.key, e.target.value === '' ? undefined : e.target.value)}
                  aria-label={option.label ?? option.key}
                >
                  <option value="">(default)</option>
                  {choices.map((c) => (
                    <option key={c.value} value={c.value}>
                      {c.label}
                    </option>
                  ))}
                </Select>
              </div>
            );
          }
          case 'number':
            return (
              <div key={option.key} className="space-y-1.5">
                <OptionLabel option={option} />
                <Input
                  type="number"
                  min={option.min}
                  max={option.max}
                  placeholder={option.placeholder ?? String(option.default ?? '')}
                  value={current == null ? '' : String(current)}
                  onChange={(e) =>
                    set(option.key, e.target.value === '' ? undefined : Number(e.target.value))
                  }
                  aria-label={option.label ?? option.key}
                />
              </div>
            );
          case 'string':
          default:
            return (
              <div key={option.key} className="space-y-1.5">
                <OptionLabel option={option} />
                <Input
                  type="text"
                  placeholder={option.placeholder ?? String(option.default ?? '')}
                  value={current == null ? '' : String(current)}
                  onChange={(e) => set(option.key, e.target.value === '' ? undefined : e.target.value)}
                  aria-label={option.label ?? option.key}
                />
              </div>
            );
        }
      })}
    </div>
  );
}

/** Read-only display of the configuration schema (for the scanners page). */
export function ConfigSchemaView({ scanner }: { scanner: ScannerRecord | null | undefined }) {
  const options = useMemo(() => manifestOptions(scanner), [scanner]);
  if (options.length === 0) {
    return <p className="text-[12.5px] text-mute">No configuration schema declared.</p>;
  }
  return (
    <ul className="space-y-2">
      {options.map((o) => (
        <li key={o.key} className="rounded-lg border border-line/70 bg-panel/50 px-3 py-2">
          <div className="flex items-center gap-2">
            <code className="font-mono text-[12px] text-accent-soft">{o.key}</code>
            <span className="rounded bg-raised px-1.5 py-0.5 font-mono text-[10.5px] text-mute">
              {o.type}
            </span>
            {o.default !== undefined && (
              <span className="text-[11px] text-mute/70">
                default: {JSON.stringify(o.default)}
              </span>
            )}
          </div>
          {o.label && o.label !== o.key && <p className="mt-0.5 text-[12.5px] text-ink/85">{o.label}</p>}
          {o.description && <p className="text-[12px] text-mute">{o.description}</p>}
          {o.options && (
            <div className="mt-1.5 flex flex-wrap gap-1">
              {normalizeChoices(o.options).map((c) => (
                <Chip key={c.value}>{c.label}</Chip>
              ))}
            </div>
          )}
        </li>
      ))}
    </ul>
  );
}
