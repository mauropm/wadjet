import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/lib/utils';

export const badgeVariants = cva(
  'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11.5px] font-medium leading-4 whitespace-nowrap',
  {
    variants: {
      tone: {
        neutral: 'border-line bg-raised text-mute',
        accent: 'border-accent/30 bg-accent/10 text-accent-soft',
        gold: 'border-gold/30 bg-gold/10 text-gold',
        danger: 'border-sev-critical/30 bg-sev-critical/10 text-sev-critical',
        outline: 'border-line bg-transparent text-mute',
      },
    },
    defaultVariants: { tone: 'neutral' },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, tone, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}

/** Raw chip for arbitrary tokens (tags, CVEs, capabilities…). */
export function Chip({
  children,
  className,
  onClick,
  active,
  as = 'span',
  title,
}: {
  children: React.ReactNode;
  className?: string;
  onClick?: () => void;
  active?: boolean;
  as?: 'span' | 'button';
  title?: string;
}) {
  const cls = cn(
    'inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-[11px] transition-colors',
    active
      ? 'border-accent/50 bg-accent/15 text-accent-soft'
      : 'border-line bg-panel text-mute',
    onClick && 'cursor-pointer hover:border-accent/40 hover:text-ink',
    className,
  );
  if (as === 'button') {
    return (
      <button type="button" onClick={onClick} className={cls} title={title} aria-pressed={active}>
        {children}
      </button>
    );
  }
  return (
    <span className={cls} title={title}>
      {children}
    </span>
  );
}
