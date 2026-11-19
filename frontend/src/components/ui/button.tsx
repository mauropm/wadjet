import { cva, type VariantProps } from 'class-variance-authority';
import { forwardRef } from 'react';
import { Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';

export const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-xl font-medium transition-colors disabled:pointer-events-none disabled:opacity-50 select-none',
  {
    variants: {
      variant: {
        primary: 'bg-accent text-base hover:bg-accent-soft active:bg-accent-soft/90 font-semibold',
        secondary: 'bg-raised text-ink border border-line hover:bg-line/60 hover:border-line',
        ghost: 'text-mute hover:text-ink hover:bg-raised',
        danger: 'bg-sev-critical/15 text-sev-critical border border-sev-critical/30 hover:bg-sev-critical/25',
        gold: 'bg-gold/15 text-gold border border-gold/30 hover:bg-gold/25',
        outline: 'border border-accent/40 text-accent-soft hover:bg-accent/10',
      },
      size: {
        sm: 'h-8 px-3 text-[13px]',
        md: 'h-9.5 px-4 text-sm',
        lg: 'h-11 px-6 text-[15px]',
        icon: 'h-9 w-9',
        'icon-sm': 'h-7 w-7',
      },
    },
    defaultVariants: { variant: 'secondary', size: 'md' },
  },
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  loading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, loading, disabled, children, ...props }, ref) => (
    <button
      ref={ref}
      className={cn(buttonVariants({ variant, size }), className)}
      disabled={disabled || loading}
      {...props}
    >
      {loading && <Loader2 className="h-4 w-4 animate-spin" aria-hidden />}
      {children}
    </button>
  ),
);
Button.displayName = 'Button';
