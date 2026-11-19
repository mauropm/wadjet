import { forwardRef, useId } from 'react';
import { cn } from '@/lib/utils';

const fieldBase =
  'w-full rounded-xl border border-line bg-panel px-3 text-sm text-ink placeholder:text-mute/60 ' +
  'transition-colors hover:border-mute/30 focus:border-accent/60 focus:outline-none ' +
  'focus-visible:ring-2 focus-visible:ring-accent/50 focus-visible:ring-offset-0 ' +
  'disabled:opacity-50 aria-[invalid=true]:border-sev-critical/60';

export const Input = forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input ref={ref} className={cn(fieldBase, 'h-9.5', className)} {...props} />
  ),
);
Input.displayName = 'Input';

export const Textarea = forwardRef<
  HTMLTextAreaElement,
  React.TextareaHTMLAttributes<HTMLTextAreaElement>
>(({ className, rows = 3, ...props }, ref) => (
  <textarea
    ref={ref}
    rows={rows}
    className={cn(fieldBase, 'py-2 leading-relaxed', className)}
    {...props}
  />
));
Textarea.displayName = 'Textarea';

export const Select = forwardRef<HTMLSelectElement, React.SelectHTMLAttributes<HTMLSelectElement>>(
  ({ className, children, ...props }, ref) => (
    <select
      ref={ref}
      className={cn(
        fieldBase,
        'h-9.5 appearance-none bg-[url("data:image/svg+xml;charset=utf-8,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22%20width%3D%2212%22%20height%3D%2212%22%20viewBox%3D%220%200%2024%2024%22%20fill%3D%22none%22%20stroke%3D%22%239BA8A0%22%20stroke-width%3D%222.5%22%20stroke-linecap%3D%22round%22%20stroke-linejoin%3D%22round%22%3E%3Cpath%20d%3D%22m6%209%206%206%206-6%22%2F%3E%3C%2Fsvg%3E")] bg-[length:12px] bg-[right_0.75rem_center] bg-no-repeat pr-8',
        className,
      )}
      {...props}
    >
      {children}
    </select>
  ),
);
Select.displayName = 'Select';

export interface LabelProps extends React.LabelHTMLAttributes<HTMLLabelElement> {
  required?: boolean;
  hint?: string;
}

export const Label = forwardRef<HTMLLabelElement, LabelProps>(
  ({ className, children, required, hint, htmlFor, ...props }, ref) => {
    const autoId = useId();
    return (
      <label
        ref={ref}
        htmlFor={htmlFor ?? autoId}
        className={cn('block text-[13px] font-medium text-mute', className)}
        {...props}
      >
        {children}
        {required && <span className="ml-0.5 text-sev-critical" aria-hidden>*</span>}
        {hint && <span className="ml-1.5 text-xs text-mute/60">{hint}</span>}
      </label>
    );
  },
);
Label.displayName = 'Label';

/** A form row: label + control + optional error text, wired for a11y (implicit label association). */
export function Field({
  label,
  required,
  hint,
  error,
  children,
  className,
}: {
  label: string;
  required?: boolean;
  hint?: string;
  error?: string | null;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <label className={cn('block space-y-1.5', className)}>
      <span className="block text-[13px] font-medium text-mute">
        {label}
        {required && <span className="ml-0.5 text-sev-critical" aria-hidden>*</span>}
        {hint && <span className="ml-1.5 text-xs text-mute/60">{hint}</span>}
      </span>
      {children}
      {error && (
        <p role="alert" className="text-xs text-sev-critical">
          {error}
        </p>
      )}
    </label>
  );
}
