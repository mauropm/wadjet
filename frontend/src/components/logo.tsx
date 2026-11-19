import { cn } from '@/lib/utils';

/**
 * Eye of Wadjet — abstract geometric mark built from strokes:
 * teardrop outline + iris circle + pupil + tail stroke + brow.
 * currentColor-driven so it inherits emerald or ink depending on context.
 */
export function WadjetEye({
  className,
  title,
}: {
  className?: string;
  title?: string;
}) {
  return (
    <svg
      viewBox="0 0 64 48"
      fill="none"
      stroke="currentColor"
      strokeWidth={2.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={cn('h-8 w-auto', className)}
      role="img"
      aria-label={title ?? 'WADJET eye logo'}
    >
      {title && <title>{title}</title>}
      {/* brow */}
      <path d="M8 14.5C15 7.5 26 4 33.5 4c8 0 14.5 3.5 19 8.5" opacity={0.55} strokeWidth={2.2} />
      {/* teardrop eye outline */}
      <path d="M6 24C13 13.5 23.5 8 32 8s19 5.5 26 16c-7 10.5-16.5 16-25 16-3.2 0-6.6-.8-9.9-2.3" />
      {/* brow shadow line under outline start */}
      <path d="M6 24c3.6 5.4 8.1 9.7 13 12.6" opacity={0.5} strokeWidth={2.2} />
      {/* iris */}
      <circle cx="32" cy="24" r="8.5" />
      {/* pupil */}
      <circle cx="32" cy="24" r="2.6" fill="currentColor" stroke="none" />
      {/* tail stroke */}
      <path d="M27.5 39.5c-1.5 4-4.5 6.5-9.5 7.5" />
      {/* secondary tail (cosmetic curl hint, abstract) */}
      <path d="M36.5 39.9c-.5 2.6-2 4.8-4.5 6.3" opacity={0.6} strokeWidth={2.2} />
    </svg>
  );
}

/** Wordmark lockup: eye + WADJET, used on login + sidebar. */
export function Wordmark({
  size = 'lg',
  className,
}: {
  size?: 'sm' | 'lg';
  className?: string;
}) {
  return (
    <div className={cn('flex items-center gap-2.5', className)}>
      <WadjetEye
        className={cn('text-accent', size === 'lg' ? 'h-9' : 'h-6')}
        title="WADJET"
      />
      <span
        className={cn(
          'font-bold tracking-[0.22em] text-ink',
          size === 'lg' ? 'text-2xl' : 'text-[15px]',
        )}
      >
        WADJET
      </span>
    </div>
  );
}
