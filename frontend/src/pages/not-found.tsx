import { Link } from 'react-router-dom';
import { WadjetEye } from '@/components/logo';
import { buttonVariants } from '@/components/ui/button';
import { cn } from '@/lib/utils';

export default function NotFoundPage() {
  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center text-center">
      <WadjetEye className="h-20 text-mute/40" title="The eye is closed" />
      <p className="mt-6 font-mono text-[13px] tracking-widest text-mute">ERROR 404</p>
      <h1 className="mt-2 text-2xl font-bold text-ink">The eye sees nothing here</h1>
      <p className="mt-2 max-w-sm text-[13.5px] text-mute">
        This page went dark. Either it never existed, or it's very, very good at hiding.
      </p>
      <div className="mt-6 flex gap-2">
        <Link to="/" className={cn(buttonVariants({ variant: 'primary' }))}>
          👁️ Back to the overview
        </Link>
        <Link to="/projects" className={cn(buttonVariants({ variant: 'secondary' }))}>
          📁 Projects
        </Link>
      </div>
    </div>
  );
}
