import { useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { Eye, LogOut, Menu, ScanSearch, Settings2, ShieldCheck } from 'lucide-react';
import { Wordmark } from '@/components/logo';
import { Button } from '@/components/ui/button';
import { Sheet } from '@/components/ui/sheet';
import { useAuth } from '@/lib/auth';
import { cn } from '@/lib/utils';

export const NAV_ITEMS = [
  { to: '/', label: '👁️ Overview', icon: Eye, end: true },
  { to: '/projects', label: '📁 Projects', icon: ShieldCheck, end: false },
  { to: '/scanners', label: '🔎 Scanners', icon: ScanSearch, end: false },
  { to: '/settings', label: '⚙️ Settings', icon: Settings2, end: false },
];

function NavList({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav aria-label="Primary" className="flex flex-col gap-0.5">
      {NAV_ITEMS.map(({ to, label, end }) => (
        <NavLink
          key={to}
          to={to}
          end={end}
          onClick={onNavigate}
          className={({ isActive }) =>
            cn(
              'rounded-xl px-3 py-2 text-[13.5px] transition-colors',
              isActive
                ? 'bg-accent/10 font-semibold text-accent-soft'
                : 'text-mute hover:bg-panel hover:text-ink',
            )
          }
        >
          {label}
        </NavLink>
      ))}
    </nav>
  );
}

function SidebarFooter() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  return (
    <div className="border-t border-line p-3">
      <div className="mb-2 flex items-center gap-2 px-2">
        <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-accent/15 text-xs font-bold text-accent-soft">
          {(user?.name || user?.email || '?').slice(0, 1).toUpperCase()}
        </div>
        <div className="min-w-0">
          <p className="truncate text-[13px] font-medium text-ink">{user?.name || 'Signed in'}</p>
          <p className="truncate text-[11px] text-mute">{user?.email}</p>
        </div>
      </div>
      <Button
        variant="ghost"
        size="sm"
        className="w-full justify-start"
        onClick={async () => {
          await logout();
          navigate('/login');
        }}
      >
        <LogOut className="h-3.5 w-3.5" /> Sign out
      </Button>
    </div>
  );
}

export function AppShell() {
  const [mobileNav, setMobileNav] = useState(false);

  return (
    <div className="flex min-h-screen bg-base">
      {/* Desktop sidebar */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-60 flex-col border-r border-line bg-panel lg:flex">
        <div className="px-5 pb-4 pt-6">
          <Wordmark size="sm" />
          <p className="mt-1.5 pl-[34px] text-[10.5px] font-medium uppercase tracking-widest text-mute/70">
            👁️ sees what hides
          </p>
        </div>
        <div className="flex-1 overflow-y-auto px-3">
          <NavList />
        </div>
        <SidebarFooter />
      </aside>

      {/* Mobile top bar */}
      <header className="fixed inset-x-0 top-0 z-30 flex h-14 items-center justify-between border-b border-line bg-panel/95 px-4 backdrop-blur lg:hidden">
        <Wordmark size="sm" />
        <Button variant="ghost" size="icon" onClick={() => setMobileNav(true)} aria-label="Open navigation">
          <Menu className="h-5 w-5" />
        </Button>
      </header>

      <Sheet open={mobileNav} onClose={() => setMobileNav(false)} title="WADJET" width="max-w-xs">
        <NavList onNavigate={() => setMobileNav(false)} />
      </Sheet>

      <main className="min-w-0 flex-1 pt-14 lg:pl-60 lg:pt-0">
        <div className="mx-auto w-full max-w-[1400px] px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}

export function PageHeader({
  emoji,
  title,
  description,
  actions,
  children,
}: {
  emoji?: string;
  title: string;
  description?: string;
  actions?: React.ReactNode;
  children?: React.ReactNode;
}) {
  return (
    <div className="mb-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="flex items-center gap-2 text-xl font-bold tracking-tight text-ink">
            {emoji && <span aria-hidden>{emoji}</span>}
            {title}
          </h1>
          {description && <p className="mt-1 text-[13.5px] text-mute">{description}</p>}
        </div>
        {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
      </div>
      {children}
    </div>
  );
}
