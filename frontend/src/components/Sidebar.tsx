import React from 'react';
import { Shield, Lock, Eye, Trash2 } from 'lucide-react';

export type ActiveTab = 'create' | 'status' | 'revoke' | 'reveal';

interface SidebarProps {
  activeTab: ActiveTab;
  onSelectTab: (tab: 'create' | 'status' | 'revoke') => void;
}

interface NavItem {
  id: 'create' | 'status' | 'revoke';
  label: string;
  ariaLabel: string;
  icon: React.ComponentType<{ size?: number; strokeWidth?: number; className?: string }>;
}

const NAV_ITEMS: NavItem[] = [
  {
    id: 'create',
    label: 'CREATE',
    ariaLabel: 'Create Secret',
    icon: Lock,
  },
  {
    id: 'status',
    label: 'STATUS',
    ariaLabel: 'Check Secret Status',
    icon: Eye,
  },
  {
    id: 'revoke',
    label: 'REVOKE',
    ariaLabel: 'Revoke Secret',
    icon: Trash2,
  },
];

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, onSelectTab }) => {
  return (
    <aside
      aria-label="Navigation Sidebar"
      className="
        fixed bottom-3 left-3 right-3 z-40 flex h-16 items-center justify-around
        rounded-pill border border-border bg-panel px-3 shadow-lg backdrop-blur-md
        md:sticky md:top-3 md:bottom-auto md:left-auto md:right-auto md:flex md:h-[640px] md:w-[72px] md:flex-col md:justify-between md:py-6 md:px-0 md:shrink-0
      "
    >
      {/* Top Logo / Shield Icon */}
      <div className="relative group flex flex-col items-center">
        <button
          type="button"
          onClick={() => onSelectTab('create')}
          aria-label="ShareShield Home"
          className="flex h-11 w-11 items-center justify-center rounded-full border border-accent-border/40 bg-surface text-accent hover:border-accent hover:shadow-glow-sm transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <Shield size={20} strokeWidth={1.8} />
        </button>

        {/* Desktop Tooltip on Hover */}
        <div
          role="tooltip"
          className="
            pointer-events-none absolute left-full ml-3.5 top-1/2 -translate-y-1/2 hidden md:group-hover:flex items-center z-50
            rounded-square border border-accent-border/90 bg-panel px-2.5 py-1
            text-[11px] font-mono font-bold uppercase tracking-widest text-accent
            shadow-glow-sm backdrop-blur-md whitespace-nowrap
          "
        >
          <div className="absolute -left-1 top-1/2 -translate-y-1/2 w-2 h-2 rotate-45 border-l border-b border-accent-border/90 bg-panel" />
          <span>HOME</span>
        </div>

        {/* Mobile Tooltip on Hover */}
        <div
          role="tooltip"
          className="
            pointer-events-none absolute bottom-full mb-2 left-1/2 -translate-x-1/2 hidden group-hover:flex md:hidden items-center z-50
            rounded-square border border-accent-border/90 bg-panel px-2 py-0.5
            text-[10px] font-mono font-bold uppercase tracking-widest text-accent
            shadow-glow-sm whitespace-nowrap
          "
        >
          <span>HOME</span>
        </div>

        <span className="mt-1.5 hidden text-[10px] font-mono tracking-widest text-muted md:inline-block">
          SHLD
        </span>
      </div>

      {/* Middle Navigation Buttons */}
      <nav className="flex items-center gap-3 md:flex-col md:gap-5" aria-label="Main Navigation">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          const isActive =
            activeTab === item.id || (item.id === 'status' && activeTab === 'reveal');

          return (
            <div key={item.id} className="relative group flex items-center justify-center">
              <button
                type="button"
                onClick={() => onSelectTab(item.id)}
                aria-label={item.ariaLabel}
                className={`
                  flex h-11 w-11 items-center justify-center rounded-full transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent
                  ${
                    isActive
                      ? 'bg-active-circle text-accent shadow-glow-sm border border-accent/50'
                      : 'border border-border/60 bg-surface/80 text-muted hover:border-accent-border/80 hover:text-text hover:bg-surface'
                  }
                `}
              >
                <Icon size={18} strokeWidth={1.8} />
              </button>

              {/* Desktop Tooltip on Hover */}
              <div
                role="tooltip"
                className="
                  pointer-events-none absolute left-full ml-3.5 top-1/2 -translate-y-1/2 hidden md:group-hover:flex items-center z-50
                  rounded-square border border-accent-border/90 bg-panel px-2.5 py-1
                  text-[11px] font-mono font-bold uppercase tracking-widest text-accent
                  shadow-glow-sm backdrop-blur-md whitespace-nowrap
                "
              >
                <div className="absolute -left-1 top-1/2 -translate-y-1/2 w-2 h-2 rotate-45 border-l border-b border-accent-border/90 bg-panel" />
                <span>{item.label}</span>
              </div>

              {/* Mobile Tooltip on Hover */}
              <div
                role="tooltip"
                className="
                  pointer-events-none absolute bottom-full mb-2 left-1/2 -translate-x-1/2 hidden group-hover:flex md:hidden items-center z-50
                  rounded-square border border-accent-border/90 bg-panel px-2 py-0.5
                  text-[10px] font-mono font-bold uppercase tracking-widest text-accent
                  shadow-glow-sm whitespace-nowrap
                "
              >
                <span>{item.label}</span>
              </div>
            </div>
          );
        })}
      </nav>

      {/* Bottom spacer for desktop pill alignment */}
      <div className="hidden md:block h-6" />
    </aside>
  );
};
