import React from 'react';
import { Shield, Lock, Eye, Trash2 } from 'lucide-react';

export type ActiveTab = 'create' | 'status' | 'revoke' | 'reveal';

interface SidebarProps {
  activeTab: ActiveTab;
  onSelectTab: (tab: 'create' | 'status' | 'revoke') => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, onSelectTab }) => {
  return (
    <aside
      aria-label="Navigation Sidebar"
      className="
        fixed bottom-4 left-4 right-4 z-40 flex h-20 items-center justify-around
        rounded-pill border border-border bg-panel px-4 shadow-lg backdrop-blur-md
        md:static md:bottom-auto md:left-auto md:right-auto md:flex md:h-[640px] md:w-[84px] md:flex-col md:justify-between md:py-6
      "
    >
      {/* Top Logo / Shield Icon */}
      <div className="flex flex-col items-center">
        <button
          type="button"
          onClick={() => onSelectTab('create')}
          aria-label="ShareShield Home"
          className="flex h-[52px] w-[52px] items-center justify-center rounded-full border border-accent-border/40 bg-surface text-accent hover:border-accent hover:shadow-glow-sm transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <Shield size={24} strokeWidth={1.8} />
        </button>
        <span className="mt-2 hidden text-[11px] font-mono tracking-widest text-muted md:inline-block">
          SHLD
        </span>
      </div>

      {/* Middle Navigation Buttons */}
      <nav className="flex items-center gap-4 md:flex-col md:gap-5" aria-label="Main Navigation">
        {/* Create Secret Button */}
        <button
          type="button"
          onClick={() => onSelectTab('create')}
          aria-label="Create Secret"
          title="Create Secret"
          className={`
            flex h-[52px] w-[52px] items-center justify-center rounded-full transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent
            ${
              activeTab === 'create'
                ? 'bg-active-circle text-accent shadow-glow-sm border border-accent/40'
                : 'border border-border/60 bg-surface/80 text-muted hover:border-accent-border/80 hover:text-text'
            }
          `}
        >
          <Lock size={22} strokeWidth={1.8} />
        </button>

        {/* Status / Check Secret Button */}
        <button
          type="button"
          onClick={() => onSelectTab('status')}
          aria-label="Check Secret Status"
          title="Check Secret Status"
          className={`
            flex h-[52px] w-[52px] items-center justify-center rounded-full transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent
            ${
              activeTab === 'status' || activeTab === 'reveal'
                ? 'bg-active-circle text-accent shadow-glow-sm border border-accent/40'
                : 'border border-border/60 bg-surface/80 text-muted hover:border-accent-border/80 hover:text-text'
            }
          `}
        >
          <Eye size={22} strokeWidth={1.8} />
        </button>

        {/* Revoke Secret Button */}
        <button
          type="button"
          onClick={() => onSelectTab('revoke')}
          aria-label="Revoke Secret"
          title="Revoke Secret"
          className={`
            flex h-[52px] w-[52px] items-center justify-center rounded-full transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent
            ${
              activeTab === 'revoke'
                ? 'bg-active-circle text-accent shadow-glow-sm border border-accent/40'
                : 'border border-border/60 bg-surface/80 text-muted hover:border-accent-border/80 hover:text-text'
            }
          `}
        >
          <Trash2 size={22} strokeWidth={1.8} />
        </button>
      </nav>

      {/* Bottom spacer for desktop pill alignment */}
      <div className="hidden md:block h-6" />
    </aside>
  );
};
