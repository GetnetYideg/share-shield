import React from 'react';
import type { ActiveTab } from './Sidebar';

interface TabBarProps {
  activeTab: ActiveTab;
  onSelectTab: (tab: 'create' | 'status' | 'revoke') => void;
}

export const TabBar: React.FC<TabBarProps> = ({ activeTab, onSelectTab }) => {
  const tabs = [
    { id: 'create', label: 'CREATE' },
    { id: 'status', label: 'STATUS' },
    { id: 'revoke', label: 'REVOKE' },
  ] as const;

  return (
    <nav
      className="flex border-b border-border/60 bg-tabbar/90 px-6"
      aria-label="Secret Management Modes"
    >
      <div className="flex gap-8">
        {tabs.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => onSelectTab(tab.id)}
              className={`
                relative py-4 text-xs font-mono font-bold uppercase tracking-label transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent
                ${isActive ? 'text-accent' : 'text-muted hover:text-text'}
              `}
            >
              {tab.label}
              {isActive && (
                <span
                  className="absolute bottom-0 left-0 right-0 h-[2px] bg-accent shadow-glow-sm"
                  aria-hidden="true"
                />
              )}
            </button>
          );
        })}
      </div>
    </nav>
  );
};
