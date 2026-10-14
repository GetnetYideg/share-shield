import React, { useState } from 'react';
import { Search } from 'lucide-react';

interface TopBarProps {
  onSearchLink: (link: string) => void;
}

export const TopBar: React.FC<TopBarProps> = ({ onSearchLink }) => {
  const [searchInput, setSearchInput] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchInput.trim()) {
      onSearchLink(searchInput.trim());
      setSearchInput('');
    }
  };

  return (
    <header className="flex flex-col gap-4 border-b border-border/80 px-6 py-4 md:flex-row md:items-center md:justify-between grid-texture">
      {/* Search Input Bar */}
      <form onSubmit={handleSubmit} className="relative flex-1 max-w-md">
        <label htmlFor="search-input" className="sr-only">
          Paste a link to check availability
        </label>
        <div className="relative flex items-center">
          <Search
            size={18}
            strokeWidth={1.8}
            className="absolute left-4 text-muted pointer-events-none"
            aria-hidden="true"
          />
          <input
            id="search-input"
            type="text"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Paste a link to check_"
            autoComplete="off"
            spellCheck="false"
            className="
              w-full rounded-full border border-border/80 bg-surface/90 py-2.5 pl-11 pr-4
              text-sm font-mono text-text placeholder:text-dim
              focus:border-accent focus:bg-surface focus:outline-none focus:ring-1 focus:ring-accent
              transition-all
            "
          />
        </div>
      </form>

      {/* Right Security & User Badges */}
      <div className="flex items-center justify-between gap-6 md:justify-end">
        {/* TLS SECURE indicator */}
        <div className="flex items-center gap-2">
          <span className="relative flex h-2 w-2" aria-hidden="true">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-accent opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-accent shadow-glow-sm"></span>
          </span>
          <span className="text-xs font-mono font-bold tracking-widest text-accent">
            TLS SECURE
          </span>
        </div>

        {/* User Identity Indicator */}
        <div className="text-right">
          <div className="text-sm font-mono font-bold text-text tracking-wide">
            Anonymous
          </div>
          <div className="text-[10px] font-mono tracking-widest text-muted uppercase">
            CREATOR
          </div>
        </div>
      </div>
    </header>
  );
};
