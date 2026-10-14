import React, { useState, useEffect } from 'react';
import { Sidebar, type ActiveTab } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { TabBar } from './components/TabBar';
import { CreateView } from './components/CreateView';
import { StatusView } from './components/StatusView';
import { RevokeView } from './components/RevokeView';
import { RevealView } from './components/RevealView';
import { parseSecretLink } from './lib/url';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ActiveTab>('create');
  const [revealToken, setRevealToken] = useState<string | null>(null);
  const [revealKey, setRevealKey] = useState<string | undefined>(undefined);
  const [statusPreloadLink, setStatusPreloadLink] = useState<string | undefined>(undefined);

  // Parse initial route on load
  useEffect(() => {
    const pathname = window.location.pathname;
    const match = pathname.match(/^\/s\/([A-Za-z0-9_-]+)/);

    if (match && match[1]) {
      const token = match[1];
      let key: string | undefined;

      // Extract key from hash before removing
      if (window.location.hash) {
        key = window.location.hash.substring(1).trim();
      }

      setRevealToken(token);
      setRevealKey(key);
      setActiveTab('reveal');
    }
  }, []);

  const handleSelectTab = (tab: 'create' | 'status' | 'revoke') => {
    setActiveTab(tab);
    // If navigating away from reveal, reset URL to root
    if (activeTab === 'reveal') {
      window.history.pushState(null, '', '/');
    }
  };

  const handleSearchLink = (input: string) => {
    const parsed = parseSecretLink(input);
    if (parsed) {
      // If link contains key fragment, or user wants to check status
      setStatusPreloadLink(input);
      setActiveTab('status');
      if (window.location.pathname !== '/') {
        window.history.pushState(null, '', '/');
      }
    } else {
      setStatusPreloadLink(input);
      setActiveTab('status');
    }
  };

  const handleNavigateToReveal = (token: string, key?: string) => {
    setRevealToken(token);
    setRevealKey(key);
    setActiveTab('reveal');
    window.history.pushState(null, '', `/s/${token}${key ? `#${key}` : ''}`);
  };

  const handleNavigateHome = () => {
    setActiveTab('create');
    setRevealToken(null);
    setRevealKey(undefined);
    window.history.pushState(null, '', '/');
  };

  return (
    <div className="min-h-screen bg-bg text-text flex items-center justify-center p-3 sm:p-6 lg:p-10 pb-28 md:pb-10">
      <div className="flex w-full max-w-7xl items-start gap-6">
        {/* Floating Pill Sidebar */}
        <Sidebar activeTab={activeTab} onSelectTab={handleSelectTab} />

        {/* Main Console Panel */}
        <main
          className="
            flex-1 w-full rounded-panel border border-border bg-panel
            shadow-2xl overflow-hidden flex flex-col min-h-[640px]
          "
        >
          {/* Top Bar with Search & Security Badge */}
          <TopBar onSearchLink={handleSearchLink} />

          {/* Navigation Tab Bar (hidden during secret reveal view) */}
          {activeTab !== 'reveal' ? (
            <TabBar activeTab={activeTab} onSelectTab={handleSelectTab} />
          ) : (
            <div className="flex items-center justify-between border-b border-border/60 bg-tabbar/90 px-6 py-3">
              <span className="text-xs font-mono font-bold tracking-widest text-accent uppercase">
                REVEAL MODE
              </span>
              <button
                type="button"
                onClick={handleNavigateHome}
                className="text-xs font-mono text-muted hover:text-text uppercase tracking-label"
              >
                &larr; Exit to Create
              </button>
            </div>
          )}

          {/* Dynamic Content Views */}
          <div className="p-6 sm:p-8 lg:p-10 flex-1">
            {activeTab === 'create' && <CreateView />}
            {activeTab === 'status' && (
              <StatusView
                initialLink={statusPreloadLink}
                onNavigateToReveal={handleNavigateToReveal}
              />
            )}
            {activeTab === 'revoke' && <RevokeView />}
            {activeTab === 'reveal' && revealToken && (
              <RevealView
                token={revealToken}
                initialKey={revealKey}
                onNavigateHome={handleNavigateHome}
              />
            )}
          </div>
        </main>
      </div>
    </div>
  );
};
