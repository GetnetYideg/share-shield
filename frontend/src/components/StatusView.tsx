import React, { useState, useEffect } from 'react';
import { Eye, CheckCircle2, XCircle, ShieldCheck } from 'lucide-react';
import { getSecretStatus, ApiError } from '../lib/api';
import { parseSecretLink } from '../lib/url';

interface StatusViewProps {
  initialLink?: string;
  onNavigateToReveal?: (token: string, key?: string) => void;
}

export const StatusView: React.FC<StatusViewProps> = ({
  initialLink,
  onNavigateToReveal,
}) => {
  const [inputLink, setInputLink] = useState(initialLink || '');
  const [isChecking, setIsChecking] = useState(false);
  const [result, setResult] = useState<{
    checked: boolean;
    available?: boolean;
    expiresAt?: string;
    token?: string;
    key?: string;
    message?: string;
  } | null>(null);

  // If initialLink was supplied, auto-trigger check
  useEffect(() => {
    if (initialLink) {
      setInputLink(initialLink);
      void handleCheck(initialLink);
    }
  }, [initialLink]);

  const handleCheck = async (linkToCheck?: string) => {
    const raw = linkToCheck || inputLink;
    if (!raw.trim()) return;

    const parsed = parseSecretLink(raw);
    if (!parsed) {
      setResult({
        checked: true,
        available: false,
        message: 'Invalid link format. Please provide a valid ShareShield link or 43-character token.',
      });
      return;
    }

    setIsChecking(true);
    setResult(null);

    try {
      const res = await getSecretStatus(parsed.token);
      setResult({
        checked: true,
        available: res.data.available,
        expiresAt: res.data.expiresAt,
        token: parsed.token,
        key: parsed.key,
      });
    } catch (err) {
      let message = 'This secret is unavailable or has already been viewed.';
      if (err instanceof ApiError) {
        message = err.message;
      }
      setResult({
        checked: true,
        available: false,
        message,
        token: parsed.token,
      });
    } finally {
      setIsChecking(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto py-4">
      {/* Header */}
      <div className="mb-6">
        <div className="text-xs font-mono font-bold tracking-subtitle text-accent uppercase mb-2">
          VAULT INSPECTOR
        </div>
        <h2 className="text-2xl font-mono font-bold tracking-hero text-text uppercase">
          CHECK SECRET AVAILABILITY
        </h2>
        <p className="mt-2 text-sm font-sans text-muted">
          Inspect whether a secret token is currently active and unconsumed without revealing its
          contents.
        </p>
      </div>

      {/* Input Form */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void handleCheck();
        }}
        className="rounded-square border border-border bg-panel p-6"
      >
        <label
          htmlFor="status-token-input"
          className="block text-xs font-mono font-bold uppercase tracking-label text-muted mb-2.5"
        >
          SHARE LINK OR TOKEN
        </label>
        <div className="flex flex-col gap-3 sm:flex-row">
          <input
            id="status-token-input"
            type="text"
            value={inputLink}
            onChange={(e) => setInputLink(e.target.value)}
            placeholder="Paste link or token here..."
            autoComplete="off"
            spellCheck="false"
            className="flex-1 rounded-square border border-border/80 bg-surface/90 p-3 font-mono text-sm text-text placeholder:text-dim focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent transition-all"
          />
          <button
            type="submit"
            disabled={isChecking || !inputLink.trim()}
            className="
              flex items-center justify-center gap-2 rounded-square
              border border-accent-border bg-accent-fill px-6 py-3
              text-xs font-mono font-bold uppercase tracking-label text-accent
              hover:border-accent hover:bg-accent-fill/90 transition-all
              disabled:cursor-not-allowed disabled:opacity-40
            "
          >
            {isChecking ? (
              <span className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-accent border-t-transparent" />
            ) : (
              <Eye size={16} strokeWidth={1.8} />
            )}
            CHECK
          </button>
        </div>

        {/* Informational note */}
        <div className="mt-4 flex items-center gap-2 text-xs font-mono text-dim">
          <ShieldCheck size={14} className="text-accent" />
          <span>Status checks are strictly read-only and never consume the secret.</span>
        </div>
      </form>

      {/* Result Cards */}
      {result && result.checked && (
        <div className="mt-6">
          {result.available ? (
            <div className="rounded-square border border-accent-border/60 bg-panel p-6 shadow-glow-sm">
              <div className="flex items-start gap-4">
                <div className="flex h-10 w-10 items-center justify-center rounded-full border border-accent/40 bg-accent/10 text-accent shrink-0">
                  <CheckCircle2 size={20} />
                </div>
                <div className="flex-1">
                  <div className="text-sm font-mono font-bold tracking-label text-accent uppercase">
                    STATUS: AVAILABLE
                  </div>
                  <p className="mt-1 text-sm font-sans text-muted">
                    This secret is unconsumed and ready to be viewed by the recipient.
                  </p>
                  {result.expiresAt && (
                    <div className="mt-3 text-xs font-mono text-dim">
                      EXPIRES AT: {new Date(result.expiresAt).toLocaleString()}
                    </div>
                  )}

                  {onNavigateToReveal && result.token && (
                    <div className="mt-5">
                      <button
                        type="button"
                        onClick={() => onNavigateToReveal(result.token!, result.key)}
                        className="rounded-square border border-accent-border bg-accent-fill px-5 py-2 text-xs font-mono font-bold uppercase tracking-label text-accent hover:border-accent transition-all"
                      >
                        PROCEED TO REVEAL SCREEN
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="rounded-square border border-border bg-panel p-6">
              <div className="flex items-start gap-4">
                <div className="flex h-10 w-10 items-center justify-center rounded-full border border-danger/40 bg-danger/10 text-danger shrink-0">
                  <XCircle size={20} />
                </div>
                <div>
                  <div className="text-sm font-mono font-bold tracking-label text-danger uppercase">
                    STATUS: UNAVAILABLE
                  </div>
                  <p className="mt-1 text-sm font-sans text-muted">
                    {result.message || 'This secret does not exist, has expired, or has already been viewed.'}
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
