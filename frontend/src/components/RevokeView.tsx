import React, { useState } from 'react';
import { Trash2, CheckCircle2, AlertTriangle } from 'lucide-react';
import { revokeSecret, ApiError } from '../lib/api';
import { parseSecretLink } from '../lib/url';

export const RevokeView: React.FC = () => {
  const [linkInput, setLinkInput] = useState('');
  const [revokeTokenInput, setRevokeTokenInput] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [statusMessage, setStatusMessage] = useState<{
    success: boolean;
    text: string;
  } | null>(null);

  const handleRevoke = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!linkInput.trim() || !revokeTokenInput.trim()) {
      setStatusMessage({
        success: false,
        text: 'Both the share link/token and revoke token are required.',
      });
      return;
    }

    const parsed = parseSecretLink(linkInput);
    if (!parsed) {
      setStatusMessage({
        success: false,
        text: 'Invalid link or token format. Please check the value.',
      });
      return;
    }

    setIsSubmitting(true);
    setStatusMessage(null);

    try {
      await revokeSecret(parsed.token, revokeTokenInput.trim());
      setStatusMessage({
        success: true,
        text: 'Secret has been permanently revoked and wiped from the vault.',
      });
      setLinkInput('');
      setRevokeTokenInput('');
    } catch (err) {
      let text = 'Failed to revoke secret. Please check your credentials.';
      if (err instanceof ApiError) {
        text = err.message;
      }
      setStatusMessage({
        success: false,
        text,
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto py-4">
      {/* Header */}
      <div className="mb-6">
        <div className="text-xs font-mono font-bold tracking-subtitle text-danger uppercase mb-2">
          CREATOR CAPABILITY
        </div>
        <h2 className="text-2xl font-mono font-bold tracking-hero text-text uppercase">
          REVOKE A SECRET
        </h2>
        <p className="mt-2 text-sm font-sans text-muted">
          Destroy an active secret before the recipient opens it. Requires the high-entropy revoke
          token provided during creation.
        </p>
      </div>

      {/* Form */}
      <form onSubmit={handleRevoke} className="rounded-square border border-border bg-panel p-6">
        {/* Share Link or Token */}
        <div className="mb-5">
          <label
            htmlFor="revoke-link-input"
            className="block text-xs font-mono font-bold uppercase tracking-label text-muted mb-2.5"
          >
            SHARE LINK OR TOKEN
          </label>
          <input
            id="revoke-link-input"
            type="text"
            value={linkInput}
            onChange={(e) => setLinkInput(e.target.value)}
            placeholder="Paste share link or token..."
            autoComplete="off"
            spellCheck="false"
            className="w-full rounded-square border border-border/80 bg-surface/90 p-3 font-mono text-sm text-text placeholder:text-dim focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent transition-all"
          />
        </div>

        {/* Revoke Token */}
        <div className="mb-6">
          <label
            htmlFor="revoke-token-input"
            className="block text-xs font-mono font-bold uppercase tracking-label text-muted mb-2.5"
          >
            CREATOR REVOKE TOKEN
          </label>
          <input
            id="revoke-token-input"
            type="text"
            value={revokeTokenInput}
            onChange={(e) => setRevokeTokenInput(e.target.value)}
            placeholder="Paste 43-character revoke token..."
            autoComplete="off"
            spellCheck="false"
            className="w-full rounded-square border border-border/80 bg-surface/90 p-3 font-mono text-sm text-danger placeholder:text-dim focus:border-danger focus:outline-none focus:ring-1 focus:ring-danger transition-all"
          />
        </div>

        {/* Submit Button */}
        <div>
          <button
            type="submit"
            disabled={isSubmitting || !linkInput.trim() || !revokeTokenInput.trim()}
            className="
              flex items-center justify-center gap-2 rounded-square
              border border-danger/80 bg-danger/10 px-8 py-3.5
              text-xs font-mono font-bold uppercase tracking-label text-danger
              hover:border-danger hover:bg-danger/20 transition-all
              disabled:cursor-not-allowed disabled:opacity-40
            "
          >
            {isSubmitting ? (
              <span className="flex items-center gap-2">
                <span className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-danger border-t-transparent" />
                REVOKING...
              </span>
            ) : (
              <>
                <Trash2 size={16} strokeWidth={1.8} />
                REVOKE PERMANENTLY
              </>
            )}
          </button>
        </div>
      </form>

      {/* Status Feedback */}
      {statusMessage && (
        <div className="mt-6">
          {statusMessage.success ? (
            <div className="rounded-square border border-accent-border/60 bg-panel p-6 shadow-glow-sm">
              <div className="flex items-start gap-4">
                <div className="flex h-10 w-10 items-center justify-center rounded-full border border-accent/40 bg-accent/10 text-accent shrink-0">
                  <CheckCircle2 size={20} />
                </div>
                <div>
                  <div className="text-sm font-mono font-bold tracking-label text-accent uppercase">
                    REVOCATION SUCCESSFUL
                  </div>
                  <p className="mt-1 text-sm font-sans text-muted">
                    {statusMessage.text}
                  </p>
                </div>
              </div>
            </div>
          ) : (
            <div className="rounded-square border border-danger/40 bg-panel p-6">
              <div className="flex items-start gap-4">
                <div className="flex h-10 w-10 items-center justify-center rounded-full border border-danger/40 bg-danger/10 text-danger shrink-0">
                  <AlertTriangle size={20} />
                </div>
                <div>
                  <div className="text-sm font-mono font-bold tracking-label text-danger uppercase">
                    REVOCATION REJECTED
                  </div>
                  <p className="mt-1 text-sm font-sans text-muted">
                    {statusMessage.text}
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
