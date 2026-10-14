import React, { useState } from 'react';
import { Link2, Copy, Check, AlertTriangle, ShieldCheck } from 'lucide-react';
import { encryptSecret } from '../lib/crypto';
import { createSecret, ApiError } from '../lib/api';
import { buildShareUrl } from '../lib/url';

const MAX_PLAINTEXT_BYTES = 10240; // 10 KiB

interface ExpiryOption {
  label: string;
  seconds: number;
}

const EXPIRY_OPTIONS: ExpiryOption[] = [
  { label: '10 MIN', seconds: 600 },
  { label: '1 HOUR', seconds: 3600 },
  { label: '24 HOURS', seconds: 86400 },
  { label: '7 DAYS', seconds: 604800 },
];

export const CreateView: React.FC = () => {
  const [plaintext, setPlaintext] = useState('');
  const [selectedExpiry, setSelectedExpiry] = useState<number>(3600); // 1 hour default
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Generated secret state (held in memory only!)
  const [createdShareUrl, setCreatedShareUrl] = useState<string | null>(null);
  const [createdRevokeToken, setCreatedRevokeToken] = useState<string | null>(null);
  const [copiedLink, setCopiedLink] = useState(false);
  const [copiedRevoke, setCopiedRevoke] = useState(false);

  // Calculate live byte size
  const byteCount = new TextEncoder().encode(plaintext).length;
  const isTooLarge = byteCount > MAX_PLAINTEXT_BYTES;

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!plaintext.trim()) {
      setErrorMessage('Please enter secret text before generating a link.');
      return;
    }
    if (isTooLarge) {
      setErrorMessage('Secret text exceeds the maximum 10 KiB limit.');
      return;
    }

    setIsSubmitting(true);
    setErrorMessage(null);

    try {
      // 1. Client-Side WebCrypto AES-256-GCM Encryption
      const encrypted = await encryptSecret(plaintext);

      // 2. Transmit ciphertext and token digest to backend API
      // Decryption key and plaintext NEVER leave the browser!
      await createSecret({
        token: encrypted.token,
        ciphertext: encrypted.ciphertext,
        iv: encrypted.iv,
        expiresInSeconds: selectedExpiry,
        payloadVersion: encrypted.payloadVersion,
        revokeToken: encrypted.revokeToken,
      });

      // 3. Assemble share URL with key in URL fragment
      const fullShareUrl = buildShareUrl(encrypted.token, encrypted.keyBase64Url);

      // 4. Update state and immediately scrub secret from input
      setCreatedShareUrl(fullShareUrl);
      setCreatedRevokeToken(encrypted.revokeToken);
      setPlaintext(''); // Clear plaintext from memory
    } catch (err) {
      if (err instanceof ApiError) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage('Failed to encrypt and store secret. Please try again.');
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCopyLink = async () => {
    if (!createdShareUrl) return;
    try {
      await navigator.clipboard.writeText(createdShareUrl);
      setCopiedLink(true);
      setTimeout(() => setCopiedLink(false), 2500);
    } catch {
      // Fallback
    }
  };

  const handleCopyRevoke = async () => {
    if (!createdRevokeToken) return;
    try {
      await navigator.clipboard.writeText(createdRevokeToken);
      setCopiedRevoke(true);
      setTimeout(() => setCopiedRevoke(false), 2500);
    } catch {
      // Fallback
    }
  };

  return (
    <div className="grid grid-cols-1 gap-10 lg:grid-cols-12">
      {/* Left Column: Form & Explanations */}
      <div className="lg:col-span-7 flex flex-col justify-between">
        <div>
          {/* Overline */}
          <div className="text-xs font-mono font-bold tracking-subtitle text-accent uppercase mb-3">
            NEW SECRET
          </div>

          {/* Hero Headings */}
          <h1 className="text-3xl font-mono font-bold tracking-hero text-text uppercase sm:text-4xl md:text-5xl leading-tight">
            SHARE ONCE.
            <br />
            THEN IT&apos;S GONE.
          </h1>

          {/* Subtitle paragraph */}
          <p className="mt-4 text-base font-sans leading-relaxed text-muted max-w-xl">
            Encrypted in your browser before it leaves. One link, one reveal, then it is
            permanently unavailable.
          </p>

          {/* Error Banner */}
          {errorMessage && (
            <div
              role="alert"
              className="mt-6 flex items-center gap-3 rounded-square border border-danger/40 bg-danger/10 p-4 text-sm font-mono text-danger"
            >
              <AlertTriangle size={18} className="shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}

          {/* Secret Text Area */}
          <form onSubmit={handleCreate} className="mt-8">
            <div className="flex flex-col">
              <label
                htmlFor="secret-text"
                className="text-xs font-mono font-bold uppercase tracking-label text-muted mb-2.5"
              >
                SECRET TEXT
              </label>
              <textarea
                id="secret-text"
                value={plaintext}
                onChange={(e) => setPlaintext(e.target.value)}
                placeholder="Paste a password, API key or note..."
                rows={6}
                autoComplete="off"
                spellCheck="false"
                className={`
                  w-full rounded-square border bg-surface/80 p-4 font-mono text-sm text-text placeholder:text-dim
                  focus:bg-surface focus:outline-none focus:ring-1 transition-all resize-y
                  ${
                    isTooLarge
                      ? 'border-danger focus:border-danger focus:ring-danger'
                      : 'border-border focus:border-accent focus:ring-accent'
                  }
                `}
              />

              {/* Character & Byte Counter */}
              <div className="mt-2 flex items-center justify-between text-xs font-mono tracking-widest text-dim">
                <span>MAX 10 KIB</span>
                <span className={isTooLarge ? 'text-danger font-bold' : ''}>
                  {byteCount} / {MAX_PLAINTEXT_BYTES}
                </span>
              </div>
            </div>

            {/* Expiry Selection */}
            <div className="mt-8">
              <label className="block text-xs font-mono font-bold uppercase tracking-label text-muted mb-2.5">
                EXPIRES IN
              </label>
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                {EXPIRY_OPTIONS.map((opt) => {
                  const isSelected = selectedExpiry === opt.seconds;
                  return (
                    <button
                      key={opt.seconds}
                      type="button"
                      onClick={() => setSelectedExpiry(opt.seconds)}
                      className={`
                        h-12 rounded-square font-mono text-xs font-bold uppercase tracking-widest transition-all focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent
                        ${
                          isSelected
                            ? 'border border-accent text-accent bg-accent-fill/80 shadow-glow-sm'
                            : 'border border-border/80 bg-surface/60 text-muted hover:border-accent-border hover:text-text'
                        }
                      `}
                    >
                      {opt.label}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Submit Button */}
            <div className="mt-8">
              <button
                type="submit"
                disabled={isSubmitting || isTooLarge || !plaintext.trim()}
                className="
                  flex h-13 w-full items-center justify-center rounded-square
                  border border-accent-border bg-accent-fill px-8 py-3.5
                  text-xs font-mono font-bold uppercase tracking-label text-accent
                  shadow-glow-sm transition-all hover:border-accent hover:bg-accent-fill/90 hover:shadow-glow
                  focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent
                  disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:shadow-none
                  sm:w-auto
                "
              >
                {isSubmitting ? (
                  <span className="flex items-center gap-2">
                    <span className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-accent border-t-transparent" />
                    ENCRYPTING IN BROWSER...
                  </span>
                ) : (
                  'ENCRYPT & GENERATE LINK'
                )}
              </button>
            </div>
          </form>
        </div>
      </div>

      {/* Right Column: Share Link & Revoke Card */}
      <div className="lg:col-span-5">
        <div className="rounded-square border border-border/80 bg-panel/80 p-6 md:p-8 backdrop-blur-sm">
          {/* Top Header Box */}
          <div className="flex items-center gap-4 mb-6">
            <div className="flex h-12 w-12 items-center justify-center rounded-square border border-accent-border/60 bg-accent-fill/40 text-accent">
              <Link2 size={22} strokeWidth={1.8} />
            </div>
            <div>
              <div className="text-sm font-mono font-bold tracking-label text-text uppercase">
                SHARE LINK
              </div>
              <div className="text-[11px] font-mono tracking-widest text-accent uppercase">
                SHOWN ONLY ONCE
              </div>
            </div>
          </div>

          {/* Share Link Field */}
          <div className="mb-4">
            <div className="relative">
              <input
                type="text"
                readOnly
                value={createdShareUrl || 'shareshield.app/s/[token]#[key]'}
                className={`
                  w-full rounded-square border p-3 font-mono text-xs tracking-wider
                  focus:outline-none transition-all
                  ${
                    createdShareUrl
                      ? 'border-accent-border/80 bg-surface text-accent select-all'
                      : 'border-border/60 bg-surface/40 text-dim cursor-not-allowed'
                  }
                `}
              />
            </div>
          </div>

          {/* Copy Link Button */}
          <button
            type="button"
            onClick={handleCopyLink}
            disabled={!createdShareUrl}
            className="
              flex w-full items-center justify-center gap-2 rounded-square
              border border-accent-border bg-accent-fill/50 py-3 text-xs font-mono font-bold uppercase tracking-label text-accent
              transition-all hover:border-accent hover:bg-accent-fill hover:shadow-glow-sm
              focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent
              disabled:cursor-not-allowed disabled:opacity-40
            "
          >
            {copiedLink ? (
              <>
                <Check size={16} strokeWidth={2} />
                COPIED TO CLIPBOARD!
              </>
            ) : (
              <>
                <Copy size={16} strokeWidth={1.8} />
                COPY LINK
              </>
            )}
          </button>

          {/* Revoke Token Section */}
          <div className="mt-8">
            <label className="block text-xs font-mono font-bold uppercase tracking-label text-muted mb-2">
              REVOKE TOKEN
            </label>
            <div
              className={`
                rounded-square border border-dashed p-3 font-mono text-xs tracking-widest text-center transition-all
                ${
                  createdRevokeToken
                    ? 'border-danger/70 bg-danger/10 text-danger select-all'
                    : 'border-border/40 bg-surface/30 text-dim'
                }
              `}
            >
              {createdRevokeToken ? (
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate">{createdRevokeToken}</span>
                  <button
                    type="button"
                    onClick={handleCopyRevoke}
                    title="Copy Revoke Token"
                    className="p-1 text-danger hover:text-text transition-colors"
                  >
                    {copiedRevoke ? <Check size={14} /> : <Copy size={14} />}
                  </button>
                </div>
              ) : (
                '[revoke-token]'
              )}
            </div>
          </div>

          {/* Warning / Security Advisory */}
          <p className="mt-6 text-xs font-sans leading-relaxed text-muted">
            Anyone with the full link can open it. Send it over a private channel.
          </p>

          {/* Zero-Knowledge Guarantee Tag */}
          <div className="mt-6 pt-4 border-t border-border/40 flex items-center gap-2 text-[11px] font-mono text-dim">
            <ShieldCheck size={14} className="text-accent" />
            <span>Zero-Knowledge: keys never touch the server</span>
          </div>
        </div>
      </div>
    </div>
  );
};
