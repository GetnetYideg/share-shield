import React, { useEffect, useState, useRef } from 'react';
import { Eye, Copy, Check, EyeOff, ShieldAlert, AlertTriangle, Lock } from 'lucide-react';
import { getSecretStatus, consumeSecret, ApiError } from '../lib/api';
import { decryptSecret } from '../lib/crypto';

interface RevealViewProps {
  token: string;
  initialKey?: string;
  onNavigateHome: () => void;
}

export const RevealView: React.FC<RevealViewProps> = ({
  token,
  initialKey,
  onNavigateHome,
}) => {
  const [key, setKey] = useState<string | null>(initialKey || null);
  const [isCheckingStatus, setIsCheckingStatus] = useState(true);
  const [isAvailable, setIsAvailable] = useState(false);
  const [expiresAt, setExpiresAt] = useState<string | null>(null);

  // Consume & Reveal state
  const [isConsuming, setIsConsuming] = useState(false);
  const [revealedPlaintext, setRevealedPlaintext] = useState<string | null>(null);
  const [isBurned, setIsBurned] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Track if fragment was scrubbed
  const hasExtractedHash = useRef(false);

  useEffect(() => {
    // 1. Extract decryption key from URL hash if not passed via props
    if (!hasExtractedHash.current) {
      hasExtractedHash.current = true;
      if (!key && window.location.hash) {
        const hashKey = window.location.hash.substring(1).trim();
        if (hashKey) {
          setKey(hashKey);
        }
        // Immediately remove fragment from URL bar (SRS §6.2)
        try {
          window.history.replaceState(null, '', window.location.pathname);
        } catch {
          // ignore
        }
      }
    }

    // 2. Read-only status check (DO NOT consume on load!)
    let isMounted = true;

    async function checkStatus() {
      setIsCheckingStatus(true);
      setErrorMessage(null);
      try {
        const res = await getSecretStatus(token);
        if (isMounted) {
          setIsAvailable(res.data.available);
          setExpiresAt(res.data.expiresAt);
        }
      } catch (err) {
        if (isMounted) {
          setIsAvailable(false);
          if (err instanceof ApiError) {
            setErrorMessage(err.message);
          } else {
            setErrorMessage('This secret is unavailable or has already been viewed.');
          }
        }
      } finally {
        if (isMounted) {
          setIsCheckingStatus(false);
        }
      }
    }

    void checkStatus();

    return () => {
      isMounted = false;
    };
  }, [token]);

  const handleReveal = async () => {
    if (!key) {
      setErrorMessage('Decryption key is missing from the link fragment.');
      return;
    }

    setIsConsuming(true);
    setErrorMessage(null);

    try {
      // 1. Atomically consume secret on the server
      const consumeRes = await consumeSecret(token);

      // 2. Decrypt locally in browser using Web Crypto
      const plaintext = await decryptSecret(
        consumeRes.data.ciphertext,
        consumeRes.data.iv,
        key
      );

      // 3. Display plaintext and mark secret burned
      setRevealedPlaintext(plaintext);
      setIsBurned(true);
    } catch (err) {
      setIsBurned(true);
      if (err instanceof ApiError) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage('Decryption failed. The secret or key may be corrupted.');
      }
    } finally {
      setIsConsuming(false);
    }
  };

  const handleCopy = async () => {
    if (!revealedPlaintext) return;
    try {
      await navigator.clipboard.writeText(revealedPlaintext);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch {
      // fallback
    }
  };

  const handleHide = () => {
    // Clear plaintext from memory state immediately
    setRevealedPlaintext(null);
  };

  return (
    <div className="max-w-2xl mx-auto py-6">
      {/* Loading state */}
      {isCheckingStatus && (
        <div className="rounded-square border border-border/80 bg-panel p-8 text-center">
          <div className="inline-block h-6 w-6 animate-spin rounded-full border-2 border-accent border-t-transparent mb-4" />
          <div className="text-sm font-mono tracking-widest text-accent uppercase">
            CONNECTING TO VAULT & VERIFYING STATUS...
          </div>
        </div>
      )}

      {/* Unavailable State */}
      {!isCheckingStatus && !isAvailable && !revealedPlaintext && (
        <div className="rounded-square border border-border bg-panel p-8 text-center">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full border border-danger/40 bg-danger/10 text-danger mb-4">
            <ShieldAlert size={28} />
          </div>
          <h2 className="text-xl font-mono font-bold tracking-hero text-text uppercase">
            SECRET UNAVAILABLE
          </h2>
          <p className="mt-3 text-sm font-sans text-muted max-w-md mx-auto">
            {errorMessage || 'This secret is unavailable or has already been viewed.'}
          </p>
          <div className="mt-8">
            <button
              type="button"
              onClick={onNavigateHome}
              className="rounded-square border border-accent-border bg-accent-fill px-6 py-2.5 text-xs font-mono font-bold uppercase tracking-label text-accent hover:border-accent transition-all"
            >
              CREATE NEW SECRET
            </button>
          </div>
        </div>
      )}

      {/* Ready to Reveal State (Status OK, not consumed yet) */}
      {!isCheckingStatus && isAvailable && !revealedPlaintext && (
        <div className="rounded-square border border-border bg-panel p-8">
          <div className="flex items-center gap-4 mb-6">
            <div className="flex h-12 w-12 items-center justify-center rounded-square border border-accent-border/60 bg-accent-fill/40 text-accent">
              <Lock size={22} strokeWidth={1.8} />
            </div>
            <div>
              <div className="text-sm font-mono font-bold tracking-label text-text uppercase">
                ONE-TIME SECRET
              </div>
              <div className="text-[11px] font-mono tracking-widest text-accent uppercase">
                READY TO REVEAL
              </div>
            </div>
          </div>

          <p className="text-sm font-sans text-muted leading-relaxed">
            A one-time secret has been sent to you. Clicking the button below will atomically claim
            the secret and permanently destroy it on the server.
          </p>

          {expiresAt && (
            <div className="mt-4 text-xs font-mono text-dim tracking-wider">
              EXPIRES AT: {new Date(expiresAt).toLocaleString()}
            </div>
          )}

          {!key && (
            <div
              role="alert"
              className="mt-6 flex items-center gap-3 rounded-square border border-danger/40 bg-danger/10 p-3 text-xs font-mono text-danger"
            >
              <AlertTriangle size={16} className="shrink-0" />
              <span>
                Decryption key missing from URL fragment. Please verify you opened the full link.
              </span>
            </div>
          )}

          {errorMessage && (
            <div
              role="alert"
              className="mt-6 flex items-center gap-3 rounded-square border border-danger/40 bg-danger/10 p-3 text-xs font-mono text-danger"
            >
              <AlertTriangle size={16} className="shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}

          <div className="mt-8">
            <button
              type="button"
              onClick={handleReveal}
              disabled={isConsuming || !key}
              className="
                flex w-full items-center justify-center gap-2 rounded-square
                border border-accent-border bg-accent-fill py-3.5 text-xs font-mono font-bold uppercase tracking-label text-accent
                shadow-glow-sm hover:border-accent hover:bg-accent-fill/90 hover:shadow-glow transition-all
                disabled:cursor-not-allowed disabled:opacity-40
              "
            >
              {isConsuming ? (
                <>
                  <span className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-accent border-t-transparent" />
                  CLAIMING & DECRYPTING...
                </>
              ) : (
                <>
                  <Eye size={16} strokeWidth={1.8} />
                  REVEAL SECRET
                </>
              )}
            </button>
          </div>
        </div>
      )}

      {/* Secret Decrypted & Revealed */}
      {revealedPlaintext && (
        <div className="rounded-square border border-accent-border/60 bg-panel p-8 shadow-glow-sm">
          <div className="flex items-center justify-between border-b border-border/60 pb-4 mb-4">
            <div className="text-xs font-mono font-bold uppercase tracking-label text-accent">
              DECRYPTED CONTENT
            </div>
            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={handleCopy}
                className="flex items-center gap-1.5 text-xs font-mono text-accent hover:text-text transition-colors"
              >
                {copied ? <Check size={14} /> : <Copy size={14} />}
                {copied ? 'COPIED!' : 'COPY'}
              </button>
              <button
                type="button"
                onClick={handleHide}
                className="flex items-center gap-1.5 text-xs font-mono text-muted hover:text-danger transition-colors"
              >
                <EyeOff size={14} />
                HIDE
              </button>
            </div>
          </div>

          {/* Plaintext Box (Pure text rendering, NEVER innerHTML) */}
          <div className="rounded-square border border-border/80 bg-surface/90 p-4 font-mono text-sm text-text whitespace-pre-wrap break-words select-text max-h-96 overflow-y-auto">
            {revealedPlaintext}
          </div>

          {/* Burn Notice */}
          <div className="mt-6 flex items-center gap-3 rounded-square border border-danger/30 bg-danger/5 p-3.5 text-xs font-mono text-danger">
            <AlertTriangle size={16} className="shrink-0" />
            <span>This secret is gone. It cannot be opened again.</span>
          </div>

          <div className="mt-6 text-right">
            <button
              type="button"
              onClick={onNavigateHome}
              className="text-xs font-mono text-muted hover:text-text underline tracking-wider"
            >
              Back to Home
            </button>
          </div>
        </div>
      )}

      {/* If hidden after burn */}
      {isBurned && !revealedPlaintext && !isCheckingStatus && (
        <div className="rounded-square border border-border bg-panel p-8 text-center mt-4">
          <p className="text-xs font-mono text-muted">
            The secret has been hidden from memory and permanently burned from the vault.
          </p>
          <div className="mt-4">
            <button
              type="button"
              onClick={onNavigateHome}
              className="rounded-square border border-accent-border bg-accent-fill px-5 py-2 text-xs font-mono text-accent uppercase tracking-label"
            >
              Done
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
