/**
 * URL and Link Utilities for ShareShield
 * Safely parses and constructs share links: /s/<token>#<keyBase64Url>
 */

export interface ParsedShareLink {
  token: string;
  key?: string;
}

const TOKEN_REGEX = /^[A-Za-z0-9_-]{43}$/;

/**
 * Extracts token and optional decryption key from a user-provided string,
 * URL, or path.
 */
export function parseSecretLink(input: string): ParsedShareLink | null {
  if (!input || typeof input !== 'string') return null;

  const trimmed = input.trim();

  // 1. If it includes a hash fragment
  const [beforeHash, ...hashParts] = trimmed.split('#');
  const keyCandidate = hashParts.join('#').trim();

  // 2. Extract token from beforeHash
  let tokenCandidate = beforeHash || '';

  // Remove protocol and host if present
  if (tokenCandidate.includes('://')) {
    try {
      const url = new URL(tokenCandidate);
      tokenCandidate = url.pathname;
    } catch {
      // Fallback to string stripping
      tokenCandidate = tokenCandidate.replace(/^https?:\/\/[^/]+/i, '');
    }
  }

  // If path is /s/<token>
  const match = tokenCandidate.match(/\/s\/([A-Za-z0-9_-]+)/);
  if (match && match[1]) {
    tokenCandidate = match[1];
  } else {
    // Or plain token
    tokenCandidate = tokenCandidate.replace(/^\/+|\/+$/g, '');
  }

  if (!TOKEN_REGEX.test(tokenCandidate)) {
    return null;
  }

  const result: ParsedShareLink = { token: tokenCandidate };

  if (keyCandidate && TOKEN_REGEX.test(keyCandidate)) {
    result.key = keyCandidate;
  }

  return result;
}

/**
 * Assembles the full share URL with the decryption key in the fragment.
 * URL fragments are client-only and are NEVER transmitted in HTTP requests.
 */
export function buildShareUrl(token: string, keyBase64Url: string): string {
  const origin = window.location.origin;
  return `${origin}/s/${token}#${keyBase64Url}`;
}
