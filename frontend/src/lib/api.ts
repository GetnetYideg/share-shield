/**
 * API Client for ShareShield Backend (REST JSON over HTTPS)
 * Matches Api_Reference.md and docs/CLIENT_CRYPTO_CONTRACT.md.
 */

export interface CreateSecretRequest {
  token: string;
  ciphertext: string;
  iv: string;
  expiresInSeconds: number;
  payloadVersion: number;
  revokeToken: string;
}

export interface CreateSecretResponse {
  data: {
    created: boolean;
    expiresAt: string;
    passkey: string;
  };
  requestId: string;
}

export interface SecretStatusResponse {
  data: {
    available: boolean;
    expiresAt: string;
    passkeyRequired?: boolean;
  };
  requestId: string;
}

export interface ConsumeSecretResponse {
  data: {
    ciphertext: string;
    iv: string;
    payloadVersion: number;
  };
  requestId: string;
}

export interface ApiErrorDetail {
  code: string;
  message: string;
  status: number;
  retryAfterSeconds?: number;
  attemptsRemaining?: number;
}

export class ApiError extends Error {
  public readonly code: string;
  public readonly status: number;
  public readonly retryAfterSeconds?: number;
  public readonly attemptsRemaining?: number;

  constructor(detail: ApiErrorDetail) {
    super(detail.message);
    this.name = 'ApiError';
    this.code = detail.code;
    this.status = detail.status;
    this.retryAfterSeconds = detail.retryAfterSeconds;
    this.attemptsRemaining = detail.attemptsRemaining;
  }
}

/**
 * Resolves the API base URL.
 * - VITE_API_URL unset  -> '/api/v1' (same-origin, e.g. Vite dev proxy)
 * - VITE_API_URL set    -> that origin/path, with '/api/v1' appended if missing
 */
export function getApiBaseUrl(): string {
  const envUrl = import.meta.env.VITE_API_URL;
  const raw =
    typeof envUrl === 'string' && envUrl.trim() !== ''
      ? envUrl.trim().replace(/\/+$/, '')
      : '/api/v1';

  return raw.endsWith('/api/v1') ? raw : `${raw}/api/v1`;
}

const API_BASE_URL = getApiBaseUrl();

// Free hosts (e.g. Render) can take ~1 minute to wake from sleep.
const REQUEST_TIMEOUT_MS = 90_000;

const NETWORK_ERROR_MESSAGE =
  'Network connection failed. Please check your connectivity, CORS configuration, or API URL.';

interface HandleOptions {
  /** Accept successful responses that have no JSON body (e.g. revoke). */
  allowEmpty?: boolean;
}

async function handleResponse<T>(res: Response, options: HandleOptions = {}): Promise<T> {
  if (res.status === 204) {
    return {} as T;
  }

  const contentType = res.headers.get('content-type') || '';
  const isJson = contentType.includes('application/json');

  if (!res.ok) {
    let errorCode = 'REQUEST_FAILED';
    let errorMessage = 'An unexpected error occurred.';
    let attemptsRemaining: number | undefined;

    if (isJson) {
      try {
        const errorJson = (await res.json()) as {
          error?: { code?: string; message?: string; attemptsRemaining?: number };
        };
        if (errorJson.error) {
          errorCode = errorJson.error.code || errorCode;
          errorMessage = errorJson.error.message || errorMessage;
          if (typeof errorJson.error.attemptsRemaining === 'number') {
            attemptsRemaining = errorJson.error.attemptsRemaining;
          }
        }
      } catch {
        // Fall back to the generic message below
      }
    }

    // Only readable cross-origin if the backend sends Access-Control-Expose-Headers: Retry-After
    let retryAfterSeconds: number | undefined;
    const retryHeader = res.headers.get('retry-after');
    if (retryHeader) {
      const parsed = parseInt(retryHeader, 10);
      if (!isNaN(parsed) && parsed > 0) {
        retryAfterSeconds = parsed;
      }
    }

    if (res.status === 429) {
      const waitText = retryAfterSeconds ? ` Please wait ${retryAfterSeconds}s.` : '';
      errorMessage = `Rate limit exceeded.${waitText}`;
    } else if (res.status === 404) {
      errorMessage = 'This secret is unavailable or has already been viewed.';
    } else if (res.status === 403 || res.status === 401) {
      if (errorCode === 'PASSKEY_INVALID') {
        if (attemptsRemaining === 0) {
          errorMessage = 'Too many incorrect attempts. This secret has been destroyed.';
        } else if (typeof attemptsRemaining === 'number') {
          errorMessage = `Incorrect passkey. ${attemptsRemaining} attempts remaining.`;
        } else {
          errorMessage = 'Incorrect passkey.';
        }
      } else {
        errorMessage = 'Invalid revoke token.';
      }
    } else if (res.status === 400) {
      errorMessage = 'Invalid token or parameters.';
    } else if (res.status === 413) {
      errorMessage = 'The secret is too large.';
    } else if (res.status >= 500) {
      errorMessage = 'The server had a problem. Please try again shortly.';
    }

    throw new ApiError({
      code: errorCode,
      message: errorMessage,
      status: res.status,
      retryAfterSeconds,
      attemptsRemaining,
    });
  }

  if (!isJson) {
    if (options.allowEmpty) {
      return {} as T;
    }
    throw new ApiError({
      code: 'UNEXPECTED_RESPONSE',
      message: 'Server returned a non-JSON response.',
      status: res.status,
    });
  }

  return (await res.json()) as T;
}

/**
 * Shared request helper: timeout, no cookies, no caching, no referrer, uniform errors.
 */
async function request<T>(
  path: string,
  init: RequestInit,
  options: HandleOptions = {}
): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const res = await fetch(`${API_BASE_URL}${path}`, {
      ...init,
      headers: {
        Accept: 'application/json',
        ...(init.headers as Record<string, string> | undefined),
      },
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      signal: controller.signal,
    });
    return await handleResponse<T>(res, options);
  } catch (err) {
    if (err instanceof ApiError) throw err;

    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new ApiError({
        code: 'TIMEOUT',
        message: 'The server took too long to respond. It may be waking up, so please try again.',
        status: 0,
      });
    }

    // Log only the error type: never the URL, token, or payload.
    console.error('[ShareShield API Error]', err instanceof Error ? err.name : 'unknown');
    throw new ApiError({
      code: 'NETWORK_ERROR',
      message: NETWORK_ERROR_MESSAGE,
      status: 0,
    });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Creates an encrypted secret record on the server.
 */
export function createSecret(payload: CreateSecretRequest): Promise<CreateSecretResponse> {
  return request<CreateSecretResponse>('/secrets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
}

/**
 * Checks secret availability without consuming it (read-only).
 */
export function getSecretStatus(token: string): Promise<SecretStatusResponse> {
  return request<SecretStatusResponse>(`/secrets/${encodeURIComponent(token)}/status`, {
    method: 'GET',
  });
}

/**
 * Atomically consumes the secret and retrieves the ciphertext.
 */
export function consumeSecret(token: string, passkey: string): Promise<ConsumeSecretResponse> {
  return request<ConsumeSecretResponse>(`/secrets/${encodeURIComponent(token)}/consume`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ passkey }),
  });
}

/**
 * Revokes an active secret using the creator's revoke token.
 */
export async function revokeSecret(token: string, revokeToken: string): Promise<void> {
  await request<void>(
    `/secrets/${encodeURIComponent(token)}`,
    {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${revokeToken.trim()}` },
    },
    { allowEmpty: true }
  );
}