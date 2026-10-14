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
  };
  requestId: string;
}

export interface SecretStatusResponse {
  data: {
    available: boolean;
    expiresAt: string;
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
}

export class ApiError extends Error {
  public readonly code: string;
  public readonly status: number;
  public readonly retryAfterSeconds?: number;

  constructor(detail: ApiErrorDetail) {
    super(detail.message);
    this.name = 'ApiError';
    this.code = detail.code;
    this.status = detail.status;
    this.retryAfterSeconds = detail.retryAfterSeconds;
  }
}

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1';

async function handleResponse<T>(res: Response): Promise<T> {
  if (res.status === 204) {
    return {} as T;
  }

  const contentType = res.headers.get('content-type') || '';
  const isJson = contentType.includes('application/json');

  if (!res.ok) {
    let errorCode = 'REQUEST_FAILED';
    let errorMessage = 'An unexpected error occurred.';

    if (isJson) {
      try {
        const errorJson = (await res.json()) as { error?: { code?: string; message?: string } };
        if (errorJson.error) {
          errorCode = errorJson.error.code || errorCode;
          errorMessage = errorJson.error.message || errorMessage;
        }
      } catch {
        // Fallback to HTTP status text
      }
    }

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
    } else if (res.status === 403) {
      errorMessage = 'Invalid revoke token.';
    } else if (res.status === 400) {
      errorMessage = 'Invalid token or parameters.';
    }

    throw new ApiError({
      code: errorCode,
      message: errorMessage,
      status: res.status,
      retryAfterSeconds,
    });
  }

  if (!isJson) {
    throw new ApiError({
      code: 'UNEXPECTED_RESPONSE',
      message: 'Server returned a non-JSON response.',
      status: res.status,
    });
  }

  return (await res.json()) as T;
}

/**
 * Creates an encrypted secret record on the server.
 */
export async function createSecret(payload: CreateSecretRequest): Promise<CreateSecretResponse> {
  try {
    const res = await fetch(`${API_BASE_URL}/secrets`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });
    return await handleResponse<CreateSecretResponse>(res);
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError({
      code: 'NETWORK_ERROR',
      message: 'Network connection failed. Please check your connectivity.',
      status: 0,
    });
  }
}

/**
 * Checks secret availability without consuming it (read-only).
 */
export async function getSecretStatus(token: string): Promise<SecretStatusResponse> {
  try {
    const res = await fetch(`${API_BASE_URL}/secrets/${encodeURIComponent(token)}/status`, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
      },
    });
    return await handleResponse<SecretStatusResponse>(res);
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError({
      code: 'NETWORK_ERROR',
      message: 'Network connection failed. Please check your connectivity.',
      status: 0,
    });
  }
}

/**
 * Atomically consumes the secret and retrieves the ciphertext.
 */
export async function consumeSecret(token: string): Promise<ConsumeSecretResponse> {
  try {
    const res = await fetch(`${API_BASE_URL}/secrets/${encodeURIComponent(token)}/consume`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({}),
    });
    return await handleResponse<ConsumeSecretResponse>(res);
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError({
      code: 'NETWORK_ERROR',
      message: 'Network connection failed. Please check your connectivity.',
      status: 0,
    });
  }
}

/**
 * Revokes an active secret using the creator's revoke token.
 */
export async function revokeSecret(token: string, revokeToken: string): Promise<void> {
  try {
    const res = await fetch(`${API_BASE_URL}/secrets/${encodeURIComponent(token)}`, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${revokeToken.trim()}`,
      },
    });
    await handleResponse<void>(res);
  } catch (err) {
    if (err instanceof ApiError) throw err;
    throw new ApiError({
      code: 'NETWORK_ERROR',
      message: 'Network connection failed. Please check your connectivity.',
      status: 0,
    });
  }
}
