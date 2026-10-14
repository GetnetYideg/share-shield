import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { CreateView } from '../src/components/CreateView';
import { RevealView } from '../src/components/RevealView';
import { StatusView } from '../src/components/StatusView';
import { RevokeView } from '../src/components/RevokeView';
import { encryptSecret } from '../src/lib/crypto';

describe('ShareShield Component Integration & Security Rules', () => {
  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    originalFetch = global.fetch;
  });

  afterEach(() => {
    global.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  describe('CreateView', () => {
    it('encrypts locally and sends ciphertext to API, NEVER leaking plaintext or key in request', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 201,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => ({
          data: {
            created: true,
            expiresAt: '2026-10-14T12:00:00.000Z',
          },
          requestId: 'req_test123',
        }),
      });
      global.fetch = mockFetch;

      render(<CreateView />);

      const textarea = screen.getByLabelText(/SECRET TEXT/i);
      const secretPlaintext = 'Confidential_System_Credentials_12345';
      fireEvent.change(textarea, { target: { value: secretPlaintext } });

      const submitButton = screen.getByRole('button', {
        name: /ENCRYPT & GENERATE LINK/i,
      });
      fireEvent.click(submitButton);

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledTimes(1);
      });

      // Inspect the exact request sent over the network
      const [calledUrl, calledInit] = mockFetch.mock.calls[0] as [string, RequestInit];
      expect(calledUrl).toBe('/api/v1/secrets');
      expect(calledInit.method).toBe('POST');

      const parsedBody = JSON.parse(calledInit.body as string) as Record<string, unknown>;

      // NON-NEGOTIABLE INVARIANTS:
      // Plaintext and Decryption Key MUST NOT appear in request body or URL!
      expect(JSON.stringify(parsedBody)).not.toContain(secretPlaintext);
      expect(parsedBody).not.toHaveProperty('key');
      expect(parsedBody).not.toHaveProperty('plaintext');
      expect(parsedBody).not.toHaveProperty('encryptionKey');

      // Ciphertext, IV, Token, RevokeToken, Expiry must be present
      expect(parsedBody.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(parsedBody.revokeToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(parsedBody.iv).toMatch(/^[A-Za-z0-9_-]{16}$/);
      expect(typeof parsedBody.ciphertext).toBe('string');
      expect(parsedBody.payloadVersion).toBe(1);

      // Verify UI renders share link and revoke token
      await waitFor(() => {
        expect(screen.getByText(/SHOWN ONLY ONCE/i)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /COPY LINK/i })).toBeInTheDocument();
      });
    });
  });

  describe('RevealView (SRS §3.1 & §6.2 Status-Before-Consume Rule)', () => {
    it('calls status endpoint on mount and NEVER calls consume on page load', async () => {
      const mockFetch = vi.fn().mockImplementation((url: string, _init?: RequestInit) => {
        if (url.includes('/status')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({
              data: {
                available: true,
                expiresAt: '2026-10-14T12:00:00.000Z',
              },
              requestId: 'req_status',
            }),
          });
        }
        return Promise.reject(new Error(`Unexpected call to: ${url}`));
      });
      global.fetch = mockFetch;

      const dummyToken = '4vQ3z9K8mN2pL7rT1wX6yB0cE5fG8hJ2kM4nP6qS8uV';
      const dummyKey = '7rT1wX6yB0cE5fG8hJ2kM4nP6qS8uV4vQ3z9K8mN2pL';

      render(
        <RevealView
          token={dummyToken}
          initialKey={dummyKey}
          onNavigateHome={vi.fn()}
        />
      );

      // Verify status endpoint was queried
      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledWith(
          `/api/v1/secrets/${dummyToken}/status`,
          expect.objectContaining({ method: 'GET' })
        );
      });

      // Verify CONSUME was NOT called on page load (so link unfurlers do not burn secret)
      const consumeCalls = mockFetch.mock.calls.filter((call) =>
        (call[0] as string).includes('/consume')
      );
      expect(consumeCalls.length).toBe(0);

      // Verify UI shows ready to reveal
      expect(screen.getByText(/READY TO REVEAL/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /REVEAL SECRET/i })).toBeInTheDocument();
    });

    it('calls consume and decrypts locally only after clicking "Reveal Secret", and allows hiding it', async () => {
      const secretText = 'Top-Secret-Database-Password-42';
      const encrypted = await encryptSecret(secretText);

      const mockFetch = vi.fn().mockImplementation((url: string, _init?: RequestInit) => {
        if (url.includes('/status')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({
              data: {
                available: true,
                expiresAt: '2026-10-14T12:00:00.000Z',
              },
              requestId: 'req_status',
            }),
          });
        }
        if (url.includes('/consume')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({
              data: {
                ciphertext: encrypted.ciphertext,
                iv: encrypted.iv,
                payloadVersion: encrypted.payloadVersion,
              },
              requestId: 'req_consume',
            }),
          });
        }
        return Promise.reject(new Error(`Unexpected call to: ${url}`));
      });
      global.fetch = mockFetch;

      render(
        <RevealView
          token={encrypted.token}
          initialKey={encrypted.keyBase64Url}
          onNavigateHome={vi.fn()}
        />
      );

      // Wait for status check to complete
      await waitFor(() => {
        expect(screen.getByRole('button', { name: /REVEAL SECRET/i })).toBeInTheDocument();
      });

      // User clicks reveal
      fireEvent.click(screen.getByRole('button', { name: /REVEAL SECRET/i }));

      // Verify consume was called
      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledWith(
          `/api/v1/secrets/${encrypted.token}/consume`,
          expect.objectContaining({ method: 'POST' })
        );
      });

      // Verify decrypted text is rendered as text
      await waitFor(() => {
        expect(screen.getByText(secretText)).toBeInTheDocument();
        expect(screen.getByText(/This secret is gone\. It cannot be opened again\./i)).toBeInTheDocument();
      });

      // User clicks HIDE button
      const hideButton = screen.getByRole('button', { name: /HIDE/i });
      fireEvent.click(hideButton);

      // Secret must be purged from view
      expect(screen.queryByText(secretText)).not.toBeInTheDocument();
    });

    it('renders uniform unavailable error when secret has expired or already consumed (404)', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => ({
          error: {
            code: 'SECRET_UNAVAILABLE',
            message: 'This secret is unavailable or has already been viewed.',
            requestId: 'req_404',
          },
        }),
      });
      global.fetch = mockFetch;

      render(
        <RevealView
          token="4vQ3z9K8mN2pL7rT1wX6yB0cE5fG8hJ2kM4nP6qS8uV"
          initialKey="7rT1wX6yB0cE5fG8hJ2kM4nP6qS8uV4vQ3z9K8mN2pL"
          onNavigateHome={vi.fn()}
        />
      );

      await waitFor(() => {
        expect(screen.getByText(/SECRET UNAVAILABLE/i)).toBeInTheDocument();
        expect(screen.getByText(/This secret is unavailable or has already been viewed/i)).toBeInTheDocument();
      });
    });

    it('displays error if decryption key is missing from URL fragment', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => ({
          data: {
            available: true,
            expiresAt: '2026-10-14T12:00:00.000Z',
          },
          requestId: 'req_status',
        }),
      });
      global.fetch = mockFetch;

      render(
        <RevealView
          token="4vQ3z9K8mN2pL7rT1wX6yB0cE5fG8hJ2kM4nP6qS8uV"
          initialKey={undefined} // No key in fragment!
          onNavigateHome={vi.fn()}
        />
      );

      await waitFor(() => {
        expect(
          screen.getByText(/Decryption key missing from URL fragment/i)
        ).toBeInTheDocument();
      });
    });
  });

  describe('StatusView', () => {
    it('queries status endpoint and displays availability without consuming', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => ({
          data: {
            available: true,
            expiresAt: '2026-10-14T15:00:00.000Z',
          },
          requestId: 'req_status',
        }),
      });
      global.fetch = mockFetch;

      render(<StatusView />);

      const input = screen.getByLabelText(/SHARE LINK OR TOKEN/i);
      const testToken = '4vQ3z9K8mN2pL7rT1wX6yB0cE5fG8hJ2kM4nP6qS8uV';
      fireEvent.change(input, { target: { value: testToken } });

      const checkButton = screen.getByRole('button', { name: /CHECK/i });
      fireEvent.click(checkButton);

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledWith(
          `/api/v1/secrets/${testToken}/status`,
          expect.objectContaining({ method: 'GET' })
        );
        expect(screen.getByText(/STATUS: AVAILABLE/i)).toBeInTheDocument();
      });
    });
  });

  describe('RevokeView', () => {
    it('submits DELETE request with Authorization Bearer header', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 204,
        headers: new Headers(),
      });
      global.fetch = mockFetch;

      render(<RevokeView />);

      const linkInput = screen.getByLabelText(/SHARE LINK OR TOKEN/i);
      const revokeTokenInput = screen.getByLabelText(/CREATOR REVOKE TOKEN/i);

      const testToken = '4vQ3z9K8mN2pL7rT1wX6yB0cE5fG8hJ2kM4nP6qS8uV';
      const testRevokeToken = '7rT1wX6yB0cE5fG8hJ2kM4nP6qS8uV4vQ3z9K8mN2pL';

      fireEvent.change(linkInput, { target: { value: testToken } });
      fireEvent.change(revokeTokenInput, { target: { value: testRevokeToken } });

      const revokeButton = screen.getByRole('button', { name: /REVOKE PERMANENTLY/i });
      fireEvent.click(revokeButton);

      await waitFor(() => {
        expect(mockFetch).toHaveBeenCalledWith(
          `/api/v1/secrets/${testToken}`,
          expect.objectContaining({
            method: 'DELETE',
            headers: {
              Authorization: `Bearer ${testRevokeToken}`,
            },
          })
        );
        expect(screen.getByText(/REVOCATION SUCCESSFUL/i)).toBeInTheDocument();
      });
    });
  });

  describe('App Layout and Navigation', () => {
    it('renders CreateView by default and switches tabs when clicking TabBar buttons', async () => {
      const { App } = await import('../src/App');
      render(<App />);

      expect(screen.getByText(/SHARE ONCE\./i)).toBeInTheDocument();

      // Click STATUS tab
      const statusTab = screen.getByRole('button', { name: 'STATUS' });
      fireEvent.click(statusTab);

      expect(screen.getByText(/CHECK SECRET AVAILABILITY/i)).toBeInTheDocument();

      // Click REVOKE tab
      const revokeTab = screen.getByRole('button', { name: 'REVOKE' });
      fireEvent.click(revokeTab);

      expect(screen.getByText(/REVOKE A SECRET/i)).toBeInTheDocument();
    });

    it('navigates to status view when searching from top bar', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: async () => ({
          data: {
            available: true,
            expiresAt: '2026-10-14T15:00:00.000Z',
          },
          requestId: 'req_search',
        }),
      });
      global.fetch = mockFetch;

      const { App } = await import('../src/App');
      render(<App />);

      const searchInput = screen.getByPlaceholderText(/Paste a link to check_/i);
      const testLink = 'https://shareshield.app/s/4vQ3z9K8mN2pL7rT1wX6yB0cE5fG8hJ2kM4nP6qS8uV';

      fireEvent.change(searchInput, { target: { value: testLink } });
      fireEvent.submit(searchInput.closest('form')!);

      await waitFor(() => {
        expect(screen.getByText(/CHECK SECRET AVAILABILITY/i)).toBeInTheDocument();
      });

      const statusInput = screen.getByLabelText(/SHARE LINK OR TOKEN/i) as HTMLInputElement;
      expect(statusInput.value).toBe(testLink);

      await waitFor(() => {
        expect(screen.getByText(/STATUS: AVAILABLE/i)).toBeInTheDocument();
      });
    });
  });
});
