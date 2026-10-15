import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { CreateView } from '../src/components/CreateView';
import { RevealView } from '../src/components/RevealView';
import { StatusView } from '../src/components/StatusView';
import { RevokeView } from '../src/components/RevokeView';
import { encryptSecret } from '../src/lib/crypto';

describe('ShareShield Component Integration & Passkey Security Rules', () => {
  let originalFetch: typeof global.fetch;

  beforeEach(() => {
    originalFetch = global.fetch;
    localStorage.clear();
    sessionStorage.clear();
  });

  afterEach(() => {
    global.fetch = originalFetch;
    localStorage.clear();
    sessionStorage.clear();
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
            passkey: '739201',
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

      // Verify UI renders TWO separate cards: Share Link Card and 6-Digit Passkey Card
      await waitFor(() => {
        // Share Link Card
        expect(screen.getByText('SHARE LINK')).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /COPY LINK/i })).toBeInTheDocument();
        expect(screen.getByText(/REVOKE TOKEN/i)).toBeInTheDocument();

        // 6-Digit Passkey Card
        expect(screen.getByText('6-DIGIT PASSKEY')).toBeInTheDocument();
        expect(screen.getByTestId('passkey-display')).toHaveTextContent('739201');
        expect(screen.getByRole('button', { name: /COPY PASSKEY/i })).toBeInTheDocument();
        expect(screen.getByText(/OUT-OF-BAND DELIVERY REQUIRED/i)).toBeInTheDocument();
        expect(
          screen.getByText(
            /Send the passkey through a different channel than the link/i
          )
        ).toBeInTheDocument();
      });

      // Memory hygiene: passkey must NEVER be stored in localStorage, sessionStorage, or URL
      expect(localStorage.getItem('passkey')).toBeNull();
      expect(sessionStorage.getItem('passkey')).toBeNull();
      expect(window.location.href).not.toContain('739201');
    });
  });

  describe('RevealView (SRS §3.1 & §6.2 Status-Before-Consume & Passkey Rules)', () => {
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

      // Verify UI shows ready to reveal with passkey input
      expect(screen.getByText(/READY TO REVEAL/i)).toBeInTheDocument();
      expect(screen.getByLabelText(/6-digit passkey/i)).toBeInTheDocument();

      // Button is disabled because passkey has not been entered yet
      const revealButton = screen.getByRole('button', { name: /REVEAL SECRET/i });
      expect(revealButton).toBeDisabled();
    });

    it('enforces 6-digit numeric passkey validation and enables reveal button only when complete', async () => {
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

      const dummyToken = '4vQ3z9K8mN2pL7rT1wX6yB0cE5fG8hJ2kM4nP6qS8uV';
      const dummyKey = '7rT1wX6yB0cE5fG8hJ2kM4nP6qS8uV4vQ3z9K8mN2pL';

      render(
        <RevealView
          token={dummyToken}
          initialKey={dummyKey}
          onNavigateHome={vi.fn()}
        />
      );

      await waitFor(() => {
        expect(screen.getByLabelText(/6-digit passkey/i)).toBeInTheDocument();
      });

      const passkeyInput = screen.getByLabelText(/6-digit passkey/i) as HTMLInputElement;
      const revealButton = screen.getByRole('button', { name: /REVEAL SECRET/i });

      // Initially empty -> button disabled
      expect(revealButton).toBeDisabled();

      // Enter non-numeric characters -> stripped out
      fireEvent.change(passkeyInput, { target: { value: 'abc!@#' } });
      expect(passkeyInput.value).toBe('');
      expect(revealButton).toBeDisabled();

      // Enter 4 digits -> still disabled
      fireEvent.change(passkeyInput, { target: { value: '1234' } });
      expect(passkeyInput.value).toBe('1234');
      expect(revealButton).toBeDisabled();

      // Enter 5 digits -> still disabled
      fireEvent.change(passkeyInput, { target: { value: '12345' } });
      expect(passkeyInput.value).toBe('12345');
      expect(revealButton).toBeDisabled();

      // Enter full 6 digits -> button becomes ENABLED
      fireEvent.change(passkeyInput, { target: { value: '123456' } });
      expect(passkeyInput.value).toBe('123456');
      expect(revealButton).not.toBeDisabled();

      // Typing more than 6 digits gets truncated to 6
      fireEvent.change(passkeyInput, { target: { value: '123456789' } });
      expect(passkeyInput.value).toBe('123456');
      expect(revealButton).not.toBeDisabled();
    });

    it('calls consume with passkey and decrypts locally only after clicking "Reveal Secret", and allows hiding it', async () => {
      const secretText = 'Top-Secret-Database-Password-42';
      const encrypted = await encryptSecret(secretText);
      const validPasskey = '654321';

      const mockFetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
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
          const body = JSON.parse((init?.body as string) || '{}') as Record<string, unknown>;
          if (body.passkey === validPasskey) {
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
          return Promise.resolve({
            ok: false,
            status: 403,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({
              error: {
                code: 'PASSKEY_INVALID',
                message: 'Incorrect passkey.',
                attemptsRemaining: 4,
                requestId: 'req_wrong',
              },
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

      // Enter the 6-digit passkey
      const passkeyInput = screen.getByLabelText(/6-digit passkey/i);
      fireEvent.change(passkeyInput, { target: { value: validPasskey } });

      // User clicks reveal
      const revealBtn = screen.getByRole('button', { name: /REVEAL SECRET/i });
      expect(revealBtn).not.toBeDisabled();
      fireEvent.click(revealBtn);

      // Verify consume was called with the passkey in body
      await waitFor(() => {
        const consumeCall = mockFetch.mock.calls.find((call) =>
          (call[0] as string).includes('/consume')
        );
        expect(consumeCall).toBeDefined();
        const body = JSON.parse(consumeCall![1].body as string) as Record<string, unknown>;
        expect(body).toEqual({ passkey: validPasskey });
      });

      // Verify decrypted text is rendered as text (never HTML)
      await waitFor(() => {
        expect(screen.getByText(secretText)).toBeInTheDocument();
        expect(screen.getByText(/This secret is gone\. It cannot be opened again\./i)).toBeInTheDocument();
      });

      // Memory hygiene: passkey must be wiped from state and not present anywhere in storage
      expect(localStorage.getItem('passkey')).toBeNull();
      expect(sessionStorage.getItem('passkey')).toBeNull();

      // User clicks HIDE button
      const hideButton = screen.getByRole('button', { name: /HIDE/i });
      fireEvent.click(hideButton);

      // Secret must be purged from view
      expect(screen.queryByText(secretText)).not.toBeInTheDocument();
      expect(
        screen.getByText(/The secret has been hidden from memory and permanently burned/i)
      ).toBeInTheDocument();
    });

    it('handles wrong passkey (403 PASSKEY_INVALID) by showing attempts remaining and clearing input', async () => {
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
            ok: false,
            status: 403,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({
              error: {
                code: 'PASSKEY_INVALID',
                message: 'Incorrect passkey.',
                attemptsRemaining: 4,
                requestId: 'req_invalid_passkey',
              },
            }),
          });
        }
        return Promise.reject(new Error(`Unexpected: ${url}`));
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

      await waitFor(() => {
        expect(screen.getByLabelText(/6-digit passkey/i)).toBeInTheDocument();
      });

      const input = screen.getByLabelText(/6-digit passkey/i) as HTMLInputElement;
      fireEvent.change(input, { target: { value: '999999' } });

      const revealBtn = screen.getByRole('button', { name: /REVEAL SECRET/i });
      fireEvent.click(revealBtn);

      // Verify error banner is shown with remaining attempts
      await waitFor(() => {
        expect(screen.getByText(/Incorrect passkey\. 4 attempts remaining\./i)).toBeInTheDocument();
      });

      // Verify passkey input was cleared so user can try again immediately
      expect(input.value).toBe('');
      expect(revealBtn).toBeDisabled();
    });

    it('shows secret destroyed notice when attempts reach 0 (attemptsRemaining: 0)', async () => {
      const mockFetch = vi.fn().mockImplementation((url: string) => {
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
            ok: false,
            status: 403,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({
              error: {
                code: 'PASSKEY_INVALID',
                message: 'Too many incorrect attempts. This secret has been destroyed.',
                attemptsRemaining: 0,
                requestId: 'req_locked',
              },
            }),
          });
        }
        return Promise.reject(new Error(`Unexpected: ${url}`));
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

      await waitFor(() => {
        expect(screen.getByLabelText(/6-digit passkey/i)).toBeInTheDocument();
      });

      const input = screen.getByLabelText(/6-digit passkey/i);
      fireEvent.change(input, { target: { value: '000000' } });

      const revealBtn = screen.getByRole('button', { name: /REVEAL SECRET/i });
      fireEvent.click(revealBtn);

      await waitFor(() => {
        expect(screen.getByText(/SECRET DESTROYED/i)).toBeInTheDocument();
        expect(
          screen.getAllByText(/Too many incorrect attempts\. This secret has been destroyed\./i).length
        ).toBeGreaterThanOrEqual(1);
      });
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
    it('shows progressive countdown on repeated wrong passkey attempts until locked', async () => {
      let attemptsRemaining = 4;
      const mockFetch = vi.fn().mockImplementation((url: string) => {
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
          const currentRemaining = attemptsRemaining;
          attemptsRemaining = Math.max(0, attemptsRemaining - 1);
          return Promise.resolve({
            ok: false,
            status: 403,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({
              error: {
                code: 'PASSKEY_INVALID',
                message: currentRemaining === 0
                  ? 'Too many incorrect attempts. This secret has been destroyed.'
                  : `Incorrect passkey. ${currentRemaining} attempts remaining.`,
                attemptsRemaining: currentRemaining,
                requestId: 'req_wrong_attempt',
              },
            }),
          });
        }
        return Promise.reject(new Error(`Unexpected call: ${url}`));
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

      await waitFor(() => {
        expect(screen.getByLabelText(/6-digit passkey/i)).toBeInTheDocument();
      });

      const input = screen.getByLabelText(/6-digit passkey/i) as HTMLInputElement;

      // Attempt 1: 4 remaining
      fireEvent.change(input, { target: { value: '111111' } });
      fireEvent.click(screen.getByRole('button', { name: /REVEAL SECRET/i }));
      await waitFor(() => {
        expect(screen.getByText(/4 attempts remaining/i)).toBeInTheDocument();
      });
      expect(input.value).toBe('');

      // Attempt 2: 3 remaining
      fireEvent.change(input, { target: { value: '222222' } });
      fireEvent.click(screen.getByRole('button', { name: /REVEAL SECRET/i }));
      await waitFor(() => {
        expect(screen.getByText(/3 attempts remaining/i)).toBeInTheDocument();
      });

      // Attempt 3: 2 remaining
      fireEvent.change(input, { target: { value: '333333' } });
      fireEvent.click(screen.getByRole('button', { name: /REVEAL SECRET/i }));
      await waitFor(() => {
        expect(screen.getByText(/2 attempts remaining/i)).toBeInTheDocument();
      });

      // Attempt 4: 1 remaining
      fireEvent.change(input, { target: { value: '444444' } });
      fireEvent.click(screen.getByRole('button', { name: /REVEAL SECRET/i }));
      await waitFor(() => {
        expect(screen.getByText(/1 attempt remaining/i)).toBeInTheDocument();
      });

      // Attempt 5: 0 remaining -> destroyed!
      fireEvent.change(input, { target: { value: '555555' } });
      fireEvent.click(screen.getByRole('button', { name: /REVEAL SECRET/i }));
      await waitFor(() => {
        expect(screen.getByText(/SECRET DESTROYED/i)).toBeInTheDocument();
        expect(
          screen.getAllByText(/Too many incorrect attempts\. This secret has been destroyed\./i).length
        ).toBeGreaterThanOrEqual(1);
      });
    });
  });

  describe('End-to-End Workflow Integration', () => {
    it('executes the complete flow: create -> receive passkey -> open reveal view -> enter passkey -> decrypt -> hide', async () => {
      const secretContent = 'Project-Omni-Access-Token-xyz987';
      const expectedPasskey = '819342';
      let storedSecret: {
        token: string;
        ciphertext: string;
        iv: string;
        payloadVersion: number;
        passkey: string;
      } | null = null;

      const mockFetch = vi.fn().mockImplementation((url: string, init?: RequestInit) => {
        // Create secret
        if (url === '/api/v1/secrets' && init?.method === 'POST') {
          const body = JSON.parse(init.body as string) as Record<string, unknown>;
          storedSecret = {
            token: body.token as string,
            ciphertext: body.ciphertext as string,
            iv: body.iv as string,
            payloadVersion: body.payloadVersion as number,
            passkey: expectedPasskey,
          };
          return Promise.resolve({
            ok: true,
            status: 201,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({
              data: {
                created: true,
                passkey: expectedPasskey,
                expiresAt: '2026-10-14T18:00:00.000Z',
              },
              requestId: 'req_create_e2e',
            }),
          });
        }

        // Status check
        if (url.includes('/status') && (!init || init.method === 'GET')) {
          return Promise.resolve({
            ok: true,
            status: 200,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({
              data: {
                available: true,
                expiresAt: '2026-10-14T18:00:00.000Z',
              },
              requestId: 'req_status_e2e',
            }),
          });
        }

        // Consume secret
        if (url.includes('/consume') && init?.method === 'POST') {
          const body = JSON.parse(init.body as string) as Record<string, unknown>;
          if (body.passkey === storedSecret?.passkey) {
            return Promise.resolve({
              ok: true,
              status: 200,
              headers: new Headers({ 'content-type': 'application/json' }),
              json: async () => ({
                data: {
                  ciphertext: storedSecret!.ciphertext,
                  iv: storedSecret!.iv,
                  payloadVersion: storedSecret!.payloadVersion,
                },
                requestId: 'req_consume_e2e',
              }),
            });
          }
          return Promise.resolve({
            ok: false,
            status: 403,
            headers: new Headers({ 'content-type': 'application/json' }),
            json: async () => ({
              error: {
                code: 'PASSKEY_INVALID',
                message: 'Incorrect passkey.',
                attemptsRemaining: 4,
                requestId: 'req_wrong_e2e',
              },
            }),
          });
        }

        return Promise.reject(new Error(`Unexpected request to: ${url}`));
      });
      global.fetch = mockFetch;

      // 1. Creator creates secret via CreateView
      const { unmount } = render(<CreateView />);

      const textarea = screen.getByLabelText(/SECRET TEXT/i);
      fireEvent.change(textarea, { target: { value: secretContent } });

      const submitBtn = screen.getByRole('button', { name: /ENCRYPT & GENERATE LINK/i });
      fireEvent.click(submitBtn);

      await waitFor(() => {
        expect(screen.getByTestId('passkey-display')).toHaveTextContent(expectedPasskey);
      });

      // Extract generated share URL and parse token & key
      const linkInput = screen.getByDisplayValue(/\/s\//i) as HTMLInputElement;
      const shareUrl = linkInput.value;
      const [pathPart, fragmentKey] = shareUrl.split('#');
      const token = pathPart?.split('/s/')[1] ?? '';

      expect(token).toBeTruthy();
      expect(fragmentKey).toBeDefined();
      expect(storedSecret).not.toBeNull();

      unmount();

      // 2. Recipient opens RevealView with token and fragmentKey
      render(
        <RevealView
          token={token}
          initialKey={fragmentKey}
          onNavigateHome={vi.fn()}
        />
      );

      // Verify status was queried, consume was NOT called yet
      await waitFor(() => {
        expect(screen.getByText(/READY TO REVEAL/i)).toBeInTheDocument();
      });
      expect(screen.getByRole('button', { name: /REVEAL SECRET/i })).toBeDisabled();

      // Recipient enters the 6-digit passkey received out-of-band
      const passkeyInput = screen.getByLabelText(/6-digit passkey/i);
      fireEvent.change(passkeyInput, { target: { value: expectedPasskey } });

      // Click Reveal
      const revealBtn = screen.getByRole('button', { name: /REVEAL SECRET/i });
      expect(revealBtn).not.toBeDisabled();
      fireEvent.click(revealBtn);

      // Verify decrypted content matches original plaintext exactly
      await waitFor(() => {
        expect(screen.getByText(secretContent)).toBeInTheDocument();
        expect(screen.getByText(/This secret is gone\. It cannot be opened again\./i)).toBeInTheDocument();
      });

      // Recipient hides secret
      fireEvent.click(screen.getByRole('button', { name: /HIDE/i }));

      // Secret is wiped from DOM
      expect(screen.queryByText(secretContent)).not.toBeInTheDocument();
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
