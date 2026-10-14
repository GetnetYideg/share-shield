import { describe, it, expect } from 'vitest';
import { parseSecretLink, buildShareUrl } from '../src/lib/url';

describe('Link & URL Utilities (SRS §6.2)', () => {
  const sampleToken = '4vQ3z9K8mN2pL7rT1wX6yB0cE5fG8hJ2kM4nP6qS8uV';
  const sampleKey = '7rT1wX6yB0cE5fG8hJ2kM4nP6qS8uV4vQ3z9K8mN2pL';

  it('correctly parses full https URL with key fragment', () => {
    const fullUrl = `https://shareshield.app/s/${sampleToken}#${sampleKey}`;
    const parsed = parseSecretLink(fullUrl);

    expect(parsed).not.toBeNull();
    expect(parsed?.token).toBe(sampleToken);
    expect(parsed?.key).toBe(sampleKey);
  });

  it('correctly parses relative path with key fragment', () => {
    const relUrl = `/s/${sampleToken}#${sampleKey}`;
    const parsed = parseSecretLink(relUrl);

    expect(parsed).not.toBeNull();
    expect(parsed?.token).toBe(sampleToken);
    expect(parsed?.key).toBe(sampleKey);
  });

  it('correctly parses URL without key fragment', () => {
    const noKeyUrl = `https://shareshield.app/s/${sampleToken}`;
    const parsed = parseSecretLink(noKeyUrl);

    expect(parsed).not.toBeNull();
    expect(parsed?.token).toBe(sampleToken);
    expect(parsed?.key).toBeUndefined();
  });

  it('correctly parses raw token and fragment notation', () => {
    const raw = `${sampleToken}#${sampleKey}`;
    const parsed = parseSecretLink(raw);

    expect(parsed).not.toBeNull();
    expect(parsed?.token).toBe(sampleToken);
    expect(parsed?.key).toBe(sampleKey);
  });

  it('correctly parses plain token string', () => {
    const parsed = parseSecretLink(sampleToken);

    expect(parsed).not.toBeNull();
    expect(parsed?.token).toBe(sampleToken);
    expect(parsed?.key).toBeUndefined();
  });

  it('rejects malformed tokens with wrong length or characters', () => {
    expect(parseSecretLink('too-short-token')).toBeNull();
    expect(parseSecretLink('token-with-invalid-chars!@#$%^&*()_+~`|}{":?><,')).toBeNull();
    expect(parseSecretLink('')).toBeNull();
  });

  it('builds share URL placing the key in the fragment', () => {
    const built = buildShareUrl(sampleToken, sampleKey);
    expect(built).toContain(`/s/${sampleToken}#${sampleKey}`);
    expect(built.startsWith('http')).toBe(true);
  });
});
