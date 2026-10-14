import { describe, it, expect } from 'vitest';
import {
  encryptSecret,
  decryptSecret,
  generateRandomToken,
  generateIv,
  importKey,
  exportKey,
  generateAesKey,
  bufferToBase64Url,
} from '../src/lib/crypto';

describe('Client-Side Web Crypto Implementation (SRS §6.2)', () => {
  it('successfully executes an end-to-end encrypt and decrypt round trip', async () => {
    const secretText = 'super-secret-password-12345!@#$%^&*()_+-=[]{}|;:,.<>?';
    const encrypted = await encryptSecret(secretText);

    expect(encrypted.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(encrypted.keyBase64Url).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(encrypted.revokeToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(encrypted.iv).toMatch(/^[A-Za-z0-9_-]{16}$/);
    expect(encrypted.payloadVersion).toBe(1);

    const decrypted = await decryptSecret(
      encrypted.ciphertext,
      encrypted.iv,
      encrypted.keyBase64Url
    );

    expect(decrypted).toBe(secretText);
  });

  it('handles maximum allowed 10 KiB plaintext correctly', async () => {
    const largeText = 'A'.repeat(10240);
    const encrypted = await encryptSecret(largeText);

    const decrypted = await decryptSecret(
      encrypted.ciphertext,
      encrypted.iv,
      encrypted.keyBase64Url
    );

    expect(decrypted).toBe(largeText);
  });

  it('handles multilingual and unicode text correctly', async () => {
    const unicodeText = '🔐 OneVault 암호화 秘密 Привет мир! 🚀';
    const encrypted = await encryptSecret(unicodeText);

    const decrypted = await decryptSecret(
      encrypted.ciphertext,
      encrypted.iv,
      encrypted.keyBase64Url
    );

    expect(decrypted).toBe(unicodeText);
  });

  it('guarantees unique 12-byte IVs for consecutive encryptions', () => {
    const ivSet = new Set<string>();
    const count = 100;

    for (let i = 0; i < count; i++) {
      const { ivBase64Url } = generateIv();
      expect(ivBase64Url).toHaveLength(16);
      ivSet.add(ivBase64Url);
    }

    expect(ivSet.size).toBe(count);
  });

  it('fails decryption if ciphertext has been tampered with (GCM authentication tag mismatch)', async () => {
    const originalText = 'Tamper-proof secret';
    const encrypted = await encryptSecret(originalText);

    // Tamper with one character in the ciphertext
    const tamperedCipher =
      encrypted.ciphertext.slice(0, -2) +
      (encrypted.ciphertext.slice(-2) === 'AA' ? 'BB' : 'AA');

    await expect(
      decryptSecret(tamperedCipher, encrypted.iv, encrypted.keyBase64Url)
    ).rejects.toThrow();
  });

  it('fails decryption if an incorrect key is provided', async () => {
    const originalText = 'Secret with wrong key';
    const encrypted = await encryptSecret(originalText);

    // Generate a completely different key
    const differentKey = await generateAesKey();
    const differentKeyBase64Url = await exportKey(differentKey);

    await expect(
      decryptSecret(encrypted.ciphertext, encrypted.iv, differentKeyBase64Url)
    ).rejects.toThrow();
  });

  it('rejects keys that do not decode to exactly 32 bytes', async () => {
    const tooShortKey = bufferToBase64Url(new Uint8Array(16));
    await expect(importKey(tooShortKey)).rejects.toThrow(/expected 32 bytes/);
  });

  it('generates high-entropy 32-byte tokens without padding', () => {
    for (let i = 0; i < 20; i++) {
      const token = generateRandomToken();
      expect(token).toHaveLength(43);
      expect(token).not.toContain('=');
      expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    }
  });
});
