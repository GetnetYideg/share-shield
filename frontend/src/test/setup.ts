import '@testing-library/jest-dom';
import { webcrypto } from 'node:crypto';

// Polyfill WebCrypto in jsdom environment if missing
if (!window.crypto || !window.crypto.subtle) {
  Object.defineProperty(window, 'crypto', {
    value: webcrypto,
    writable: true,
  });
}
