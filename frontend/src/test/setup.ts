import '@testing-library/jest-dom';
import { webcrypto } from 'node:crypto';

// Polyfill WebCrypto in jsdom environment if missing
if (!window.crypto || !window.crypto.subtle) {
  Object.defineProperty(window, 'crypto', {
    value: webcrypto,
    writable: true,
  });
}

// Storage mock for jsdom environment
class StorageMock implements Storage {
  private store: Record<string, string> = {};
  get length() {
    return Object.keys(this.store).length;
  }
  clear() {
    this.store = {};
  }
  getItem(key: string) {
    return this.store[key] ?? null;
  }
  setItem(key: string, value: string) {
    this.store[key] = String(value);
  }
  removeItem(key: string) {
    delete this.store[key];
  }
  key(index: number) {
    return Object.keys(this.store)[index] ?? null;
  }
}

const localMock = new StorageMock();
const sessionMock = new StorageMock();

Object.defineProperty(window, 'localStorage', {
  value: localMock,
  writable: true,
});
Object.defineProperty(window, 'sessionStorage', {
  value: sessionMock,
  writable: true,
});

// Also define on globalThis for Node scope access
(globalThis as unknown as { localStorage: Storage }).localStorage = localMock;
(globalThis as unknown as { sessionStorage: Storage }).sessionStorage = sessionMock;
