import {
  pino,
  stdTimeFunctions,
  type DestinationStream,
  type Logger,
  type LoggerOptions,
} from 'pino';

export interface CreateLoggerOptions {
  level?: string;
  stream?: DestinationStream;
}

const REDACTED_PATHS = [
  'token',
  '*.token',
  'revokeToken',
  '*.revokeToken',
  'ciphertext',
  '*.ciphertext',
  'iv',
  '*.iv',
  'key',
  '*.key',
  'passkey',
  '*.passkey',
  'passkeyHash',
  '*.passkeyHash',
  'plaintext',
  '*.plaintext',
  'password',
  '*.password',
  'authorization',
  '*.authorization',
  'headers',
  '*.headers',
  'cookie',
  '*.cookie',
  'body',
  '*.body',
  'query',
  '*.query',
  'params',
  '*.params',
  'req',
  'res',
  'ip',
  'remoteAddress',
];

export function createLogger(options: CreateLoggerOptions = {}): Logger {
  const pinoOptions: LoggerOptions = {
    level: options.level ?? 'info',
    redact: {
      paths: REDACTED_PATHS,
      remove: true,
    },
    base: {
      service: 'onevault-api',
    },
    timestamp: stdTimeFunctions.isoTime,
  };

  if (options.stream) {
    return pino(pinoOptions, options.stream);
  }

  return pino(pinoOptions);
}
