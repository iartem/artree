import crypto from 'crypto';

if (!('crypto' in global)) {
  Object.defineProperty(global, 'crypto', {
    value: {
      getRandomValues: (arr: Uint8Array) => crypto.randomBytes(arr.length),
    },
  });
}
