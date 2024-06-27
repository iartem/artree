import { gcm } from '@noble/ciphers/aes';
import { secp256k1 } from '@noble/curves/secp256k1';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from 'crypto';
import { setCrypto, SK, SI, PK, concat } from '../src';

beforeEach(function () {
  if (expect.getState().testPath.includes('/no-crypt.spec.ts')) {
    return;
  }

  setCrypto({
    generateSecretKey: secp256k1.utils.randomPrivateKey,
    derivePublicKey: secp256k1.getPublicKey,
    getSharedSecret: secp256k1.getSharedSecret,
    hash_256: sha256,
    sign: function (data: Uint8Array, sk: SK) {
      return secp256k1.sign(data, sk, { prehash: true }).toCompactRawBytes();
    },
    verify: function (si: SI, data: Uint8Array, pk: PK) {
      return secp256k1.verify(si, data, pk, { prehash: true });
    },
    hkdf: hkdf.bind(null, sha256),
    encrypt: function (data: Uint8Array, key: SK) {
      const nonce = randomBytes(this.ENCRYPTION_PREFIX_LENGTH);
      return concat(nonce, gcm(key, nonce).encrypt(data));
    },
    decrypt: function (data: Uint8Array, key: SK) {
      const nonce = data.subarray(0, this.ENCRYPTION_PREFIX_LENGTH);
      try {
        return gcm(key, nonce).decrypt(data.subarray(this.ENCRYPTION_PREFIX_LENGTH));
      } catch {
        return null;
      }
    },
    PK_LENGTH: 33,
    SK_LENGTH: 32,
    SI_LENGTH: 64,
    ENCRYPTION_PREFIX_LENGTH: 12,
    ENCRYPTION_SUFFIX_LENGTH: 16,
  });
});
