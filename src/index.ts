import { Err, ErrCode } from './err';
import { Crypt } from './types';

/**
 * General abstractions used throughout the package
 */
export * from './types';

/**
 * ART & other types
 */
export * from './art/index';

/**
 * Error class & code enum
 */
export * from './err';

/**
 * Handy utilities
 */
export * from './util';

/**
 * Stub to provide your own crypto implementation (tests use @noble/curves/secp256k1)
 * Note that implementation must support both: DH & sign/verify for the same key.
 * secp256k1 supports both out of the box, 25519 would need extra handling.
 */
export let crypt: Crypt = {
  generateSecretKey: () => {
    throw new Err(ErrCode.INCONSISTENT_STATE, 'call setCrypt() before using');
  },
  derivePublicKey: () => {
    throw new Err(ErrCode.INCONSISTENT_STATE, 'call setCrypt() before using');
  },
  getSharedSecret: () => {
    throw new Err(ErrCode.INCONSISTENT_STATE, 'call setCrypt() before using');
  },
  hash_256: () => {
    throw new Err(ErrCode.INCONSISTENT_STATE, 'call setCrypt() before using');
  },
  sign: () => {
    throw new Err(ErrCode.INCONSISTENT_STATE, 'call setCrypt() before using');
  },
  verify: () => {
    throw new Err(ErrCode.INCONSISTENT_STATE, 'call setCrypt() before using');
  },
  hkdf: () => {
    throw new Err(ErrCode.INCONSISTENT_STATE, 'call setCrypt() before using');
  },
  encrypt: () => {
    throw new Err(ErrCode.INCONSISTENT_STATE, 'call setCrypt() before using');
  },
  decrypt: () => {
    throw new Err(ErrCode.INCONSISTENT_STATE, 'call setCrypt() before using');
  },
  PK_LENGTH: -1,
  SK_LENGTH: -1,
  SI_LENGTH: -1,
  ENCRYPTION_PREFIX_LENGTH: -1,
  ENCRYPTION_SUFFIX_LENGTH: -1,
};

/**
 * Set crypto implementation
 *
 * @param crypto underlying crypto implementaion
 */
export function setCrypto(crypto: Crypt): void {
  crypt = crypto;
}
