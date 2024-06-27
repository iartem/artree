/**
 * Used for expressiveness, PK = Public Key
 */
export type PK = Uint8Array;

/**
 * Used for expressiveness, SK = Secret Key (Private Key)
 */
export type SK = Uint8Array;

/**
 * Used for expressiveness, SI = Signature
 */
export type SI = Uint8Array;

export type Keypair = { pk: PK; sk: SK };

/**
 * Interface to underlying crypto implementation, think of @noble/curves or SubtleCrypto
 */
export interface Crypt {
  generateSecretKey: () => SK;
  derivePublicKey: (sk: SK) => PK;
  getSharedSecret: (sk: SK, pk: PK) => SK;
  sign: (data: Uint8Array, sk: SK) => SI;
  verify: (si: SI, data: Uint8Array, pk: PK) => boolean;
  hash_256: (data: Uint8Array) => Uint8Array;
  hkdf: (input: Uint8Array, salt: Uint8Array | undefined, info: Uint8Array | undefined, length: number) => Uint8Array;
  encrypt: (data: Uint8Array, key: SK) => Uint8Array;
  decrypt: (data: Uint8Array, key: SK) => Uint8Array | null;
  PK_LENGTH: number;
  SK_LENGTH: number;
  SI_LENGTH: number;
  ENCRYPTION_PREFIX_LENGTH: number;
  ENCRYPTION_SUFFIX_LENGTH: number;
}

export interface Clonable {
  clone: () => ThisType<this>;
}
