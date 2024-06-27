import { crypt } from '../src';

const arr = new Uint8Array();
describe('no crypt', () => {
  it("should throw on any crypt use when it's not set", () => {
    expect(() => crypt.decrypt(arr, arr)).toThrow();
    expect(() => crypt.derivePublicKey(arr)).toThrow();
    expect(() => crypt.encrypt(arr, arr)).toThrow();
    expect(() => crypt.generateSecretKey()).toThrow();
    expect(() => crypt.getSharedSecret(arr, arr)).toThrow();
    expect(() => crypt.hash_256(arr)).toThrow();
    expect(() => crypt.hkdf(arr, arr, arr, 32)).toThrow();
    expect(() => crypt.sign(arr, arr)).toThrow();
    expect(() => crypt.verify(arr, arr, arr)).toThrow();
  });
});
