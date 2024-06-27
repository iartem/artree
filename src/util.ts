import { Leaf, Me, Node, crypt } from '.';
import { Err, ErrCode } from './err';
import { Keypair, PK, SK } from './types';

export function keypair(sk?: SK): Keypair {
  sk = sk || crypt.generateSecretKey();
  const pk = crypt.derivePublicKey(sk);
  return { sk, pk };
}

/**
 * X3DH send
 */
export function keyExchangeSend(
  selfIdentity: Keypair,
  remoteIdentity: PK,
  keyExchangeKeyPair: Keypair,
  remoteEphemeralKey: PK
): Uint8Array {
  const k1 = crypt.getSharedSecret(selfIdentity.sk, remoteIdentity);
  const k2 = crypt.getSharedSecret(selfIdentity.sk, remoteEphemeralKey);
  const k3 = crypt.getSharedSecret(keyExchangeKeyPair.sk, remoteIdentity);
  const k4 = crypt.getSharedSecret(keyExchangeKeyPair.sk, remoteEphemeralKey);
  return crypt.hash_256(concat(k1, k2, k3, k4));
}

/**
 * X3DH receive
 */
export function keyExchangeReceive(selfIdentity: Keypair, remoteIdentity: PK, ephemeralKey: Keypair, keyExchangeKey: PK): Uint8Array {
  const k1 = crypt.getSharedSecret(selfIdentity.sk, remoteIdentity);
  const k2 = crypt.getSharedSecret(ephemeralKey.sk, remoteIdentity);
  const k3 = crypt.getSharedSecret(selfIdentity.sk, keyExchangeKey);
  const k4 = crypt.getSharedSecret(ephemeralKey.sk, keyExchangeKey);
  return crypt.hash_256(concat(k1, k2, k3, k4));
}

/**
 * Concat several arrays into one
 */
export function concat(...arrays: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(arrays.reduce((a, b) => a + b.length, 0));
  arrays.reduce((a, b) => {
    result.set(b, a);
    return a + b.length;
  }, 0);
  return result;
}

/**
 * Split big array into several smaller ones of length item_length.
 * Does alloc for each subarray.
 */
export function split(data: Uint8Array, offset: Offset, item_length: number, item_count?: number): Uint8Array[] {
  const result = [];
  while (offset.value < data.byteLength - item_length && (item_count === undefined || result.length < item_count)) {
    result.push(data.slice(offset.add(item_length), offset.value));
  }
  return result;
}

/**
 * Compare two arrays
 */
export function equals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

/**
 * Stringify Uint8Array into hex form
 *
 * @param array array to convert
 * @returns hex string of array
 */
export function toHex(array: Uint8Array): string {
  const strs: string[] = [];
  array.forEach((i) => strs.push(i.toString(16).padStart(2, '0')));
  return strs.join('');
}

/**
 * Print three first numbers of Uint8Array
 *
 * @param array array to convert
 * @returns hex string of array
 */
export function toFirstThree(array: Uint8Array): string {
  return array.slice(0, 3).join('.');
}

/**
 * Just a handy class for arrays parsing, returns old value when adding to it
 */
export class Offset {
  constructor(private counter = 0) {}

  get value(): number {
    return this.counter;
  }

  add(n: number): number {
    const old = this.counter;
    this.counter += n;
    return old;
  }

  assert(n: number): void {
    if (this.value !== n) {
      throw new Err(ErrCode.ENCODING_ERROR, `Wrong offset ${this.value} whereas it should be ${n}`);
    }
  }
}

export const Gen = {
  collect<G, T>(g: Generator<G>, f: (g: G) => T): T[] {
    const result = [];
    for (const x of g) result.push(f(x));
    return result;
  },

  find<G>(g: Generator<G>, f: (g: G) => boolean): G | undefined {
    for (const x of g) {
      if (f(x)) {
        return x;
      }
    }
    return undefined;
  },
};

export function printTree(node: Node | Leaf, level = 1, toString = toFirstThree): void {
  const offset = new Array(level * 2).fill('-').join('');
  console.log(offset, node instanceof Leaf ? 'Leaf' : 'Node');
  console.log(offset, 'pk', toString(node.pk));
  console.log(offset, 'sk', node.sk ? toString(node.sk) : undefined);
  if (node instanceof Leaf) {
    console.log(
      offset,
      `${node.peer instanceof Me ? 'Me' : 'Peer'} (${toString(node.peer.identity_pk)}, ${toString(node.peer.ephemeral_pk)})`
    );
  } else {
    console.log(offset, 'left: ');
    printTree(node.left, level + 1, toString);
    console.log(offset, 'right: ');
    printTree(node.right, level + 1, toString);
  }
}
