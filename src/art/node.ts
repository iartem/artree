import { crypt } from '..';
import { Err, ErrCode } from '../err';
import { Clonable, Keypair, PK, SK } from '../types';
import { equals } from '../util';
import { Leaf } from './leaf';
import { Peer } from './peer';

export class Node implements Clonable {
  public pk: PK;
  public sk?: SK;

  constructor(public left: Node | Leaf, public right: Node | Leaf, pk?: PK) {
    if (this.left.sk || this.right.sk) {
      this.pk = this.derive();
    } else if (pk) {
      this.pk = pk;
    } else {
      throw new Err(ErrCode.INCONSISTENT_STATE, "Can't construct node not on my path without PK");
    }
  }

  clone(): Node {
    return new Node(this.left.clone(), this.right.clone(), this.pk?.slice());
  }

  update(pk: PK): void {
    if (this.isOnMyPath) {
      this.derive();
      if (!equals(this.pk, pk)) {
        throw new Err(ErrCode.INCONSISTENT_STATE, 'Updated PK is not equal to derived one');
      }
    } else {
      this.pk = pk;
    }
  }

  derive(): PK {
    const sk = this.left.sk || this.right.sk;
    if (sk) {
      const pk = this.left.sk ? this.right.pk : this.left.pk;
      const keys = Node.derive(sk, pk);
      this.sk = keys.sk;
      this.pk = keys.pk;
      return this.pk;
    } else {
      throw new Err(ErrCode.INCONSISTENT_STATE, "Can't construct node not on my path without PK");
    }
  }

  private static derive(sec: SK, pub: PK): Keypair {
    const sk = crypt.hkdf(crypt.getSharedSecret(sec, pub), undefined, undefined, crypt.SK_LENGTH);
    const pk = crypt.derivePublicKey(sk);
    return { sk, pk };
  }

  get length(): number {
    return this.left.length + this.right.length + 1;
  }

  get isOnMyPath(): boolean {
    return this.left.isOnMyPath || this.right.isOnMyPath;
  }

  split(at: PK, peer: Peer, init: PK[] | { identity: Keypair; exchange: Keypair } | { identity_pk: PK; exchange_pk: PK }): Node | boolean {
    const left = this.left.split(at, peer, init);
    if (left instanceof Node) {
      this.left = left;
    }
    const right = this.right.split(at, peer, init);
    if (right instanceof Node) {
      this.right = right;
    }

    if (left || right) {
      if (Array.isArray(init)) {
        const t = init.shift();
        if (t === undefined) {
          throw new Err(ErrCode.INCONSISTENT_STATE, 'Not enough PKs to process split');
        }
        this.pk = t;
      }

      if (this.left.sk || this.right.sk) {
        this.derive();
      }
    }

    return !!left || !!right;
  }

  *members(): Generator<Node | Leaf> {
    yield this;
    for (const n of this.left.members()) {
      yield n;
    }
    for (const n of this.right.members()) {
      yield n;
    }
  }

  *leafs(): Generator<Leaf> {
    for (const l of this.left.leafs()) {
      yield l;
    }
    for (const l of this.right.leafs()) {
      yield l;
    }
  }

  *pathOf(peer: Peer): Generator<Node | Leaf> {
    let yelded = false;
    if (this.left instanceof Leaf) {
      if (this.left.peer === peer) {
        yield this.left;
        yelded = true;
      }
    } else {
      for (const l of this.left.pathOf(peer)) {
        yelded = true;
        yield l;
      }
    }

    if (this.right instanceof Leaf) {
      if (this.right.peer === peer) {
        yield this.right;
        yelded = true;
      }
    } else {
      for (const l of this.right.pathOf(peer)) {
        yelded = true;
        yield l;
      }
    }

    if (yelded) {
      yield this;
    }
  }
}

export type SecretNode = Node & { sk: SK };
