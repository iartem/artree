import { Peer, Me } from './peer';
import { Node } from './node';
import { PK, SK, Keypair, Clonable } from '../types';
import { keypair, keyExchangeReceive, keyExchangeSend, equals } from '../util';
import { Err, ErrCode } from '../err';

export class Leaf implements Clonable {
  private constructor(public peer: Peer, public pk: PK, public sk?: SK) {}

  clone(): Leaf {
    return new Leaf(this.peer.clone(), this.pk.slice(), this.sk?.slice());
  }

  static me(me: Me, init?: { identity_pk: PK; exchange_pk: PK }): Leaf {
    if (init) {
      const { pk, sk } = keypair(keyExchangeReceive(me.identity, init.identity_pk, me.ephemeral, init.exchange_pk));
      return new Leaf(me, pk, sk);
    } else {
      return new Leaf(me, me.ephemeral.pk, me.ephemeral.sk);
    }
  }

  static member(member: Peer, init: PK | { identity: Keypair; exchange: Keypair }): Leaf {
    if (init instanceof Uint8Array) {
      return new Leaf(member, init);
    } else {
      const { pk, sk } = keypair(keyExchangeSend(init.identity, member.identity_pk, init.exchange, member.ephemeral_pk));
      return new Leaf(member, pk, sk);
    }
  }

  get length(): number {
    return 1;
  }

  get isOnMyPath(): boolean {
    return this.peer.isMy;
  }

  split(
    at: PK,
    peer: Peer,
    init: PK[] | { identity: Keypair; exchange: Keypair } | { identity_pk: PK; exchange_pk: PK }
  ): Node | undefined {
    if (equals(at, this.pk)) {
      if (Array.isArray(init)) {
        const leaf_pk = init.shift();
        const node_pk = init.shift();
        if (leaf_pk === undefined || node_pk === undefined) {
          throw new Err(ErrCode.INCONSISTENT_STATE, 'Not enough PKs to process split');
        }
        return new Node(this, Leaf.member(peer, leaf_pk), node_pk);
      } else if (peer instanceof Me && 'identity_pk' in init) {
        return new Node(this, Leaf.me(peer, init));
      } else if ('identity' in init) {
        return new Node(this, Leaf.member(peer, init));
      }
      throw new Err(ErrCode.INCONSISTENT_STATE, "Can't create a member leaf with this init");
    }
    return undefined;
  }

  update(pk: PK): void {
    this.pk = pk;
  }

  *members(): Generator<Leaf> {
    yield this;
  }

  *leaves(): Generator<Leaf> {
    yield this;
  }
}
