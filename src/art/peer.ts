import { crypt } from '..';
import { Err, ErrCode } from '../err';
import { Clonable, Keypair, PK, SI } from '../types';

export class Peer implements Clonable {
  constructor(public identity_pk: PK, public ephemeral_pk: PK, public ephemeral_signature: SI) {
    if (!crypt.verify(this.ephemeral_signature, this.ephemeral_pk, this.identity_pk)) {
      throw new Err(ErrCode.INVALID_SIGNATURE, 'Invalid ephemeral signature');
    }
  }

  clone(): Peer {
    return new Peer(this.identity_pk.slice(), this.ephemeral_pk.slice(), this.ephemeral_signature.slice());
  }

  get isMy(): boolean {
    return false;
  }
}

export class Me extends Peer {
  constructor(public identity: Keypair, public ephemeral: Keypair) {
    super(identity.pk, ephemeral.pk, crypt.sign(ephemeral.pk, identity.sk));
  }

  clone(): Me {
    return new Me(
      { pk: this.identity.pk.slice(), sk: this.identity.sk.slice() },
      { pk: this.ephemeral.pk.slice(), sk: this.ephemeral.sk.slice() }
    );
  }

  get isMy(): boolean {
    return true;
  }
}
