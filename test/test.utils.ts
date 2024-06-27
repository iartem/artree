import { ART, Keypair, Me, Peer, crypt, keypair } from '../src';

export function generate(n: number): { identity: Keypair; ephemeral: Keypair; ephemeral_signature: Uint8Array }[] {
  return new Array(n).fill(0).map(() => {
    const identity = keypair();
    const ephemeral = keypair();
    return { identity, ephemeral, ephemeral_signature: crypt.sign(ephemeral.pk, identity.sk) };
  });
}

export function referenceGroup(): [ART, ART, ART] {
  const keys = generate(3);

  const art = ART.initiate(
    keys.map(({ identity, ephemeral, ephemeral_signature }, i) =>
      i === 0 ? new Me(identity, ephemeral) : new Peer(identity.pk, ephemeral.pk, ephemeral_signature)
    )
  );

  return [art].concat(keys.slice(1).map((keys) => ART.fromSetupMessage(new Me(keys.identity, keys.ephemeral), art.setupMessage))) as [
    ART,
    ART,
    ART
  ];
}
