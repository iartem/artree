import { crypt } from '../src';
import { Gen, Offset, keyExchangeReceive, keyExchangeSend, keypair } from '../src/util';
import { Peer, Me, Leaf, Node, createTree, serializeTree, deserializeTree } from '../src/art';
import { generate } from './test.utils';

function serDeser(node: Node): Node {
  const data = new Uint8Array(
    node.length * (1 + crypt.PK_LENGTH) + Array.from(node.leaves()).length * (2 * crypt.PK_LENGTH + crypt.SI_LENGTH)
  );
  const offset1 = new Offset();
  serializeTree(data, new DataView(data.buffer), offset1, node);
  offset1.assert(data.length);

  const offset2 = new Offset();
  const de = deserializeTree(data, new DataView(data.buffer), offset2);
  offset2.assert(data.length);
  return de as Node;
}

describe('ART Tree', () => {
  it('should throw with invalid data', () => {
    expect(() => createTree([], { identity: keypair(), exchange: keypair() })).toThrow();
    expect(() => createTree([null as unknown as Peer], { identity: keypair(), exchange: keypair() })).toThrow();
  });

  it('should construct 2-tree', () => {
    const [peer0, peer1] = generate(2);
    if (!peer0 || !peer1) throw new Error();
    const exchange = keypair();
    const peers = [new Me(peer0.identity, peer0.ephemeral), new Peer(peer1.identity.pk, peer1.ephemeral.pk, peer1.ephemeral_signature)];
    const tree = createTree(peers, {
      identity: peer0.identity,
      exchange,
    });

    expect(tree.length).toEqual(3);
    expect(tree).toBeInstanceOf(Node);
    expect(tree.left).toBeInstanceOf(Leaf);
    expect(tree.right).toBeInstanceOf(Leaf);
    expect(tree.left.pk).toEqual(peer0.ephemeral.pk);
    expect(tree.right.pk).toEqual(keypair(keyExchangeSend(peer0.identity, peer1.identity.pk, exchange, peer1.ephemeral.pk)).pk);

    const reverse = serDeser(tree);
    expect(reverse.length).toEqual(3);
    expect(reverse).toBeInstanceOf(Node);
    expect(reverse.left).toBeInstanceOf(Leaf);
    expect(reverse.right).toBeInstanceOf(Leaf);
    expect(reverse.left.pk).toEqual(peer0.ephemeral.pk);
    expect(reverse.right.pk).toEqual(keypair(keyExchangeReceive(peer1.identity, peer0.identity.pk, peer1.ephemeral, exchange.pk)).pk);
    expect(reverse.pk).toEqual(tree.pk);
  });

  it('should construct 3-tree', () => {
    const [peer0, peer1, peer2] = generate(3);
    if (!peer0 || !peer1 || !peer2) throw new Error();
    const exchange = keypair();
    const peers = [
      new Me(peer0.identity, peer0.ephemeral),
      new Peer(peer1.identity.pk, peer1.ephemeral.pk, peer1.ephemeral_signature),
      new Peer(peer2.identity.pk, peer2.ephemeral.pk, peer2.ephemeral_signature),
    ];
    const tree = createTree(peers, {
      identity: peer0.identity,
      exchange,
    });

    expect(tree.length).toEqual(5);
    expect(tree).toBeInstanceOf(Node);
    expect(tree.left).toBeInstanceOf(Node);
    expect(tree.right).toBeInstanceOf(Leaf);
    const n0pk = peer0.ephemeral.pk;
    expect((tree.left as Node).left.pk).toEqual(n0pk);
    const n1 = keypair(keyExchangeSend(peer0.identity, peer1.identity.pk, exchange, peer1.ephemeral.pk));
    expect((tree.left as Node).right.pk).toEqual(n1.pk);
    const n2 = keypair(keyExchangeSend(peer0.identity, peer2.identity.pk, exchange, peer2.ephemeral.pk));
    expect(tree.right.pk).toEqual(n2.pk);

    const n3 = keypair(crypt.hkdf(crypt.getSharedSecret(peer0.ephemeral.sk, n1.pk), undefined, undefined, crypt.SK_LENGTH));
    const n4 = keypair(crypt.hkdf(crypt.getSharedSecret(n3.sk, n2.pk), undefined, undefined, crypt.SK_LENGTH));
    expect(tree.pk).toEqual(n4.pk);

    const reverse = serDeser(tree);
    expect(reverse.length).toEqual(5);
    expect(reverse).toBeInstanceOf(Node);
    expect(reverse.left).toBeInstanceOf(Node);
    expect(reverse.right).toBeInstanceOf(Leaf);

    expect((reverse.left as Node).left.pk).toEqual((tree.left as Node).left.pk);
    expect((reverse.left as Node).right.pk).toEqual((tree.left as Node).right.pk);
    expect(reverse.right.pk).toEqual(keypair(keyExchangeReceive(peer2.identity, peer0.identity.pk, peer2.ephemeral, exchange.pk)).pk);
    expect(reverse.pk).toEqual(tree.pk);
  });

  it('should construct 4-tree', () => {
    const [peer0, peer1, peer2, peer3] = generate(4);
    if (!peer0 || !peer1 || !peer2 || !peer3) throw new Error();
    const exchange = keypair();
    const peers = [
      new Me(peer0.identity, peer0.ephemeral),
      new Peer(peer1.identity.pk, peer1.ephemeral.pk, peer1.ephemeral_signature),
      new Peer(peer2.identity.pk, peer2.ephemeral.pk, peer2.ephemeral_signature),
      new Peer(peer3.identity.pk, peer3.ephemeral.pk, peer3.ephemeral_signature),
    ];
    const tree = createTree(peers, {
      identity: peer0.identity,
      exchange,
    });

    const dh1 = keypair(keyExchangeSend(peer0.identity, peer1.identity.pk, exchange, peer1.ephemeral.pk));
    const dh2 = keypair(keyExchangeSend(peer0.identity, peer2.identity.pk, exchange, peer2.ephemeral.pk));
    const dh3 = keypair(keyExchangeSend(peer0.identity, peer3.identity.pk, exchange, peer3.ephemeral.pk));

    expect(tree.length).toEqual(7);
    expect(tree).toBeInstanceOf(Node);
    expect(tree.left).toBeInstanceOf(Node);
    expect(tree.right).toBeInstanceOf(Node);
    expect((tree.left as Node).left.pk).toEqual(peer0.ephemeral.pk);
    expect((tree.left as Node).right.pk).toEqual(dh1.pk);
    expect((tree.right as Node).left.pk).toEqual(dh2.pk);
    expect((tree.right as Node).right.pk).toEqual(dh3.pk);

    const n2 = keypair(crypt.hkdf(crypt.getSharedSecret(peer0.ephemeral.sk, dh1.pk), undefined, undefined, crypt.SK_LENGTH));
    const n3 = keypair(crypt.hkdf(crypt.getSharedSecret(dh2.sk, dh3.pk), undefined, undefined, crypt.SK_LENGTH));
    const n1 = keypair(crypt.hkdf(crypt.getSharedSecret(n2.sk, n3.pk), undefined, undefined, crypt.SK_LENGTH));
    expect(tree.pk).toEqual(n1.pk);

    const pks = Gen.collect(tree.members(), (n) => n.pk);
    expect(pks.length).toEqual(7);

    const reverse = serDeser(tree);
    expect(reverse.length).toEqual(7);
    expect(reverse).toBeInstanceOf(Node);
    expect(reverse.left).toBeInstanceOf(Node);
    expect(reverse.right).toBeInstanceOf(Node);

    expect((reverse.left as Node).left.pk).toEqual((tree.left as Node).left.pk);
    expect((reverse.left as Node).right.pk).toEqual(
      keypair(keyExchangeReceive(peer1.identity, peer0.identity.pk, peer1.ephemeral, exchange.pk)).pk
    );
    expect(reverse.right.pk).toEqual(tree.right.pk);
    expect(reverse.pk).toEqual(tree.pk);
  });

  it('should split 3-tree at 3rd leaf', () => {
    const [peer0, peer1, peer2, peer3] = generate(4);
    if (!peer0 || !peer1 || !peer2 || !peer3) throw new Error();
    const exchange = keypair();
    const peers = [
      new Me(peer0.identity, peer0.ephemeral),
      new Peer(peer1.identity.pk, peer1.ephemeral.pk, peer1.ephemeral_signature),
      new Peer(peer2.identity.pk, peer2.ephemeral.pk, peer2.ephemeral_signature),
    ];
    const tree = createTree(peers, {
      identity: peer0.identity,
      exchange,
    });
    expect(tree.length).toEqual(5);

    const pks = Gen.collect(tree.members(), (n) => n.pk);
    expect(pks.length).toEqual(5);

    const reverse = serDeser(tree);
    expect(reverse.length).toEqual(5);

    const exchange_new = keypair();
    expect(
      tree.split(tree.right.pk, new Peer(peer3.identity.pk, peer3.ephemeral.pk, peer3.ephemeral_signature), {
        identity: peer0.identity,
        exchange: exchange_new,
      })
    ).toBe(true);
    expect(tree.length).toEqual(7);
    expect(tree.left).toBeInstanceOf(Node);
    expect(tree.right).toBeInstanceOf(Node);
    expect((tree.left as Node).left).toBeInstanceOf(Leaf);
    expect((tree.left as Node).right).toBeInstanceOf(Leaf);
    expect((tree.right as Node).left).toBeInstanceOf(Leaf);
    expect((tree.right as Node).right).toBeInstanceOf(Leaf);

    const dh1 = keypair(keyExchangeSend(peer0.identity, peer1.identity.pk, exchange, peer1.ephemeral.pk));
    const dh2 = keypair(keyExchangeSend(peer0.identity, peer2.identity.pk, exchange, peer2.ephemeral.pk));
    const dh3 = keypair(keyExchangeSend(peer0.identity, peer3.identity.pk, exchange_new, peer3.ephemeral.pk));

    expect((tree.left as Node).left.pk).toEqual(peer0.ephemeral.pk);
    expect((tree.left as Node).right.pk).toEqual(dh1.pk);
    expect((tree.right as Node).left.pk).toEqual(dh2.pk);
    expect((tree.right as Node).right.pk).toEqual(dh3.pk);

    const n2 = keypair(crypt.hkdf(crypt.getSharedSecret(peer0.ephemeral.sk, dh1.pk), undefined, undefined, crypt.SK_LENGTH));
    const n3 = keypair(crypt.hkdf(crypt.getSharedSecret(dh2.sk, dh3.pk), undefined, undefined, crypt.SK_LENGTH));
    const n1 = keypair(crypt.hkdf(crypt.getSharedSecret(n2.sk, n3.pk), undefined, undefined, crypt.SK_LENGTH));
    expect(tree.pk).toEqual(n1.pk);

    expect(
      reverse.split(reverse.right.pk, new Peer(peer3.identity.pk, peer3.ephemeral.pk, peer3.ephemeral_signature), [dh3.pk, n3.pk, n1.pk])
    ).toBe(true);
    expect(reverse.length).toEqual(7);
    expect(reverse.left).toBeInstanceOf(Node);
    expect(reverse.right).toBeInstanceOf(Node);
    expect((reverse.left as Node).left).toBeInstanceOf(Leaf);
    expect((reverse.left as Node).right).toBeInstanceOf(Leaf);
    expect((reverse.right as Node).left).toBeInstanceOf(Leaf);
    expect((reverse.right as Node).right).toBeInstanceOf(Leaf);

    expect((reverse.left as Node).left.pk).toEqual(peer0.ephemeral.pk);
    expect((reverse.left as Node).right.pk).toEqual(dh1.pk);
    expect((reverse.right as Node).left.pk).toEqual(dh2.pk);
    expect((reverse.right as Node).right.pk).toEqual(dh3.pk);
    expect(reverse.pk).toEqual(n1.pk);

    // expect((reverse.left as Node).left.pk).toEqual((tree.left as Node).left.pk);
    // expect((reverse.left as Node).right.pk).toEqual(
    //   keypair(keyExchangeReceive(peer1.identity, peer0.identity.pk, peer1.ephemeral, exchange.pk)).pk
    // );
    // expect(reverse.right.pk).toEqual(tree.right.pk);
    expect(reverse.pk).toEqual(tree.pk);
  });
});
