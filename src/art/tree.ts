import { crypt } from '..';
import { Err, ErrCode } from '../err';
import { Keypair } from '../types';
import { Offset } from '../util';
import { Leaf } from './leaf';
import { Node } from './node';
import { Me, Peer } from './peer';

export function createTree(peers: Peer[], init: { identity: Keypair; exchange: Keypair }): Node {
  const initiator = peers[0];
  if (!initiator) {
    throw new Err(ErrCode.INCONSISTENT_STATE, 'Null first per');
  }
  const tree = createTreeRecurcive(peers, init) as Node;
  cleanupTree(tree, initiator);
  return tree;
}

export function cleanupTree(tree: Node, peer: Peer): void {
  const my: (Node | Leaf)[] = Array.from(tree.pathOf(peer));
  for (const member of tree.members()) {
    if (!my.includes(member)) {
      member.sk = undefined;
    }
  }
}

function createTreeRecurcive(peers: Peer[], init: { identity: Keypair; exchange: Keypair }): Node | Leaf {
  switch (peers.length) {
    case 0:
      throw new Err(ErrCode.INCONSISTENT_STATE, 'No peers');
    case 1:
      if (peers[0] instanceof Me) {
        return Leaf.me(peers[0]);
      } else if (peers[0] instanceof Peer) {
        return Leaf.member(peers[0], init);
      } else {
        throw new Err(ErrCode.INCONSISTENT_STATE, 'Unreachable');
      }
    default: {
      const l = leftTreeSize(peers.length);
      const left = createTreeRecurcive(peers.slice(0, l), init);
      const right = createTreeRecurcive(peers.slice(l, peers.length), init);
      return new Node(left, right);
    }
  }
}

function leftTreeSize(numLeaves: number): number {
  return Math.pow(2, Math.ceil(Math.log(numLeaves) / Math.log(2)) - 1);
}

export function serializeTree(data: Uint8Array, view: DataView, offset: Offset, node: Node | Leaf): void {
  if (node instanceof Leaf) {
    view.setUint8(offset.add(1), 0);
    data.set(node.pk, offset.add(crypt.PK_LENGTH));
    data.set(node.peer.identity_pk, offset.add(crypt.PK_LENGTH));
    data.set(node.peer.ephemeral_pk, offset.add(crypt.PK_LENGTH));
    data.set(node.peer.ephemeral_signature, offset.add(crypt.SI_LENGTH));
  } else {
    view.setUint8(offset.add(1), 1);
    data.set(node.pk, offset.add(crypt.PK_LENGTH));
    serializeTree(data, view, offset, node.left);
    serializeTree(data, view, offset, node.right);
  }
}

export function deserializeTree(data: Uint8Array, view: DataView, offset: Offset): Node | Leaf {
  const kind = view.getUint8(offset.add(1));
  const pk = data.slice(offset.add(crypt.PK_LENGTH), offset.value);
  if (kind === 0) {
    const identity_pk = data.slice(offset.add(crypt.PK_LENGTH), offset.value);
    const ephemeral_pk = data.slice(offset.add(crypt.PK_LENGTH), offset.value);
    const ephemeral_signature = data.slice(offset.add(crypt.SI_LENGTH), offset.value);
    return Leaf.member(new Peer(identity_pk, ephemeral_pk, ephemeral_signature), pk);
  } else {
    const left = deserializeTree(data, view, offset);
    const right = deserializeTree(data, view, offset);
    return new Node(left, right, pk);
  }
}
