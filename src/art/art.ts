import { Clonable, Keypair, PK, SK, crypt } from '..';
import { Err, ErrCode } from '../err';
import { cleanupTree, createTree, deserializeTree, serializeTree } from './tree';
import { concat, split, Offset, equals, keypair, Gen, keyExchangeReceive, keyExchangeSend } from '../util';
import { Me, Peer } from './peer';
import { Node } from './node';
import { Leaf } from './leaf';

export class ART implements Clonable {
  stage: Keypair;

  private constructor(public me: Me, public root: Node, public setupMessage: Uint8Array, stage?: SK | Keypair) {
    if (stage instanceof Uint8Array) {
      // fromSplitMessage
      this.stage = keypair(stage);
      this.stage = this.deriveStageKey();
    } else if (stage && 'sk' in stage) {
      // clone()
      this.stage = stage;
    } else {
      // all others
      this.stage = this.deriveStageKey();
    }
  }

  /**
   * Clone ART instance
   */
  clone(): ART {
    return new ART(this.me.clone(), this.root.clone(), this.setupMessage.slice(), {
      sk: this.stage.sk.slice(),
      pk: this.stage.pk.slice(),
    });
  }

  /**
   * Get my leaf
   */
  get leaf(): Leaf {
    const leaf = this.leafOf(this.me);
    if (!leaf) {
      throw new Err(ErrCode.INCONSISTENT_STATE, 'No my leaves in the tree');
    }
    return leaf;
  }

  /**
   * Get leaf of any peer
   * @param peer can be either Peer instance (then compared with ===), or peer identity PK / ephemeral PK
   */
  leafOf(peer: Peer | PK): Leaf | undefined {
    return Gen.find(
      this.root.leaves(),
      (l) => l.peer === peer || (peer instanceof Uint8Array && (equals(l.peer.identity_pk, peer) || equals(l.peer.ephemeral_pk, peer)))
    );
  }

  /**
   * Get first leaf, that is a leaf of tree initiator
   */
  get initiator(): Leaf {
    let node: Node = this.root;
    while (node.left) {
      if (node.left instanceof Node) {
        node = node.left;
      } else {
        break;
      }
    }
    if (node.left instanceof Leaf) {
      return node.left;
    } else {
      throw new Err(ErrCode.INCONSISTENT_STATE, 'No leftmost leaf');
    }
  }

  /**
   * Check if tree is made by initiator
   */
  get isInitiator(): boolean {
    return this.initiator.peer === this.me;
  }

  /**
   * Get list of tree Peers
   */
  get peers(): Peer[] {
    return Gen.collect(this.root.leaves(), (l) => l.peer);
  }

  /**
   * Get all leaves
   */
  get leaves(): Leaf[] {
    return Gen.collect(this.root.leaves(), (l) => l);
  }

  /**
   * Derive current stage key from the tree.
   *
   * @returns stage key
   */
  private deriveStageKey(): Keypair {
    const root_sk = this.root.sk;
    if (!root_sk) {
      throw new Err(ErrCode.INCONSISTENT_STATE, 'Unreachable');
    }
    const ikm = new Uint8Array((this.stage ? crypt.SK_LENGTH : 0) + root_sk.length + this.root.length * crypt.PK_LENGTH);
    const offset = new Offset();
    if (this.stage) {
      ikm.set(this.stage.sk, offset.add(crypt.SK_LENGTH));
    }
    ikm.set(root_sk, offset.add(crypt.SK_LENGTH));
    for (const member of this.root.members()) {
      ikm.set(member.pk, offset.add(crypt.PK_LENGTH));
    }
    offset.assert(ikm.length);

    const info = concat(...Gen.collect(this.root.leaves(), (leaf) => leaf.peer.identity_pk));

    return (this.stage = keypair(crypt.hkdf(ikm, undefined, info, crypt.SK_LENGTH)));
  }

  /**
   * Initiate new ART Tree with given members. First member must be instance of `Me`, that is tree initiator.
   *
   * @param peers tree members
   * @returns
   */
  static initiate(peers: Peer[]): ART {
    if (!(peers[0] instanceof Me)) {
      throw new Err(ErrCode.INCONSISTENT_STATE, 'First peer must be initiator');
    }
    if (peers.length < 2) {
      throw new Err(ErrCode.INVALID_ARGUMENT, 'Minimal number of peers for ART is 2');
    }
    const exchange = keypair();
    const me = peers[0];
    const tree = createTree(peers, { identity: me.identity, exchange });

    const message = ART.snapshot(tree, me, exchange);

    return new ART(me, tree, message);
  }

  /**
   * Reconstruction of a tree created by `ART.initiate()` from setup message
   *
   * @param me my peer
   * @param message setup message from initiator peer
   * @returns
   */
  static fromSetupMessage(me: Me, message: Uint8Array): ART {
    const { tree, exchange_pk, signature } = ART.decodeSnapshot(message);
    const initiatorLeaf = Gen.find(tree.leaves(), () => true);
    if (!initiatorLeaf) {
      throw new Err(ErrCode.INCONSISTENT_STATE, 'Unreachable');
    }

    if (!crypt.verify(signature, message.subarray(0, -crypt.SI_LENGTH), initiatorLeaf.peer.identity_pk)) {
      throw new Err(ErrCode.INVALID_SIGNATURE, 'Invalid signature of setup message');
    }

    const myLeaf = Leaf.me(me, {
      identity_pk: initiatorLeaf.peer.identity_pk,
      exchange_pk,
    });

    for (const member of tree.members()) {
      if (member instanceof Node) {
        if (member.left instanceof Leaf && equals(member.left.peer.ephemeral_pk, me.ephemeral.pk)) {
          member.left = myLeaf;
        } else if (member.right instanceof Leaf && equals(member.right.peer.ephemeral_pk, me.ephemeral.pk)) {
          member.right = myLeaf;
        }
      }
    }

    for (const member of tree.pathOf(me)) {
      if (member instanceof Node) {
        member.derive();
      }
    }

    return new ART(me, tree, message);
  }

  /**
   * Reconstruction of a tree created by `ART.split()` from split snapshot & message
   *
   * @param me my peer
   * @param snapshot last known snapshot of the tree
   * @param splitMessage split message
   * @returns
   */
  static fromSplitMessage(me: Me, snapshot: Uint8Array, splitMessage: Uint8Array): ART {
    const {
      at,
      identity_pk,
      ephemeral_pk,
      ephemeral_signature,
      signature: messageSignature,
      splitter_signature,
    } = ART.parseSplitMessage(splitMessage);
    if (
      !equals(me.identity_pk, identity_pk) ||
      !equals(me.ephemeral_pk, ephemeral_pk || !equals(me.ephemeral_signature, ephemeral_signature))
    ) {
      throw new Err(ErrCode.INVALID_ARGUMENT, 'Split message is for another peer');
    }

    const { tree, exchange_pk, signature, stage_sk } = ART.decodeSnapshot(snapshot, me);
    if (!stage_sk) {
      throw new Err(ErrCode.INCONSISTENT_STATE, 'No stage key in split snapshot');
    }

    const initiatorLeaf = Gen.find(tree.leaves(), () => true);
    if (!initiatorLeaf) {
      throw new Err(ErrCode.INCONSISTENT_STATE, 'Unreachable');
    }

    if (!crypt.verify(signature, snapshot.subarray(0, -crypt.SI_LENGTH), initiatorLeaf.peer.identity_pk)) {
      if (!crypt.verify(signature, snapshot.subarray(0, -crypt.SI_LENGTH), me.identity_pk)) {
        throw new Err(ErrCode.INVALID_SIGNATURE, 'Invalid signature of split snapshot');
      }
    }

    if (!crypt.verify(messageSignature, splitMessage.subarray(0, -crypt.SI_LENGTH), keypair(stage_sk).pk)) {
      throw new Err(ErrCode.INVALID_SIGNATURE, 'Invalid signature of split message');
    }

    const leaf = Gen.find(tree.leaves(), (leaf) => equals(leaf.pk, at));
    if (!leaf) {
      throw new Err(ErrCode.INVALID_ARGUMENT, 'No leaf to split at');
    }

    let init_pk;
    if (Gen.find(tree.leaves(), (l) => equals(l.peer.identity_pk, identity_pk))) {
      if (!crypt.verify(splitter_signature, splitMessage.subarray(0, -2 * crypt.SI_LENGTH), leaf.peer.ephemeral_pk)) {
        throw new Err(ErrCode.INVALID_SIGNATURE, 'Invalid signature of split message creator');
      }
      init_pk = leaf.peer.ephemeral_pk;
    } else {
      if (!crypt.verify(splitter_signature, splitMessage.subarray(0, -2 * crypt.SI_LENGTH), initiatorLeaf.peer.ephemeral_pk)) {
        throw new Err(ErrCode.INVALID_SIGNATURE, 'Invalid signature of split message creator');
      }
      init_pk = initiatorLeaf.peer.ephemeral_pk;
    }

    if (!tree.split(at, me, { identity_pk: init_pk, exchange_pk })) {
      throw new Err(ErrCode.INVALID_ARGUMENT, 'No such member to split at');
    }

    return new ART(me, tree, snapshot, stage_sk);
  }

  /**
   * Update my ephemeral key with new one. This is main "ratcheting" method, it updates
   * stage key. Returned message must be distributed to all other peers, preferrably in encrypted form.
   *
   * @returns update key message
   */
  updateKey(key = keypair()): Uint8Array {
    const updates = Gen.collect(this.root.pathOf(this.me), (node: Node | Leaf) => {
      const old = node.pk;
      if (node instanceof Leaf) {
        const { sk, pk } = key;
        this.me.ephemeral = { sk, pk };
        this.me.ephemeral_pk = pk;
        this.me.ephemeral_signature = crypt.sign(pk, this.me.identity.sk);
        node.pk = pk;
        node.sk = sk;
        return [old, node.pk];
      } else {
        node.derive();
        return [old, node.pk];
      }
    }).flat();

    const message = new Uint8Array(updates.reduce((a, b) => a + b.length, 0) + crypt.SI_LENGTH + crypt.SI_LENGTH);
    const offset = new Offset();
    updates.forEach((pk) => message.set(pk, offset.add(crypt.PK_LENGTH)));
    message.set(this.me.ephemeral_signature, offset.add(crypt.SI_LENGTH));
    const signature = crypt.sign(message.subarray(0, -crypt.SI_LENGTH), this.stage.sk);
    message.set(signature, offset.add(crypt.SI_LENGTH));
    offset.assert(message.length);

    this.deriveStageKey();

    return message;
  }

  /**
   * Process key update message from another peer. Updates stage key locally.
   */
  processKeyUpdate(message: Uint8Array): void {
    const pk_count = (message.length - crypt.SI_LENGTH - crypt.SI_LENGTH) / crypt.PK_LENGTH;
    if (Math.round(pk_count) !== pk_count) {
      throw new Err(ErrCode.INVALID_ARGUMENT, 'Invalid key update message length');
    }
    if (!pk_count || pk_count % 2 !== 0) {
      throw new Err(ErrCode.INVALID_ARGUMENT, 'Invalid number of pks');
    }
    const offset = new Offset(0);
    const pks = split(message, offset, crypt.PK_LENGTH, pk_count);
    if (pks.length < 2) {
      throw new Err(ErrCode.INCONSISTENT_STATE, 'Unreachable');
    }

    const ephemeral_signature = message.slice(offset.add(crypt.SI_LENGTH), offset.value);
    const signature = message.slice(offset.add(crypt.SI_LENGTH), offset.value);
    offset.assert(message.length);

    if (!crypt.verify(signature, message.subarray(0, -crypt.SI_LENGTH), this.stage.pk)) {
      throw new Err(ErrCode.INVALID_SIGNATURE, 'Invalid signature of key update message');
    }

    const [leafPk, peerPk] = pks;
    if (!leafPk || !peerPk) {
      throw new Err(ErrCode.INCONSISTENT_STATE, 'Not enough PKs in key update');
    }
    const leaf = Gen.find(this.root.leaves(), (l) => equals(leafPk, l.pk));
    if (!leaf) {
      throw new Err(ErrCode.INVALID_ARGUMENT, 'No such leaf');
    }

    if (!crypt.verify(ephemeral_signature, peerPk, leaf.peer.identity_pk)) {
      throw new Err(ErrCode.INVALID_SIGNATURE, 'Invalid key signature in key update message');
    }

    leaf.peer.ephemeral_pk = peerPk;
    leaf.peer.ephemeral_signature = ephemeral_signature;

    for (const node of this.root.pathOf(leaf.peer)) {
      const old = pks.shift();
      const neo = pks.shift();
      if (!old || !neo || !equals(node.pk, old)) {
        throw new Err(ErrCode.INVALID_ARGUMENT, 'Invalid old PK');
      }
      node.update(neo);
    }

    if (pks.length) {
      throw new Err(ErrCode.INCONSISTENT_STATE, 'Some PKs left for update');
    }

    this.deriveStageKey();
  }

  /**
   * Split one of the leaves into 2 adding new one to the right of old one.
   * Can be used in 2 ways:
   * - [at = undefined] any tree member can split their own leaf with new peer which has the same identity key
   * - [at != undefined] tree initiator can split any tree leaf
   *
   * @param peer new Peer to add
   * @param at leaf PK of the leaf to split (only for initiator)
   * @returns {message, snapshot}. Message must be sent to all other peers, snapshot & message must be sent to new peer.
   */
  split(peer: Peer, at?: Uint8Array): { message: Uint8Array; snapshot: Uint8Array } {
    const exchange = keypair();
    let leaf: Leaf;
    let encryption_key;

    if (Gen.find(this.root.leaves(), (l) => equals(l.peer.identity_pk, peer.identity_pk))) {
      leaf = this.leaf;
      encryption_key = this.me.identity.sk;
    } else {
      if (!this.isInitiator) {
        throw new Err(ErrCode.INVALID_ARGUMENT, 'You can only split your node with a peer with the same identity key');
      }
      const l = Gen.find(this.root.leaves(), (l) => equals(l.pk, at || this.leaf.pk));
      if (!l) {
        throw new Err(ErrCode.INVALID_ARGUMENT, 'No such leaf to split at');
      }
      leaf = l;
      encryption_key = keyExchangeSend(this.me.identity, peer.identity_pk, exchange, peer.ephemeral_pk);
    }

    const snapshot = ART.snapshot(this.root, this.me, exchange, { sk: this.stage.sk, encryption_key });

    if (
      !this.root.split(leaf.pk, peer, {
        identity: this.me.ephemeral, // otherwise new peer is going to have DH(c1, C1) key
        exchange,
      })
    ) {
      throw new Err(ErrCode.INVALID_ARGUMENT, 'No such member to split at');
    }

    const pks = Gen.collect(this.root.pathOf(peer), (n) => n.pk);

    const message = new Uint8Array(crypt.PK_LENGTH * 3 + crypt.SI_LENGTH + pks.length * crypt.PK_LENGTH + crypt.SI_LENGTH * 2);
    const offset = new Offset();

    message.set(leaf.pk, offset.add(crypt.PK_LENGTH));
    message.set(peer.identity_pk, offset.add(crypt.PK_LENGTH));
    message.set(peer.ephemeral_pk, offset.add(crypt.PK_LENGTH));
    message.set(peer.ephemeral_signature, offset.add(crypt.SI_LENGTH));
    pks.forEach((pk) => message.set(pk, offset.add(crypt.PK_LENGTH)));
    message.set(crypt.sign(message.subarray(0, -2 * crypt.SI_LENGTH), this.me.ephemeral.sk), offset.add(crypt.SI_LENGTH));
    message.set(crypt.sign(message.subarray(0, -crypt.SI_LENGTH), this.stage.sk), offset.add(crypt.SI_LENGTH));

    offset.assert(message.length);

    this.deriveStageKey();

    cleanupTree(this.root, this.me);

    return { message, snapshot };
  }

  /**
   * Process split message created by other peers. Update stage key.
   *
   * @param message Split message made by {@link split} method
   */
  processSplit(message: Uint8Array): void {
    const { at, identity_pk, ephemeral_pk, ephemeral_signature, pks, signature, splitter_signature } = ART.parseSplitMessage(message);

    if (!crypt.verify(signature, message.subarray(0, -crypt.SI_LENGTH), this.stage.pk)) {
      throw new Err(ErrCode.INVALID_SIGNATURE, 'Invalid signature of split message');
    }

    const leaf = Gen.find(this.root.leaves(), (leaf) => equals(leaf.pk, at));
    if (!leaf) {
      throw new Err(ErrCode.INVALID_ARGUMENT, 'No leaf to split at');
    }
    if (!crypt.verify(splitter_signature, message.subarray(0, -2 * crypt.SI_LENGTH), leaf.peer.ephemeral_pk)) {
      if (!crypt.verify(splitter_signature, message.subarray(0, -2 * crypt.SI_LENGTH), this.initiator.peer.ephemeral_pk)) {
        throw new Err(ErrCode.INVALID_SIGNATURE, 'Invalid signature of split message creator');
      }
    }

    const peer = new Peer(identity_pk, ephemeral_pk, ephemeral_signature);
    if (!this.root.split(at, peer, pks)) {
      throw new Err(ErrCode.INVALID_ARGUMENT, 'No such member to split at');
    }

    if (pks.length) {
      throw new Err(ErrCode.INCONSISTENT_STATE, 'Some PKs left for update');
    }

    this.deriveStageKey();
  }

  /**
   * Create tree snapshot containing all node PKs & peers identity PK, ephemeral PK & ephemeral signature.
   * Snapshot is used in setup message & split snapshot, therefore it also has exchange key for new peers.
   */
  private static snapshot(tree: Node, me: Me, exchange: Keypair, stage?: { sk: SK; encryption_key: SK }) {
    const peers = Gen.collect(tree.leaves(), (l) => l.peer);
    const snapshot = new Uint8Array(
      peers.length * crypt.PK_LENGTH + // peers' PKs
        peers.length * crypt.PK_LENGTH + // peers' ephemeral PKs
        peers.length * crypt.SI_LENGTH + // peers' ephemeral signatures
        (peers.length * 2 - 1) * 1 + // node & leaf kind uint8s
        (peers.length * 2 - 1) * crypt.PK_LENGTH + // node & leaf PKs
        crypt.PK_LENGTH + // exchange key PK
        (stage ? crypt.SK_LENGTH + crypt.ENCRYPTION_PREFIX_LENGTH + crypt.ENCRYPTION_SUFFIX_LENGTH : 0) +
        crypt.SI_LENGTH // signature
    );
    const view = new DataView(snapshot.buffer, snapshot.byteOffset);
    const offset = new Offset();
    serializeTree(snapshot, view, offset, tree);
    snapshot.set(exchange.pk, offset.add(crypt.PK_LENGTH));
    if (stage) {
      snapshot.set(
        crypt.encrypt(stage.sk, stage.encryption_key),
        offset.add(crypt.SK_LENGTH + crypt.ENCRYPTION_PREFIX_LENGTH + crypt.ENCRYPTION_SUFFIX_LENGTH)
      );
    }

    const signature = crypt.sign(snapshot.subarray(0, -crypt.SI_LENGTH), me.identity.sk);
    snapshot.set(signature, offset.add(crypt.SI_LENGTH));

    offset.assert(snapshot.length);
    return snapshot;
  }

  /**
   * Decode snapshot into usable types
   */
  private static decodeSnapshot(message: Uint8Array, me?: Me) {
    const view = new DataView(message.buffer, message.byteOffset);
    const offset = new Offset(0);
    const tree = deserializeTree(message, view, offset) as Node;
    const exchange_pk = message.slice(offset.add(crypt.PK_LENGTH), offset.value);
    let stage_sk = undefined;
    if (me) {
      const peers = Gen.collect(tree.leaves(), (l) => l.peer);
      const initiator = peers[0];
      if (!initiator) {
        throw new Err(ErrCode.INCONSISTENT_STATE, 'Unreachable');
      }
      let encryption_key;
      switch (peers.findIndex((peer) => equals(peer.identity_pk, me.identity_pk))) {
        case -1:
          encryption_key = keyExchangeReceive(me.identity, initiator.identity_pk, me.ephemeral, exchange_pk);
          break;
        default:
          encryption_key = me.identity.sk;
      }
      stage_sk = crypt.decrypt(
        message.slice(offset.add(crypt.SK_LENGTH + crypt.ENCRYPTION_SUFFIX_LENGTH + crypt.ENCRYPTION_PREFIX_LENGTH), offset.value),
        encryption_key
      );
      if (stage_sk === null) {
        throw new Err(ErrCode.INVALID_SIGNATURE, 'Failed to decrypt stage key');
      }
    }
    const signature = message.slice(offset.add(crypt.SI_LENGTH), offset.value);
    offset.assert(message.length);

    return { tree, exchange_pk, signature, stage_sk };
  }

  /**
   * Parse split message into usable types.
   */
  private static parseSplitMessage(message: Uint8Array) {
    if (message.length < crypt.PK_LENGTH * 3 + crypt.SI_LENGTH * 3) {
      throw new Err(ErrCode.INVALID_ARGUMENT, 'Invalid split message length');
    }
    const pks_length = (message.length - crypt.PK_LENGTH * 3 - crypt.SI_LENGTH * 3) / crypt.PK_LENGTH;
    if (Math.round(pks_length) !== pks_length) {
      throw new Err(ErrCode.INVALID_ARGUMENT, 'Invalid split message length!');
    }

    const offset = new Offset();
    const at = message.slice(offset.add(crypt.PK_LENGTH), offset.value);
    const identity_pk = message.slice(offset.add(crypt.PK_LENGTH), offset.value);
    const ephemeral_pk = message.slice(offset.add(crypt.PK_LENGTH), offset.value);
    const ephemeral_signature = message.slice(offset.add(crypt.SI_LENGTH), offset.value);
    const pks = split(message, offset, crypt.PK_LENGTH, pks_length);
    const splitter_signature = message.slice(offset.add(crypt.SI_LENGTH), offset.value);
    const signature = message.slice(offset.add(crypt.SI_LENGTH), offset.value);

    offset.assert(message.length);
    return { at, identity_pk, ephemeral_pk, ephemeral_signature, pks, signature, splitter_signature };
  }
}
