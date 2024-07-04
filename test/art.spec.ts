import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { generate, referenceGroup } from './test.utils';
import { ART, Me, Peer } from '../src/art/index';
import { equals, keypair, printTree, toFirstThree, toHex } from '../src/util';
import { crypt } from '../src';

describe('ART', () => {
  beforeEach(() => {
    global.console = require('console');
  });

  describe('coverage tests', () => {
    it('should throw with null me', () => {
      const [a] = referenceGroup();
      Object.assign(a, { me: null });
      expect(() => a.leaf).toThrow();
    });

    it('should throw with non me first peer on initiate', () => {
      const [a, b] = generate(2);
      if (!a || !b) throw new Error();
      expect(() => {
        ART.initiate([
          new Peer(a.identity.pk, a.ephemeral.pk, a.ephemeral_signature),
          new Peer(b.identity.pk, b.ephemeral.pk, b.ephemeral_signature),
        ]);
      }).toThrow();
    });

    it('should throw with single peer on initiate', () => {
      const [a] = generate(1);
      if (!a) throw new Error();
      expect(() => {
        ART.initiate([new Me(a.identity, a.ephemeral)]);
      }).toThrow();
    });

    it('should return peers & leaves', () => {
      const [a] = referenceGroup();
      expect(a.peers.length).toEqual(3);
      expect(a.leaves.length).toEqual(3);
    });

    it('Peer should throw if ephemeral key signature is invalud', () => {
      const [a] = generate(1);
      if (!a) throw new Error();
      expect(() => {
        new Peer(a.identity.pk, a.ephemeral.pk, a.ephemeral.pk);
      }).toThrow();
      expect(() => {
        new Peer(a.identity.pk, a.ephemeral.pk, a.ephemeral_signature);
      }).not.toThrow();
    });
  });

  it('should work', () => {
    const keys = new Array(3).fill(0).map(() => {
      const identity = keypair(); // {sk: Uint8Array, pk: Uint8Array}, Secret Key & Private Key
      const ephemeral = keypair();
      const ephemeral_signature = secp256k1.sign(sha256(ephemeral.pk), identity.sk).toCompactRawBytes();
      return { identity, ephemeral, ephemeral_signature };
    });
    const [k0, k1, k2] = keys;
    if (!k0 || !k1 || !k2) throw new Error();

    // Alice initiates ART
    const alice = ART.initiate(
      keys.map(({ identity, ephemeral, ephemeral_signature }, i) => {
        if (i === 0) {
          // initiator knows own secret keys
          return new Me(identity, ephemeral);
        } else {
          // initiator knows only public keys & signature of other members
          return new Peer(identity.pk, ephemeral.pk, ephemeral_signature);
        }
      })
    );

    // Alice also generated setup message which she needs to send to other members
    // The message should be encrypted with DH key of each member
    const setupMessage = alice.setupMessage;

    // Bob receives setup message and joins the group
    // He only needs setup message and his identity & ephemeral keys to start turning the tree
    const bob = ART.fromSetupMessage(new Me(k1.identity, k1.ephemeral), setupMessage);
    expect(bob.stage.sk).toEqual(alice.stage.sk); // look Ma, same keys!

    // Charlie also joins
    const charlie = ART.fromSetupMessage(new Me(k2.identity, k2.ephemeral), setupMessage);
    expect(charlie.stage.sk).toEqual(alice.stage.sk);

    // Each member can update their key
    // the only requirement - key updates cannot be made in parallel
    const bobUpdateMessage = bob.updateKey();
    alice.processKeyUpdate(bobUpdateMessage);
    expect(bob.stage.sk).toEqual(alice.stage.sk);

    const aliceUpdateMessage = alice.updateKey();
    // this won't work until Bob's key update is processed by Charlie
    // because Charlie won't be able to confirm aliceUpdateMessage - it's one step ahead
    // charlie.processKeyUpdate(aliceUpdateMessage);

    // let's get back to order
    charlie.processKeyUpdate(bobUpdateMessage);
    charlie.processKeyUpdate(aliceUpdateMessage);
    bob.processKeyUpdate(aliceUpdateMessage);
    expect(bob.stage.sk).toEqual(alice.stage.sk);
    expect(charlie.stage.sk).toEqual(alice.stage.sk);

    // now Charlie opens chat from another device, let's add new node to the tree
    // ARTree allows following modes of tree growing:
    // - any member can split it's own leaf as long as identity key for new tree member is the same as the one who splits
    // - initiator can split any leaf
    // !!!NOTE!!!: This is potentially dangerous operation as it allows a malicious user to join the tree with acceptance of just one member.
    //             ARTree just provides a way to do it. Whether to use it, restrict it or not use it at all is up to you.
    const charliePhoneKeys = (() => {
      const identity = charlie.me.identity;
      const ephemeral = keypair();
      const ephemeral_signature = secp256k1.sign(sha256(ephemeral.pk), identity.sk).toCompactRawBytes();
      return { identity, ephemeral, ephemeral_signature };
    })();
    const charliePhoneSplit = charlie.split(
      new Peer(charliePhoneKeys.identity.pk, charliePhoneKeys.ephemeral.pk, charliePhoneKeys.ephemeral_signature)
    );

    // in order to reconstruct the tree, phone needs to use new snapshot
    const charliePhone = ART.fromSplitMessage(
      new Me(charliePhoneKeys.identity, charliePhoneKeys.ephemeral),
      charliePhoneSplit.snapshot,
      charliePhoneSplit.message
    );
    [alice, bob].forEach((art) => art.processSplit(charliePhoneSplit.message));
    expect(bob.stage.sk).toEqual(alice.stage.sk);
    expect(charlie.stage.sk).toEqual(alice.stage.sk);
    expect(charliePhone.stage.sk).toEqual(alice.stage.sk);

    // let's check phone turns the ratchet just as well as others
    const charliePhoneUpdateMessage = charliePhone.updateKey();
    [alice, bob, charlie].forEach((art) => art.processKeyUpdate(charliePhoneUpdateMessage));
    expect(bob.stage.sk).toEqual(alice.stage.sk);
    expect(charlie.stage.sk).toEqual(alice.stage.sk);
    expect(charliePhone.stage.sk).toEqual(alice.stage.sk);

    // ... and finally, let's bring new member to the tree
    // only tree initiator, that is Alice, can add members at not her own nodes
    const dylanKeys = (() => {
      const identity = keypair();
      const ephemeral = keypair();
      const ephemeral_signature = secp256k1.sign(sha256(ephemeral.pk), identity.sk).toCompactRawBytes();
      return { identity, ephemeral, ephemeral_signature };
    })();
    const bobsLeaf = alice.leafOf(bob.me.identity_pk);
    if (!bobsLeaf) throw new Error();
    const dylanSplit = alice.split(new Peer(dylanKeys.identity.pk, dylanKeys.ephemeral.pk, dylanKeys.ephemeral_signature), bobsLeaf.pk);
    [bob, charlie, charliePhone].forEach((art) => art.processSplit(dylanSplit.message));
    expect(bob.stage.sk).toEqual(alice.stage.sk);
    expect(charlie.stage.sk).toEqual(alice.stage.sk);
    expect(charliePhone.stage.sk).toEqual(alice.stage.sk);

    const dylan = ART.fromSplitMessage(new Me(dylanKeys.identity, dylanKeys.ephemeral), dylanSplit.snapshot, dylanSplit.message);
    expect(dylan.stage.sk).toEqual(alice.stage.sk);

    // thanks for reading :)
  });

  it('should turn the ratchet & grow', () => {
    const [p0, p1, p2, p3, p4, p5] = generate(6);
    if (!p0 || !p1 || !p2 || !p3 || !p4 || !p5) throw Error();

    const art0 = ART.initiate([
      new Me(p0.identity, p0.ephemeral),
      new Peer(p1.identity.pk, p1.ephemeral.pk, p1.ephemeral_signature),
      new Peer(p2.identity.pk, p2.ephemeral.pk, p2.ephemeral_signature),
      new Peer(p3.identity.pk, p3.ephemeral.pk, p3.ephemeral_signature),
    ]);

    const art1 = ART.fromSetupMessage(new Me(p1.identity, p1.ephemeral), art0.setupMessage);
    const art2 = ART.fromSetupMessage(new Me(p2.identity, p2.ephemeral), art0.setupMessage);
    const art3 = ART.fromSetupMessage(new Me(p3.identity, p3.ephemeral), art0.setupMessage);
    const arts = [art0, art1, art2, art3];

    arts.forEach((art) => expect(art.stage.sk).toEqual(art0.stage.sk));

    for (const art of arts) {
      const update = art.updateKey();
      arts
        .filter((a) => a !== art)
        .forEach((a) => {
          a.processKeyUpdate(update);
          expect(a.stage).toEqual(art.stage);
        });
    }

    const peer4 = new Peer(p4.identity.pk, p4.ephemeral.pk, p4.ephemeral_signature);
    const myleaf = art0.leafOf(art0.me.identity_pk);
    if (!myleaf) throw new Error();
    const split4 = art0.split(peer4, myleaf.pk);
    for (const art of arts.filter((a) => a !== art0)) {
      art.processSplit(split4.message);
      expect(art0.stage).toEqual(art.stage);
    }

    const peer5 = new Peer(p5.identity.pk, p5.ephemeral.pk, p5.ephemeral_signature);
    const peer3leaf = art0.leafOf(art3.me.identity_pk);
    if (!peer3leaf) throw new Error();
    const split5 = art0.split(peer5, peer3leaf.pk);
    for (const art of arts.filter((a) => a !== art0)) {
      art.processSplit(split5.message);
      expect(art0.stage).toEqual(art.stage);
    }

    arts.forEach((art) => expect(art).toEqual(art.clone()));
  });

  it('double adding', () => {
    const [p0, p1, p2, p3] = generate(4);
    if (!p0 || !p1 || !p2 || !p3) throw Error();

    const art0 = ART.initiate([new Me(p0.identity, p0.ephemeral), new Peer(p1.identity.pk, p1.ephemeral.pk, p1.ephemeral_signature)]);
    printTree(art0.root, 0, toHex);

    const art1 = ART.fromSetupMessage(new Me(p1.identity, p1.ephemeral), art0.setupMessage);

    const art1leaf = art0.leafOf(art1.me.identity_pk);
    if (!art1leaf) throw new Error();
    const add2 = art0.split(new Peer(p2.identity.pk, p2.ephemeral.pk, p2.ephemeral_signature), art1leaf.pk);
    const art2 = ART.fromSplitMessage(new Me(p2.identity, p2.ephemeral), add2.snapshot, add2.message);
    const arts = [art0, art1, art2];
    art1.processSplit(add2.message);
    arts.forEach((art) => expect(art.stage.sk).toEqual(art0.stage.sk));

    [art1, art2, art1, art0].forEach((art) => {
      const update = art.updateKey();
      arts.filter((other) => other !== art).forEach((other) => other.processKeyUpdate(update));
    });

    const add3 = art0.split(new Peer(p3.identity.pk, p3.ephemeral.pk, p3.ephemeral_signature), art1leaf.pk);

    expect(() => {
      ART.fromSplitMessage(new Me(keypair(), keypair()), add3.snapshot, add3.message);
    }).toThrow();

    expect(() => {
      ART.fromSplitMessage(new Me(p3.identity, p3.ephemeral), art0.setupMessage, add3.message);
    }).toThrow();

    const art3 = ART.fromSplitMessage(new Me(p3.identity, p3.ephemeral), add3.snapshot, add3.message);
    arts.push(art3);

    art1.processSplit(add3.message);
    art2.processSplit(add3.message);

    expect(art1.stage.sk).toEqual(art0.stage.sk);
    expect(art2.stage.sk).toEqual(art0.stage.sk);
    expect(art3.stage.sk).toEqual(art0.stage.sk);
  });

  it('should successfully perform randomized worload test', () => {
    const member_counts = [2, Math.floor(Math.random() * 10 + 2), Math.floor(Math.random() * 50 + 12)];
    for (const member_count of member_counts) {
      const keys = generate(member_count);

      const init = ART.initiate(
        keys.map(({ identity, ephemeral, ephemeral_signature }, i) =>
          i === 0 ? new Me(identity, ephemeral) : new Peer(identity.pk, ephemeral.pk, ephemeral_signature)
        )
      );

      const rest = keys.slice(1).map((keys) => ART.fromSetupMessage(new Me(keys.identity, keys.ephemeral), init.setupMessage));

      const all = () => [init].concat(rest);

      all().forEach((art) => {
        console.log(`=== init ${all().indexOf(art)}th: ${toFirstThree(art.me.identity.pk)}`);
      });

      const pick = (): ART => {
        const arts = all();
        return arts[Math.floor(arts.length * Math.random())] as ART;
      };

      let operations = 30;
      while (operations--) {
        const picked = pick();
        const non_picked = all().filter((a) => a !== picked);
        const non_initiators = all().filter((a) => a !== init);

        switch (Math.floor(Math.random() * 3)) {
          case 0: {
            const update = picked.updateKey();
            console.log(`updating key for ${all().indexOf(picked)}th ${toFirstThree(picked.me.identity.pk)}`);
            non_picked.forEach((member) => {
              member.processKeyUpdate(update);
              expect(member.stage).toEqual(picked.stage);
            });
            break;
          }

          case 1: {
            const phone = {
              identity: picked.me.identity,
              ephemeral: keypair(),
            };
            console.log(
              `adding phone ${toFirstThree(phone.ephemeral.pk)} to ${all().indexOf(picked)}th ${toFirstThree(phone.identity.pk)}`
            );
            const phoneSplit = picked.split(
              new Peer(phone.identity.pk, phone.ephemeral.pk, crypt.sign(phone.ephemeral.pk, phone.identity.sk))
            );

            non_picked.forEach((member) => {
              member.processSplit(phoneSplit.message);
              if (!equals(member.stage.sk, picked.stage.sk)) {
                printTree(member.root);
                printTree(picked.root);
                expect(member.stage).toEqual(picked.stage);
              }
            });

            const phoneArt = ART.fromSplitMessage(new Me(phone.identity, phone.ephemeral), phoneSplit.snapshot, phoneSplit.message);
            if (!equals(phoneArt.stage.sk, picked.stage.sk)) {
              printTree(phoneArt.root);
              printTree(picked.root);
              expect(phoneArt.stage).toEqual(picked.stage);
            }
            rest.push(phoneArt);

            break;
          }

          case 2: {
            const peer = generate(1)[0];
            if (!peer) throw new Error();
            const leaves = Array.from(init.root.leaves());
            const leaf = leaves[Math.floor(Math.random() * leaves.length)];
            if (!leaf) throw new Error();

            console.log(`adding member ${toFirstThree(peer.identity.pk)} to the right of ${toFirstThree(leaf.peer.identity_pk)}`);

            const memberSplit = init.split(new Peer(peer.identity.pk, peer.ephemeral.pk, peer.ephemeral_signature), leaf.pk);

            non_initiators.forEach((member) => {
              member.processSplit(memberSplit.message);
              if (!equals(member.stage.sk, init.stage.sk)) {
                printTree(member.root);
                printTree(init.root);
                expect(member.stage).toEqual(init.stage);
              }
            });

            const memberArt = ART.fromSplitMessage(new Me(peer.identity, peer.ephemeral), memberSplit.snapshot, memberSplit.message);
            if (!equals(memberArt.stage.sk, init.stage.sk)) {
              printTree(memberArt.root);
              printTree(init.root);
              expect(memberArt.stage).toEqual(init.stage);
            }
            rest.push(memberArt);

            break;
          }
        }
      }
    }
  });
});
