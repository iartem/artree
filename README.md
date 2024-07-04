# ARTree

[![npm package][npm-img]][npm-url]
[![Build Status][build-img]][build-url]
[![Downloads][downloads-img]][downloads-url]
[![Issues][issues-img]][issues-url]
[![Code Coverage][codecov-img]][codecov-url]
[![Commitizen Friendly][commitizen-img]][commitizen-url]
[![Semantic Release][semantic-release-img]][semantic-release-url]

> Asynchronous Ratcheting Tree implementation in Typescript

Asyncronous Ratcheting Tree (see [ART paper](https://eprint.iacr.org/2017/666)) is PKE and key derivation protocol which allows group of users to agree on using one common key while keeping forward secrecy and asynchronous nature of group communcation.

**TLDR:** a binary tree of Diffie Hellman keys. Each node is HKDF(DH(A, B)) where A & B are keys of 2 of its children.

<figure>
  <img
  src="/assets/tree.png"
  alt="DH binary tree">
  <figcaption>Figure courtesy of https://eprint.iacr.org/2017/666</figcaption>
</figure>

<br/>

The reasons why ART is preferred over over plain ratchets, double ratchets and alike, include:

1. In order to calculate stage (top level) key you need a secret key of one of the leaves and public keys of other nodes. Single secret key is required and is enough.
2. Parent node keys can be calculated by either of its children with all of them ending up with the same top level key.
3. Any leaf can change its key asynchronously. While some members are offline, for example.
4. One key! No need to send N - 1 messages for any message in group of N members.

This implementation is largely based on [ART paper](https://eprint.iacr.org/2017/666), yet it adds several extra features (use with caution, not verified or scientifically proven!) necessary for real world application:

- Ability to split tree leaves and add new users.
- Ability to redistribute up to date tree to users who were offline while other memebers updated their keys. Useful when you don't store messages.

> [!WARNING]
> Note that ARTree does not encrypt messages it produces. It's implied that **<u>package user will encrypt messages</u>** between ART members with `art.stage` key. Both synchronous & asynchronous encryption is supported as `art.stage` is a keypair. That being said, ARTree actually uses encryption in one place: it encrypts stage key transferred to new tree member on split; it does that because encryption key would be tricky to calculate outside of the library.

## Getting started

### Install

```bash
npm install artree
```

### Add your crypto implementaion

ARTree is BYOCrypto, abstracted from crypto implementation, but tested with awesome [paulmillr](https://github.com/paulmillr)'s [@noble](https://github.com/paulmillr/noble-curves) set of packages:

```bash
npm install @noble/curves @noble/hashes @noble/ciphers
```

```ts
import { gcm } from '@noble/ciphers/aes';
import { secp256k1 } from '@noble/curves/secp256k1';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from 'crypto';
import { setCrypto, SK, SI, PK, concat } from 'artree';

setCrypto({
  generateSecretKey: secp256k1.utils.randomPrivateKey,
  derivePublicKey: secp256k1.getPublicKey,
  getSharedSecret: secp256k1.getSharedSecret,
  hash_256: sha256,
  sign: function (data: Uint8Array, sk: SK) {
    return secp256k1.sign(data, sk, { prehash: true }).toCompactRawBytes();
  },
  verify: function (si: SI, data: Uint8Array, pk: PK) {
    return secp256k1.verify(si, data, pk, { prehash: true });
  },
  hkdf: hkdf.bind(null, sha256),
  encrypt: function (data: Uint8Array, key: SK) {
    const nonce = randomBytes(this.ENCRYPTION_PREFIX_LENGTH);
    return concat(nonce, gcm(key, nonce).encrypt(data));
  },
  decrypt: function (data: Uint8Array, key: SK) {
    const nonce = data.subarray(0, this.ENCRYPTION_PREFIX_LENGTH);
    return gcm(key, nonce).decrypt(data.subarray(this.ENCRYPTION_PREFIX_LENGTH));
  },
  PK_LENGTH: 33,
  SK_LENGTH: 32,
  SI_LENGTH: 64,
  ENCRYPTION_PREFIX_LENGTH: 12,
  ENCRYPTION_SUFFIX_LENGTH: 16,
});
```

### Start turning!

In order to create ART you'd need identity & ephemeral private keys for initiator and identity & ephemeral public keys for each participant. Also ephemeral keys must be signed with corresponding identity key to prove it belongs to identity secret key owner:

```ts
import { ART, Me, Peer, keypair } from 'artree';

const keys = new Array(2).fill(0).map(() => {
  const identity = keypair(); // {sk: Uint8Array, pk: Uint8Array}, Secret Key & Public Key
  const ephemeral = keypair();
  const ephemeral_signature = secp256k1.sign(sha256(ephemeral.pk), identity.sk).toCompactRawBytes();
  return { identity, ephemeral, ephemeral_signature };
});

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
// The message should be encrypted when transferring to them
const setupMessage = alice.setupMessage;

// Bob receives setup message and joins the tree
// He only needs setup message and his identity & ephemeral keys to start turning the tree
const bob = ART.fromSetupMessage(new Me(keys[1]!.identity, keys[1]!.ephemeral), setupMessage);

expect(bob.stage.sk).toEqual(alice.stage.sk); // look Ma, same keys!

// Once set up, members can turn the ratchet at their will
const bobUpdateMessage = bob.updateKey();
alice.processKeyUpdate(bobUpdateMessage);

expect(alice.stage.sk).toEqual(bob.stage.sk); // look Ma, same keys!
```

See full example [in tests](https://github.com/iartem/artree/blob/main/test/art.spec.ts#L57).

### Tree modifications after initialization

ARTree allows new tree members to join the tree after its initialization:

- Any tree member can replace its tree leaf with a node consisting of 2 leaves: old leaf and new leaf with the same identity key as the old one. Think of one user having multiple devices.
- Tree initiator can add new leaves at arbitrary position.

> [!CAUTION]
> Using this feature (`art.split()`) is not required and in fact not advised if security is your main concern.

The problem comes from the fact that the very top level (stage) key is an HKDF which uses previous key as one of its inputs. Therefore adding a tree member requires sharing current stage key with this member in order for newcomer to be able to calculate next stage key.

Alternative to current implementation would be not using HKDF for stage key calculation, but that would come at a cost of forward secrecy.

Bottomline: if you don't need to add new tree members after its initialization, better don't.

## API

### Intro

`Peer` - a class with public identity & ephemeral keys + signature of ephemeral key by identity key.

`Me` - a class with identity & ephemeral keypair, generates signature automatically.

`SK`, `sk` - secret (private) key.

`PK`, `pk` - public key.

`ART` - main package class.

<br/>

### `ART.initiate(peers: Peer[]): ART`

Create new tree for given peers. Called by tree initiator. One of `Peer` objects must be initiator's `Me` instance. Returns ready to use tree with `setupMessage` property set to a message to be sent to other members.

<br/>

### `ART.fromSetupMessage(me: Me, message: Uint8Array): ART`

Recreate tree at non-initiator side from setup message.

<br/>

### `ART.fromSplitMessage(me: Me, snapshot: Uint8Array, splitMessage: Uint8Array): ART`

**USE WITH CAUTION** Recreate tree at non-initiator side from split snapshot & message. Used to add new members to the tree after its initiation. `snapshot` & `splitMessage` are results of `art.split()` call.

<br/>

### `art.updateKey(key = keypair()): Uint8Array`

Replace ephemeral key of a tree member with new one. Returns a message which should be sent to every other tree member. Failure to do so will make them unable to process next messages as their stage key will be outdated. By default `key` is randomly generated.

<br/>

### `art.processKeyUpdate(message: Uint8Array): void`

Process key update message from another peer.

<br/>

### `art.split(peer: Peer, at?: Uint8Array): {message: Uint8Array, snapshot: Uint8Array}`

**USE WITH CAUTION** Splits one of the leaves into two, adding new member to the tree. Initiator can add members at arbitrary positions (by setting `at` parameter to leaf's `pk`), while other members can only add new members with the same identity key right next to their own node (`at === undefined`). See [Tree modifications after initialization](#tree-modifications-after-initialization) for details.

<br/>

### `art.processSplit(message: Uint8Array)`

**USE WITH CAUTION** Updates tree with new Peer. See [Tree modifications after initialization](#tree-modifications-after-initialization) for details.

[build-img]: https://github.com/iartem/artree/actions/workflows/release.yml/badge.svg
[build-url]: https://github.com/iartem/artree/actions/workflows/release.yml
[downloads-img]: https://img.shields.io/npm/dt/artree
[downloads-url]: https://www.npmtrends.com/artree
[npm-img]: https://img.shields.io/npm/v/artree
[npm-url]: https://www.npmjs.com/package/artree
[issues-img]: https://img.shields.io/github/issues/iartem/artree
[issues-url]: https://github.com/iartem/artree/issues
[codecov-img]: https://codecov.io/gh/iartem/artree/branch/main/graph/badge.svg
[codecov-url]: https://codecov.io/gh/iartem/artree
[semantic-release-img]: https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg
[semantic-release-url]: https://github.com/semantic-release/semantic-release
[commitizen-img]: https://img.shields.io/badge/commitizen-friendly-brightgreen.svg
[commitizen-url]: http://commitizen.github.io/cz-cli/
