import { Peer, ErrCode, ART, Me, keypair, crypt } from '../../src';
import { generate, referenceGroup } from '../test.utils';

export function messageSignatures(): void {
  it('should not accept setup message with invalid data or signature', () => {
    const [a, b] = referenceGroup();

    const invalidSetupMessage = a.setupMessage.slice();
    invalidSetupMessage[100] = (invalidSetupMessage[100] || 0) + 1;

    expect(() => ART.fromSetupMessage(b.me, invalidSetupMessage)).toThrow(expect.objectContaining({ code: ErrCode.INVALID_SIGNATURE }));
  });

  it('should not accept update key message with invalid data or signature', () => {
    const [a, b] = referenceGroup();

    const update = b.updateKey();
    const invalidUpdate = update.slice();
    invalidUpdate[10] = (invalidUpdate[10] || 0) + 1;

    expect(() => a.processKeyUpdate(invalidUpdate)).toThrow(expect.objectContaining({ code: ErrCode.INVALID_SIGNATURE }));

    const malicious = keypair();
    const substitutedUpdate = update.slice();
    substitutedUpdate.set(
      crypt.sign(substitutedUpdate.slice(0, -crypt.SI_LENGTH), malicious.sk),
      substitutedUpdate.length - crypt.SI_LENGTH
    );
    expect(() => a.processKeyUpdate(substitutedUpdate)).toThrow(expect.objectContaining({ code: ErrCode.INVALID_SIGNATURE }));
  });

  it('should not accept update key message with invalid data or signature', () => {
    const [a, , c] = referenceGroup();
    const d = generate(1)[0];
    if (!d) {
      throw new Error();
    }
    const { message, snapshot } = a.split(
      new Peer(d.identity.pk, d.ephemeral.pk, d.ephemeral_signature),
      a.leafOf(c.me.identity_pk)?.pk || new Uint8Array()
    );
    const invalidMessage = message.slice();
    const invalidSnapshot = snapshot.slice();
    invalidMessage[100] = (invalidMessage[100] || 0) + 1;
    invalidSnapshot[100] = (invalidSnapshot[100] || 0) + 1;

    expect(() => a.processSplit(invalidMessage)).toThrow(expect.objectContaining({ code: ErrCode.INVALID_SIGNATURE }));
    expect(() => ART.fromSplitMessage(new Me(d.identity, d.ephemeral), invalidSnapshot, message)).toThrow(
      expect.objectContaining({ code: ErrCode.INVALID_SIGNATURE })
    );
    expect(() => ART.fromSplitMessage(new Me(d.identity, d.ephemeral), snapshot, invalidMessage)).toThrow(
      expect.objectContaining({ code: ErrCode.INVALID_SIGNATURE })
    );

    const malicious = keypair();
    const substitutedSnapshot = snapshot.slice();
    const substitutedMessage = message.slice();
    substitutedMessage.set(
      crypt.sign(substitutedMessage.slice(0, -crypt.SI_LENGTH), malicious.sk),
      substitutedMessage.length - crypt.SI_LENGTH
    );
    substitutedSnapshot.set(
      crypt.sign(substitutedSnapshot.slice(0, -crypt.SI_LENGTH), malicious.sk),
      substitutedSnapshot.length - crypt.SI_LENGTH
    );
    expect(() => a.processSplit(substitutedMessage)).toThrow(expect.objectContaining({ code: ErrCode.INVALID_SIGNATURE }));
    expect(() => ART.fromSplitMessage(new Me(d.identity, d.ephemeral), substitutedSnapshot, message)).toThrow(
      expect.objectContaining({ code: ErrCode.INVALID_SIGNATURE })
    );
    expect(() => ART.fromSplitMessage(new Me(d.identity, d.ephemeral), snapshot, substitutedMessage)).toThrow(
      expect.objectContaining({ code: ErrCode.INVALID_SIGNATURE })
    );
  });
}
