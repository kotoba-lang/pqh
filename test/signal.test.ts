import { describe, it, expect, beforeEach } from 'vitest';
import { establishSession, wrapKey, unwrapKey, _clearSessions } from '../src/signal';
import { randomBytes } from '@noble/hashes/utils';

describe('@etzhayyim/sdk: signal', () => {
  beforeEach(() => {
    _clearSessions();
  });

  const senderDid = 'did:example:sender';
  const recipientDid = 'did:example:recipient';

  it('should perform a successful wrapKey/unwrapKey roundtrip', () => {
    const session = establishSession({ senderDid, recipientDid });
    const plaintext = 'This is a secret message for key wrapping.';

    const { ciphertext } = wrapKey({ session, plaintext });
    const decrypted = unwrapKey({ session, ciphertext });

    expect(decrypted).toBe(plaintext);
  });

  it('should throw an error when unwrapping with a different session', () => {
    const session1 = establishSession({ senderDid, recipientDid });
    const session2 = establishSession({ senderDid, recipientDid });
    const plaintext = 'This should not be decryptable.';

    const { ciphertext } = wrapKey({ session: session1, plaintext });

    // Noble ciphers will throw on AEAD tag mismatch
    expect(() => {
      unwrapKey({ session: session2, ciphertext });
    }).toThrow();
  });

  it('should correctly handle an empty plaintext string', () => {
    const session = establishSession({ senderDid, recipientDid });
    const plaintext = '';

    const { ciphertext } = wrapKey({ session, plaintext });
    const decrypted = unwrapKey({ session, ciphertext });

    expect(decrypted).toBe(plaintext);
  });

  it('should correctly handle plaintext with unicode characters', () => {
    const session = establishSession({ senderDid, recipientDid });
    const plaintext = 'こんにちは、世界！ (Hello, World!) 😃';

    const { ciphertext } = wrapKey({ session, plaintext });
    const decrypted = unwrapKey({ session, ciphertext });

    expect(decrypted).toBe(plaintext);
  });

  it('should correctly handle a large (16KB) plaintext', () => {
    const session = establishSession({ senderDid, recipientDid });
    const largeString = Buffer.from(randomBytes(16 * 1024)).toString('base64');

    const { ciphertext } = wrapKey({ session, plaintext: largeString });
    const decrypted = unwrapKey({ session, ciphertext });

    expect(decrypted).toBe(largeString);
  });

  it('should throw when unwrapping with an invalid session handle', () => {
    const session = establishSession({ senderDid, recipientDid });
    const { ciphertext } = wrapKey({ session, plaintext: 'test' });

    expect(() => {
      unwrapKey({ session: 'invalid-session-handle', ciphertext });
    }).toThrow('Invalid session handle');
  });

  it('should throw when wrapping with an invalid session handle', () => {
    expect(() => {
      wrapKey({
        session: 'invalid-session-handle',
        plaintext: 'test',
      });
    }).toThrow('Invalid session handle');
  });
});

