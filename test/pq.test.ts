import { describe, it, expect, beforeEach } from 'vitest';
import {
  PQ_SUITE,
  generateHybridKemKeyPair,
  hybridEncapsulate,
  hybridDecapsulate,
  generateMlDsaKeyPair,
  mlDsaSign,
  mlDsaVerify,
  MLKEM768_PUBLIC_BYTES,
  MLKEM768_CIPHERTEXT_BYTES,
  HYBRID_SHARED_SECRET_BYTES,
} from '../src/pq';
import {
  signSignalIdentityHybrid,
  verifySignalIdentityHybrid,
  verifySignalIdentity,
  type SignalIdentityBody,
} from '../src/did-signal';
import {
  establishSessionInitiator,
  establishSessionResponder,
  wrapKey,
  unwrapKey,
  _clearSessions,
} from '../src/signal';
import { ed25519 } from '@noble/curves/ed25519';
import { randomBytes } from '@noble/hashes/utils';

const utf8 = (s: string) => new TextEncoder().encode(s);

describe('@etzhayyim/sdk: pq hybrid KEM (pqh-v1)', () => {
  it('encapsulate/decapsulate derive the same 32-byte shared secret', () => {
    const { publicBundle, secretBundle } = generateHybridKemKeyPair();
    expect(publicBundle.mlkemPublicKey.length).toBe(MLKEM768_PUBLIC_BYTES);

    const info = utf8('did:example:a|did:example:b');
    const { sharedSecret, handshake } = hybridEncapsulate(publicBundle, info);
    expect(sharedSecret.length).toBe(HYBRID_SHARED_SECRET_BYTES);
    expect(handshake.suite).toBe(PQ_SUITE);
    expect(handshake.mlkemCiphertext.length).toBe(MLKEM768_CIPHERTEXT_BYTES);

    const derived = hybridDecapsulate(handshake, secretBundle, publicBundle, info);
    expect(Buffer.from(derived).toString('hex')).toBe(
      Buffer.from(sharedSecret).toString('hex'),
    );
  });

  it('different info (DID pair) derives a different key', () => {
    const { publicBundle, secretBundle } = generateHybridKemKeyPair();
    const { sharedSecret, handshake } = hybridEncapsulate(
      publicBundle,
      utf8('did:a|did:b'),
    );
    const other = hybridDecapsulate(
      handshake,
      secretBundle,
      publicBundle,
      utf8('did:a|did:MALLORY'),
    );
    expect(Buffer.from(other).toString('hex')).not.toBe(
      Buffer.from(sharedSecret).toString('hex'),
    );
  });

  it('tampered ML-KEM ciphertext yields a different secret (implicit rejection)', () => {
    const { publicBundle, secretBundle } = generateHybridKemKeyPair();
    const { sharedSecret, handshake } = hybridEncapsulate(publicBundle);
    const tampered = {
      ...handshake,
      mlkemCiphertext: handshake.mlkemCiphertext.slice(),
    };
    tampered.mlkemCiphertext[0] ^= 0x01;
    const derived = hybridDecapsulate(tampered, secretBundle, publicBundle);
    expect(Buffer.from(derived).toString('hex')).not.toBe(
      Buffer.from(sharedSecret).toString('hex'),
    );
  });

  it('rejects an unknown suite', () => {
    const { publicBundle } = generateHybridKemKeyPair();
    expect(() =>
      hybridEncapsulate({ ...publicBundle, suite: 'rsa-2048' as never }),
    ).toThrow(/unsupported suite/);
  });
});

describe('@etzhayyim/sdk: pq ML-DSA-65', () => {
  it('sign/verify roundtrip; rejects wrong key and tampered message', () => {
    const kp = generateMlDsaKeyPair();
    const msg = utf8('canonical body bytes');
    const sig = mlDsaSign(kp.secretKey, msg);

    expect(mlDsaVerify(kp.publicKey, msg, sig)).toBe(true);
    expect(mlDsaVerify(kp.publicKey, utf8('tampered'), sig)).toBe(false);

    const other = generateMlDsaKeyPair();
    expect(mlDsaVerify(other.publicKey, msg, sig)).toBe(false);
  });

  it('is deterministic from a 32-byte seed', () => {
    const seed = randomBytes(32);
    const a = generateMlDsaKeyPair(seed);
    const b = generateMlDsaKeyPair(seed);
    expect(Buffer.from(a.publicKey).toString('hex')).toBe(
      Buffer.from(b.publicKey).toString('hex'),
    );
  });
});

describe('@etzhayyim/sdk: did-signal hybrid dual signature', () => {
  const edSecret = ed25519.utils.randomPrivateKey();
  const edPublic = ed25519.getPublicKey(edSecret);
  const pqKp = generateMlDsaKeyPair();
  const kem = generateHybridKemKeyPair();

  const body: SignalIdentityBody = {
    did: 'did:web:etzhayyim.com',
    signalIdentityKey: randomBytes(32),
    signalRegistrationId: 42,
    pqSuite: PQ_SUITE,
    pqX25519PublicKey: kem.publicBundle.x25519PublicKey,
    pqMlkemPublicKey: kem.publicBundle.mlkemPublicKey,
    createdAt: '2026-06-11T00:00:00.000Z',
  };

  it('dual-signed identity verifies under both keys', () => {
    const signed = signSignalIdentityHybrid(body, edSecret, pqKp.secretKey);
    expect(
      verifySignalIdentityHybrid({
        signed,
        didVerificationKey: edPublic,
        didPqVerificationKey: pqKp.publicKey,
      }),
    ).toBe(true);
  });

  it('legacy verifier (no PQ key) still accepts a dual-signed identity', () => {
    const signed = signSignalIdentityHybrid(body, edSecret, pqKp.secretKey);
    expect(
      verifySignalIdentity({ signed, didVerificationKey: edPublic }),
    ).toBe(true);
  });

  it('stripping pqSignature fails when the verifier knows the PQ key (no downgrade)', () => {
    const signed = signSignalIdentityHybrid(body, edSecret, pqKp.secretKey);
    const { pqSignature: _stripped, ...downgraded } = signed;
    expect(
      verifySignalIdentityHybrid({
        signed: downgraded,
        didVerificationKey: edPublic,
        didPqVerificationKey: pqKp.publicKey,
      }),
    ).toBe(false);
  });

  it('tampering the KEM bundle in the body breaks both signatures', () => {
    const signed = signSignalIdentityHybrid(body, edSecret, pqKp.secretKey);
    const evil = generateHybridKemKeyPair();
    const tampered = { ...signed, pqMlkemPublicKey: evil.publicBundle.mlkemPublicKey };
    expect(
      verifySignalIdentity({ signed: tampered, didVerificationKey: edPublic }),
    ).toBe(false);
    expect(
      verifySignalIdentityHybrid({
        signed: tampered,
        didVerificationKey: edPublic,
        didPqVerificationKey: pqKp.publicKey,
      }),
    ).toBe(false);
  });
});

describe('@etzhayyim/sdk: signal pqh-v1 sessions', () => {
  beforeEach(() => _clearSessions());

  const senderDid = 'did:example:sender';
  const recipientDid = 'did:example:recipient';

  it('initiator and responder derive interoperable session keys', () => {
    const kem = generateHybridKemKeyPair();
    const { session: initiator, handshake } = establishSessionInitiator({
      senderDid,
      recipientDid,
      recipientKem: kem.publicBundle,
    });
    const responder = establishSessionResponder({
      senderDid,
      recipientDid,
      handshake,
      recipientKemSecret: kem.secretBundle,
      recipientKemPublic: kem.publicBundle,
    });

    const plaintext = 'per-record symmetric key material';
    const { ciphertext } = wrapKey({ session: initiator, plaintext });
    expect(unwrapKey({ session: responder, ciphertext })).toBe(plaintext);
  });

  it('a responder with the wrong KEM secret cannot unwrap', () => {
    const kem = generateHybridKemKeyPair();
    const wrong = generateHybridKemKeyPair();
    const { session: initiator, handshake } = establishSessionInitiator({
      senderDid,
      recipientDid,
      recipientKem: kem.publicBundle,
    });
    const responder = establishSessionResponder({
      senderDid,
      recipientDid,
      handshake,
      recipientKemSecret: wrong.secretBundle,
      recipientKemPublic: wrong.publicBundle,
    });

    const { ciphertext } = wrapKey({ session: initiator, plaintext: 'secret' });
    expect(() => unwrapKey({ session: responder, ciphertext })).toThrow();
  });
});
