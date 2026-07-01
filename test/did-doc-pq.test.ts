/**
 * pqVerificationKeyFromDidDoc (ADR-2606111300): extraction of the ML-DSA-65
 * verification key from a DID document, end-to-end against the same multikey
 * encoding did-web emits, feeding verifySignalIdentityHybrid enforcement.
 */
import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "@noble/hashes/utils";

import {
  pqVerificationKeyFromDidDoc,
  signSignalIdentityHybrid,
  verifySignalIdentityHybrid,
} from "../src/did-signal";
import { generateMlDsaKeyPair } from "../src/pq";

// Mirror of did-web's mlDsa65PubToDidKey encoding (multicodec 0x1211 varint
// [0x91, 0x24] + base58btc multibase 'z') so the SDK test proves cross-package
// compatibility without importing across package boundaries.
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58btcEncode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = "1".repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]];
  return out;
}
function mlDsa65Multibase(pub: Uint8Array): string {
  const prefixed = new Uint8Array(2 + pub.length);
  prefixed.set([0x91, 0x24], 0);
  prefixed.set(pub, 2);
  return "z" + base58btcEncode(prefixed);
}

function didDocWith(vm: unknown[]): unknown {
  return {
    "@context": ["https://www.w3.org/ns/did/v1"],
    id: "did:web:etzhayyim.com:actor:kanae",
    verificationMethod: vm,
  };
}

describe("pqVerificationKeyFromDidDoc", () => {
  const pq = generateMlDsaKeyPair();
  const edPub = ed25519.getPublicKey(ed25519.utils.randomPrivateKey());

  it("extracts the ML-DSA-65 key next to an Ed25519 entry", () => {
    const doc = didDocWith([
      {
        id: "did:web:etzhayyim.com:actor:kanae#key-1",
        type: "Ed25519VerificationKey2020",
        publicKeyMultibase: "z" + base58btcEncode(new Uint8Array([0xed, 0x01, ...edPub])),
      },
      {
        id: "did:web:etzhayyim.com:actor:kanae#pq-key-1",
        type: "Multikey",
        publicKeyMultibase: mlDsa65Multibase(pq.publicKey),
      },
    ]);
    const key = pqVerificationKeyFromDidDoc(doc);
    expect(key).not.toBeNull();
    expect(Buffer.from(key!).toString("hex")).toBe(
      Buffer.from(pq.publicKey).toString("hex"),
    );
  });

  it("returns null for an Ed25519-only document (legacy read-compat)", () => {
    const doc = didDocWith([
      {
        type: "Ed25519VerificationKey2020",
        publicKeyMultibase: "z" + base58btcEncode(new Uint8Array([0xed, 0x01, ...edPub])),
      },
    ]);
    expect(pqVerificationKeyFromDidDoc(doc)).toBeNull();
    expect(pqVerificationKeyFromDidDoc(null)).toBeNull();
    expect(pqVerificationKeyFromDidDoc({})).toBeNull();
  });

  it("ignores malformed multibase entries instead of throwing", () => {
    const doc = didDocWith([
      { type: "Multikey", publicKeyMultibase: "z0OIl" }, // invalid base58 chars
      { type: "Multikey", publicKeyMultibase: 42 },
      { type: "Multikey", publicKeyMultibase: mlDsa65Multibase(pq.publicKey) },
    ]);
    expect(pqVerificationKeyFromDidDoc(doc)).not.toBeNull();
  });

  it("the extracted key enforces the hybrid binding end-to-end", () => {
    const edSecret = ed25519.utils.randomPrivateKey();
    const doc = didDocWith([
      { type: "Multikey", publicKeyMultibase: mlDsa65Multibase(pq.publicKey) },
    ]);
    const didPqVerificationKey = pqVerificationKeyFromDidDoc(doc)!;

    const signed = signSignalIdentityHybrid(
      {
        did: "did:web:etzhayyim.com:actor:kanae",
        signalIdentityKey: randomBytes(32),
        signalRegistrationId: 7,
        createdAt: "2026-06-11T00:00:00.000Z",
      },
      edSecret,
      pq.secretKey,
    );

    expect(
      verifySignalIdentityHybrid({
        signed,
        didVerificationKey: ed25519.getPublicKey(edSecret),
        didPqVerificationKey,
      }),
    ).toBe(true);

    // With the doc-published PQ key known, a stripped pqSignature fails closed.
    const { pqSignature: _pq, ...downgraded } = signed;
    expect(
      verifySignalIdentityHybrid({
        signed: downgraded,
        didVerificationKey: ed25519.getPublicKey(edSecret),
        didPqVerificationKey,
      }),
    ).toBe(false);
  });
});
