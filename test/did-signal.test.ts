/**
 * Unit tests for `@etzhayyim/sdk/did-signal`.
 *
 * Scope: signing + verifying the DID ↔ Signal IdentityKey binding using
 * the canonical CBOR-over-body Ed25519 construction.
 *
 * Out of scope: actual DID document resolution (network) and libsignal
 * IdentityKey generation (covered by signal.test.ts scaffold).
 */

import {describe, it, expect} from "vitest";
import {ed25519} from "@noble/curves/ed25519";
import {
  canonicalSigningBytes,
  signSignalIdentity,
  signalIdentityFingerprint,
  verifySignalIdentity,
  type SignalIdentityBody,
} from "../src/did-signal.js";

function fixtureBody(did = "did:web:alice.example"): SignalIdentityBody {
  return {
    did,
    signalIdentityKey: new Uint8Array(32).fill(0xab),
    signalRegistrationId: 4242,
    createdAt: "2026-05-18T11:00:00.000Z",
  };
}

describe("did-signal binding", () => {
  it("signs and verifies a binding", () => {
    const privKey = ed25519.utils.randomPrivateKey();
    const pubKey = ed25519.getPublicKey(privKey);
    const body = fixtureBody();

    const signed = signSignalIdentity(body, privKey);

    expect(signed.signature).toHaveLength(64);
    expect(
      verifySignalIdentity({signed, didVerificationKey: pubKey})
    ).toBe(true);
  });

  it("rejects verification under a different DID key", () => {
    const priv1 = ed25519.utils.randomPrivateKey();
    const priv2 = ed25519.utils.randomPrivateKey();
    const pub2 = ed25519.getPublicKey(priv2);
    const signed = signSignalIdentity(fixtureBody(), priv1);

    expect(
      verifySignalIdentity({signed, didVerificationKey: pub2})
    ).toBe(false);
  });

  it("rejects verification when the body has been tampered with", () => {
    const priv = ed25519.utils.randomPrivateKey();
    const pub = ed25519.getPublicKey(priv);
    const signed = signSignalIdentity(fixtureBody(), priv);

    signed.signalRegistrationId = 9999;

    expect(
      verifySignalIdentity({signed, didVerificationKey: pub})
    ).toBe(false);
  });

  it("rejects an empty DID", () => {
    const priv = ed25519.utils.randomPrivateKey();
    const pub = ed25519.getPublicKey(priv);
    const signed = signSignalIdentity(fixtureBody(""), priv);

    expect(
      verifySignalIdentity({signed, didVerificationKey: pub})
    ).toBe(false);
  });

  it("canonical bytes are stable across calls", () => {
    const body = fixtureBody();
    const a = canonicalSigningBytes(body);
    const b = canonicalSigningBytes(body);
    expect(a).toEqual(b);
  });

  it("fingerprint is 16 hex chars and deterministic", () => {
    const key = new Uint8Array(32).fill(0x01);
    const fp = signalIdentityFingerprint(key);
    expect(fp).toHaveLength(16);
    expect(fp).toMatch(/^[0-9a-f]+$/);
    expect(signalIdentityFingerprint(key)).toBe(fp);
  });
});
