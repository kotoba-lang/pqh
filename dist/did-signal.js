/**
 * @etzhayyim/sdk/did-signal — DID ↔ Signal IdentityKey binding verification.
 *
 * Per ADR-2605181100. An actor publishes their Signal IdentityKey in their
 * own PDS as `com.etzhayyim.encrypted.signalIdentity`, signed by the DID
 * document's signing key. Verifiers MUST check this signature before
 * trusting any PreKeyBundle to belong to that DID, otherwise a malicious
 * PDS could substitute a different Signal identity to MitM key-wrap traffic.
 *
 * Signature scheme: Ed25519 over CBOR-encoded canonical body. did:web key
 * resolution per W3C DID core spec; did:plc key resolution per atproto
 * `did:plc` spec. did:key resolution is supported for testing.
 *
 * Post-quantum (suite pqh-v1, ADR-2606111300): the body MAY additionally
 * carry the actor's hybrid KEM public keys, and the binding MAY carry a
 * second ML-DSA-65 signature over the same canonical bytes. When the PQ
 * signature is present, verifiers given the PQ verification key MUST check
 * BOTH signatures — a forger then has to break Ed25519 AND ML-DSA-65.
 */
import { encode as cborEncode } from "@ipld/dag-cbor";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { mlDsaSign, mlDsaVerify } from "./pq.js";
/**
 * Canonical bytes to sign / verify. CBOR-encoded body without the signature
 * field, in lexicographic key order (dag-cbor enforces this).
 */
export function canonicalSigningBytes(body) {
    return cborEncode(body);
}
/**
 * Sign a SignalIdentityBody with the actor's DID Ed25519 signing key. The
 * caller is responsible for ensuring `signingKey` corresponds to the
 * verification method published in `body.did`'s DID document.
 */
export function signSignalIdentity(body, signingKey) {
    const msg = canonicalSigningBytes(body);
    const signature = ed25519.sign(msg, signingKey);
    return { ...body, signature };
}
/**
 * Verify the binding signature. Returns `true` only if:
 *   - `signed.did` is non-empty,
 *   - the Ed25519 signature over CBOR(body) verifies under `didVerificationKey`.
 */
export function verifySignalIdentity(opts) {
    const { signed, didVerificationKey } = opts;
    if (!signed.did)
        return false;
    const { signature, pqSignature: _pq, ...body } = signed;
    const msg = canonicalSigningBytes(body);
    try {
        return ed25519.verify(signature, msg, didVerificationKey);
    }
    catch {
        return false;
    }
}
/**
 * Dual-sign a SignalIdentityBody (suite pqh-v1): Ed25519 with the DID
 * signing key plus ML-DSA-65 with the DID's post-quantum signing key, both
 * over the same canonical CBOR bytes.
 */
export function signSignalIdentityHybrid(body, signingKey, pqSigningKey) {
    const msg = canonicalSigningBytes(body);
    return {
        ...body,
        signature: ed25519.sign(msg, signingKey),
        pqSignature: mlDsaSign(pqSigningKey, msg),
    };
}
/**
 * Verify a (possibly dual-signed) binding. Semantics:
 *   - The Ed25519 signature must always verify.
 *   - If the verifier knows a PQ verification key for this DID, the
 *     ML-DSA-65 signature must be present AND verify (AND-composition:
 *     forgery requires breaking both schemes).
 *   - With no PQ key known, a pqSignature is ignored (legacy verifier path,
 *     one R-cycle read-compat per crypto-agility-policy).
 */
export function verifySignalIdentityHybrid(opts) {
    const { signed, didVerificationKey, didPqVerificationKey } = opts;
    if (!signed.did)
        return false;
    const { signature, pqSignature, ...body } = signed;
    const msg = canonicalSigningBytes(body);
    try {
        if (!ed25519.verify(signature, msg, didVerificationKey))
            return false;
    }
    catch {
        return false;
    }
    if (didPqVerificationKey) {
        if (!pqSignature)
            return false;
        return mlDsaVerify(didPqVerificationKey, msg, pqSignature);
    }
    return true;
}
/**
 * Fingerprint of a Signal IdentityKey, suitable for human-readable
 * confirmation ("safety number" pattern). First 16 hex chars of SHA-256.
 */
export function signalIdentityFingerprint(identityKey) {
    return bytesToHex(sha256(identityKey)).slice(0, 16);
}
// ── DID-document key extraction (pqh-v1, ADR-2606111300) ────────────────────
// mldsa-65-pub = 0x1211 (multicodec registry, draft; FIPS 204) → varint [0x91, 0x24].
const MLDSA65_MULTICODEC = [0x91, 0x24];
const MLDSA65_PUB_BYTES = 1952;
const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const B58_MAP = {};
for (let i = 0; i < B58_ALPHABET.length; i++)
    B58_MAP[B58_ALPHABET[i]] = i;
function base58btcDecode(str) {
    let zeros = 0;
    while (zeros < str.length && str[zeros] === "1")
        zeros++;
    const bytes = [];
    for (let i = zeros; i < str.length; i++) {
        let carry = B58_MAP[str[i]];
        if (carry === undefined)
            throw new Error(`invalid base58 char: ${str[i]}`);
        for (let j = 0; j < bytes.length; j++) {
            carry += bytes[j] * 58;
            bytes[j] = carry & 0xff;
            carry >>= 8;
        }
        while (carry > 0) {
            bytes.push(carry & 0xff);
            carry >>= 8;
        }
    }
    const out = new Uint8Array(zeros + bytes.length);
    for (let i = 0; i < bytes.length; i++)
        out[zeros + bytes.length - 1 - i] = bytes[i];
    return out;
}
/**
 * Extract the DID's ML-DSA-65 verification key from a resolved DID document.
 *
 * Scans `verificationMethod` for a multibase 'z' (base58btc) key whose
 * decoded bytes carry the `mldsa-65-pub` multicodec prefix (0x1211, draft
 * registry) and a 1952-byte FIPS 204 encapsulation of the public key — the
 * encoding emitted by did-web's `mlDsa65PubToDidKey`. Entry `type` is not
 * trusted for dispatch (Multikey / MlDsa65VerificationKey2026 both appear in
 * the wild); the multicodec prefix is authoritative.
 *
 * Returns the raw key for `verifySignalIdentityHybrid`'s
 * `didPqVerificationKey`, or null when the document publishes none (legacy
 * read-compat — verification then stays Ed25519-only).
 */
export function pqVerificationKeyFromDidDoc(didDoc) {
    if (typeof didDoc !== "object" || didDoc === null)
        return null;
    const vm = didDoc.verificationMethod;
    if (!Array.isArray(vm))
        return null;
    for (const entry of vm) {
        const mb = entry?.publicKeyMultibase;
        if (typeof mb !== "string" || !mb.startsWith("z"))
            continue;
        let decoded;
        try {
            decoded = base58btcDecode(mb.slice(1));
        }
        catch {
            continue;
        }
        if (decoded.length === 2 + MLDSA65_PUB_BYTES &&
            decoded[0] === MLDSA65_MULTICODEC[0] &&
            decoded[1] === MLDSA65_MULTICODEC[1]) {
            return decoded.slice(2);
        }
    }
    return null;
}
