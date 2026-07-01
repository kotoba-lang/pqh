/**
 * @etzhayyim/sdk/pq — post-quantum hybrid layer (suite "pqh-v1").
 *
 * Per ADR-2606111300. The Shor-vulnerable asymmetric primitives in the
 * substrate (X25519 key agreement, Ed25519 signatures) are paired with the
 * NIST-standardized lattice schemes so an attacker must break BOTH the
 * classical and the post-quantum component:
 *
 *   KEM: X25519 + ML-KEM-768 (FIPS 203) → HKDF-SHA256 combiner.
 *        Defends session/key-wrap traffic against harvest-now-decrypt-later.
 *   SIG: Ed25519 + ML-DSA-65 (FIPS 204) → dual signature, verifier requires
 *        both when the PQ component is present.
 *
 * The symmetric layer (XChaCha20-Poly1305, 256-bit) is only Grover-bounded
 * (effective 128-bit, BBBV-optimal) and is intentionally unchanged.
 *
 * Apps MUST NOT import @noble/post-quantum directly; this module is the SDK
 * seam, mirroring the @noble/ciphers rule of ADR-2605181100. Suite identifier
 * and versioning follow 90-docs/security/crypto-agility-policy.md.
 */
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { x25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/ciphers/webcrypto";
export const PQ_SUITE = "pqh-v1";
export const X25519_PUBLIC_BYTES = 32;
export const MLKEM768_PUBLIC_BYTES = 1184;
export const MLKEM768_CIPHERTEXT_BYTES = 1088;
export const MLDSA65_PUBLIC_BYTES = 1952;
export const HYBRID_SHARED_SECRET_BYTES = 32;
const KEM_COMBINER_SALT = new TextEncoder().encode("etzhayyim/pqh-v1/kem");
/** Generate a fresh hybrid (X25519 + ML-KEM-768) KEM key pair. */
export function generateHybridKemKeyPair() {
    const xSecret = x25519.utils.randomPrivateKey();
    const xPublic = x25519.getPublicKey(xSecret);
    const kem = ml_kem768.keygen();
    return {
        publicBundle: {
            suite: PQ_SUITE,
            x25519PublicKey: xPublic,
            mlkemPublicKey: kem.publicKey,
        },
        secretBundle: {
            suite: PQ_SUITE,
            x25519SecretKey: xSecret,
            mlkemSecretKey: kem.secretKey,
        },
    };
}
function concatBytes(...arrays) {
    const total = arrays.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrays) {
        out.set(a, off);
        off += a.length;
    }
    return out;
}
/**
 * KEM combiner: HKDF-SHA256 over the concatenated classical and PQ shared
 * secrets, with the full handshake transcript hash bound into `info` (X-Wing
 * pattern) so neither component's ciphertext can be swapped independently.
 * The result is IND-CCA secure as long as EITHER X25519 OR ML-KEM-768 holds.
 */
function combineSharedSecrets(args) {
    const transcriptHash = sha256(concatBytes(...args.transcript));
    const info = concatBytes(transcriptHash, args.info ?? new Uint8Array(0));
    return hkdf(sha256, concatBytes(args.ssClassical, args.ssPq), KEM_COMBINER_SALT, info, HYBRID_SHARED_SECRET_BYTES);
}
/**
 * Initiator side: encapsulate to a recipient's published bundle. Returns the
 * 32-byte shared secret (use directly as an XChaCha20-Poly1305 key) and the
 * handshake to transmit.
 *
 * `info` SHOULD bind the application context, e.g.
 * `utf8("${senderDid}|${recipientDid}")`, so a transcript replayed between
 * different parties derives a different key.
 */
export function hybridEncapsulate(recipient, info) {
    assertSuite(recipient.suite);
    const ephSecret = x25519.utils.randomPrivateKey();
    const ephPublic = x25519.getPublicKey(ephSecret);
    const ssClassical = x25519.getSharedSecret(ephSecret, recipient.x25519PublicKey);
    const { cipherText, sharedSecret: ssPq } = ml_kem768.encapsulate(recipient.mlkemPublicKey);
    const sharedSecret = combineSharedSecrets({
        ssClassical,
        ssPq,
        transcript: [
            ephPublic,
            cipherText,
            recipient.x25519PublicKey,
            recipient.mlkemPublicKey,
        ],
        info,
    });
    return {
        sharedSecret,
        handshake: {
            suite: PQ_SUITE,
            x25519Ephemeral: ephPublic,
            mlkemCiphertext: cipherText,
        },
    };
}
/**
 * Responder side: derive the same shared secret from a received handshake.
 * ML-KEM implicit rejection means a tampered ciphertext yields a *different*
 * secret rather than an error; downstream AEAD authentication catches it.
 */
export function hybridDecapsulate(handshake, secret, recipientPublic, info) {
    assertSuite(handshake.suite);
    assertSuite(secret.suite);
    const ssClassical = x25519.getSharedSecret(secret.x25519SecretKey, handshake.x25519Ephemeral);
    const ssPq = ml_kem768.decapsulate(handshake.mlkemCiphertext, secret.mlkemSecretKey);
    return combineSharedSecrets({
        ssClassical,
        ssPq,
        transcript: [
            handshake.x25519Ephemeral,
            handshake.mlkemCiphertext,
            recipientPublic.x25519PublicKey,
            recipientPublic.mlkemPublicKey,
        ],
        info,
    });
}
function assertSuite(suite) {
    if (suite !== PQ_SUITE) {
        throw new Error(`[etzhayyim-sdk/pq] unsupported suite: ${suite}`);
    }
}
/**
 * Generate an ML-DSA-65 key pair. A 32-byte seed may be supplied for
 * deterministic derivation (e.g. from a vault-held master secret); omit it
 * for a random pair.
 */
export function generateMlDsaKeyPair(seed) {
    const s = seed ?? randomBytes(32);
    if (s.length !== 32) {
        throw new Error("[etzhayyim-sdk/pq] ML-DSA seed must be 32 bytes");
    }
    const { publicKey, secretKey } = ml_dsa65.keygen(s);
    return { publicKey, secretKey };
}
/** Sign a message with ML-DSA-65. Pairs with an Ed25519 signature in pqh-v1. */
export function mlDsaSign(secretKey, message) {
    return ml_dsa65.sign(message, secretKey);
}
/** Verify an ML-DSA-65 signature. Returns false (never throws) on mismatch. */
export function mlDsaVerify(publicKey, message, signature) {
    try {
        return ml_dsa65.verify(signature, message, publicKey);
    }
    catch {
        return false;
    }
}
