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
export declare const PQ_SUITE: "pqh-v1";
export type PqSuite = typeof PQ_SUITE;
export declare const X25519_PUBLIC_BYTES = 32;
export declare const MLKEM768_PUBLIC_BYTES = 1184;
export declare const MLKEM768_CIPHERTEXT_BYTES = 1088;
export declare const MLDSA65_PUBLIC_BYTES = 1952;
export declare const HYBRID_SHARED_SECRET_BYTES = 32;
/** Public half of a hybrid KEM identity: publish both keys under the DID. */
export interface HybridKemPublicBundle {
    suite: PqSuite;
    x25519PublicKey: Uint8Array;
    mlkemPublicKey: Uint8Array;
}
/** Secret half of a hybrid KEM identity. NEVER leaves the member device. */
export interface HybridKemSecretBundle {
    suite: PqSuite;
    x25519SecretKey: Uint8Array;
    mlkemSecretKey: Uint8Array;
}
export interface HybridKemKeyPair {
    publicBundle: HybridKemPublicBundle;
    secretBundle: HybridKemSecretBundle;
}
/**
 * Wire message the initiator sends alongside (or inside) the first wrapped
 * key so the responder can derive the same shared secret.
 */
export interface HybridKemHandshake {
    suite: PqSuite;
    /** Initiator's ephemeral X25519 public key (32 bytes). */
    x25519Ephemeral: Uint8Array;
    /** ML-KEM-768 ciphertext against the recipient's mlkemPublicKey (1088 bytes). */
    mlkemCiphertext: Uint8Array;
}
/** Generate a fresh hybrid (X25519 + ML-KEM-768) KEM key pair. */
export declare function generateHybridKemKeyPair(): HybridKemKeyPair;
export interface HybridEncapsulation {
    sharedSecret: Uint8Array;
    handshake: HybridKemHandshake;
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
export declare function hybridEncapsulate(recipient: HybridKemPublicBundle, info?: Uint8Array): HybridEncapsulation;
/**
 * Responder side: derive the same shared secret from a received handshake.
 * ML-KEM implicit rejection means a tampered ciphertext yields a *different*
 * secret rather than an error; downstream AEAD authentication catches it.
 */
export declare function hybridDecapsulate(handshake: HybridKemHandshake, secret: HybridKemSecretBundle, recipientPublic: HybridKemPublicBundle, info?: Uint8Array): Uint8Array;
export interface MlDsaKeyPair {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
}
/**
 * Generate an ML-DSA-65 key pair. A 32-byte seed may be supplied for
 * deterministic derivation (e.g. from a vault-held master secret); omit it
 * for a random pair.
 */
export declare function generateMlDsaKeyPair(seed?: Uint8Array): MlDsaKeyPair;
/** Sign a message with ML-DSA-65. Pairs with an Ed25519 signature in pqh-v1. */
export declare function mlDsaSign(secretKey: Uint8Array, message: Uint8Array): Uint8Array;
/** Verify an ML-DSA-65 signature. Returns false (never throws) on mismatch. */
export declare function mlDsaVerify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
