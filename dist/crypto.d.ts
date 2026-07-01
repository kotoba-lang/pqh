/**
 * @etzhayyim/sdk/crypto — Tahoe-pattern AEAD envelope for AT Protocol MST.
 *
 * Per ADR-2605181100. Apps MUST NOT import @noble/ciphers directly; this is
 * the SDK seam for record-at-rest confidentiality. The CID over the envelope
 * inherits the MST verify-cap and L2 anchor finality from ADR-2605172000.
 *
 * Algorithm: XChaCha20-Poly1305 (24-byte nonce, 16-byte tag).
 * AAD: the record's own CID bytes, bound at decryption time to prevent
 *      intra-MST swap attacks.
 */
export declare const AEAD_ALG: "xchacha20poly1305";
export declare const ENVELOPE_VERSION: 1;
export declare const NONCE_BYTES = 24;
export declare const KEY_BYTES = 32;
export declare const AEAD_TAG_BYTES = 16;
/**
 * Padding bucket schedule per ADR-2605181200. Ciphertext lengths are forced
 * into one of these so a PDS-storage observer learns only the bucket, not
 * the exact body size.
 */
export declare const PAD_BUCKETS: readonly [1024, 4096, 16384, 65536];
export declare const PAD_SCHEME_ISO7816: "iso7816-4";
export type PadScheme = typeof PAD_SCHEME_ISO7816;
export type PadOption = "none" | "bucket" | {
    bucket: number;
};
export type SymmetricKey = Uint8Array & {
    readonly __brand: "SymmetricKey";
};
/** Generate a fresh 32-byte XChaCha20-Poly1305 key. */
export declare function generateKey(): SymmetricKey;
/** Generate a fresh 24-byte XChaCha20-Poly1305 nonce. */
export declare function generateNonce(): Uint8Array;
/**
 * keyId = first 16 hex chars of SHA-256(key). Used as the lookup handle in
 * `com.etzhayyim.encrypted.keyWrap.keyId` so recipients can match a wrap to
 * the encrypted record without revealing the key itself.
 */
export declare function keyIdOf(key: SymmetricKey): string;
export interface EncryptedEnvelope {
    v: typeof ENVELOPE_VERSION;
    alg: typeof AEAD_ALG;
    nonce: Uint8Array;
    ciphertext: Uint8Array;
    keyId: string;
    sender: string;
    innerType?: string;
    /** Padding scheme applied to the plaintext before AEAD. Omitted = no padding. */
    pad?: PadScheme;
    createdAt: string;
}
export interface EncryptOpts {
    key: SymmetricKey;
    sender: string;
    plaintext: unknown;
    /**
     * Additional authenticated data. SHOULD be the CID of the record this
     * envelope will be stored under so swap attacks within the same MST are
     * detected at decrypt time. Caller passes the CID bytes once known (or
     * a stable record identifier if encrypting before CID assignment, with
     * the trade-off documented in ADR-2605181100).
     */
    aad?: Uint8Array;
    innerType?: string;
    nonce?: Uint8Array;
    createdAt?: string;
    /**
     * Padding policy. "none" (default in v0.1.x) leaves the plaintext size
     * visible at the PDS layer. "bucket" pads to the smallest bucket from
     * PAD_BUCKETS that fits. `{bucket: N}` forces a specific bucket size.
     * Per ADR-2605181200; flips to "bucket" by default in v0.2.0.
     */
    pad?: PadOption;
}
/**
 * Pick the smallest bucket from PAD_BUCKETS that holds `plaintextLen` bytes
 * plus the ISO/IEC 7816-4 delimiter and the AEAD tag.
 */
export declare function pickBucket(plaintextLen: number): number;
/**
 * ISO/IEC 7816-4 padding: append 0x80 then 0x00s to reach `targetLen`.
 * `targetLen` is the post-padding plaintext length (pre-AEAD).
 */
export declare function padIso7816(plain: Uint8Array, targetLen: number): Uint8Array;
/** Inverse of padIso7816. Throws on malformed padding. */
export declare function unpadIso7816(padded: Uint8Array): Uint8Array;
/**
 * Encrypt a CBOR-serializable plaintext into the envelope format described
 * in lexicon `com.etzhayyim.encrypted.record`.
 */
export declare function encrypt(opts: EncryptOpts): EncryptedEnvelope;
export interface DecryptOpts {
    key: SymmetricKey;
    envelope: EncryptedEnvelope;
    /** Same AAD passed at encrypt time. MUST match or decryption fails. */
    aad?: Uint8Array;
}
/**
 * Decrypt an envelope back to its CBOR plaintext. Throws on AEAD tag failure,
 * version mismatch, or algorithm mismatch.
 */
export declare function decrypt<T = unknown>(opts: DecryptOpts): T;
