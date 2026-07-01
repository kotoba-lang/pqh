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
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { randomBytes } from "@noble/ciphers/webcrypto";
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex } from "@noble/hashes/utils";
import { encode as cborEncode, decode as cborDecode } from "@ipld/dag-cbor";
export const AEAD_ALG = "xchacha20poly1305";
export const ENVELOPE_VERSION = 1;
export const NONCE_BYTES = 24;
export const KEY_BYTES = 32;
export const AEAD_TAG_BYTES = 16;
/**
 * Padding bucket schedule per ADR-2605181200. Ciphertext lengths are forced
 * into one of these so a PDS-storage observer learns only the bucket, not
 * the exact body size.
 */
export const PAD_BUCKETS = [1024, 4096, 16384, 65536];
export const PAD_SCHEME_ISO7816 = "iso7816-4";
/** Generate a fresh 32-byte XChaCha20-Poly1305 key. */
export function generateKey() {
    return randomBytes(KEY_BYTES);
}
/** Generate a fresh 24-byte XChaCha20-Poly1305 nonce. */
export function generateNonce() {
    return randomBytes(NONCE_BYTES);
}
/**
 * keyId = first 16 hex chars of SHA-256(key). Used as the lookup handle in
 * `com.etzhayyim.encrypted.keyWrap.keyId` so recipients can match a wrap to
 * the encrypted record without revealing the key itself.
 */
export function keyIdOf(key) {
    return bytesToHex(sha256(key)).slice(0, 16);
}
/**
 * Pick the smallest bucket from PAD_BUCKETS that holds `plaintextLen` bytes
 * plus the ISO/IEC 7816-4 delimiter and the AEAD tag.
 */
export function pickBucket(plaintextLen) {
    const need = plaintextLen + 1 + AEAD_TAG_BYTES;
    for (const b of PAD_BUCKETS) {
        if (need <= b)
            return b;
    }
    throw new Error(`[etzhayyim-sdk/crypto] plaintext ${plaintextLen} bytes exceeds largest inline ` +
        `bucket ${PAD_BUCKETS[PAD_BUCKETS.length - 1]}; store via ciphertextBlob.`);
}
/**
 * ISO/IEC 7816-4 padding: append 0x80 then 0x00s to reach `targetLen`.
 * `targetLen` is the post-padding plaintext length (pre-AEAD).
 */
export function padIso7816(plain, targetLen) {
    if (plain.length + 1 > targetLen) {
        throw new Error(`[etzhayyim-sdk/crypto] padding target ${targetLen} too small for ` +
            `plaintext ${plain.length} + delimiter`);
    }
    const out = new Uint8Array(targetLen);
    out.set(plain, 0);
    out[plain.length] = 0x80;
    return out;
}
/** Inverse of padIso7816. Throws on malformed padding. */
export function unpadIso7816(padded) {
    let i = padded.length - 1;
    while (i >= 0 && padded[i] === 0x00)
        i--;
    if (i < 0 || padded[i] !== 0x80) {
        throw new Error("[etzhayyim-sdk/crypto] invalid ISO/IEC 7816-4 padding");
    }
    return padded.subarray(0, i);
}
/**
 * Encrypt a CBOR-serializable plaintext into the envelope format described
 * in lexicon `com.etzhayyim.encrypted.record`.
 */
export function encrypt(opts) {
    if (opts.key.length !== KEY_BYTES) {
        throw new Error(`[etzhayyim-sdk/crypto] key must be ${KEY_BYTES} bytes`);
    }
    const nonce = opts.nonce ?? generateNonce();
    if (nonce.length !== NONCE_BYTES) {
        throw new Error(`[etzhayyim-sdk/crypto] nonce must be ${NONCE_BYTES} bytes`);
    }
    const plaintextBytes = cborEncode(opts.plaintext);
    let toEncrypt = plaintextBytes;
    let padScheme;
    const pad = opts.pad ?? "none";
    if (pad !== "none") {
        let target;
        if (pad === "bucket") {
            target = pickBucket(plaintextBytes.length) - AEAD_TAG_BYTES;
        }
        else {
            if (pad.bucket <= AEAD_TAG_BYTES + 1) {
                throw new Error(`[etzhayyim-sdk/crypto] explicit bucket ${pad.bucket} too small`);
            }
            target = pad.bucket - AEAD_TAG_BYTES;
        }
        toEncrypt = padIso7816(plaintextBytes, target);
        padScheme = PAD_SCHEME_ISO7816;
    }
    const cipher = xchacha20poly1305(opts.key, nonce, opts.aad);
    const ciphertext = cipher.encrypt(toEncrypt);
    return {
        v: ENVELOPE_VERSION,
        alg: AEAD_ALG,
        nonce,
        ciphertext,
        keyId: keyIdOf(opts.key),
        sender: opts.sender,
        innerType: opts.innerType,
        pad: padScheme,
        createdAt: opts.createdAt ?? new Date().toISOString(),
    };
}
/**
 * Decrypt an envelope back to its CBOR plaintext. Throws on AEAD tag failure,
 * version mismatch, or algorithm mismatch.
 */
export function decrypt(opts) {
    const { envelope, key, aad } = opts;
    if (envelope.v !== ENVELOPE_VERSION) {
        throw new Error(`[etzhayyim-sdk/crypto] unsupported envelope version: ${envelope.v}`);
    }
    if (envelope.alg !== AEAD_ALG) {
        throw new Error(`[etzhayyim-sdk/crypto] unsupported AEAD algorithm: ${envelope.alg}`);
    }
    if (keyIdOf(key) !== envelope.keyId) {
        throw new Error("[etzhayyim-sdk/crypto] key does not match envelope.keyId");
    }
    const cipher = xchacha20poly1305(key, envelope.nonce, aad);
    const padded = cipher.decrypt(envelope.ciphertext);
    const plaintextBytes = envelope.pad === PAD_SCHEME_ISO7816 ? unpadIso7816(padded) : padded;
    return cborDecode(plaintextBytes);
}
