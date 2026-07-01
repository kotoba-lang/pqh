/**
 * @etzhayyim/sdk/kdf — password-based key derivation seam (suite "argon2id-v1").
 *
 * Per the survivability analysis (90-docs/security/2606111200) the weakest
 * layer under an algorithmic-discovery (T3) adversary is human-password
 * entropy, not the mathematical ciphers. Argon2id (RFC 9106) is
 * memory-hard: an attacker testing candidate passwords pays the configured
 * memory cost per guess, which GPU/ASIC farms cannot amortize the way they
 * do PBKDF2's pure compute cost.
 *
 * Apps MUST NOT import @noble/hashes/argon2 directly; this module is the
 * SDK seam (same rule as ./pq and ADR-2605181100's @noble/ciphers rule).
 * Suite identifiers and read-compat follow
 * 90-docs/security/crypto-agility-policy.md — readers keep PBKDF2 support
 * for existing envelopes; new writes use argon2id-v1.
 */
import { argon2id } from "@noble/hashes/argon2";
export const KDF_ARGON2ID_V1 = "argon2id-v1";
/** Legacy suite id kept for read-compat envelope dispatch. */
export const KDF_PBKDF2_SHA256 = "pbkdf2-sha256";
export const KDF_KEY_BYTES = 32;
export const KDF_SALT_BYTES = 16;
/**
 * OWASP Password Storage Cheat Sheet minimum recommended configuration
 * (19 MiB, t=2, p=1). Chosen as the default because the derivation runs in
 * browsers (vault unlock / key-bundle enroll) where the RFC 9106
 * first-recommended 2 GiB is not realistic.
 */
export const ARGON2ID_DEFAULT_PARAMS = { mKiB: 19_456, t: 2, p: 1 };
/** RFC 9106 second recommended option (64 MiB, t=3) for non-interactive use. */
export const ARGON2ID_HIGH_PARAMS = { mKiB: 65_536, t: 3, p: 1 };
/**
 * Derive a symmetric key from a password with Argon2id. The caller persists
 * `salt` and the returned `params` alongside the ciphertext (envelope
 * metadata) so the key can be re-derived on any device.
 */
export function deriveKeyArgon2id(opts) {
    const params = opts.params ?? ARGON2ID_DEFAULT_PARAMS;
    if (opts.salt.length < 8) {
        throw new Error("[etzhayyim-sdk/kdf] salt must be at least 8 bytes");
    }
    if (params.mKiB < 8 * params.p || params.t < 1 || params.p < 1) {
        throw new Error("[etzhayyim-sdk/kdf] invalid Argon2id parameters");
    }
    const password = typeof opts.password === "string"
        ? new TextEncoder().encode(opts.password)
        : opts.password;
    const key = argon2id(password, opts.salt, {
        m: params.mKiB,
        t: params.t,
        p: params.p,
        dkLen: opts.dkLen ?? KDF_KEY_BYTES,
    });
    return { suite: KDF_ARGON2ID_V1, key, params };
}
