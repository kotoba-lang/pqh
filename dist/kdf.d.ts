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
export declare const KDF_ARGON2ID_V1: "argon2id-v1";
/** Legacy suite id kept for read-compat envelope dispatch. */
export declare const KDF_PBKDF2_SHA256: "pbkdf2-sha256";
export declare const KDF_KEY_BYTES = 32;
export declare const KDF_SALT_BYTES = 16;
export interface Argon2idParams {
    /** Memory cost in KiB. */
    mKiB: number;
    /** Time cost (passes). */
    t: number;
    /** Parallelism lanes. */
    p: number;
}
/**
 * OWASP Password Storage Cheat Sheet minimum recommended configuration
 * (19 MiB, t=2, p=1). Chosen as the default because the derivation runs in
 * browsers (vault unlock / key-bundle enroll) where the RFC 9106
 * first-recommended 2 GiB is not realistic.
 */
export declare const ARGON2ID_DEFAULT_PARAMS: Argon2idParams;
/** RFC 9106 second recommended option (64 MiB, t=3) for non-interactive use. */
export declare const ARGON2ID_HIGH_PARAMS: Argon2idParams;
export interface DeriveKeyArgon2idOpts {
    /** UTF-8 password / passphrase material. */
    password: string | Uint8Array;
    /** Random salt, >= 8 bytes (16 recommended; see KDF_SALT_BYTES). */
    salt: Uint8Array;
    /** Cost parameters. Default: ARGON2ID_DEFAULT_PARAMS. */
    params?: Argon2idParams;
    /** Output length in bytes. Default: KDF_KEY_BYTES (32). */
    dkLen?: number;
}
export interface DerivedKeyArgon2id {
    suite: typeof KDF_ARGON2ID_V1;
    key: Uint8Array;
    /** Echo of the parameters actually used — persist them with the envelope. */
    params: Argon2idParams;
}
/**
 * Derive a symmetric key from a password with Argon2id. The caller persists
 * `salt` and the returned `params` alongside the ciphertext (envelope
 * metadata) so the key can be re-derived on any device.
 */
export declare function deriveKeyArgon2id(opts: DeriveKeyArgon2idOpts): DerivedKeyArgon2id;
