import { type HybridKemPublicBundle, type HybridKemSecretBundle, type HybridKemHandshake } from './pq.js';
export type SessionHandle = string;
/**
 * Establishes a new cryptographic session for secure key wrapping.
 * R1.0: Generates a per-session symmetric key and stores it in-memory.
 *
 * @deprecated Per ADR-2606111300 this local-only random key cannot be
 * transported to the recipient and carries no post-quantum protection. New
 * code MUST use {@link establishSessionInitiator} /
 * {@link establishSessionResponder} (suite pqh-v1). Retained one R-cycle
 * for read-compat per 90-docs/security/crypto-agility-policy.md.
 *
 * @param args - The arguments for establishing the session.
 * @param args.senderDid - The DID of the message sender.
 * @param args.recipientDid - The DID of the message recipient.
 * @returns A handle to the established session.
 */
export declare const establishSession: (args: {
    senderDid: string;
    recipientDid: string;
}) => SessionHandle;
/**
 * Wraps a plaintext key using the established session's symmetric key.
 *
 * @param args - The arguments for wrapping the key.
 * @param args.session - The handle for the session to use.
 * @param args.plaintext - The plaintext to encrypt.
 * @returns An object containing the ciphertext and the session ID.
 * @throws if the session handle is invalid.
 */
export declare const wrapKey: (args: {
    session: SessionHandle;
    plaintext: string;
}) => {
    ciphertext: Uint8Array;
    signalSessionId: string;
};
/**
 * Unwraps a ciphertext to retrieve the original plaintext key.
 *
 * @param args - The arguments for unwrapping the key.
 * @param args.session - The handle for the session used for encryption.
 * @param args.ciphertext - The ciphertext to decrypt.
 * @returns The original plaintext.
 * @throws if the session handle is invalid or decryption fails (tag mismatch).
 */
export declare const unwrapKey: (args: {
    session: SessionHandle;
    ciphertext: Uint8Array;
}) => string;
/**
 * Initiator side of a pqh-v1 (X25519 + ML-KEM-768 hybrid) session. The
 * derived 32-byte secret becomes the session's XChaCha20-Poly1305 key; the
 * returned handshake is transmitted to the recipient, who calls
 * {@link establishSessionResponder} to derive the same key. An attacker
 * recording the handshake must break BOTH X25519 AND ML-KEM-768 to recover
 * the session key (harvest-now-decrypt-later defence per ADR-2606111300).
 */
export declare const establishSessionInitiator: (args: {
    senderDid: string;
    recipientDid: string;
    recipientKem: HybridKemPublicBundle;
}) => {
    session: SessionHandle;
    handshake: HybridKemHandshake;
};
/**
 * Responder side of a pqh-v1 session: derive the initiator's session key
 * from the received handshake and the recipient's secret KEM bundle.
 * Ciphertexts wrapped under the initiator's handle unwrap under the handle
 * returned here (and vice versa).
 */
export declare const establishSessionResponder: (args: {
    senderDid: string;
    recipientDid: string;
    handshake: HybridKemHandshake;
    recipientKemSecret: HybridKemSecretBundle;
    recipientKemPublic: HybridKemPublicBundle;
}) => SessionHandle;
export declare const _clearSessions: () => void;
