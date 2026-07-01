import { randomBytes } from '@noble/hashes/utils';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { hybridEncapsulate, hybridDecapsulate, } from './pq.js';
// In-memory store for sessions. R1.0 stage.
const sessions = new Map();
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
export const establishSession = (args) => {
    const sessionId = `session_${Buffer.from(randomBytes(16)).toString('hex')}`;
    const session = {
        sessionId,
        key: randomBytes(32), // 256-bit key for XChaCha20-Poly1305
        senderDid: args.senderDid,
        recipientDid: args.recipientDid,
        createdAt: Date.now(),
    };
    sessions.set(sessionId, session);
    return sessionId;
};
/**
 * Wraps a plaintext key using the established session's symmetric key.
 *
 * @param args - The arguments for wrapping the key.
 * @param args.session - The handle for the session to use.
 * @param args.plaintext - The plaintext to encrypt.
 * @returns An object containing the ciphertext and the session ID.
 * @throws if the session handle is invalid.
 */
export const wrapKey = (args) => {
    const session = sessions.get(args.session);
    if (!session) {
        throw new Error('Invalid session handle');
    }
    const nonce = randomBytes(24); // 24-byte nonce for XChaCha20
    const plaintextBytes = new TextEncoder().encode(args.plaintext);
    const ciphertext = xchacha20poly1305(session.key, nonce).encrypt(plaintextBytes);
    const finalCiphertext = new Uint8Array(nonce.length + ciphertext.length);
    finalCiphertext.set(nonce);
    finalCiphertext.set(ciphertext, nonce.length);
    return {
        ciphertext: finalCiphertext,
        signalSessionId: session.sessionId,
    };
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
export const unwrapKey = (args) => {
    const session = sessions.get(args.session);
    if (!session) {
        throw new Error('Invalid session handle');
    }
    if (args.ciphertext.length < 24) {
        throw new Error('Invalid ciphertext: too short');
    }
    const nonce = args.ciphertext.slice(0, 24);
    const encryptedBody = args.ciphertext.slice(24);
    const decryptedBytes = xchacha20poly1305(session.key, nonce).decrypt(encryptedBody);
    return new TextDecoder().decode(decryptedBytes);
};
/**
 * Initiator side of a pqh-v1 (X25519 + ML-KEM-768 hybrid) session. The
 * derived 32-byte secret becomes the session's XChaCha20-Poly1305 key; the
 * returned handshake is transmitted to the recipient, who calls
 * {@link establishSessionResponder} to derive the same key. An attacker
 * recording the handshake must break BOTH X25519 AND ML-KEM-768 to recover
 * the session key (harvest-now-decrypt-later defence per ADR-2606111300).
 */
export const establishSessionInitiator = (args) => {
    const info = new TextEncoder().encode(`${args.senderDid}|${args.recipientDid}`);
    const { sharedSecret, handshake } = hybridEncapsulate(args.recipientKem, info);
    const sessionId = `session_${Buffer.from(randomBytes(16)).toString('hex')}`;
    sessions.set(sessionId, {
        sessionId,
        key: sharedSecret,
        senderDid: args.senderDid,
        recipientDid: args.recipientDid,
        createdAt: Date.now(),
    });
    return { session: sessionId, handshake };
};
/**
 * Responder side of a pqh-v1 session: derive the initiator's session key
 * from the received handshake and the recipient's secret KEM bundle.
 * Ciphertexts wrapped under the initiator's handle unwrap under the handle
 * returned here (and vice versa).
 */
export const establishSessionResponder = (args) => {
    const info = new TextEncoder().encode(`${args.senderDid}|${args.recipientDid}`);
    const key = hybridDecapsulate(args.handshake, args.recipientKemSecret, args.recipientKemPublic, info);
    const sessionId = `session_${Buffer.from(randomBytes(16)).toString('hex')}`;
    sessions.set(sessionId, {
        sessionId,
        key,
        senderDid: args.senderDid,
        recipientDid: args.recipientDid,
        createdAt: Date.now(),
    });
    return sessionId;
};
// Test hook to clear sessions
export const _clearSessions = () => {
    sessions.clear();
};
