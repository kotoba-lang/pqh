(ns kotoba.lang.pqh.signal
  "Deprecated in-memory session/key-wrap stand-in -- JVM port of pqh's
   src/signal.ts. Kept only because a real test
   (kotoba.lang.pqh.pq-test, mirroring pq.test.ts) exercises the
   PQ-hybrid-into-session-wrap path against it. Not a real Signal/libsignal
   integration; see kotoba.lang.pqh.crypto for the AEAD envelope this
   package prefers for actual record-at-rest use.

   JVM-only (depends on kotoba.lang.pqh.crypto and kotoba.lang.pqh.pq, both
   JVM-only -- see their docstrings and this repo's README)."
  (:require [kotoba.lang.pqh.util :as u]
            [kotoba.lang.pqh.crypto :as crypto]
            [kotoba.lang.pqh.pq :as pq])
  (:import (java.util Arrays)))

;; In-memory store for sessions. R1.0 stage.
(defonce ^:private sessions (atom {}))

(defn- new-session-id []
  (str "session_" (u/bytes->hex (u/random-bytes 16))))

(defn establish-session
  "@deprecated Per ADR-2606111300 this local-only random key cannot be
   transported to the recipient and carries no post-quantum protection. New
   code MUST use establish-session-initiator / establish-session-responder
   (suite pqh-v1).

   opts: {:sender-did string :recipient-did string}. Returns a session handle."
  [{:keys [sender-did recipient-did]}]
  (let [session-id (new-session-id)]
    (swap! sessions assoc session-id
           {:session-id session-id
            :key (u/random-bytes 32)
            :sender-did sender-did
            :recipient-did recipient-did
            :created-at (System/currentTimeMillis)})
    session-id))

(defn wrap-key
  "opts: {:session handle :plaintext string}.
   Returns {:ciphertext bytes :signal-session-id string}. Throws on an
   invalid session handle."
  [{:keys [session plaintext]}]
  (if-let [s (@sessions session)]
    (let [nonce (u/random-bytes 24)
          plaintext-bytes (.getBytes ^String plaintext "UTF-8")
          ciphertext (crypto/xchacha20poly1305-encrypt (:key s) nonce nil plaintext-bytes)]
      {:ciphertext (u/concat-bytes nonce ciphertext)
       :signal-session-id (:session-id s)})
    (throw (ex-info "Invalid session handle" {}))))

(defn unwrap-key
  "opts: {:session handle :ciphertext bytes}. Returns the plaintext string.
   Throws on an invalid session handle or AEAD tag mismatch."
  ^String [{:keys [session ciphertext]}]
  (if-let [s (@sessions session)]
    (do
      (when (< (alength ^bytes ciphertext) 24)
        (throw (ex-info "Invalid ciphertext: too short" {})))
      (let [nonce (Arrays/copyOfRange ^bytes ciphertext 0 24)
            body (Arrays/copyOfRange ^bytes ciphertext 24 (alength ^bytes ciphertext))
            decrypted (crypto/xchacha20poly1305-decrypt (:key s) nonce nil body)]
        (String. decrypted "UTF-8")))
    (throw (ex-info "Invalid session handle" {}))))

(defn establish-session-initiator
  "Initiator side of a pqh-v1 (X25519 + ML-KEM-768 hybrid) session.
   opts: {:sender-did :recipient-did :recipient-kem (a pq/public-bundle)}.
   Returns {:session handle :handshake (transmit this to the recipient)}."
  [{:keys [sender-did recipient-did recipient-kem]}]
  (let [info (.getBytes (str sender-did "|" recipient-did) "UTF-8")
        {:keys [shared-secret handshake]} (pq/hybrid-encapsulate recipient-kem info)
        session-id (new-session-id)]
    (swap! sessions assoc session-id
           {:session-id session-id
            :key shared-secret
            :sender-did sender-did
            :recipient-did recipient-did
            :created-at (System/currentTimeMillis)})
    {:session session-id :handshake handshake}))

(defn establish-session-responder
  "Responder side of a pqh-v1 session: derive the initiator's session key
   from the received handshake and the recipient's secret KEM bundle.
   opts: {:sender-did :recipient-did :handshake :recipient-kem-secret
          :recipient-kem-public}. Returns a session handle."
  [{:keys [sender-did recipient-did handshake recipient-kem-secret recipient-kem-public]}]
  (let [info (.getBytes (str sender-did "|" recipient-did) "UTF-8")
        key (pq/hybrid-decapsulate handshake recipient-kem-secret recipient-kem-public info)
        session-id (new-session-id)]
    (swap! sessions assoc session-id
           {:session-id session-id
            :key key
            :sender-did sender-did
            :recipient-did recipient-did
            :created-at (System/currentTimeMillis)})
    session-id))

;; Test hook to clear sessions.
(defn clear-sessions! [] (reset! sessions {}))
