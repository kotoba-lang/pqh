(ns kotoba.lang.pqh.did-signal
  "DID <-> Signal IdentityKey binding verification (did:web / did:plc /
   did:key), with optional ML-DSA-65 hybrid signature -- JVM port of pqh's
   src/did-signal.ts. Per ADR-2605181100 + ADR-2606111300 (etzhayyim/root).

   Signature scheme: Ed25519 over canonical dag-cbor-encoded body (optionally
   dual-signed with ML-DSA-65, suite pqh-v1).

   Ed25519 delegates to `ed25519.core` (io.github.kotoba-lang/ed25519) --
   verified in this port's test suite to reproduce @noble/curves/ed25519
   byte-for-byte (public key AND signature) for the same 32-byte seed.
   Canonical CBOR delegates to `cbor.core` (io.github.kotoba-lang/dag-cbor)
   -- verified to reproduce @ipld/dag-cbor's canonical encoding byte-for-byte
   for this namespace's body shapes.

   WIRE-FORMAT NOTE: a SignalIdentityBody/SignedSignalIdentity here is a
   plain Clojure map with STRING keys matching the TS field names verbatim
   (\"did\", \"signalIdentityKey\", \"signalRegistrationId\", ...) -- not
   kebab-case keywords -- because dag-cbor's canonical encoding must produce
   byte-identical signing bytes to the TS side (`cbor.core/encode` sorts map
   keys canonically regardless of insertion order, so the exact key STRINGS
   matter but their order in the map literal does not).

   JVM-only for the (optional) PQ-hybrid path (no Web Crypto ML-DSA), but
   this namespace's Ed25519-only baseline (sign-signal-identity /
   verify-signal-identity / canonical-signing-bytes / signal-identity-
   fingerprint) is, in principle, the best CLJS-port candidate in this
   package (Ed25519 sign/verify is in the current Web Crypto spec, and
   canonical CBOR is portable pure-data logic) -- deferred to a follow-up
   rather than shipped here unverified, since this repo has no CLJS
   build/test tooling yet to check a hand-written Web Crypto branch against;
   see the README \"Clojure/CLJC port\" section."
  (:require [ed25519.core :as ed]
            [cbor.core :as cbor]
            [kotoba.lang.pqh.util :as u]
            [kotoba.lang.pqh.pq :as pq]
            [clojure.string :as str]))

;; ── canonical signing bytes + Ed25519 ────────────────────────────────────

(defn canonical-signing-bytes
  "Canonical dag-cbor bytes to sign/verify for a SignalIdentityBody map
   (string keys, no \"signature\"/\"pqSignature\" field)."
  ^bytes [body]
  (cbor/encode body))

(defn sign-signal-identity
  "Sign a SignalIdentityBody with the actor's DID Ed25519 signing key
   (32-byte seed). Returns the body plus a \"signature\" field."
  [body signing-key]
  (let [msg (canonical-signing-bytes body)]
    (assoc body "signature" (ed/sign signing-key msg))))

(defn verify-signal-identity
  "opts: {:signed signed-map, :did-verification-key bytes}.
   true only if signed.did is non-empty and the Ed25519 signature verifies."
  [{:keys [signed did-verification-key]}]
  (let [did (get signed "did")]
    (if (or (nil? did) (= did ""))
      false
      (let [body (dissoc signed "signature" "pqSignature")
            msg (canonical-signing-bytes body)
            signature (get signed "signature")]
        (try
          (boolean (ed/verify did-verification-key msg signature))
          (catch Exception _ false))))))

;; ── pqh-v1 dual signature (Ed25519 + ML-DSA-65) ──────────────────────────

(defn sign-signal-identity-hybrid
  "Dual-sign a SignalIdentityBody (suite pqh-v1): Ed25519 with the DID
   signing key plus ML-DSA-65 with the DID's post-quantum signing key, both
   over the same canonical bytes."
  [body signing-key pq-signing-key]
  (let [msg (canonical-signing-bytes body)]
    (assoc body
           "signature" (ed/sign signing-key msg)
           "pqSignature" (pq/ml-dsa-sign pq-signing-key msg))))

(defn verify-signal-identity-hybrid
  "opts: {:signed :did-verification-key :did-pq-verification-key (optional)}.
   The Ed25519 signature must always verify. If a PQ verification key is
   known, a pqSignature is REQUIRED and must verify too (no downgrade)."
  [{:keys [signed did-verification-key did-pq-verification-key]}]
  (let [did (get signed "did")]
    (if (or (nil? did) (= did ""))
      false
      (let [pq-signature (get signed "pqSignature")
            body (dissoc signed "signature" "pqSignature")
            msg (canonical-signing-bytes body)
            signature (get signed "signature")
            ed-ok (try (boolean (ed/verify did-verification-key msg signature))
                       (catch Exception _ false))]
        (cond
          (not ed-ok) false
          (nil? did-pq-verification-key) true
          (nil? pq-signature) false
          :else (pq/ml-dsa-verify did-pq-verification-key msg pq-signature))))))

(defn signal-identity-fingerprint
  "Fingerprint of a Signal IdentityKey (\"safety number\" pattern). First 16
   hex chars of SHA-256."
  ^String [^bytes identity-key]
  (subs (u/bytes->hex (u/sha256 identity-key)) 0 16))

;; ── DID-document key extraction (pqh-v1, ADR-2606111300) ─────────────────

(def ^:private MLDSA65-PUB-BYTES 1952)
;; mldsa-65-pub = 0x1211 (multicodec registry, draft; FIPS 204) -> varint [0x91 0x24].
(def ^:private MLDSA65-MULTICODEC-0 0x91)
(def ^:private MLDSA65-MULTICODEC-1 0x24)

(defn pq-verification-key-from-did-doc
  "Extract the DID's ML-DSA-65 verification key from a resolved DID document
   (a Clojure map with STRING keys, mirroring the JSON/JS document shape).
   Scans \"verificationMethod\" for a multibase 'z' (base58btc) key whose
   decoded bytes carry the mldsa-65-pub multicodec prefix and a 1952-byte
   FIPS 204 public key. Returns nil when the document publishes none
   (legacy read-compat)."
  [did-doc]
  (when (map? did-doc)
    (let [vm (get did-doc "verificationMethod")]
      (when (sequential? vm)
        (some (fn [entry]
                (let [mb (get entry "publicKeyMultibase")]
                  (when (and (string? mb) (str/starts-with? mb "z"))
                    (try
                      (let [decoded (ed/b58-decode (subs mb 1))]
                        (when (and (= (alength decoded) (+ 2 MLDSA65-PUB-BYTES))
                                   (= (bit-and (aget decoded 0) 0xff) MLDSA65-MULTICODEC-0)
                                   (= (bit-and (aget decoded 1) 0xff) MLDSA65-MULTICODEC-1))
                          (java.util.Arrays/copyOfRange decoded 2 (alength decoded))))
                      (catch Exception _ nil)))))
              vm)))))
