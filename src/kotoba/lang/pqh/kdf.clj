(ns kotoba.lang.pqh.kdf
  "Password-based key derivation seam (suite \"argon2id-v1\") -- JVM port of
   pqh's src/kdf.ts. Argon2id (RFC 9106) via Bouncy Castle's
   Argon2BytesGenerator (`bcprov-jdk18on`), verified byte-identical to
   @noble/hashes' argon2id for the same password/salt/params in this port's
   test suite (kotoba.lang.pqh.kdf-test).

   JVM-only: Web Crypto has no native Argon2id primitive (only PBKDF2/HKDF),
   so a CLJS branch would mean hand-porting @noble/hashes' pure-JS Argon2id
   into ClojureScript -- deferred; see this repo's README."
  (:import (org.bouncycastle.crypto.generators Argon2BytesGenerator)
           (org.bouncycastle.crypto.params Argon2Parameters Argon2Parameters$Builder)))

(def KDF-ARGON2ID-V1 "argon2id-v1")
;; Legacy suite id kept for read-compat envelope dispatch.
(def KDF-PBKDF2-SHA256 "pbkdf2-sha256")

(def KDF-KEY-BYTES 32)
(def KDF-SALT-BYTES 16)

;; OWASP Password Storage Cheat Sheet minimum recommended configuration
;; (19 MiB, t=2, p=1). Browser-friendly default.
(def ARGON2ID-DEFAULT-PARAMS {:m-kib 19456 :t 2 :p 1})

;; RFC 9106 second recommended option (64 MiB, t=3) for non-interactive use.
(def ARGON2ID-HIGH-PARAMS {:m-kib 65536 :t 3 :p 1})

(defn derive-key-argon2id
  "opts: {:password (string or bytes), :salt bytes (>= 8 bytes),
          :params {:m-kib :t :p} (default ARGON2ID-DEFAULT-PARAMS),
          :dk-len int (default KDF-KEY-BYTES)}
   Returns {:suite KDF-ARGON2ID-V1, :key bytes, :params the-params-used}."
  [{:keys [password salt params dk-len]
    :or {params ARGON2ID-DEFAULT-PARAMS dk-len KDF-KEY-BYTES}}]
  (when (< (alength ^bytes salt) 8)
    (throw (ex-info "[kotoba.lang.pqh/kdf] salt must be at least 8 bytes" {})))
  (let [{:keys [m-kib t p]} params]
    (when (or (< m-kib (* 8 p)) (< t 1) (< p 1))
      (throw (ex-info "[kotoba.lang.pqh/kdf] invalid Argon2id parameters" {})))
    (let [pw-bytes (if (string? password) (.getBytes ^String password "UTF-8") password)
          bc-params (-> (Argon2Parameters$Builder. Argon2Parameters/ARGON2_id)
                        (.withSalt salt)
                        (.withParallelism (int p))
                        (.withMemoryAsKB (int m-kib))
                        (.withIterations (int t))
                        (.withVersion Argon2Parameters/ARGON2_VERSION_13)
                        (.build))
          gen (doto (Argon2BytesGenerator.) (.init bc-params))
          out (byte-array dk-len)]
      (.generateBytes gen ^bytes pw-bytes out)
      {:suite KDF-ARGON2ID-V1 :key out :params params})))
