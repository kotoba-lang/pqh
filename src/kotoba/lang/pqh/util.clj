(ns kotoba.lang.pqh.util
  "Shared byte/hex/random-bytes/SHA-256 helpers used across the
   kotoba.lang.pqh.* namespaces. Not part of pqh's TS surface -- an internal
   convenience shared by this port's five modules."
  (:import (java.security MessageDigest SecureRandom)))

(defonce ^:private secure-random (SecureRandom.))

(defn random-bytes
  "n cryptographically-random bytes (java.security.SecureRandom)."
  ^bytes [^long n]
  (let [b (byte-array n)]
    (.nextBytes secure-random b)
    b))

(defn concat-bytes
  "Concatenate any number of byte arrays into one."
  ^bytes [& arrays]
  (let [total (reduce + (map alength arrays))
        out (byte-array total)]
    (loop [off 0 as arrays]
      (if (seq as)
        (let [^bytes a (first as)]
          (System/arraycopy a 0 out off (alength a))
          (recur (+ off (alength a)) (rest as)))
        out))))

(defn sha256
  ^bytes [^bytes b]
  (.digest (MessageDigest/getInstance "SHA-256") b))

(defn bytes->hex
  ^String [^bytes b]
  (let [sb (StringBuilder. (* 2 (alength b)))]
    (doseq [by b]
      (.append sb (format "%02x" (bit-and (int by) 0xff))))
    (.toString sb)))

(defn hex->bytes
  ^bytes [^String s]
  (byte-array (map (fn [[a b]] (unchecked-byte (Integer/parseInt (str a b) 16)))
                   (partition 2 s))))
