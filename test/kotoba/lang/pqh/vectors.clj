(ns kotoba.lang.pqh.vectors
  "Cross-language known-answer test vectors, generated programmatically from
   this repo's own npm deps (@noble/ciphers, @noble/hashes, @noble/curves,
   @noble/post-quantum, @ipld/dag-cbor) -- see vectors.edn (checked in
   alongside this namespace) and this repo's README \"Clojure/CLJC port\"
   section for the generator script this data came from. All random inputs
   were generated with node:crypto's randomBytes (never hand-typed hex) to
   avoid transcription errors."
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [kotoba.lang.pqh.util :as u]))

(def vectors
  (edn/read-string (slurp (io/resource "kotoba/lang/pqh/vectors.edn"))))

(defn hb ^bytes [hex-string] (u/hex->bytes hex-string))
