# pqh

`@etzhayyim/pqh` — the crypto-agility seam: AEAD envelope encryption,
password-based KDF, a post-quantum hybrid layer, DID&harr;Signal identity
binding, and a deprecated toy Signal-session stand-in.

| Namespace | What it does |
|---|---|
| `crypto.clj` | XChaCha20-Poly1305 AEAD envelope (24-byte nonce, 16-byte tag) over dag-cbor, with an ISO/IEC-7816-4 padding-bucket scheme; raw AEAD behind the `IAead` seam |
| `kdf.clj` | Argon2id (RFC 9106) password-based key derivation, suite `argon2id-v1`; raw Argon2id behind the `IKdf` seam |
| `pq.clj` | Post-quantum hybrid layer, suite `pqh-v1`: X25519+ML-KEM-768 (FIPS 203) KEM combiner, Ed25519+ML-DSA-65 (FIPS 204) dual signatures; raw primitives behind the `IPq` seam |
| `did_signal.clj` | DID&harr;Signal `IdentityKey` binding verification (did:web / did:plc / did:key), with optional ML-DSA-65 hybrid signature |
| `signal.clj` | **Deprecated** in-memory session/key-wrap stand-in, retained only because a real test exercises the PQ-hybrid-into-session-wrap path against it |

Zero business-logic coupling — every collection/DID/purpose value is a plain
parameter, not a hardcoded etzhayyim NSID. Per ADR-2607012200 the pure core
imports no vendor crypto SDK: the raw primitives (XChaCha20-Poly1305, Argon2id,
X25519/ML-KEM/ML-DSA, HKDF) are injected capabilities (`IAead`/`IKdf`/`IPq`)
bound via dynamic vars, with the JVM BouncyCastle host impls in the test
fixtures `test/kotoba/lang/pqh/{aead,kdf,pq}_bc.clj`.

## Provenance

Relocated 2026-07-01 from `etzhayyim/root:20-actors/etzhayyim-sdk/src/
{crypto,kdf,pq,did-signal,signal}.ts` to `kotoba-lang/pqh` per the
org-taxonomy library-placement rule (any library/substrate code belongs in
`kotoba-lang`, ADR-2606302300). Design authority remains ADR-2605181100
(AEAD envelope + Signal keywrap) and ADR-2606111300 (PQ hybrid layer),
both in `etzhayyim/root`.

Named `pqh` (the suite identifier the code already uses, "pqh-v1"), not
`crypto` — `kotoba-lang/crypto` already exists as an unrelated, independently
authored CLJC "foundational stdlib" repo (hash/HMAC/HKDF + a host-injected
AEAD *interface*, no cipher implementation). Different abstraction layer,
same domain name; a future CLJC port of this package could plausibly build
on that repo's primitives rather than duplicate them.

Former TS consumers (`etzhayyim-sdk`'s re-export shims, the karute app via
`@etzhayyim/sdk/signal`) consumed this package's now-deleted npm `dist/`. With
the TypeScript deleted per ADR-2607012200, those paths need reconciliation to
the Clojure implementation. The only in-tree source dependency was
`kotoba-lang/checkpointer`'s `src/checkpointer.ts`, which is itself ported to
Clojure in a follow-up step (ADR-2607012200 §Step-6); other references are
doc/ADR only.

The initial relocation was a **physical move only** (TypeScript unchanged).
A Clojure port then landed and is now the only implementation: the TypeScript
(`src/*.ts` + committed `dist/`) was deleted per ADR-2607012200 (the
`kotoba-lang` org's pure-Clojure admission rule), with the crypto primitives
moved behind injected-capability seams (`IAead`/`IKdf`/`IPq`).

## Clojure port

`src/kotoba/lang/pqh/{crypto,kdf,pq,did_signal,signal}.clj` is a port of the
five former TS modules, one namespace per file
(`kotoba.lang.pqh.{crypto,kdf,pq,did-signal,signal}`), following the
`kotoba.lang.*` namespace convention established by `kotoba-lang/crypto` and
`kotoba-lang/ipfs`. Per ADR-2607012200 the pure core imports no vendor crypto
SDK: the raw primitives are injected capabilities (`crypto/IAead`,
`kdf/IKdf`, `pq/IPq`) bound via dynamic vars, with JVM BouncyCastle host
impls in `test/kotoba/lang/pqh/{aead,kdf,pq}_bc.clj`. The "crypto library
choices" below name the BouncyCastle primitives those host impls wrap (and
that the test-suite parity vectors were verified against); the JDK
`java.security` (MessageDigest/SecureRandom) used by `util.clj` /
`did_signal.clj` is platform, not vendor.

**JVM (`.clj`, not `.cljc`) scope decision.** Unlike `kotoba-lang/ipfs`
(real `.cljc` with a genuine CLJS `fetch`/`Blob` branch), this port ships
JVM-only for now, even though a plausible browser consumer for this package
demonstrably exists (`60-apps/etzhayyim-project-karute`'s Svelte app
encrypts PHI client-side via `@etzhayyim/sdk/encrypted`, and `kdf.ts`'s own
docstring targets browser "vault unlock / key-bundle enroll"). The reason
is narrower than "no browser use case" (witness-quorum's reason for going
`.clj`-only) — it's that **every one of this package's five modules needs
at least one primitive with zero Web Crypto browser coverage**:
XChaCha20-Poly1305 AEAD (`crypto.ts`), Argon2id (`kdf.ts`), and ML-KEM-768 /
ML-DSA-65 (`pq.ts`) all have no native `SubtleCrypto` primitive (Web Crypto
covers AES-GCM/CBC/CTR + PBKDF2/HKDF, not XChaCha20 or Argon2id, and no
browser ships lattice-based KEM/signature primitives at all). A genuine CLJS
branch for those three modules would mean hand-porting `@noble/ciphers`' and
`@noble/hashes`' own pure-JS implementations into ClojureScript from
scratch — a real, separate undertaking, not a thin reader-conditional
branch. `did-signal.ts`'s *baseline* path (Ed25519 sign/verify + canonical
CBOR) is the one piece that could plausibly get a genuine Web-Crypto CLJS
branch (Ed25519 sign/verify is in the current Web Crypto spec, and canonical
CBOR encoding is portable pure-data logic) — but this repo has **no CLJS
build/test tooling yet** to check a hand-written `js/crypto.subtle` branch
against, and shipping an unverified crypto/CBOR-encoding CLJS path is
exactly the kind of risk not worth taking silently. That branch is a
well-scoped follow-up, not something forced into this PR for symmetry with
`ipfs`. `signal.clj` is JVM-only because it depends on `crypto.clj` and
`pq.clj`, both JVM-only.

**Crypto library choices (JVM):**

- **AEAD (`crypto.clj`)** — XChaCha20-Poly1305 is composed from two pieces:
  HChaCha20 subkey derivation (hand-rolled, ~30 lines, matching
  `@noble/ciphers`' exported `hchacha()` function instruction-for-instruction)
  plus Bouncy Castle's standard RFC 8439 `ChaCha20Poly1305` AEAD
  (`bcprov-jdk18on`, `org.bouncycastle.crypto.modes.ChaCha20Poly1305`) for the
  inner 12-byte-nonce step. Bouncy Castle 1.79 does not expose XChaCha20
  directly, so composing it from HChaCha20 + standard ChaCha20-Poly1305 (the
  documented, standard construction) was the right call over vendoring a
  second AEAD library.
- **KDF (`kdf.clj`)** — Bouncy Castle's `Argon2BytesGenerator` +
  `Argon2Parameters.Builder(ARGON2_id)`, version `ARGON2_VERSION_13`.
- **Ed25519 (`did-signal.clj`)** — delegates to the peer library
  `kotoba-lang/ed25519` (`ed25519.core`, a git dependency) rather than
  reimplementing Ed25519 or reaching for Bouncy Castle: JDK's own
  `java.security.KeyPairGenerator.getInstance("Ed25519")`, driven through a
  seeded `SecureRandom`, does **not** reproduce the RFC 8032 public key for
  that seed (verified independently this session on a parallel port); Bouncy
  Castle's `Ed25519PrivateKeyParameters`/`Ed25519Signer` do work, but
  `kotoba-lang/ed25519` already solves this correctly with a *different*
  technique (PKCS8-wrapping the raw seed directly and driving JDK's own
  `KeyFactory`/`Signature` — no BouncyCastle, babashka-friendly) and is
  reused here rather than duplicated. This port independently re-verified
  `ed25519.core`'s `pubkey-from-seed`/`sign`/`verify` against
  `@noble/curves/ed25519` byte-for-byte (not just against its own JCA
  self-check).
- **X25519 / ML-KEM-768 / ML-DSA-65 (`pq.clj`)** — Bouncy Castle
  (`org.bouncycastle.crypto.params.X25519*`,
  `org.bouncycastle.pqc.crypto.mlkem.*`,
  `org.bouncycastle.pqc.crypto.mldsa.*`). HKDF-SHA256 (the KEM combiner) is
  BC's `HKDFBytesGenerator`.
- **Canonical CBOR** (`crypto.clj`'s plaintext envelope, `did-signal.clj`'s
  signing bytes) — delegates to the peer library `kotoba-lang/dag-cbor`
  (`cbor.core`, a git dependency), not reimplemented.

**What was cross-verified byte-for-byte** against this repo's own npm deps
(never against a hand-typed hex literal — every vector is programmatically
generated with `node:crypto`'s `randomBytes`, per this session's own
"don't hand-transcribe hex" lesson): XChaCha20-Poly1305 ciphertext+tag
(`@noble/ciphers`), Argon2id output (`@noble/hashes`), Ed25519 public key +
signature (`@noble/curves`), canonical dag-cbor encoding (`@ipld/dag-cbor`),
X25519 shared secret (`@noble/curves`), HKDF-SHA256 output (`@noble/hashes`),
ML-KEM-768 decapsulated shared secret + key encodings (`@noble/post-quantum`),
and ML-DSA-65 keygen-from-seed (public key AND full encoded secret key) plus
cross-verification of a `@noble/post-quantum`-signed message under a
Bouncy-Castle-loaded public key. The vectors live in
`test/kotoba/lang/pqh/vectors.edn`; regenerate with
`node scripts/gen-cross-lang-vectors.mjs > test/kotoba/lang/pqh/vectors.edn`.

**One documented, deliberate API divergence.** `pq.ts`'s
`generateMlDsaKeyPair` returns a `secretKey` in `@noble/post-quantum`'s FIPS
204 *expanded* encoding (4032 bytes for ML-DSA-65). This port's
`generate-ml-dsa-key-pair` instead returns `:secret-key` as the 32-byte FIPS
204 *seed*. This was a *found*, not assumed, constraint: Bouncy Castle
1.79's `MLDSAPrivateKeyParameters(params, seed)` constructor (32-byte input)
was verified to reproduce noble's public key **and** its full expanded
secret-key encoding byte-for-byte for the same seed — but the *same class'*
single-byte-array constructor, given a full 4032-byte expanded key instead
of a seed, does **not** reconstruct a signing-capable key, even when
round-tripping Bouncy Castle's *own* freshly-generated key through its own
`getEncoded()`. (That isolation test — BC-own-keygen → `getEncoded()` →
re-`MLDSAPrivateKeyParameters` → sign → verify-with-original-pubkey — is
what confirmed this is a real constructor-scope limitation, not a
noble-compatibility gap.) The seed representation is also FIPS 204's own
NIST-recommended canonical storage form, and `pq.ts` itself always derives
from a seed internally (`randomBytes(32)` when the caller doesn't supply
one) — this port just retains that seed instead of discarding it. Secret
keys never cross the wire in this package's actual protocol (only
`publicKey`, ciphertexts, and signatures do, and all three of those ARE
byte/verification-compatible with noble), so this divergence is contained;
it is called out explicitly in `kotoba.lang.pqh.pq`'s namespace docstring.

**Nothing was scoped out silently.** Every primitive this package uses
(XChaCha20-Poly1305, Argon2id, Ed25519, ML-KEM-768, ML-DSA-65, X25519,
HKDF-SHA256, canonical dag-cbor) was independently verified against this
repo's own npm dependencies before being relied on; none was shipped on the
strength of a memorized spec or an assumption about a library's behavior.

## Development

```bash
clojure -M:lint      # clj-kondo (errors fail)
clojure -M:test      # cognitect test-runner (binds the BouncyCastle host impls)
```

Cross-language known-answer vectors (`test/kotoba/lang/pqh/vectors.edn`) can
be regenerated from the @noble reference libs with
`node scripts/gen-cross-lang-vectors.mjs` (install `@noble/ciphers`,
`@noble/hashes`, `@noble/post-quantum`, `@noble/curves`, `@ipld/dag-cbor`
ad hoc — the committed vectors are the source of truth; the script is
provenance for how they were generated).

## License

Apache 2.0 + Charter Compliance Rider v3.6 (`/CHARTER-RIDER.md`).
