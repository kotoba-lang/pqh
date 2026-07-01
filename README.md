# pqh

`@etzhayyim/pqh` — the crypto-agility seam: AEAD envelope encryption,
password-based KDF, a post-quantum hybrid layer, DID&harr;Signal identity
binding, and a deprecated toy Signal-session stand-in.

| Module | What it does |
|---|---|
| `crypto.ts` | XChaCha20-Poly1305 AEAD envelope (24-byte nonce, 16-byte tag) over dag-cbor, with an ISO/IEC-7816-4 padding-bucket scheme |
| `kdf.ts` | Argon2id (RFC 9106) password-based key derivation, suite `argon2id-v1` |
| `pq.ts` | Post-quantum hybrid layer, suite `pqh-v1`: X25519+ML-KEM-768 (FIPS 203) KEM combiner, Ed25519+ML-DSA-65 (FIPS 204) dual signatures |
| `did-signal.ts` | DID&harr;Signal `IdentityKey` binding verification (did:web / did:plc / did:key), with optional ML-DSA-65 hybrid signature |
| `signal.ts` | **Deprecated** in-memory session/key-wrap stand-in, retained only because a real test (`pq.test.ts`) exercises the PQ-hybrid-into-session-wrap path against it |

Zero business-logic coupling — every collection/DID/purpose value is a plain
parameter, not a hardcoded etzhayyim NSID. Apps are expected to import this
seam instead of the underlying libraries directly (`@noble/ciphers`,
`@noble/hashes`, `@noble/post-quantum`, `@noble/curves`) — see
`70-tools/scripts/lint/substrate-boundary.mjs` in `etzhayyim/root`.

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

Unlike the earlier `kami-nv-compat` relocation, this package has real
consumers inside `etzhayyim-sdk` (`encrypted.ts`) and in a downstream app
(`60-apps/etzhayyim-project-karute`'s svelte `sdk-init.ts`, via
`@etzhayyim/sdk/signal`). `etzhayyim-sdk`'s own `src/{crypto,kdf,pq,
did-signal,signal}.ts` become thin re-export shims over this package (`export
* from "@etzhayyim/pqh/<module>.js"`) so every existing `@etzhayyim/sdk/*`
import path keeps working unchanged.

This is a **physical move only** (TypeScript unchanged, same as
`kami-nv-compat`'s relocation) — a CLJC port is deferred to a later,
separate task.

## Development

```bash
npm install
npm run build
npm test
```

## License

Apache 2.0 + Charter Compliance Rider v3.6 (`/CHARTER-RIDER.md`).
