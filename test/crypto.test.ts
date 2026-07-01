/**
 * Unit tests for `@etzhayyim/sdk/crypto`.
 *
 * Scope: AEAD round-trip, AAD binding, tamper detection, key-id derivation.
 * Out of scope: PDS write/read integration (covered when encryptedWrite/
 * encryptedRead land on the main Etzhayyim class).
 */

import {describe, it, expect} from "vitest";
import {
  AEAD_ALG,
  AEAD_TAG_BYTES,
  ENVELOPE_VERSION,
  KEY_BYTES,
  NONCE_BYTES,
  PAD_BUCKETS,
  PAD_SCHEME_ISO7816,
  decrypt,
  encrypt,
  generateKey,
  generateNonce,
  keyIdOf,
  padIso7816,
  pickBucket,
  unpadIso7816,
} from "../src/crypto.js";

const SENDER = "did:web:alice.example";

describe("crypto envelope round-trip", () => {
  it("encrypts and decrypts a CBOR-serializable plaintext", () => {
    const key = generateKey();
    const plaintext = {hello: "world", n: 42, list: [1, 2, 3]};

    const env = encrypt({key, sender: SENDER, plaintext});

    expect(env.v).toBe(ENVELOPE_VERSION);
    expect(env.alg).toBe(AEAD_ALG);
    expect(env.nonce).toHaveLength(NONCE_BYTES);
    expect(env.sender).toBe(SENDER);
    expect(env.keyId).toBe(keyIdOf(key));

    const out = decrypt<typeof plaintext>({key, envelope: env});
    expect(out).toEqual(plaintext);
  });

  it("propagates innerType when supplied", () => {
    const key = generateKey();
    const env = encrypt({
      key,
      sender: SENDER,
      plaintext: {x: 1},
      innerType: "com.etzhayyim.governance.proposal",
    });
    expect(env.innerType).toBe("com.etzhayyim.governance.proposal");
  });

  it("uses a deterministic nonce when caller supplies one", () => {
    const key = generateKey();
    const nonce = generateNonce();
    const env = encrypt({key, sender: SENDER, plaintext: {a: 1}, nonce});
    expect(env.nonce).toEqual(nonce);
  });
});

describe("crypto AEAD binding", () => {
  it("rejects ciphertext when AAD differs at decrypt", () => {
    const key = generateKey();
    const env = encrypt({
      key,
      sender: SENDER,
      plaintext: {confidential: true},
      aad: new Uint8Array([1, 2, 3]),
    });
    expect(() =>
      decrypt({key, envelope: env, aad: new Uint8Array([9, 9, 9])})
    ).toThrow();
  });

  it("rejects ciphertext when AAD is missing at decrypt", () => {
    const key = generateKey();
    const env = encrypt({
      key,
      sender: SENDER,
      plaintext: {confidential: true},
      aad: new Uint8Array([1, 2, 3]),
    });
    expect(() => decrypt({key, envelope: env})).toThrow();
  });

  it("detects ciphertext tampering", () => {
    const key = generateKey();
    const env = encrypt({key, sender: SENDER, plaintext: {x: 1}});
    env.ciphertext[0] ^= 0xff;
    expect(() => decrypt({key, envelope: env})).toThrow();
  });

  it("rejects wrong key", () => {
    const key1 = generateKey();
    const key2 = generateKey();
    const env = encrypt({key: key1, sender: SENDER, plaintext: {x: 1}});
    expect(() => decrypt({key: key2, envelope: env})).toThrow();
  });
});

describe("crypto invariants", () => {
  it("rejects key of wrong length", () => {
    const badKey = new Uint8Array(16) as ReturnType<typeof generateKey>;
    expect(() => encrypt({key: badKey, sender: SENDER, plaintext: {}})).toThrow();
  });

  it("rejects nonce of wrong length", () => {
    const key = generateKey();
    const badNonce = new Uint8Array(12);
    expect(() =>
      encrypt({key, sender: SENDER, plaintext: {}, nonce: badNonce})
    ).toThrow();
  });

  it("rejects unknown envelope version at decrypt", () => {
    const key = generateKey();
    const env = encrypt({key, sender: SENDER, plaintext: {}});
    const bumped = {...env, v: 99 as unknown as typeof ENVELOPE_VERSION};
    expect(() => decrypt({key, envelope: bumped})).toThrow(/envelope version/);
  });

  it("keyIdOf is deterministic and 16 hex chars", () => {
    const key = generateKey();
    const id1 = keyIdOf(key);
    const id2 = keyIdOf(key);
    expect(id1).toBe(id2);
    expect(id1).toHaveLength(16);
    expect(id1).toMatch(/^[0-9a-f]+$/);
  });

  it("generateKey returns 32 bytes", () => {
    expect(generateKey()).toHaveLength(KEY_BYTES);
  });
});

describe("crypto padding (ADR-2605181200)", () => {
  it("padIso7816 appends 0x80 then 0x00s; unpad recovers original", () => {
    const plain = new Uint8Array([1, 2, 3, 4, 5]);
    const padded = padIso7816(plain, 16);
    expect(padded.length).toBe(16);
    expect(padded[5]).toBe(0x80);
    for (let i = 6; i < 16; i++) expect(padded[i]).toBe(0);
    expect(Array.from(unpadIso7816(padded))).toEqual(Array.from(plain));
  });

  it("padIso7816 rejects target too small", () => {
    expect(() => padIso7816(new Uint8Array(10), 10)).toThrow(/too small/);
  });

  it("unpadIso7816 rejects missing delimiter", () => {
    expect(() => unpadIso7816(new Uint8Array(16))).toThrow(/invalid/);
  });

  it("pickBucket picks the smallest bucket that fits plaintext + delimiter + tag", () => {
    // 1 byte plaintext + 1 delimiter + 16 tag = 18 → bucket 1024
    expect(pickBucket(1)).toBe(1024);
    // 1007 + 1 + 16 = 1024 → fits
    expect(pickBucket(1024 - 1 - AEAD_TAG_BYTES)).toBe(1024);
    // 1008 + 1 + 16 = 1025 → next bucket
    expect(pickBucket(1024 - AEAD_TAG_BYTES)).toBe(4096);
    // largest bucket
    expect(pickBucket(60000)).toBe(65536);
  });

  it("pickBucket throws when plaintext exceeds largest bucket", () => {
    expect(() => pickBucket(100000)).toThrow(/exceeds/);
  });

  it("encrypt(pad: 'bucket') yields ciphertext exactly equal to the bucket size", () => {
    const key = generateKey();
    const env = encrypt({key, sender: "did:test:a", plaintext: {x: 1}, pad: "bucket"});
    expect(env.pad).toBe(PAD_SCHEME_ISO7816);
    expect(env.ciphertext.length).toBe(PAD_BUCKETS[0]); // 1024 — tiny plaintext
    const back = decrypt({key, envelope: env});
    expect(back).toEqual({x: 1});
  });

  it("encrypt(pad: {bucket: 4096}) forces the explicit bucket", () => {
    const key = generateKey();
    const env = encrypt({
      key,
      sender: "did:test:a",
      plaintext: {x: 1},
      pad: {bucket: 4096},
    });
    expect(env.ciphertext.length).toBe(4096);
    const back = decrypt({key, envelope: env});
    expect(back).toEqual({x: 1});
  });

  it("differently-sized plaintexts encrypt to the same bucket length", () => {
    const key = generateKey();
    const small = encrypt({key, sender: "did:test:a", plaintext: {x: 1}, pad: "bucket"});
    const bigger = encrypt({
      key,
      sender: "did:test:a",
      plaintext: {body: "x".repeat(500), tag: "fill"},
      pad: "bucket",
    });
    expect(small.ciphertext.length).toBe(bigger.ciphertext.length);
    expect(small.ciphertext.length).toBe(PAD_BUCKETS[0]);
  });

  it("pad: 'none' (default) leaves ciphertext at native CBOR size + tag", () => {
    const key = generateKey();
    const env = encrypt({key, sender: "did:test:a", plaintext: {x: 1}});
    expect(env.pad).toBeUndefined();
    // Native CBOR of {x: 1} is 4 bytes; AEAD adds 16-byte tag → 20.
    expect(env.ciphertext.length).toBeLessThan(64);
  });

  it("envelope with pad set decrypts back to plaintext (no caller-side unpad arg)", () => {
    const key = generateKey();
    const obj = {body: "hi", n: 7};
    const env = encrypt({key, sender: "did:test:a", plaintext: obj, pad: "bucket"});
    expect(decrypt({key, envelope: env})).toEqual(obj);
  });
});
