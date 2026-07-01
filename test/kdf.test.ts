import { describe, it, expect } from "vitest";
import { randomBytes } from "@noble/hashes/utils";
import {
  deriveKeyArgon2id,
  ARGON2ID_DEFAULT_PARAMS,
  ARGON2ID_HIGH_PARAMS,
  KDF_ARGON2ID_V1,
  KDF_KEY_BYTES,
} from "../src/kdf";

describe("@etzhayyim/sdk: kdf (argon2id-v1)", () => {
  const salt = randomBytes(16);

  it("derives a 32-byte key deterministically", () => {
    const a = deriveKeyArgon2id({ password: "correct horse battery staple", salt });
    const b = deriveKeyArgon2id({ password: "correct horse battery staple", salt });
    expect(a.suite).toBe(KDF_ARGON2ID_V1);
    expect(a.key.length).toBe(KDF_KEY_BYTES);
    expect(Buffer.from(a.key).toString("hex")).toBe(Buffer.from(b.key).toString("hex"));
    expect(a.params).toEqual(ARGON2ID_DEFAULT_PARAMS);
  });

  it("different password, salt, or params change the key", () => {
    const base = deriveKeyArgon2id({ password: "pw", salt });
    const otherPw = deriveKeyArgon2id({ password: "pw2", salt });
    const otherSalt = deriveKeyArgon2id({ password: "pw", salt: randomBytes(16) });
    const otherParams = deriveKeyArgon2id({
      password: "pw",
      salt,
      params: { mKiB: 8_192, t: 3, p: 1 },
    });
    const hex = (k: Uint8Array) => Buffer.from(k).toString("hex");
    expect(hex(otherPw.key)).not.toBe(hex(base.key));
    expect(hex(otherSalt.key)).not.toBe(hex(base.key));
    expect(hex(otherParams.key)).not.toBe(hex(base.key));
  });

  it("rejects a short salt and degenerate params", () => {
    expect(() => deriveKeyArgon2id({ password: "pw", salt: randomBytes(4) })).toThrow(
      /salt/,
    );
    expect(() =>
      deriveKeyArgon2id({ password: "pw", salt, params: { mKiB: 1, t: 1, p: 1 } }),
    ).toThrow(/parameters/);
  });

  it("high profile derives with RFC 9106 second recommended params", () => {
    const r = deriveKeyArgon2id({
      password: "pw",
      salt,
      params: ARGON2ID_HIGH_PARAMS,
    });
    expect(r.params.mKiB).toBe(65_536);
    expect(r.key.length).toBe(KDF_KEY_BYTES);
  });
});
