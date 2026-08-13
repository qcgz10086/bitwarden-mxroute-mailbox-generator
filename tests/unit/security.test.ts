import { describe, expect, it } from "vitest";

import {
  randomApiToken,
  randomMailboxPassword,
  randomPrefix,
} from "../../packages/security/src/random";
import {
  decryptPassword,
  encryptPassword,
  tokenHmac,
  type EncryptedPassword,
} from "../../packages/security/src/crypto";

const PRIMARY_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const SECONDARY_KEY = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const PLAINTEXT = "An8!mailbox_Pass";
const PUBLIC_ID = "mbx_01J3Q6J6V6BX8JVNNPQ2P8G5TZ";
const EMAIL = "billing@example.test";

function decryptInput(encrypted: EncryptedPassword, key = PRIMARY_KEY, email = EMAIL) {
  return { encrypted, key, publicId: PUBLIC_ID, email };
}

describe("random mailbox credentials", () => {
  it("generates a prefix with the requested length from the permitted alphabet", () => {
    const prefix = randomPrefix(64);

    expect(prefix).toHaveLength(64);
    expect(prefix).toMatch(/^[23456789abcdefghjkmnpqrstuvwxyz]+$/);
  });

  it("generates an MXroute-compatible 18-character password", () => {
    const password = randomMailboxPassword();

    expect(password).toHaveLength(18);
    expect(password).toMatch(/^[ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%_-]+$/);
    expect(password).toMatch(/[A-Z]/);
    expect(password).toMatch(/[a-z]/);
    expect(password).toMatch(/[0-9]/);
  });

  it("does not repeat a mailbox password across 2,000 generations", () => {
    const passwords = new Set(
      Array.from({ length: 2_000 }, () => randomMailboxPassword()),
    );

    expect(passwords).toHaveLength(2_000);
  });

  it("encodes 32 random API-token bytes as base64url", () => {
    const token = randomApiToken();
    const padded = `${token}${"=".repeat((4 - (token.length % 4)) % 4)}`;
    const bytes = Uint8Array.from(atob(padded.replace(/-/g, "+").replace(/_/g, "/")), (character) =>
      character.charCodeAt(0),
    );

    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(bytes).toHaveLength(32);
  });
});

describe("encrypted mailbox passwords", () => {
  it("decrypts a password with its original key and associated mailbox identity", async () => {
    const encrypted = await encryptPassword({
      password: PLAINTEXT,
      key: PRIMARY_KEY,
      publicId: PUBLIC_ID,
      email: EMAIL,
      keyVersion: 1,
    });

    await expect(decryptPassword(decryptInput(encrypted))).resolves.toBe(PLAINTEXT);
  });

  it("creates a fresh 96-bit nonce for each encryption", async () => {
    const first = await encryptPassword({
      password: PLAINTEXT,
      key: PRIMARY_KEY,
      publicId: PUBLIC_ID,
      email: EMAIL,
      keyVersion: 1,
    });
    const second = await encryptPassword({
      password: PLAINTEXT,
      key: PRIMARY_KEY,
      publicId: PUBLIC_ID,
      email: EMAIL,
      keyVersion: 1,
    });

    expect(first.nonce).toHaveLength(12);
    expect(second.nonce).toHaveLength(12);
    expect(second.nonce).not.toEqual(first.nonce);
  });

  it("rejects decryption with a different encryption key", async () => {
    const encrypted = await encryptPassword({
      password: PLAINTEXT,
      key: PRIMARY_KEY,
      publicId: PUBLIC_ID,
      email: EMAIL,
      keyVersion: 1,
    });

    await expect(decryptPassword(decryptInput(encrypted, SECONDARY_KEY))).rejects.toThrow();
  });

  it("rejects a modified ciphertext", async () => {
    const encrypted = await encryptPassword({
      password: PLAINTEXT,
      key: PRIMARY_KEY,
      publicId: PUBLIC_ID,
      email: EMAIL,
      keyVersion: 1,
    });
    const ciphertext = new Uint8Array(encrypted.ciphertext);
    ciphertext[ciphertext.length - 1]! ^= 1;

    await expect(
      decryptPassword(decryptInput({ ...encrypted, ciphertext })),
    ).rejects.toThrow();
  });

  it("rejects decryption when the email AAD changes", async () => {
    const encrypted = await encryptPassword({
      password: PLAINTEXT,
      key: PRIMARY_KEY,
      publicId: PUBLIC_ID,
      email: EMAIL,
      keyVersion: 1,
    });

    await expect(
      decryptPassword(decryptInput(encrypted, PRIMARY_KEY, "support@example.test")),
    ).rejects.toThrow();
  });

  it("rejects decryption when the public ID AAD changes", async () => {
    const encrypted = await encryptPassword({
      password: PLAINTEXT,
      key: PRIMARY_KEY,
      publicId: PUBLIC_ID,
      email: EMAIL,
      keyVersion: 1,
    });

    await expect(
      decryptPassword({
        encrypted,
        key: PRIMARY_KEY,
        publicId: "mbx_01J3Q6J6V6BX8JVNNPQ2P8G5U0",
        email: EMAIL,
      }),
    ).rejects.toThrow();
  });

  it("rejects decryption when the key-version AAD changes", async () => {
    const encrypted = await encryptPassword({
      password: PLAINTEXT,
      key: PRIMARY_KEY,
      publicId: PUBLIC_ID,
      email: EMAIL,
      keyVersion: 1,
    });

    await expect(
      decryptPassword(decryptInput({ ...encrypted, keyVersion: 2 })),
    ).rejects.toThrow();
  });
});

describe("API-token HMACs", () => {
  it("returns the standard HMAC-SHA-256 digest for a token and base64url pepper", async () => {
    const digest = await tokenHmac("what do ya want for nothing?", "SmVmZQ");

    expect(Array.from(digest)).toEqual([
      0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
      0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
      0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
      0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43,
    ]);
  });

  it("is deterministic for a token and pepper", async () => {
    const first = await tokenHmac("token-value", "SmVmZQ");
    const second = await tokenHmac("token-value", "SmVmZQ");

    expect(second).toEqual(first);
  });

  it("produces distinct digests for distinct tokens", async () => {
    const first = await tokenHmac("token-one", "SmVmZQ");
    const second = await tokenHmac("token-two", "SmVmZQ");

    expect(second).not.toEqual(first);
  });
});
