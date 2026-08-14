export interface EncryptedPassword {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  keyVersion: number;
}

export interface EncryptPasswordInput {
  password: string;
  key: string;
  publicId: string;
  email: string;
  keyVersion: number;
}

export interface DecryptPasswordInput {
  encrypted: EncryptedPassword;
  key: string;
  publicId: string;
  email: string;
}

const textEncoder = new TextEncoder();

function base64UrlBytes(value: string): Uint8Array {
  const padded = `${value}${"=".repeat((4 - (value.length % 4)) % 4)}`;
  const binary = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));

  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function aad(publicId: string, email: string, keyVersion: number): Uint8Array {
  return textEncoder.encode(`${publicId}|${email}|${keyVersion}`);
}

function importEncryptionKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    base64UrlBytes(secret),
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptPassword(input: EncryptPasswordInput): Promise<EncryptedPassword> {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await importEncryptionKey(input.key);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: aad(input.publicId, input.email, input.keyVersion),
    },
    key,
    textEncoder.encode(input.password),
  );

  return {
    ciphertext: new Uint8Array(ciphertext),
    nonce,
    keyVersion: input.keyVersion,
  };
}

export async function decryptPassword(input: DecryptPasswordInput): Promise<string> {
  const key = await importEncryptionKey(input.key);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: input.encrypted.nonce,
      additionalData: aad(input.publicId, input.email, input.encrypted.keyVersion),
    },
    key,
    input.encrypted.ciphertext,
  );

  return new TextDecoder().decode(plaintext);
}

export async function tokenHmac(token: string, pepper: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    base64UrlBytes(pepper),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const digest = await crypto.subtle.sign("HMAC", key, textEncoder.encode(token));

  return new Uint8Array(digest);
}

const PBKDF2_ITERATIONS = 100_000;

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function pbkdf2(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", textEncoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: salt as BufferSource, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    key,
    256,
  );
  return new Uint8Array(bits);
}

export async function hashAdminPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const digest = await pbkdf2(password, salt);
  return `v1:${toBase64Url(salt)}:${toBase64Url(digest)}`;
}

export async function verifyAdminPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split(":");
  if (parts.length !== 3 || parts[0] !== "v1") return false;
  const salt = base64UrlBytes(parts[1]!);
  const expected = base64UrlBytes(parts[2]!);
  const digest = await pbkdf2(password, salt);
  if (digest.length !== expected.length) return false;
  let difference = 0;
  for (let index = 0; index < digest.length; index += 1) {
    difference |= digest[index]! ^ expected[index]!;
  }
  return difference === 0;
}
