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
