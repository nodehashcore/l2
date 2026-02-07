import crypto from "crypto";

const CLIENT_SECRET = "salt";
const WALLET_SALT = "seed";

function hexToBuffer(hex: string) {
  return Buffer.from(hex, "hex");
}

function deriveKey(secret: string) {
  return crypto.pbkdf2Sync(secret, WALLET_SALT, 100000, 32, "sha256");
}

export function decryptLayer2Payload(payloadHex: string, ivHex: string) {
  const key = deriveKey(CLIENT_SECRET);
  const iv = hexToBuffer(ivHex);
  const encrypted = hexToBuffer(payloadHex);

  const authTag = encrypted.subarray(encrypted.length - 16);
  const data = encrypted.subarray(0, encrypted.length - 16);

  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);

  const decrypted =
    decipher.update(data, undefined, "utf8") + decipher.final("utf8");

  return JSON.parse(decrypted);
}

export function decryptSeedPhrase(
  encryptedSeed: {
    ciphertext: string;
    salt: string;
    iv: string;
  },
  pin: string,
) {
  const key = crypto.pbkdf2Sync(
    pin,
    Buffer.from(encryptedSeed.salt, "base64"),
    100000,
    32,
    "sha256",
  );

  const cipherBuf = Buffer.from(encryptedSeed.ciphertext, "base64");
  const authTag = cipherBuf.subarray(cipherBuf.length - 16);
  const data = cipherBuf.subarray(0, cipherBuf.length - 16);

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(encryptedSeed.iv, "base64"),
  );

  decipher.setAuthTag(authTag);

  return decipher.update(data, undefined, "utf8") + decipher.final("utf8");
}
