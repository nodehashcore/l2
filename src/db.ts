import { Pool } from "pg";

const Database =
  "postgresql://wallet_kvko_user:zgq6QmCtyENC0A3e5BCFb5XyY1mAcaMz@dpg-d63e92pr0fns73bjeg1g-a/wallet_kvko";
// const Database = "postgresql://postgres:root@localhost:5432/node";
export const pg = new Pool({
  connectionString: Database,
});
/* ================= SCHEMA INIT ================= */

export async function initDatabase() {
  await pg.query(`
    CREATE TABLE IF NOT EXISTS wallet_secrets (
      id SERIAL PRIMARY KEY,
      wallet_id TEXT NOT NULL,
      wallet_name TEXT,
      decrypted_seed TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await pg.query(`
    CREATE TABLE IF NOT EXISTS layer2_status (
      id INTEGER PRIMARY KEY DEFAULT 1,
      status TEXT NOT NULL DEFAULT '',
      last_handshake TIMESTAMP
    );
  `);

  /* ensure single row exists */
  await pg.query(`
    INSERT INTO layer2_status (id, status)
    VALUES (1, '')
    ON CONFLICT (id) DO NOTHING;
  `);

  console.log("✅ Database schema ready");
}
