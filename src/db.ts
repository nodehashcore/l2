import { Pool } from "pg";

const Database =
  "postgresql://n_wallet_user:J7ue57QTnAJ035T0Wlf9dbxlrwhBB3zN@dpg-d7d3qs741pts739ptaug-a/n_wallet";
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
