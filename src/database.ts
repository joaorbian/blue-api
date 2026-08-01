import "dotenv/config";

import { Pool, PoolClient, QueryResultRow } from "pg";

function getDatabaseUrl(): string {
  const databaseUrl = process.env.DATABASE_URL;

  if (!databaseUrl) {
    throw new Error("DATABASE_URL não configurada.");
  }

  return databaseUrl;
}

const useSsl = process.env.DATABASE_SSL === "true";

export const pool = new Pool({
  connectionString: getDatabaseUrl(),
  ssl: useSsl
    ? {
        rejectUnauthorized: false
      }
    : false
});

export async function query<T extends QueryResultRow>(
  text: string,
  params: unknown[] = []
): Promise<T[]> {
  const result = await pool.query<T>(text, params);
  return result.rows;
}

export async function queryOne<T extends QueryResultRow>(
  text: string,
  params: unknown[] = []
): Promise<T | null> {
  const result = await pool.query<T>(text, params);
  return result.rows[0] ?? null;
}

export async function transaction<T>(
  callback: (client: PoolClient) => Promise<T>
): Promise<T> {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await callback(client);

    await client.query("COMMIT");

    return result;
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

export async function initDb(): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      email VARCHAR(255) NOT NULL UNIQUE,
      nickname VARCHAR(100),
      password TEXT NOT NULL,
      goal INTEGER NOT NULL DEFAULT 100,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS studies_group (
      id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      user_id INTEGER NOT NULL UNIQUE,
      continuous_study_day INTEGER NOT NULL DEFAULT 0,
      total_days_studied INTEGER NOT NULL DEFAULT 0,
      total_experience_points INTEGER NOT NULL DEFAULT 0,
      last_study_date DATE,
      last_penalty_date DATE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

      CONSTRAINT fk_studies_group_user
        FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
    );
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_studies_group_experience
    ON studies_group(total_experience_points DESC);
  `);

  await pool.query("SELECT 1");

  console.log("PostgreSQL conectado e tabelas verificadas.");
}

export async function closeDb(): Promise<void> {
  await pool.end();
}