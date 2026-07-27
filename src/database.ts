import sqlite3 from "sqlite3";
import { open } from "sqlite";

export async function openDb() {
  return open({
    filename: "./database.sqlite",
    driver: sqlite3.Database
  });
}

export async function initDb() {
  const db = await openDb();

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      nickname TEXT,
      password TEXT NOT NULL,
      goal INTEGER NOT NULL DEFAULT 100
    );

    CREATE TABLE IF NOT EXISTS studies_group (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      continuous_study_day INTEGER NOT NULL DEFAULT 0,
      total_days_studied INTEGER NOT NULL DEFAULT 0,
      total_experience_points INTEGER NOT NULL DEFAULT 0,
      last_study_date TEXT,
      last_penalty_date TEXT,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );
  `);

  return db;
}