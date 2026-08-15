import { applyD1Migrations, env, type D1Migration } from "cloudflare:test";
import { expect, it } from "vitest";

type TestEnv = Env & { TEST_MIGRATIONS: D1Migration[] };

it("applies all Core migrations to a fresh database", async () => {
  await applyD1Migrations(env.DB, (env as TestEnv).TEST_MIGRATIONS);
  const columns = await env.DB.prepare("PRAGMA table_info(mailboxes)").all<{ name: string }>();
  expect(columns.results.map((column) => column.name)).toContain("recovery_attempt_count");
  expect(columns.results.map((column) => column.name)).toContain("note");
  const status = await env.DB.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='mailboxes'").first<{ sql: string }>();
  expect(status?.sql ?? "").toContain("'registered'");
  expect(status?.sql ?? "").toContain("'activating'");
  const passwordColumn = (await env.DB.prepare("PRAGMA table_info(mailboxes)").all<{ name: string; notnull: number }>()).results.find((column) => column.name === "password_ciphertext");
  expect(passwordColumn?.notnull).toBe(0);
  const applied = await env.DB.prepare("SELECT name FROM d1_migrations ORDER BY id").all<{ name: string }>();
  expect(applied.results.map((row) => row.name)).toEqual(["0001.sql", "0002.sql", "0003.sql", "0004.sql", "0005.sql", "0006.sql", "0007.sql"]);
  expect(await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='login_attempts'").first()).not.toBeNull();
  const passwordVersion = await env.DB.prepare("SELECT value FROM settings WHERE key='admin_password_version'").first<{ value: string }>();
  expect(passwordVersion?.value).toBe("0");
});
