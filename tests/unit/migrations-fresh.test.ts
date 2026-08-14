import { applyD1Migrations, env, type D1Migration } from "cloudflare:test";
import { expect, it } from "vitest";

type TestEnv = Env & { TEST_MIGRATIONS: D1Migration[] };

it("applies all Core migrations to a fresh database", async () => {
  await applyD1Migrations(env.DB, (env as TestEnv).TEST_MIGRATIONS);
  const columns = await env.DB.prepare("PRAGMA table_info(mailboxes)").all<{ name: string }>();
  expect(columns.results.map((column) => column.name)).toContain("recovery_attempt_count");
  expect(columns.results.map((column) => column.name)).toContain("note");
  const applied = await env.DB.prepare("SELECT name FROM d1_migrations ORDER BY id").all<{ name: string }>();
  expect(applied.results.map((row) => row.name)).toEqual(["0001.sql", "0002.sql", "0003.sql", "0004.sql", "0005.sql"]);
});
