import { applyD1Migrations, env, type D1Migration } from "cloudflare:test";
import { describe, expect, it } from "vitest";

type TestEnv = Env & { TEST_MIGRATIONS: D1Migration[] };

describe("Core D1 migrations", () => {
  it("upgrades a database where 0001 is already recorded", async () => {
    const migrations = (env as TestEnv).TEST_MIGRATIONS;
    expect(migrations).toHaveLength(2);
    await applyD1Migrations(env.DB, [migrations[0]!]);
    const before = await env.DB.prepare("PRAGMA table_info(mailboxes)").all<{ name: string }>();
    expect(before.results.map((column) => column.name)).not.toContain("recovery_attempt_count");

    await applyD1Migrations(env.DB, migrations);

    const columns = await env.DB.prepare("PRAGMA table_info(mailboxes)").all<{ name: string }>();
    expect(columns.results.map((column) => column.name)).toEqual(expect.arrayContaining([
      "next_password_key_version", "recovery_attempt_count", "recovery_next_at",
    ]));
    const auditColumns = await env.DB.prepare("PRAGMA table_info(audit_events)").all<{ name: string }>();
    expect(auditColumns.results.map((column) => column.name)).toContain("actor_email");
  });
});
