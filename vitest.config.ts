import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const testMigrations = await readD1Migrations("./workers/core/migrations");

export default defineConfig({
  plugins: [
    cloudflareTest({
      miniflare: { bindings: { TEST_MIGRATIONS: testMigrations } },
      wrangler: { configPath: "./workers/core/wrangler.jsonc" },
    }),
  ],
  test: { include: ["tests/unit/**/*.test.ts"] },
});
