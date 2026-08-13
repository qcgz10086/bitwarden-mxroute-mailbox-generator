import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [cloudflareTest({ wrangler: { configPath: "./workers/core/wrangler.jsonc" } })],
  test: { include: ["tests/unit/**/*.test.ts"] },
});
