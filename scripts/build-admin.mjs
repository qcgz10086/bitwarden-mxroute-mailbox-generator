import { build, transform } from "esbuild";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { findUnsafeAssetContent } from "./admin-asset-policy.mjs";

const root = new URL("../", import.meta.url);
const ui = new URL("workers/admin/ui/", root);
const output = new URL("workers/admin/public/", root);
await mkdir(output, { recursive: true });
await build({ entryPoints: [fileURLToPath(new URL("app.ts", ui))], outfile: fileURLToPath(new URL("app.js", output)), bundle: true, format: "esm", target: "es2023", minify: true, legalComments: "none", sourcemap: false, charset: "utf8", logLevel: "silent" });
const css = await readFile(new URL("styles.css", ui), "utf8");
const minified = await transform(css, { loader: "css", minify: true, target: "es2023", legalComments: "none", sourcemap: false });
await writeFile(new URL("styles.css", output), minified.code, "utf8");
for (const name of ["index.html", "app.js", "styles.css"]) {
  const content = await readFile(new URL(name, output), "utf8");
  const violation = findUnsafeAssetContent(content);
  if (violation) throw new Error(`Unsafe content detected in ${name}: ${violation}`);
}
