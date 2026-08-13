import { mkdir, writeFile } from "node:fs/promises";

const publicDirectory = new URL("../workers/admin/public/", import.meta.url);
const indexHtml = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Mailbox Admin</title>
  </head>
  <body>
    <main>Mailbox administration interface placeholder.</main>
  </body>
</html>
`;

await mkdir(publicDirectory, { recursive: true });
await writeFile(new URL("index.html", publicDirectory), indexHtml, "utf8");
