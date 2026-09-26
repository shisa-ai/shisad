import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseEnv } from "node:util";

const root = new URL("../", import.meta.url);
const localFile = new URL(".env.local", root);
const local = existsSync(localFile) ? parseEnv(readFileSync(localFile, "utf8")) : {};
const token = (process.env.SHISAD_LEDGER_ORIGIN_TOKEN ?? local.SHISAD_LEDGER_ORIGIN_TOKEN ?? "").trim();
if (!token) {
  console.error("Set SHISAD_LEDGER_ORIGIN_TOKEN in the build environment or bridge .env.local before building/testing.");
  process.exit(1);
}
const directory = new URL("src/generated/", root);
mkdirSync(directory, { recursive: true });
writeFileSync(new URL("origin-token.ts", directory),
  "// Generated application configuration. Do not commit.\n" +
  `export const APPLICATION_ORIGIN_TOKEN: string = ${JSON.stringify(token)};\n`, { mode: 0o600 });
console.log(`Injected Ledger application configuration into ${fileURLToPath(directory)}`);

// npm packages exclude package-lock.json; carry the same pinned tree for consumers.
const lock = new URL("package-lock.json", root);
if (existsSync(lock)) copyFileSync(lock, new URL("npm-shrinkwrap.json", root));
