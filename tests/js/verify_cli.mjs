// Usage: node verify_cli.mjs <receipt.json> <pubkey-hex>
// Prints the verification result as JSON; exit 0 if valid, 1 otherwise.
import { readFileSync } from "node:fs";
import { verifyReceipt } from "../../airlock/web/static/verify.js";

const [file, pub] = process.argv.slice(2);
const res = await verifyReceipt(readFileSync(file, "utf8"), pub);
process.stdout.write(JSON.stringify(res) + "\n");
process.exit(res.ok ? 0 : 1);
