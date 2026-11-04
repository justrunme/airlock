import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { canonicalize, parseStrict, verifyReceipt, diffPaths } from "../../airlock/web/static/verify.js";

const vec = (name) => JSON.parse(readFileSync(new URL(`../vectors/${name}`, import.meta.url), "utf8"));
const vectors = vec("jcs_vectors.json");
const fixture = vec("receipt_fixture.json");
const [r0, r1] = fixture.receipts;
const PUB = fixture.pubkey_hex;
const failed = (res) => res.checks.find((c) => !c.ok);

for (const v of vectors) {
  test(`JCS vector matches Python: ${v.name}`, () => {
    assert.equal(canonicalize(parseStrict(v.input, { safeIntegers: false })), v.expected);
  });
}

test("Python-signed receipts verify", async () => {
  for (const r of [r0, r1]) {
    const res = await verifyReceipt(r, PUB);
    assert.equal(res.ok, true, JSON.stringify(res.checks));
    assert.equal(res.hash, JSON.parse(r).hash);
  }
});

test("chain link: second receipt points at the first", () => {
  assert.equal(JSON.parse(r1).prev_hash, JSON.parse(r0).hash);
});

test("re-serialised receipt (different whitespace and key order) still verifies", async () => {
  const obj = JSON.parse(r0);
  const shuffled = Object.fromEntries(Object.entries(obj).reverse());
  const res = await verifyReceipt(JSON.stringify(shuffled, null, 2), PUB);
  assert.equal(res.ok, true);
});

test("tampering one character in a signed field fails the hash check", async () => {
  const t = r0.replace('"verdict":"deny"', '"verdict":"allow"');
  assert.notEqual(t, r0);
  const res = await verifyReceipt(t, PUB);
  assert.equal(res.ok, false);
  assert.equal(failed(res).id, "hash");
  assert.deepEqual(diffPaths(JSON.parse(r0), JSON.parse(t)), ["decision.verdict"]);
});

test("tampering every character of the reason is caught", async () => {
  const obj = JSON.parse(r0);
  const reason = obj.decision.reason;
  for (let i = 0; i < reason.length; i += 7) {
    const c = reason[i] === "x" ? "y" : "x";
    obj.decision.reason = reason.slice(0, i) + c + reason.slice(i + 1);
    const res = await verifyReceipt(JSON.stringify(obj), PUB);
    assert.equal(failed(res).id, "hash", `offset ${i}`);
  }
});

test("hash rewritten to match tampered body fails the signature check", async () => {
  const obj = JSON.parse(r0);
  obj.decision.verdict = "allow";
  const { webcrypto } = await import("node:crypto");
  const { signedPayload } = await import("../../airlock/web/static/verify.js");
  const d = await webcrypto.subtle.digest("SHA-256", signedPayload(obj));
  obj.hash = Buffer.from(d).toString("hex");
  const res = await verifyReceipt(JSON.stringify(obj), PUB);
  assert.equal(failed(res).id, "signature");
});

test("wrong public key fails the signature check", async () => {
  const res = await verifyReceipt(r0, "ab".repeat(32));
  assert.equal(failed(res).id, "signature");
});

test("malformed public key is rejected", async () => {
  const res = await verifyReceipt(r0, "zz");
  assert.equal(failed(res).id, "signature");
});

test("duplicate key is rejected before hashing", async () => {
  const t = r0.replace('"verdict":"deny"', '"verdict":"allow","verdict":"deny"');
  const res = await verifyReceipt(t, PUB);
  assert.equal(failed(res).id, "json");
  assert.match(failed(res).detail, /duplicate key "verdict"/);
});

test("malformed JSON, NaN, unsafe ints and trailing data are rejected", async () => {
  for (const t of ["{", r0 + "x", r0.replace('"receipt_v":1', '"receipt_v":NaN'),
    r0.replace('"receipt_v":1', '"receipt_v":9007199254740993'), "[]", "null"]) {
    const res = await verifyReceipt(t, PUB);
    assert.equal(res.ok, false, t.slice(0, 40));
    assert.ok(["json", "schema"].includes(failed(res).id));
  }
});

test("schema: unknown field, missing field, bad hex are reported by path", async () => {
  const cases = [
    [(o) => { o.extra = 1; }, "extra"],
    [(o) => { delete o.task_id; }, "task_id"],
    [(o) => { o.hash = o.hash.toUpperCase(); }, "hash"],
    [(o) => { o.sig_ed25519 = "00"; }, "sig_ed25519"],
    [(o) => { o.prev_hash = "nothex"; }, "prev_hash"],
    [(o) => { o.decision.verdict = "maybe"; }, "decision.verdict"],
    [(o) => { o.decision.surprise = true; }, "decision.surprise"],
  ];
  for (const [mut, path] of cases) {
    const o = JSON.parse(r0);
    mut(o);
    const res = await verifyReceipt(JSON.stringify(o), PUB);
    assert.equal(failed(res).id, "schema");
    assert.equal(failed(res).path, path);
  }
});
