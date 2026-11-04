// Airlock receipt verification: strict JSON parsing, RFC 8785 (JCS)
// canonicalisation, SHA-256 and Ed25519 via WebCrypto. Runs unchanged in the
// browser and in Node >= 20. No network access, no dependencies.

const MAX_SAFE = 2n ** 53n; // same inclusive bound as airlock/receipt.py

export class ReceiptError extends Error {
  constructor(check, message, path = null) {
    super(message);
    this.check = check;
    this.path = path;
  }
}

// paths whose number token had a fraction or exponent, keyed by parsed root
const FLOAT_TOKENS = new WeakMap();

// ---- strict JSON parser: rejects duplicate keys, NaN/Infinity, trailing data
export function parseStrict(text, { safeIntegers = true } = {}) {
  let i = 0;
  const notIntLiteral = new Set();
  const err = (msg) => {
    throw new ReceiptError("json", `${msg} at offset ${i}`);
  };
  const ws = () => {
    while (i < text.length && " \t\n\r".includes(text[i])) i++;
  };
  const value = (path) => {
    ws();
    const c = text[i];
    if (c === "{") return object(path);
    if (c === "[") return array(path);
    if (c === '"') return string();
    if (c === "t" && text.startsWith("true", i)) { i += 4; return true; }
    if (c === "f" && text.startsWith("false", i)) { i += 5; return false; }
    if (c === "n" && text.startsWith("null", i)) { i += 4; return null; }
    return number(path);
  };
  const object = (path) => {
    i++;
    const out = {};
    const seen = new Set();
    ws();
    if (text[i] === "}") { i++; return out; }
    for (;;) {
      ws();
      if (text[i] !== '"') err("expected key");
      const k = string();
      if (seen.has(k)) throw new ReceiptError("json", `duplicate key "${k}"`, path);
      seen.add(k);
      ws();
      if (text[i] !== ":") err("expected ':'");
      i++;
      Object.defineProperty(out, k, {
        value: value(path ? `${path}.${k}` : k),
        enumerable: true, writable: true, configurable: true,
      });
      ws();
      if (text[i] === ",") { i++; continue; }
      if (text[i] === "}") { i++; return out; }
      err("expected ',' or '}'");
    }
  };
  const array = (path) => {
    i++;
    const out = [];
    ws();
    if (text[i] === "]") { i++; return out; }
    for (;;) {
      out.push(value(`${path}[${out.length}]`));
      ws();
      if (text[i] === ",") { i++; continue; }
      if (text[i] === "]") { i++; return out; }
      err("expected ',' or ']'");
    }
  };
  const string = () => {
    const m = /^"(?:[^"\\\u0000-\u001f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/.exec(text.slice(i));
    if (!m) err("bad string");
    i += m[0].length;
    return JSON.parse(m[0]);
  };
  const number = (path) => {
    const m = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(text.slice(i));
    if (!m) err("unexpected character");
    i += m[0].length;
    const n = Number(m[0]);
    if (!Number.isFinite(n)) throw new ReceiptError("json", "number out of range", path);
    if (safeIntegers) {
      // one encoding per value: no -0, integers within +/-2^53, and remember
      // where a fraction or exponent was used (1.0, 1e0) so integer fields reject it
      if (n === 0 && m[0][0] === "-") throw new ReceiptError("json", "negative zero is not allowed", path);
      if (/^-?\d+$/.test(m[0])) {
        const big = BigInt(m[0]);
        if (big > MAX_SAFE || -big > MAX_SAFE) throw new ReceiptError("json", "integer beyond +/-2^53", path);
      } else {
        notIntLiteral.add(path);
      }
    }
    return n;
  };
  const v = value("");
  ws();
  if (i !== text.length) err("trailing data");
  if (v !== null && typeof v === "object") FLOAT_TOKENS.set(v, notIntLiteral);
  return v;
}

// ---- RFC 8785 JSON Canonicalization Scheme
export function canonicalize(v) {
  if (v === null || typeof v === "boolean") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new ReceiptError("jcs", "non-finite number");
    return JSON.stringify(v); // ES Number serialisation == JCS number form
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(",")}]`;
  if (typeof v === "object") {
    // default sort compares UTF-16 code units, as RFC 8785 requires
    const keys = Object.keys(v).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(v[k])}`).join(",")}}`;
  }
  throw new ReceiptError("jcs", `unsupported type ${typeof v}`);
}

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const unhex = (s) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));

// ---- receipt schema (mirrors airlock.schemas.Receipt at the top level and Decision)
const T = {
  str: (x) => typeof x === "string",
  int: (x) => Number.isInteger(x),
  obj: (x) => x !== null && typeof x === "object" && !Array.isArray(x),
  arr: Array.isArray,
};
const nullable = (f) => (x) => x === null || f(x);
const RECEIPT_FIELDS = {
  schema_v: T.int, receipt_v: T.int, task_id: T.str, action_id: T.str,
  decision: T.obj, execution: nullable(T.obj), verification: nullable(T.obj),
  cleanup: nullable(T.obj), model: nullable(T.obj), prev_hash: nullable(T.str),
  hash: T.str, sig_ed25519: T.str,
};
// optional signed fields: may be absent; if present they must have this shape
const OPTIONAL_FIELDS = {
  context: (x) => T.obj(x) && Object.values(x).every(T.str),
};
const DECISION_FIELDS = {
  schema_v: T.int, action_id: T.str, verdict: (x) => ["allow", "deny", "require_approval"].includes(x),
  rules_fired: T.arr, blast_radius: T.obj, caps: T.obj, policy_sha256: T.str, reason: nullable(T.str),
};

function checkFields(obj, spec, prefix, optional = {}) {
  for (const [k, ok] of Object.entries(optional)) {
    if (k in obj && !ok(obj[k])) throw new ReceiptError("schema", `wrong type or value`, prefix + k);
  }
  for (const k of Object.keys(obj)) {
    if (!(k in spec) && !(k in optional)) throw new ReceiptError("schema", `unexpected field`, prefix + k);
  }
  for (const [k, ok] of Object.entries(spec)) {
    if (!(k in obj)) throw new ReceiptError("schema", `missing field`, prefix + k);
    if (!ok(obj[k])) throw new ReceiptError("schema", `wrong type or value`, prefix + k);
  }
}

export function checkSchema(r) {
  if (!T.obj(r)) throw new ReceiptError("schema", "receipt must be a JSON object");
  // every typed number in a receipt is an integer (as in airlock.schemas);
  // only the free-form decision.caps may hold a fraction such as cpus: 0.5
  for (const p of FLOAT_TOKENS.get(r) ?? []) {
    if (!/^decision\.caps(?:[.[]|$)/.test(p)) {
      throw new ReceiptError("schema", "integer field written with a fraction or exponent", p);
    }
  }
  checkFields(r, RECEIPT_FIELDS, "", OPTIONAL_FIELDS);
  checkFields(r.decision, DECISION_FIELDS, "decision.");
  if (!/^[0-9a-f]{64}$/.test(r.hash)) throw new ReceiptError("schema", "must be 64 lowercase hex", "hash");
  if (!/^[0-9a-f]{128}$/.test(r.sig_ed25519)) {
    throw new ReceiptError("schema", "must be 128 lowercase hex", "sig_ed25519");
  }
  if (r.prev_hash !== null && !/^[0-9a-f]{64}$/.test(r.prev_hash)) {
    throw new ReceiptError("schema", "must be null or 64 lowercase hex", "prev_hash");
  }
}

export function signedPayload(r) {
  const body = {};
  for (const k of Object.keys(r)) if (k !== "hash" && k !== "sig_ed25519") body[k] = r[k];
  return new TextEncoder().encode(canonicalize(body));
}

// Paths whose values differ between two parsed documents.
export function diffPaths(a, b, path = "") {
  if (Object.is(a, b)) return [];
  const bothObj = T.obj(a) && T.obj(b);
  const bothArr = T.arr(a) && T.arr(b);
  if (!bothObj && !bothArr) return [path || "$"];
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  const out = [];
  for (const k of keys) {
    const p = bothArr ? `${path}[${k}]` : path ? `${path}.${k}` : k;
    if (!(k in a) || !(k in b)) out.push(p);
    else out.push(...diffPaths(a[k], b[k], p));
  }
  return out;
}

/**
 * Verify a receipt. Returns {ok, checks:[{id, ok, detail, path}], hash}.
 * Each check runs only if the previous one passed, so the first failing
 * check is the reason.
 */
export async function verifyReceipt(text, publicKeyHex, subtle = globalThis.crypto?.subtle) {
  const checks = [];
  const add = (id, ok, detail, path = null) => checks.push({ id, ok, detail, path });
  let r;
  try {
    r = parseStrict(text);
    add("json", true, "strict JSON, no duplicate keys");
    checkSchema(r);
    add("schema", true, "all receipt and decision fields present with the right types");
  } catch (e) {
    if (!(e instanceof ReceiptError)) throw e;
    if (e.check === "json") add("json", false, e.message, e.path);
    else add("schema", false, e.message, e.path);
    return { ok: false, checks };
  }
  if (!subtle) {
    add("crypto", false, "WebCrypto is not available in this environment");
    return { ok: false, checks };
  }
  const payload = signedPayload(r);
  const digest = hex(await subtle.digest("SHA-256", payload));
  if (digest !== r.hash) {
    add("hash", false, `SHA-256 of the canonical receipt is ${digest}, receipt says ${r.hash}`, "hash");
    return { ok: false, checks, hash: digest };
  }
  add("hash", true, `SHA-256(JCS(receipt without hash, sig)) = ${digest}`);
  if (!/^[0-9a-f]{64}$/.test(publicKeyHex || "")) {
    add("signature", false, "public key must be 64 hex characters (raw Ed25519)");
    return { ok: false, checks, hash: digest };
  }
  let valid = false;
  try {
    const key = await subtle.importKey("raw", unhex(publicKeyHex), { name: "Ed25519" }, false, ["verify"]);
    valid = await subtle.verify({ name: "Ed25519" }, key, unhex(r.sig_ed25519), payload);
  } catch (e) {
    add("signature", false, `Ed25519 not usable here: ${e.message}`);
    return { ok: false, checks, hash: digest };
  }
  add("signature", valid, valid ? "Ed25519 signature valid for this public key" : "Ed25519 signature does not match", valid ? null : "sig_ed25519");
  return { ok: valid, checks, hash: digest };
}
