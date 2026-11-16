# agents

Project-local instructions for agents working in this repo.

## What this is

Zero-dependency Web Push (RFC 8030) client built on WebCrypto: aes128gcm
message encryption (RFC 8291, RFC 8188) with VAPID authentication (RFC 8292).
Everything lives in `src/index.ts`; runs in Node and browsers. ESM only,
targets the latest Node (native TypeScript type stripping, no build step to
run or test).

## Commands

- `npm install` — installs dev deps and runs `prepare` (`tsc`), which
  type-checks `src/`, `test/` and `example/` and builds `dist/` (only
  `dist/src` is published). Run `npx tsc` after changes.
- `npm test` — the `node:test` suite (`test/*.test.ts`). Always run after
  changes. Tests use `node:assert/strict`.
- `npm run cover` — tests with Node's built-in coverage (what CI runs).
- `npm run dev` — run the demo on http://127.0.0.1:8000 with `node --watch`
  (writes `.vapid-key.json`, gitignored).
- Style: single quotes, no semicolons (see `prettier` in `package.json`).
  Fetch mocks in the tests return `Promise.resolve(...)` instead of `async`.

## Working here

- TODOs live in `todo.md` (gitignored). Each top-list item becomes one commit
  with a brief message. On "continue", read `todo.md` first.
- Hard constraint: zero runtime dependencies (TypeScript and `@types/node`
  are the only dev dependencies). Only erasable TypeScript syntax (no enums, namespaces or
  parameter properties) since Node strips types. Use platform built-ins only (WebCrypto,
  `TextEncoder`, `Uint8Array.fromBase64`/`toBase64`, `fetch`). Never hand-roll
  crypto — importKey/exportKey/deriveBits/sign for everything.
- Keep `src/index.ts` a single module with the public API on top-level exports.

## Architecture notes

- Public API: `generateVapidKey()`, `vapidPublicKey(vapid)`,
  `encrypt(subscription, message, options, deps?)`, `send(...)`, plus types
  `Subscription`, `SendOptions`, `Deps`, `EncryptedRequest`,
  `PushError`, `Urgency`. `generateVapidKey` returns the private key as a
  `JsonWebKey`; derive the public point with `vapidPublicKey` (async).
- VAPID private keys are `JsonWebKey` or JSON-serialized JWK; the public key is
  the base64url raw point (65 bytes, 0x04 prefix).
- VAPID key material (imported ECDSA `CryptoKey` + base64url public point) is
  cached: a WeakMap keyed by the caller's JWK object, plus a Map keyed by the
  serialized JSON string. The cached promise deduplicates concurrent imports.
  A test asserts exactly one `importKey` per JWK and one per serialized
  string.
- ECDSA signatures are raw r||s (64 bytes) — WebCrypto is spec'd that way; do
  not reintroduce DER handling.
- Encryption is pinned to RFC 8291 appendix A vectors via `deps.keyPair` and
  `deps.salt`; a test also asserts the KDF intermediates (sharedSecret, ikm,
  cek, nonce). Any change to the ECDH/HKDF/AES-GCM path must keep those
  passing.
- Max message size is `MAX_RECORD_SIZE - MIN_OVERHEAD` (4096 - 103): 86-byte
  aes128gcm header + 1 delimiter + 16-byte GCM tag.
- Base64 decode is permissive (standard or URL-safe alphabet, padding
  optional); all output is unpadded base64url.
- ECDH app keys and salts are fresh per message; `deps` injects them only for
  deterministic tests.
