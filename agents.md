# agents

Project-local instructions for agents working in this repo.

## What this is

Zero-dependency Web Push (RFC 8030) client built on WebCrypto: aes128gcm
message encryption (RFC 8291, RFC 8188) with VAPID authentication (RFC 8292).
Everything lives in `mod.ts`; runs in Deno, Node, and browsers.

## Commands

- `deno test` — the test suite; also type-checks. Always run after changes.
- `deno check example/server.ts` — type-checks the example server.
- `deno task dev` — run the demo on http://127.0.0.1:8000 (writes
  `.vapid-key.json`, gitignored).
- `deno lint` — clean. Don't add new findings. Fetch mocks in the tests
  return `Promise.resolve(...)` instead of `async` to satisfy
  `require-await`.
- Do NOT run `deno fmt`: the tree deliberately uses single quotes and no
  semicolons, which `deno fmt` would rewrite wholesale.

## Working here

- TODOs live in `todo.md` (gitignored). Each top-list item becomes one commit
  with a brief message. On "continue", read `todo.md` first.
- Hard constraint: zero dependencies. Use platform built-ins only (WebCrypto,
  `TextEncoder`, `Uint8Array.fromBase64`/`toBase64`, `fetch`). Never hand-roll
  crypto — importKey/exportKey/deriveBits/sign for everything.
- Keep `mod.ts` a single module with the public API on top-level exports.

## Architecture notes

- Public API: `generateVapidKeys()`, `vapidPublicKey(vapid)`,
  `encrypt(subscription, message, options, deps?)`, `send(...)`, plus types
  `Subscription`, `SendOptions`, `Deps`, `EncryptedRequest`,
  `PushError`, `Urgency`. `generateVapidKeys` returns the private key as a
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
