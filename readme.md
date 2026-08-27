# webpush-js

Web Push client built on WebCrypto: aes128gcm message encryption
([RFC 8291](https://www.rfc-editor.org/rfc/rfc8291)) with VAPID authentication
([RFC 8292](https://www.rfc-editor.org/rfc/rfc8292)). Runs in Deno, Node, and
browsers. No dependencies.

## Usage

```ts
import { generateVapidKeys, send, vapidPublicKey } from './mod.ts'

const privateKey = await generateVapidKeys()
const publicKey = vapidPublicKey(privateKey)
// publicKey goes to the frontend for pushManager.subscribe,
// privateKey (base64url raw scalar) is stored server-side.

await send(subscription, JSON.stringify({ title: 'Hello' }), {
  vapid: privateKey,
  subscriber: 'mailto:admin@example.com',
  ttl: 60,
})
```

`subscription` is the object from the browser's `PushSubscription`, and
`send` rejects with a `PushError` (`statusCode`, `body`, `endpointHost`,
`permanent`, `location`) when the push service responds with a non-2xx status.

## API

- `generateVapidKeys()` — new VAPID private key (base64url raw scalar)
- `vapidPublicKey(privateKey)` — derive the base64url raw public point
- `encrypt(subscription, message, options, deps?)` — build the request without sending
- `send(subscription, message, options, deps?)` — encrypt and POST

`deps.fetch` injects the network call for mocking; `deps.keyPair` and
`deps.salt` pin the encryption for deterministic tests.

## Example

```
deno task dev
```

Serves the demo page on http://127.0.0.1:8000. A VAPID key is generated and
cached in `.vapid-key` on first run.

Ported from [daaku/webpush](https://github.com/daaku/webpush) (MIT).
