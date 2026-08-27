# webpush-js

Web Push client built on WebCrypto: aes128gcm message encryption
([RFC 8291](https://www.rfc-editor.org/rfc/rfc8291)) with VAPID authentication
([RFC 8292](https://www.rfc-editor.org/rfc/rfc8292)). Runs in Deno, Node, and
browsers. No dependencies.

## Usage

```ts
import { generateVapidKey, send, vapidPublicKey } from './mod.ts'

const privateKey = await generateVapidKey()
// vapidPublicKey(privateKey) goes to the frontend for pushManager.subscribe,
// privateKey (JWK) is stored server-side.

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

- `generateVapidKey()` - new VAPID private key (JWK)
- `vapidPublicKey(vapid)` - raw public point (base64url) derived from a JWK (or JSON-serialized JWK)
- `encrypt(subscription, message, options)` - build the request without sending
- `send(subscription, message, options)` - encrypt and POST

`options.vapid` accepts the private key as a `JsonWebKey` or a JSON string.

## Example

```
deno task dev
```

Serves the demo page on http://127.0.0.1:8000.
A VAPID key pair is generated and cached in `.vapid-key.json` on first run.
