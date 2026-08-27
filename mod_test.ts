// Tests against RFC 8291 appendix A test vectors and a mocked fetch.

import { encrypt, generateVapidKey, send, vapidPublicKey } from './mod.ts'
import type { PushError, SendOptions, Subscription } from './mod.ts'

const textEncoder = new TextEncoder()

function b64url(bytes: Uint8Array): string {
  let bin = ''
  for (const byte of bytes) bin += String.fromCharCode(byte)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function b64d(input: string): Uint8Array<ArrayBuffer> {
  const bin = atob(
    input.replace(/-/g, '+').replace(/_/g, '/').padEnd(
      Math.ceil(input.length / 4) * 4,
      '=',
    ),
  )
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0))
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

function assert(
  condition: unknown,
  message = 'assertion failed',
): asserts condition {
  if (!condition) throw new Error(message)
}

function assertEq(actual: unknown, expected: unknown, message?: string) {
  const a = JSON.stringify(actual)
  const e = JSON.stringify(expected)
  if (a !== e) throw new Error(message ?? `expected ${e}, got ${a}`)
}

async function assertRejects(fn: () => Promise<unknown>): Promise<unknown> {
  try {
    await fn()
  } catch (error) {
    return error
  }
  throw new Error('expected the promise to reject')
}

// RFC 8291 appendix A test vector -------------------------------------------

const RFC_MESSAGE = 'When I grow up, I want to be a watermelon'
const RFC_AUTH = b64d('BTBZMqHH6r4Tts7J_aSIgg')
const RFC_SALT = b64d('DGv6ra1nlYgDCS1FRnbzlw')
const RFC_UA_PUBLIC =
  'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4'
const RFC_AS_PUBLIC =
  'BP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8'
const RFC_BODY =
  'DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN'

// JWK forms of the RFC's private keys, public points derived from the scalars.
const RFC_AS_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: '_jP0qw3qcZFNtVgj9ztUlI9BMG2SBzLbuaWaUyhkgiA',
  y: 'Dll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A8',
  d: 'yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw',
}
const RFC_UA_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: 'JXGyvs3942BVGq8e0PTNNmwRzr5VX4m8t7GGpTM5FzE',
  y: 'aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4',
  d: 'q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94',
}

const RFC_SUBSCRIPTION: Subscription = {
  endpoint: 'https://push.example.net/push/JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV',
  keys: {
    auth: 'BTBZMqHH6r4Tts7J_aSIgg',
    p256dh: RFC_UA_PUBLIC,
  },
}

async function rfcDeps() {
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    RFC_AS_JWK,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  )
  const publicKey = await crypto.subtle.importKey(
    'raw',
    b64d(RFC_AS_PUBLIC),
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    [],
  )
  return { keyPair: { privateKey, publicKey }, salt: RFC_SALT }
}

const RFC_OPTIONS = {
  vapid: RFC_AS_JWK,
  subscriber: 'https://example.com/',
  ttl: 60,
}

Deno.test('send produces the exact RFC 8291 test vector body', async () => {
  let captured: { url: string; headers: Headers; body: Uint8Array } | undefined
  const fetchMock = async (input: RequestInfo | URL, init?: RequestInit) => {
    captured = {
      url: String(input),
      headers: new Headers(init?.headers),
      body: new Uint8Array(await new Response(init?.body).arrayBuffer()),
    }
    return new Response(null, { status: 201 })
  }
  await send(RFC_SUBSCRIPTION, RFC_MESSAGE, RFC_OPTIONS, {
    fetch: fetchMock,
    ...(await rfcDeps()),
  })
  assert(captured)
  assertEq(captured.url, RFC_SUBSCRIPTION.endpoint)
  assertEq(captured.headers.get('content-encoding'), 'aes128gcm')
  assertEq(captured.headers.get('content-type'), 'application/octet-stream')
  assertEq(captured.headers.get('ttl'), '60')
  assertEq(b64url(captured.body), RFC_BODY)
  const authorization = captured.headers.get('authorization') ?? ''
  assertEq(authorization.split(', k=')[1], RFC_AS_PUBLIC)
})

Deno.test('body decrypts like a browser and matches RFC intermediates', async () => {
  const { body } = await encrypt(
    RFC_SUBSCRIPTION,
    RFC_MESSAGE,
    RFC_OPTIONS,
    await rfcDeps(),
  )

  const salt = body.slice(0, 16)
  const recordSize = new DataView(body.buffer).getUint32(16, false)
  const keyLen = body[20]
  const appPublic = body.slice(21, 21 + keyLen)
  const ciphertext = body.slice(21 + keyLen)
  assertEq(recordSize, 4096)
  assertEq(keyLen, 65)

  const uaKey = await crypto.subtle.importKey(
    'jwk',
    RFC_UA_JWK,
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits'],
  )
  const appKey = await crypto.subtle.importKey(
    'raw',
    appPublic,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  )
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: appKey },
    uaKey,
    256,
  )
  const ecdhKey = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    'HKDF',
    false,
    [
      'deriveBits',
      'deriveKey',
    ],
  )
  const ikm = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: RFC_AUTH,
      info: concat(
        textEncoder.encode('WebPush: info\0'),
        b64d(RFC_UA_PUBLIC),
        appPublic,
      ),
    },
    ecdhKey,
    256,
  )
  const ikmKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, [
    'deriveBits',
    'deriveKey',
  ])
  const cek = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: textEncoder.encode('Content-Encoding: aes128gcm\0'),
    },
    ikmKey,
    { name: 'AES-GCM', length: 128 },
    true,
    ['decrypt'],
  )
  const nonce = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: textEncoder.encode('Content-Encoding: nonce\0'),
    },
    ikmKey,
    96,
  )

  // RFC appendix A intermediate values
  assertEq(
    b64url(new Uint8Array(sharedSecret)),
    'kyrL1jIIOHEzg3sM2ZWRHDRB62YACZhhSlknJ672kSs',
  )
  assertEq(
    b64url(new Uint8Array(ikm)),
    'S4lYMb_L0FxCeq0WhDx813KgSYqU26kOyzWUdsXYyrg',
  )
  assertEq(
    b64url(new Uint8Array(await crypto.subtle.exportKey('raw', cek))),
    'oIhVW04MRdy2XN9CiKLxTg',
  )
  assertEq(b64url(new Uint8Array(nonce)), '4h_95klXJ5E_qnoN')

  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce },
      cek,
      ciphertext,
    ),
  )
  assertEq(
    b64url(plaintext),
    b64url(concat(textEncoder.encode(RFC_MESSAGE), new Uint8Array([2]))),
  )
})

// VAPID keys and JWT ---------------------------------------------------------

Deno.test('generateVapidKey returns a private JWK; vapidPublicKey derives its public key', async () => {
  const keys = await generateVapidKey()
  assertEq(keys.kty, 'EC')
  assertEq(keys.crv, 'P-256')
  assert(keys.d)
  const pub = b64d(await vapidPublicKey(keys))
  assertEq(pub.length, 65)
  assertEq(pub[0], 4)
  // x and y of the JWK must assemble into the raw public point.
  assertEq(
    await vapidPublicKey(keys),
    b64url(
      concat(
        new Uint8Array([4]),
        b64d(keys.x ?? ''),
        b64d(keys.y ?? ''),
      ),
    ),
  )
})

Deno.test('vapidPublicKey marshals JWK x and y into the raw public point', async () => {
  assertEq(await vapidPublicKey(RFC_AS_JWK), RFC_AS_PUBLIC)
  assertEq(await vapidPublicKey(JSON.stringify(RFC_AS_JWK)), RFC_AS_PUBLIC)
})

Deno.test('authorization header carries a valid ES256 JWT', async () => {
  const keys = await generateVapidKey()
  const publicKey = await vapidPublicKey(keys)
  const subscriber = 'mailto:admin@example.com'
  let request: Request | undefined
  const fetchMock = (input: RequestInfo | URL, init?: RequestInit) => {
    request = new Request(input, init)
    return Promise.resolve(new Response(null, { status: 201 }))
  }
  await send(
    RFC_SUBSCRIPTION,
    'test',
    { vapid: keys, subscriber, ttl: 3600 },
    { fetch: fetchMock },
  )
  assert(request)
  const authorization = request.headers.get('authorization') ?? ''
  assert(authorization.startsWith('vapid t='))
  const [jwt, k] = authorization.slice('vapid t='.length).split(', k=')
  assert(jwt && k)

  const [header, payload, sig] = jwt.split('.')
  assertEq(JSON.parse(new TextDecoder().decode(b64d(header))), {
    typ: 'JWT',
    alg: 'ES256',
  })
  const claims = JSON.parse(new TextDecoder().decode(b64d(payload)))
  assertEq(claims.aud, 'https://push.example.net')
  assertEq(claims.sub, subscriber)
  assert(
    Math.abs(claims.exp - (Math.floor(Date.now() / 1000) + 12 * 60 * 60)) < 10,
  )

  const verifyKey = await crypto.subtle.importKey(
    'raw',
    b64d(k),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  )
  const valid = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    verifyKey,
    b64d(sig),
    textEncoder.encode(`${header}.${payload}`),
  )
  assert(valid, 'JWT signature does not verify')

  // k is the raw public point marshaled from the JWK; it must equal the
  // public key WebCrypto generated alongside the private key.
  assertEq(k, await vapidPublicKey(keys))
  assertEq(k, publicKey)
})

// send() behavior -------------------------------------------------------------

const SUBSCRIPTION: Subscription = {
  endpoint: 'https://the.push.server/capability-url',
  keys: {
    auth: 'RW2wUiDEKNzSyDxlg7ArbQ',
    p256dh:
      'BOaRpSCtjsB92YouZnj8iNgCdFDNVNbid40AGxLcR47DI1S-zQkYf1CDG2G4y9GXeg74-8U_mEMzSZc-mRF_X0Y',
  },
}

Deno.test('vapid key material is imported and cached once per JWK or string', async () => {
  const original = crypto.subtle.importKey.bind(crypto.subtle)
  let ecdsaImports = 0
  const wrapped = ((...args: Parameters<typeof original>) => {
    const [format, , algorithm] = args
    if (
      (format as string) === 'jwk'
      && (algorithm as { name: string }).name === 'ECDSA'
    ) {
      ecdsaImports++
    }
    return original(...args)
  }) as typeof original
  crypto.subtle.importKey = wrapped
  try {
    const keys = await generateVapidKey()
    const publicKey = await vapidPublicKey(keys)
    const subscriber = 'mailto:admin@example.com'
    const fetchMock = () => Promise.resolve(new Response(null, { status: 201 }))
    for (let i = 0; i < 3; i++) {
      await send(SUBSCRIPTION, 'x', { vapid: keys, subscriber, ttl: 60 }, {
        fetch: fetchMock,
      })
      assertEq(await vapidPublicKey(keys), publicKey)
    }
    // Repeated sends with the same JWK object reuse the cached import.
    assertEq(ecdsaImports, 1)
    const serialized = JSON.stringify(keys)
    for (let i = 0; i < 3; i++) {
      await send(
        SUBSCRIPTION,
        'x',
        { vapid: serialized, subscriber, ttl: 60 },
        { fetch: fetchMock },
      )
      assertEq(await vapidPublicKey(serialized), publicKey)
    }
    // One import for the JWK object, one for the serialized string.
    assertEq(ecdsaImports, 2)
  } finally {
    crypto.subtle.importKey = original
  }
})

Deno.test('send posts the encrypted record with the expected headers', async () => {
  const keys = await generateVapidKey()
  let request: Request | undefined
  const fetchMock = (input: RequestInfo | URL, init?: RequestInit) => {
    request = new Request(input, init)
    return Promise.resolve(new Response(null, { status: 201 }))
  }
  await send(
    SUBSCRIPTION,
    'Test',
    {
      vapid: keys,
      subscriber: 'https://app.example.com/',
      ttl: 3600,
      topic: 'a-topic',
      urgency: 'high',
    },
    { fetch: fetchMock },
  )
  assert(request)
  assertEq(request.method, 'POST')
  assertEq(request.url, SUBSCRIPTION.endpoint)
  assertEq(request.headers.get('content-encoding'), 'aes128gcm')
  assertEq(request.headers.get('content-type'), 'application/octet-stream')
  assertEq(request.headers.get('ttl'), '3600')
  assertEq(request.headers.get('topic'), 'a-topic')
  assertEq(request.headers.get('urgency'), 'high')
  assert((request.headers.get('authorization') ?? '').startsWith('vapid t='))

  const body = new Uint8Array(await request.arrayBuffer())
  assertEq(body.length, 103 + 4)
  assertEq(new DataView(body.buffer).getUint32(16, false), 4096)
  assertEq(body[20], 65)
})

Deno.test('send throws PushError on endpoint errors', async () => {
  const keys = await generateVapidKey()
  const options = {
    vapid: keys,
    subscriber: 'mailto:admin@example.com',
    ttl: 60,
  }
  const cases: Array<{
    status: number
    headers: Record<string, string>
    body: string
    message: string
    permanent: boolean
    location?: string
  }> = [
    {
      status: 404,
      headers: {
        'content-type': 'application/json',
        location: 'https://new.example.com/x',
      },
      body: '{"message":"gone"}',
      message: 'gone',
      permanent: true,
      location: 'https://new.example.com/x',
    },
    {
      status: 410,
      headers: {},
      body: '{"reason":"Expired."}',
      message: 'Expired.',
      permanent: true,
    },
    {
      status: 500,
      headers: { 'content-type': 'text/plain' },
      body: ' Internal Server Error\n',
      message: 'Internal Server Error',
      permanent: false,
    },
  ]
  for (const c of cases) {
    const error = await assertRejects(() =>
      send(SUBSCRIPTION, 'x', options, {
        fetch: () =>
          Promise.resolve(
            new Response(c.body, { status: c.status, headers: c.headers }),
          ),
      })
    ) as PushError
    assert(error instanceof Error)
    assertEq(error.statusCode, c.status)
    assertEq(error.message, c.message)
    assertEq(error.permanent, c.permanent)
    assertEq(error.endpointHost, 'the.push.server')
    if (c.location !== undefined) assertEq(error.location, c.location)
  }
})

Deno.test('send validates its inputs', async () => {
  const keys = await generateVapidKey()
  const options = {
    vapid: keys,
    subscriber: 'mailto:admin@example.com',
    ttl: 60,
  }

  await assertRejects(() =>
    send({ endpoint: '', keys: { auth: 'x', p256dh: 'x' } }, 'x', options)
  )
  await assertRejects(() =>
    send(
      {
        ...SUBSCRIPTION,
        keys: { auth: '{}', p256dh: SUBSCRIPTION.keys.p256dh },
      },
      'x',
      options,
    )
  )
  await assertRejects(() =>
    send(
      {
        ...SUBSCRIPTION,
        keys: { auth: 'AAAA', p256dh: SUBSCRIPTION.keys.p256dh },
      },
      'x',
      options,
    )
  )
  await assertRejects(() =>
    send(
      { ...SUBSCRIPTION, keys: { auth: SUBSCRIPTION.keys.auth, p256dh: '{}' } },
      'x',
      options,
    )
  )
  await assertRejects(() => send(SUBSCRIPTION, 'a'.repeat(3994), options))
  await assertRejects(() =>
    send(SUBSCRIPTION, 'a'.repeat(10), { ...options, recordSize: 100 })
  )
  await assertRejects(() =>
    send(
      SUBSCRIPTION,
      'x',
      { ...options, urgency: 'urgent' } as unknown as SendOptions,
    )
  )
  await assertRejects(() =>
    send(SUBSCRIPTION, 'x', { ...options, subscriber: 'example.com' })
  )
  await assertRejects(() =>
    send({ ...SUBSCRIPTION, endpoint: 'not a url' }, 'x', options)
  )
  await assertRejects(() =>
    send(SUBSCRIPTION, 'x', { ...options, vapid: 'not json' })
  )
  await assertRejects(() =>
    send(SUBSCRIPTION, 'x', { ...options, vapid: {} as JsonWebKey })
  )
  const { ttl: _ttl, ...noTtl } = options
  await assertRejects(() => send(SUBSCRIPTION, 'x', noTtl as SendOptions))
})

Deno.test('accepts a JSON-serialized VAPID private key', async () => {
  const keys = await generateVapidKey()
  let sent = false
  await send(SUBSCRIPTION, 'x', {
    vapid: JSON.stringify(keys),
    subscriber: 'https://app.example.com/',
    ttl: 60,
  }, {
    fetch: () => {
      sent = true
      return Promise.resolve(new Response(null, { status: 201 }))
    },
  })
  assert(sent)
})
