// Web Push (RFC 8030) client built on WebCrypto: aes128gcm message encryption
// (RFC 8291, RFC 8188) with VAPID authentication (RFC 8292).
// VAPID private keys are base64url raw scalars; pass any global dependency
// (fetch) explicitly for mocking.

const textEncoder = new TextEncoder()

const KEY_INFO = textEncoder.encode('WebPush: info\0')
const CEK_INFO = textEncoder.encode('Content-Encoding: aes128gcm\0')
const NONCE_INFO = textEncoder.encode('Content-Encoding: nonce\0')

const MAX_RECORD_SIZE = 4096
const MIN_OVERHEAD = 103 // 86-byte header + 1 delimiter + 16-byte GCM tag
const JWT_TTL = 12 * 60 * 60

const URGENCIES = ['very-low', 'low', 'normal', 'high'] as const

export type Urgency = (typeof URGENCIES)[number]

/** A PushSubscription as delivered by the browser. */
export interface Subscription {
  endpoint: string
  keys: {
    auth: string
    p256dh: string
  }
}

export interface SendOptions {
  vapid: string // base64url raw VAPID private scalar
  subscriber: string // https URL or mailto: address identifying the application
  ttl: number // seconds
  topic?: string
  urgency?: Urgency
  recordSize?: number // default 4096
  vapidExpiration?: Date // default now + 12 hours
}

/** Injectables for tests: fetch replaces the network, keyPair and salt pin the encryption.
 * @internal */
export interface Deps {
  fetch?: typeof fetch
  keyPair?: CryptoKeyPair
  salt?: Uint8Array
}

/** The encrypted request produced by encrypt(). */
export interface EncryptedRequest {
  body: Uint8Array<ArrayBuffer>
  headers: Record<string, string>
  endpoint: string
}

/** Thrown by send() when the push endpoint responds with a non-2xx status. */
export interface PushError extends Error {
  statusCode: number
  body: string
  endpointHost: string
  permanent: boolean
  location: string
}

function b64Alphabet(input: string) {
  for (const c of input) {
    if (c === '+' || c === '/') return 'base64'
    if (c === '-' || c === '_') return 'base64url'
  }
  return 'base64'
}

// Permissive: accepts URL-safe or standard alphabets, with or without padding.
function b64decode(input: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.fromBase64(input, { alphabet: b64Alphabet(input) })
}

function b64urlEncode(bytes: Uint8Array): string {
  return bytes.toBase64({ alphabet: 'base64url', omitPadding: true })
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

// VAPID (RFC 8292) ----------------------------------------------------------

// P-256 parameters for deriving the public point from a private scalar.
const P256_P = 2n ** 256n - 2n ** 224n + 2n ** 192n + 2n ** 96n - 1n
const P256_N =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n
const P256_GX =
  0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n
const P256_GY =
  0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n

function bytesToBigint(bytes: Uint8Array): bigint {
  let value = 0n
  for (const byte of bytes) value = (value << 8n) | BigInt(byte)
  return value
}

function bigintToBytes(value: bigint): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(32)
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(value & 0xffn)
    value >>= 8n
  }
  return out
}

// Double-and-add scalar multiplication of the P-256 base point.
function p256Point(d: bigint): [bigint, bigint] {
  const mod = (a: bigint) => ((a % P256_P) + P256_P) % P256_P
  const inv = (a: bigint): bigint => {
    let [x, r] = [mod(a), 1n]
    for (let e = P256_P - 2n; e > 0n; e >>= 1n) {
      if (e & 1n) r = mod(r * x)
      x = mod(x * x)
    }
    return r
  }
  const add = (
    px: bigint,
    py: bigint,
    qx: bigint,
    qy: bigint,
  ): [bigint, bigint] => {
    if (px === 0n && py === 0n) return [qx, qy]
    if (qx === 0n && qy === 0n) return [px, py]
    if (px === qx && mod(py + qy) === 0n) return [0n, 0n]
    const slope = px === qx && py === qy
      ? mod((3n * px * px - 3n) * inv(2n * py))
      : mod((qy - py) * inv(qx - px))
    const rx = mod(slope * slope - px - qx)
    const ry = mod(slope * (px - rx) - py)
    return [rx, ry]
  }
  let [rx, ry] = [0n, 0n]
  let [bx, by] = [P256_GX, P256_GY]
  while (d > 0n) {
    if (d & 1n) [rx, ry] = add(rx, ry, bx, by)
    ;[bx, by] = add(bx, by, bx, by)
    d >>= 1n
  }
  return [rx, ry]
}

interface VapidKeyMaterial {
  jwk: JsonWebKey
  publicKey: Uint8Array<ArrayBuffer>
}

const MAX_CACHED_KEYS = 10

// WebCrypto cannot import raw ECDSA private keys, so the scalar is expanded
// into a full JWK (x and y via p256Point) before it can sign. Cache per key:
// the derivation costs ~20ms and deployments typically use a single VAPID key.
// Strings can't be WeakMap keys, hence the capped Map.
const vapidKeyCache = new Map<string, VapidKeyMaterial>()

function vapidKeyMaterial(privateKey: string): VapidKeyMaterial {
  let material = vapidKeyCache.get(privateKey)
  if (material) return material
  const d = b64decode(privateKey)
  if (d.length !== 32) {
    throw new Error('invalid VAPID private key, expected 32 bytes')
  }
  const scalar = bytesToBigint(d)
  if (scalar === 0n || scalar >= P256_N) {
    throw new Error('invalid VAPID private key scalar')
  }
  const [x, y] = p256Point(scalar)
  const xBytes = bigintToBytes(x)
  const yBytes = bigintToBytes(y)
  material = {
    jwk: {
      kty: 'EC',
      crv: 'P-256',
      x: b64urlEncode(xBytes),
      y: b64urlEncode(yBytes),
      d: b64urlEncode(d),
    },
    publicKey: concat(new Uint8Array([4]), xBytes, yBytes),
  }
  if (vapidKeyCache.size >= MAX_CACHED_KEYS) {
    vapidKeyCache.delete(vapidKeyCache.keys().next().value!)
  }
  vapidKeyCache.set(privateKey, material)
  return material
}

/** Generate a new VAPID private key (base64url raw scalar). */
export async function generateVapidKeys(): Promise<string> {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign'],
  )
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey)
  return jwk.d!
}

/** The base64url raw public point for a VAPID private key. */
export function vapidPublicKey(privateKey: string): string {
  return b64urlEncode(vapidKeyMaterial(privateKey).publicKey)
}

function b64urlJson(value: unknown): string {
  return b64urlEncode(textEncoder.encode(JSON.stringify(value)))
}

async function signJwt(
  jwk: JsonWebKey,
  claims: Record<string, unknown>,
): Promise<string> {
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  )
  const unsigned = `${b64urlJson({ typ: 'JWT', alg: 'ES256' })}.${
    b64urlJson(claims)
  }`
  const sig = new Uint8Array(
    await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      textEncoder.encode(unsigned),
    ),
  )
  if (sig.length !== 64) throw new Error(`unexpected ECDSA sig: ${sig.length}`)
  return `${unsigned}.${b64urlEncode(sig)}`
}

async function authHeader(
  endpoint: string,
  subscriber: string,
  privateKey: string,
  expiration: Date,
): Promise<string> {
  let url: URL
  try {
    url = new URL(endpoint)
  } catch {
    throw new Error(`invalid endpoint: ${endpoint}`)
  }
  if (!url.protocol || !url.hostname) {
    throw new Error(`invalid endpoint: ${endpoint}`)
  }
  if (!subscriber.startsWith('https:') && !subscriber.startsWith('mailto:')) {
    throw new Error(`invalid subscriber: ${subscriber}`)
  }
  const { jwk, publicKey } = vapidKeyMaterial(privateKey)
  const jwt = await signJwt(jwk, {
    aud: url.origin,
    exp: Math.floor(expiration.getTime() / 1000),
    sub: subscriber,
  })
  return `vapid t=${jwt}, k=${b64urlEncode(publicKey)}`
}

// Message encryption (RFC 8188 aes128gcm) ------------------------------------

async function encryptRecord(
  uaPublic: Uint8Array<ArrayBuffer>,
  authSecret: Uint8Array<ArrayBuffer>,
  message: Uint8Array,
  recordSize: number,
  keyPair: CryptoKeyPair,
  salt: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const subtle = crypto.subtle
  const uaKey = await subtle.importKey(
    'raw',
    uaPublic,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  )
  const sharedSecret = await subtle.deriveBits(
    { name: 'ECDH', public: uaKey },
    keyPair.privateKey,
    256,
  )
  const ecdhKey = await subtle.importKey('raw', sharedSecret, 'HKDF', false, [
    'deriveBits',
    'deriveKey',
  ])

  const appPublic = new Uint8Array(
    await subtle.exportKey('raw', keyPair.publicKey),
  )
  const ikm = await subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: authSecret,
      info: concat(KEY_INFO, uaPublic, appPublic),
    },
    ecdhKey,
    256,
  )
  const ikmKey = await subtle.importKey('raw', ikm, 'HKDF', false, [
    'deriveBits',
    'deriveKey',
  ])

  const cek = await subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: CEK_INFO },
    ikmKey,
    { name: 'AES-GCM', length: 128 },
    false,
    ['encrypt'],
  )
  const nonce = await subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info: NONCE_INFO },
    ikmKey,
    96,
  )

  const plaintext = concat(message, new Uint8Array([2])) // message || delimiter
  const ciphertext = new Uint8Array(
    await subtle.encrypt({ name: 'AES-GCM', iv: nonce }, cek, plaintext),
  )

  // aes128gcm header: salt || record size || keyid length || keyid
  const header = new Uint8Array(86)
  header.set(salt, 0)
  new DataView(header.buffer).setUint32(16, recordSize, false)
  header[20] = appPublic.length
  header.set(appPublic, 21)
  return concat(header, ciphertext)
}

// Public API -----------------------------------------------------------------

/**
 * Build the encrypted request for a push notification without sending it.
 * Returns the request body, headers, and endpoint.
 */
export async function encrypt(
  subscription: Subscription,
  message: string | Uint8Array,
  options: SendOptions,
  deps: Deps = {},
): Promise<EncryptedRequest> {
  const { endpoint, keys } = subscription
  if (!endpoint || !keys.auth || !keys.p256dh) {
    throw new Error('invalid subscription, missing endpoint or keys')
  }

  const authSecret = b64decode(keys.auth)
  if (authSecret.length !== 16) {
    throw new Error('invalid auth secret, expected 16 bytes')
  }
  const uaPublic = b64decode(keys.p256dh)

  const recordSize = options.recordSize || MAX_RECORD_SIZE
  const messageBytes = typeof message === 'string'
    ? textEncoder.encode(message)
    : message
  if (messageBytes.length > recordSize - MIN_OVERHEAD) {
    throw new Error(
      `message length of ${messageBytes.length} is too long for record size of ${recordSize}`,
    )
  }
  if (!Number.isFinite(options.ttl)) throw new Error('ttl is required')
  if (options.urgency && !URGENCIES.includes(options.urgency)) {
    throw new Error(`invalid urgency: ${options.urgency}`)
  }

  const keyPair = deps.keyPair
    ?? await crypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      true,
      ['deriveBits'],
    )
  const salt =
    (deps.salt ?? crypto.getRandomValues(new Uint8Array(16))) as Uint8Array<
      ArrayBuffer
    >

  const expiration = options.vapidExpiration
    ?? new Date(Date.now() + JWT_TTL * 1000)
  const authorization = await authHeader(
    endpoint,
    options.subscriber,
    options.vapid,
    expiration,
  )

  const headers: Record<string, string> = {
    'Content-Encoding': 'aes128gcm',
    'Content-Type': 'application/octet-stream',
    TTL: String(Math.trunc(options.ttl)),
    Authorization: authorization,
  }
  if (options.topic) headers.Topic = options.topic
  if (options.urgency) headers.Urgency = options.urgency

  const body = await encryptRecord(
    uaPublic,
    authSecret,
    messageBytes,
    recordSize,
    keyPair,
    salt,
  )
  return { body, headers, endpoint }
}

/**
 * Encrypt and send a push notification to a subscription.
 * Rejects with a PushError when the endpoint returns a non-2xx status.
 */
export async function send(
  subscription: Subscription,
  message: string | Uint8Array,
  options: SendOptions,
  deps: Deps = {},
): Promise<void> {
  const { body, headers, endpoint } = await encrypt(
    subscription,
    message,
    options,
    deps,
  )
  const response = await (deps.fetch ?? fetch)(endpoint, {
    method: 'POST',
    headers,
    body,
  })
  if (response.status >= 200 && response.status < 300) return
  throw await pushError(endpoint, response)
}

async function pushError(
  endpoint: string,
  response: Response,
): Promise<PushError> {
  const body = await response.text()
  let message = `error from push endpoint with status=${response.status}`
  if (body.startsWith('{')) {
    try {
      const json = JSON.parse(body)
      message = json.message ?? json.reason ?? message
    } catch {
      // keep the default message
    }
  } else if (response.headers.get('content-type')?.startsWith('text/plain')) {
    message = body.trim()
  }
  return Object.assign(new Error(message), {
    statusCode: response.status,
    body,
    endpointHost: new URL(endpoint).hostname,
    permanent: response.status === 404 || response.status === 410,
    location: response.headers.get('location') ?? '',
  })
}
