// Example web push server: serves the demo page, generates VAPID keys on
// first run, and schedules pushes against subscriptions posted by the page.

import { generateVapidKeys, send, vapidPublicKey } from '../mod.ts'
import type { Subscription } from '../mod.ts'

const PORT = Number(Deno.env.get('PORT') ?? 8000)
const HOST = Deno.env.get('HOST') ?? '127.0.0.1'
const VAPID_FILE = '.vapid-key.json'
const ROOT = import.meta.dirname ?? '.'

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
}

async function loadVapidKeys(): Promise<JsonWebKey> {
  try {
    return JSON.parse(await Deno.readTextFile(VAPID_FILE)) as JsonWebKey
  } catch {
    const keys = await generateVapidKeys()
    await Deno.writeTextFile(VAPID_FILE, JSON.stringify(keys, null, 2))
    console.log(`generated new VAPID keys, stored in ${VAPID_FILE}`)
    return keys
  }
}

function serveFile(pathname: string): Response {
  const path = ROOT + '/static' + (pathname === '/' ? '/index.html' : pathname)
  try {
    const bytes = Deno.readFileSync(path)
    const type = MIME[path.slice(path.lastIndexOf('.'))]
      ?? 'application/octet-stream'
    return new Response(bytes, { headers: { 'content-type': type } })
  } catch {
    return new Response('Not found', { status: 404 })
  }
}

const vapid = await loadVapidKeys()

Deno.serve({ hostname: HOST, port: PORT }, async req => {
  const url = new URL(req.url)
  if (url.pathname === '/vapid-public-key') {
    return new Response(await vapidPublicKey(vapid), {
      headers: { 'content-type': 'text/plain' },
    })
  }
  if (url.pathname === '/push' && req.method === 'POST') {
    let subscription: Subscription
    try {
      subscription = await req.json() as Subscription
    } catch {
      return new Response('invalid JSON', { status: 400 })
    }
    const message = JSON.stringify({ title: 'Test push from WebPush Example' })
    setTimeout(async () => {
      try {
        await send(subscription, message, {
          vapid,
          subscriber: 'https://example.com/webpush',
          ttl: 60,
        })
        console.log('push sent')
      } catch (error) {
        console.error('push failed', error)
      }
    }, 5000)
    return new Response('scheduled', { status: 202 })
  }
  return serveFile(url.pathname)
})

console.log(`Serving on http://${HOST}:${PORT}`)
