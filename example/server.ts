// Example web push server: serves the demo page, generates VAPID keys on
// first run, and schedules pushes against subscriptions posted by the page.

import { readFile, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { extname, join } from 'node:path'
import { json } from 'node:stream/consumers'
import { generateVapidKey, send, vapidPublicKey } from '../src/index.ts'
import type { Subscription } from '../src/index.ts'

const PORT = Number(process.env.PORT ?? 8000)
const HOST = process.env.HOST ?? '127.0.0.1'
const VAPID_FILE = '.vapid-key.json'
const STATIC = join(import.meta.dirname, 'static')

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
}

async function loadVapidKeys(): Promise<JsonWebKey> {
  try {
    return JSON.parse(await readFile(VAPID_FILE, 'utf8')) as JsonWebKey
  } catch {
    const keys = await generateVapidKey()
    await writeFile(VAPID_FILE, JSON.stringify(keys, null, 2))
    console.log(`generated new VAPID keys, stored in ${VAPID_FILE}`)
    return keys
  }
}

const vapid = await loadVapidKeys()

createServer(async (req, res) => {
  const { pathname } = new URL(req.url ?? '/', 'http://localhost')
  if (pathname === '/vapid-public-key') {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end(await vapidPublicKey(vapid))
    return
  }
  if (pathname === '/push' && req.method === 'POST') {
    let subscription: Subscription
    try {
      subscription = (await json(req)) as Subscription
    } catch {
      res.writeHead(400).end('invalid JSON')
      return
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
    res.writeHead(202).end('scheduled')
    return
  }
  // URL parsing already resolves any `..` segments in pathname.
  const path = join(STATIC, pathname === '/' ? 'index.html' : pathname)
  try {
    const bytes = await readFile(path)
    const type = MIME[extname(path)] ?? 'application/octet-stream'
    res.writeHead(200, { 'content-type': type }).end(bytes)
  } catch {
    res.writeHead(404).end('Not found')
  }
}).listen(PORT, HOST, () => console.log(`Listening on http://${HOST}:${PORT}`))
