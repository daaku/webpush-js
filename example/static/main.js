const msg = document.getElementById('msg')
const status = document.querySelector('.status')
const show = text => {
  msg.innerText = text
}

async function refresh() {
  const registration = await navigator.serviceWorker.register(
    '/service-worker.js',
    { updateViaCache: 'none' },
  )
  if (!registration.pushManager) {
    document.body.className = 'push-unavailable'
    return
  }
  const state = await registration.pushManager.permissionState({
    userVisibleOnly: true,
  })
  status.textContent = `Push permission: ${state}`
}

document.querySelector('#send-push').addEventListener('click', async () => {
  const publicKey = await (await fetch('/vapid-public-key')).text()
  const registration = await navigator.serviceWorker.getRegistration()
  const subscription = await registration.pushManager.subscribe({
    userVisibleOnly: true,
    applicationServerKey: Uint8Array.fromBase64(publicKey, {
      alphabet: 'base64url',
    }),
  })
  const res = await fetch('/push', {
    method: 'POST',
    body: JSON.stringify(subscription),
  })
  show(res.ok ? 'Push scheduled. Check the server logs.' : await res.text())
  refresh()
})

document.querySelector('#unsubscribe').addEventListener('click', async () => {
  const registration = await navigator.serviceWorker.getRegistration()
  const subscription = await registration.pushManager.getSubscription()
  if (!subscription) {
    show('No existing subscription.')
    return
  }
  await subscription.unsubscribe()
  show('Unsubscribed.')
  refresh()
})

globalThis.addEventListener('unhandledrejection', ev => show(ev.reason))
globalThis.addEventListener('error', ev => show(ev.error))

refresh()
