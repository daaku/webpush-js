const msg = document.getElementById('msg')
const status = document.querySelector('.status')
const show = text => {
  msg.innerText = text
}

function base64urlDecode(s) {
  const bin = atob(
    s.replace(/-/g, '+').replace(/_/g, '/').padEnd(
      Math.ceil(s.length / 4) * 4,
      '=',
    ),
  )
  return Uint8Array.from(bin, c => c.charCodeAt(0))
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
    applicationServerKey: base64urlDecode(publicKey),
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

window.addEventListener('unhandledrejection', ev => show(ev.reason))
window.addEventListener('error', ev => show(ev.error))

refresh()
