addEventListener('push', ev => {
  const data = ev.data.json()
  ev.waitUntil(self.registration.showNotification(data.title, data))
})

addEventListener('notificationclick', ev => {
  ev.notification.close()
  ev.waitUntil((async () => {
    const clientList = await clients.matchAll()
    if (clientList.length > 0) return clientList[0].focus()
    return clients.openWindow(ev.notification.data?.url ?? '/')
  })())
})

addEventListener('install', () => skipWaiting())
