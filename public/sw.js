// v20 — network-first, and purge any caches an older SW may have left behind
self.addEventListener("install", e => self.skipWaiting());
self.addEventListener("activate", e =>
  e.waitUntil(
    caches.keys()
      .then(ks => Promise.all(ks.map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  )
);
self.addEventListener("fetch", e => {
  if (e.request.url.includes("/api/")) return;
  e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
});
