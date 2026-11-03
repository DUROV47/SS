/* Elyx для iPhone: программа сохраняется на телефоне и открывается без интернета. Данные бизнеса здесь не хранятся —
   только файлы программы с этого сайта. Новая версия подхватывается при следующем открытии. */
const CACHE = "elyx-2.9.18-80d2c56c9cea";
self.addEventListener("install", (e) => { self.skipWaiting(); e.waitUntil(caches.open(CACHE).then((c) => c.addAll(["./", "index.html", "app.js", "app.css", "style.css", "web_native.js", "py/pyodide.js"]))); });
self.addEventListener("activate", (e) => e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim())));
self.addEventListener("fetch", (e) => {
  const u = new URL(e.request.url);
  if (e.request.method !== "GET" || u.origin !== location.origin) return;   // чужие адреса не кэшируем и не трогаем
  if (e.request.mode === "navigate") {   // страницу берём из сети первой: обновление приходит сразу; без интернета — из кэша
    e.respondWith(fetch(e.request).then((r) => { if (r.ok) caches.open(CACHE).then((c) => c.put(e.request, r.clone())); return r; })
      .catch(() => caches.match(e.request, { ignoreSearch: true }).then((r) => r || caches.match("index.html"))));
    return;
  }
  e.respondWith(caches.open(CACHE).then(async (c) => {
    const hit = await c.match(e.request, { ignoreSearch: true });
    if (hit) return hit;
    const r = await fetch(e.request);
    if (r.ok) c.put(e.request, r.clone());
    return r;
  }));
});
