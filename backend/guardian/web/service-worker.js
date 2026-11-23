"use strict";

const cacheName = "appguardian-web-v3";
const assets = ["./", "./styles.css", "./dashboard.js", "./home.js", "./manifest.webmanifest", "./icon-192.png", "./icon-512.png"];
const urls = new Set(assets.map(path => new URL(path, self.registration.scope).href));

self.addEventListener("install", event => {
  event.waitUntil(caches.open(cacheName).then(cache => cache.addAll(assets)));
});
self.addEventListener("activate", event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(
    keys.filter(key => key.startsWith("appguardian-web-") && key !== cacheName).map(key => caches.delete(key))
  )));
});
self.addEventListener("fetch", event => {
  if (event.request.method !== "GET" || !urls.has(event.request.url)) return;
  event.respondWith(fetch(event.request).catch(async () => {
    const cached = await caches.match(event.request);
    return cached || Response.error();
  }));
});
