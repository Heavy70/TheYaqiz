const CACHE='yaqiz-v62';
const SHELL=['/','/index.html','/manifest.webmanifest','/registry.js','/engine.js','/icon-192.png','/icon-512.png','/logo-mark.png','/persona.jpg','/i18n-x.js','/apple-touch-icon.png','/uae-flag.png'];
self.addEventListener('install',e=>{e.waitUntil(caches.open(CACHE).then(c=>c.addAll(SHELL)).then(()=>self.skipWaiting()))});
self.addEventListener('activate',e=>{e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==CACHE).map(k=>caches.delete(k)))).then(()=>self.clients.claim()))});
self.addEventListener('fetch',e=>{
  const u=new URL(e.request.url);
  if(e.request.method!=='GET'||u.pathname.startsWith('/api/')||u.pathname.startsWith('/gov/'))return;
  if(u.origin!==location.origin){e.respondWith(caches.match(e.request).then(r=>r||fetch(e.request).then(res=>{const cp=res.clone();caches.open(CACHE).then(c=>c.put(e.request,cp));return res}).catch(()=>r)));return}
  e.respondWith(fetch(e.request).then(res=>{if(res.ok){const cp=res.clone();caches.open(CACHE).then(c=>c.put(e.request.mode==='navigate'?'/':e.request,cp))}return res})
    .catch(()=>caches.match(e.request.mode==='navigate'?'/':e.request).then(r=>r||caches.match('/'))));
});
