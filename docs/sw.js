// Расшифровывает файлы из vault/ для всего, что запрошено по адресу app/*.
// Ключи создаёт экран входа и кладёт в IndexedDB неизвлекаемыми (JS не может прочитать их значение).
const SCOPE = new URL('./', self.location).pathname;
const APP = `${SCOPE}app/`;
const MIME = {
  html: 'text/html; charset=utf-8', css: 'text/css; charset=utf-8', js: 'text/javascript; charset=utf-8',
  mjs: 'text/javascript; charset=utf-8', json: 'application/json; charset=utf-8', txt: 'text/plain; charset=utf-8',
  svg: 'image/svg+xml', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp',
  ogg: 'audio/ogg', m4a: 'audio/mp4', mp3: 'audio/mpeg', woff: 'font/woff', woff2: 'font/woff2', ttf: 'font/ttf',
  glb: 'model/gltf-binary', wasm: 'application/wasm',
};

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

function readKeys() {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('proto-vault', 1);
    open.onupgradeneeded = () => open.result.createObjectStore('keys');
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const get = db.transaction('keys').objectStore('keys').get('session');
      get.onerror = () => { db.close(); reject(get.error); };
      get.onsuccess = () => { db.close(); resolve(get.result || null); };
    };
  });
}

const enc = new TextEncoder();

async function decryptFile(path, keys) {
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', keys.mac, enc.encode(path)));
  const name = [...mac].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 40);
  const res = await fetch(`${SCOPE}vault/${name}.bin`);
  if (!res.ok) return null;
  const blob = new Uint8Array(await res.arrayBuffer());
  const plain = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: blob.subarray(0, 12), additionalData: enc.encode(path) }, keys.aes, blob.subarray(12),
  ));
  const payload = plain.subarray(1);
  if (plain[0] !== 1) return payload;
  const stream = new Blob([payload]).stream().pipeThrough(new DecompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

// Safari запрашивает аудио и видео через Range и без ответа 206 их не играет.
function respond(data, type, rangeHeader) {
  const headers = { 'Content-Type': type, 'Accept-Ranges': 'bytes', 'X-Content-Type-Options': 'nosniff' };
  const m = rangeHeader && /^bytes=(\d*)-(\d*)$/.exec(rangeHeader);
  if (!m || (!m[1] && !m[2])) return new Response(data, { headers: { ...headers, 'Content-Length': String(data.length) } });
  const size = data.length;
  const start = m[1] ? Number(m[1]) : Math.max(0, size - Number(m[2]));
  const end = m[1] && m[2] ? Math.min(Number(m[2]), size - 1) : size - 1;
  if (start >= size || start > end) return new Response(null, { status: 416, headers: { 'Content-Range': `bytes */${size}` } });
  return new Response(data.subarray(start, end + 1), {
    status: 206,
    headers: { ...headers, 'Content-Length': String(end - start + 1), 'Content-Range': `bytes ${start}-${end}/${size}` },
  });
}

async function handle(request, url) {
  const keys = await readKeys();
  if (!keys) {
    return request.mode === 'navigate' ? Response.redirect(SCOPE, 302) : new Response('Требуется вход', { status: 401 });
  }
  let path = decodeURIComponent(url.pathname.slice(APP.length));
  if (path === '' || path.endsWith('/')) path += 'index.html';
  const data = await decryptFile(path, keys);
  if (data) {
    const type = MIME[path.split('.').pop().toLowerCase()] || 'application/octet-stream';
    return respond(data, type, request.headers.get('range'));
  }
  // После смены пароля имена файлов другие, и старый ключ видит только 404: возвращаем на форму.
  if (request.mode === 'navigate' && !(await keyIsCurrent(keys))) return Response.redirect(`${SCOPE}?expired=1`, 302);
  return new Response('Не найдено', { status: 404 });
}

async function keyIsCurrent(keys) {
  const vault = await (await fetch(`${SCOPE}vault.json`, { cache: 'no-store' })).json();
  const check = Uint8Array.from(atob(vault.check), (c) => c.charCodeAt(0));
  try {
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv: check.subarray(0, 12), additionalData: enc.encode('check') }, keys.aes, check.subarray(12));
    return true;
  } catch {
    return false;
  }
}

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin || !url.pathname.startsWith(APP) || e.request.method !== 'GET') return;
  e.respondWith(handle(e.request, url));
});
