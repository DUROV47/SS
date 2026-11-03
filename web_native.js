/* Elyx для iPhone (сайт, который ставится «На экран Домой»): оболочка вместо Android.
   Защита:
   • База бизнеса шифруется AES-256-GCM. Ключ выводится из пароля через PBKDF2-SHA-256, 600 000 повторов,
     у каждого профиля своя соль, у каждого сохранения новый вектор. Ключ «неизвлекаемый»: даже код страницы
     не может его прочитать, только шифровать им.
   • Зашифрованная база лежит только в памяти этого iPhone (IndexedDB сайта). На сервер сайта ничего не уходит:
     сервер раздаёт только файлы программы.
   • Неверный пароль 5 раз — пауза 30 с, дальше пауза удваивается (перебор пароля становится бесполезен).
   • Свернули сайт больше чем на 5 минут — он закрывается и забывает ключ, нужен пароль заново.
   • В интернет программа ходит только по HTTPS и только к списку сервисов, как в Android. */
(() => {
  "use strict";
  if (window.top !== window.self) { document.documentElement.innerHTML = ""; return; }   // не даём встроить сайт в чужую страницу

  const ALLOWED = ["egrul.nalog.ru", "bo.nalog.ru", "bo.nalog.gov.ru", "overpass-api.de", "maps.mail.ru", "overpass.private.coffee",
    "nominatim.openstreetmap.org", "photon.komoot.io", "search-maps.yandex.ru", "static-maps.yandex.ru",
    "ofv-api-v0-1-1.evotor.ru", "universal-api.1-ofd.ru", "llm.api.cloud.yandex.net", "ai.api.cloud.yandex.net",
    "suggestions.dadata.ru", "api-seller.ozon.ru", "platform-api2.max.ru", "raw.githubusercontent.com", "api.met.no"];
  const ITER = 600000, LOCK_MIN = 5, VERSION = "2.9.17-web";
  const META = "elyx-vault-meta", LAST = "elyx-last";
  const enc = new TextEncoder(), dec = new TextDecoder();
  const J = (o) => JSON.stringify(o);
  const cb = (id, data) => setTimeout(() => window.KPNativeCallback && window.KPNativeCallback(id, J(data)), 0);
  const b64 = (u8) => { let s = ""; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); };
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

  // ---------- хранилище: метаданные (без секретов) — localStorage, шифротекст — IndexedDB
  const meta = () => { try { return JSON.parse(localStorage.getItem(META)) || {}; } catch { return {}; } };
  const setMeta = (m) => { try { localStorage.setItem(META, J(m)); } catch { /* приватный режим */ } };
  const idb = () => new Promise((res, rej) => {
    const r = indexedDB.open("elyx-vault", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("db");
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
  const idbDo = async (mode, fn) => {
    const d = await idb();
    return new Promise((res, rej) => {
      const t = d.transaction("db", mode), r = fn(t.objectStore("db"));
      t.oncomplete = () => res(r && r.result);
      t.onerror = () => rej(t.error);
    });
  };
  try { navigator.storage && navigator.storage.persist && navigator.storage.persist(); } catch { /* не страшно */ }

  // ---------- шифрование
  const derive = async (pass, salt) => {
    const base = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" }, base,
      { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  };
  const seal = async (key, inn, text) => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(inn) }, key, enc.encode(text)));
    return { iv: b64(iv), ct };
  };

  let session = null;          // { inn, key, pass } — только в памяти вкладки
  let writing = Promise.resolve();
  const doPersist = async (db) => {        // вызывается только внутри очереди writing
    const s = session;
    if (!s || !s.key) return;
    const { iv, ct } = await seal(s.key, s.inn, db);
    await idbDo("readwrite", (st) => st.put(ct, s.inn));
    const m = meta(); if (m[s.inn]) { m[s.inn].iv = iv; setMeta(m); }
  };
  const queue = (fn) => { writing = writing.then(fn).catch((e) => console.warn("Elyx: не удалось сохранить", e)); return writing; };
  const persist = (db) => queue(() => doPersist(db));

  // ---------- автоблокировка
  let hiddenAt = 0;
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) { hiddenAt = Date.now(); return; }
    if (session && hiddenAt && Date.now() - hiddenAt > LOCK_MIN * 60000) { session = null; writing.finally(() => location.reload()); }
  });

  // ---------- сеть: только HTTPS к разрешённым сервисам
  const FORBIDDEN = /^(user-agent|host|content-length|connection|cookie|origin|referer|accept-encoding)$/i;
  function http(reqJson) {
    let req;
    try { req = JSON.parse(reqJson); } catch { return J({ error: "неверный запрос" }); }
    let u;
    try { u = new URL(req.url); } catch { return J({ error: "неверный адрес" }); }
    if (u.protocol !== "https:" || !ALLOWED.includes(u.hostname)) return J({ error: "Адрес не разрешён: " + u.hostname });
    const x = new XMLHttpRequest();
    try {
      x.open(req.method || "GET", u.href, false);
      x.overrideMimeType("text/plain; charset=x-user-defined");
      for (const [k, v] of Object.entries(req.headers || {})) if (!FORBIDDEN.test(k)) x.setRequestHeader(k, v);
      x.send(req.body ? unb64(req.body) : null);
    } catch {
      return J({ error: `Сервис ${u.hostname} не пускает запросы из браузера iPhone. Эта функция работает в приложении для Android.` });
    }
    if (!x.status) return J({ error: `Нет ответа от ${u.hostname}: проверьте интернет. Если не поможет — сервис закрыт для браузера, функция есть в приложении для Android.` });
    const raw = x.responseText, out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i) & 0xff;
    const headers = x.getAllResponseHeaders().trim().split(/\r?\n/).filter(Boolean).map((l) => { const i = l.indexOf(":"); return [l.slice(0, i).trim(), l.slice(i + 1).trim()]; });
    return J({ status: x.status, headers, body: b64(out) });
  }

  const no = (what) => J({ ok: false, error: what + " — есть в приложении для Android" });

  window.KPNative = {
    appInfo: () => J({ version: VERSION, biometric: "none", verifyUrl: "", secureScreen: false, autoLock: LOCK_MIN, bioOn: false, updates: false, web: true, demo: true }),
    ready: () => {}, busy: () => {}, vibrate: () => {}, schedule: () => {}, toast: () => J({ ok: true }),
    setSecureScreen: () => J({ ok: true }), setAutoLock: () => J({ ok: true }),

    vaultList: () => {
      const m = meta();
      return J({ profiles: Object.values(m).map((p) => ({ inn: p.inn, bio: false, name: p.name, keys: p.keys || "" })),
        last: localStorage.getItem(LAST) || "" });
    },
    vaultCreate: (inn, pass, db, metaJson) => {
      const m = meta();
      let name = "";
      try { name = String(JSON.parse(metaJson).name || "").slice(0, 80); } catch { /* без имени */ }
      const salt = crypto.getRandomValues(new Uint8Array(16));
      m[inn] = { inn, name, salt: b64(salt), iv: "", keys: "", fails: 0, until: 0 };
      setMeta(m);
      try { localStorage.setItem(LAST, inn); } catch { /* ок */ }
      session = { inn, key: null, pass };
      queue(async () => { session = { inn, key: await derive(pass, salt), pass }; await doPersist(db); });
      return J({ ok: true });
    },
    vaultOpenAsync: (inn, pass, id) => {
      (async () => {
        await writing;                       // сначала дописываем то, что ещё сохраняется
        const m = meta(), p = m[inn];
        if (!p) return cb(id, { ok: false, error: "На этом iPhone нет входа для этого ИНН. Зарегистрируйтесь." });
        if (p.until > Date.now()) return cb(id, { ok: false, error: `Слишком много попыток. Подождите ${Math.ceil((p.until - Date.now()) / 1000)} с.` });
        const ct = await idbDo("readonly", (st) => st.get(inn));
        if (!ct || !p.iv) return cb(id, { ok: false, error: "База этого профиля не найдена на iPhone" });
        const key = await derive(pass, unb64(p.salt));
        try {
          const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(p.iv), additionalData: enc.encode(inn) }, key, ct);
          p.fails = 0; p.until = 0; setMeta(m);
          localStorage.setItem(LAST, inn);
          session = { inn, key, pass };
          cb(id, { ok: true, db: dec.decode(plain) });
        } catch {
          p.fails = (p.fails || 0) + 1;
          if (p.fails >= 5) p.until = Date.now() + 30000 * 2 ** (p.fails - 5);
          setMeta(m);
          cb(id, { ok: false, error: p.fails >= 5 ? "Неверный пароль. Вход на паузе — подождите." : `Неверный пароль. Осталось попыток до паузы: ${5 - p.fails}` });
        }
      })().catch(() => cb(id, { ok: false, error: "Не удалось открыть базу" }));
    },
    vaultOpen: () => no("Вход без ожидания"),
    vaultSave: (db) => { if (!session) return J({ ok: false, error: "закрыто" }); persist(db); return J({ ok: true }); },
    vaultLock: () => { session = null; return J({ ok: true }); },
    vaultSetKeys: (keys) => { if (!session) return J({ ok: false, error: "закрыто" }); const m = meta(); if (m[session.inn]) { m[session.inn].keys = keys; setMeta(m); } return J({ ok: true }); },
    vaultChangePassword: (oldp, newp) => {
      if (!session || session.pass !== oldp) return J({ ok: false, error: "Неверный текущий пароль" });
      const s = session, m = meta(), salt = crypto.getRandomValues(new Uint8Array(16));
      queue(async () => {
        const old = await idbDo("readonly", (st) => st.get(s.inn));
        const plain = dec.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(meta()[s.inn].iv), additionalData: enc.encode(s.inn) }, s.key, old));
        const key = await derive(newp, salt);
        m[s.inn].salt = b64(salt); setMeta(m);
        session = { inn: s.inn, key, pass: newp };
        await doPersist(plain);
      });
      return J({ ok: true });
    },
    vaultDelete: (pass) => {
      if (!session || session.pass !== pass) return J({ ok: false, error: "Неверный пароль" });
      const inn = session.inn, m = meta();
      delete m[inn]; setMeta(m); session = null;
      queue(() => idbDo("readwrite", (st) => st.delete(inn)));
      return J({ ok: true });
    },
    vaultTake: () => no("Вход по отпечатку"),
    bioOpen: (inn, id) => cb(id, { ok: false, error: "На iPhone вход по паролю" }),
    bioEnable: (id) => cb(id, { ok: false, error: "На iPhone вход по паролю" }),
    bioDisable: () => J({ ok: true }),

    http,
    lanGet: () => J({ error: "Камеры в Wi-Fi кофейни подключаются в приложении для Android" }),
    locate: (id) => {
      if (!navigator.geolocation) return cb(id, { ok: false, error: "Геолокация недоступна" });
      navigator.geolocation.getCurrentPosition((p) => cb(id, { ok: true, lat: p.coords.latitude, lon: p.coords.longitude, accuracy: p.coords.accuracy }),
        () => cb(id, { ok: false, error: "Разрешите сайту доступ к геопозиции: Настройки → Safari → Геопозиция" }), { enableHighAccuracy: true, timeout: 15000 });
    },
    saveFile: (name, mime, data) => {
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([unb64(data)], { type: mime }));
      a.download = name; document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 30000);
      return J({ ok: true });
    },
    takePhoto: (id) => {
      const i = document.createElement("input");
      i.type = "file"; i.accept = "image/*"; i.capture = "environment";
      i.onchange = () => {
        const f = i.files && i.files[0];
        if (!f) return cb(id, { ok: false, error: "Фото не выбрано" });
        const r = new FileReader();
        r.onload = () => cb(id, { ok: true, mime: f.type || "image/jpeg", b64: String(r.result).split(",")[1] });
        r.readAsDataURL(f);
      };
      i.click();
    },
    copyText: (t) => { try { navigator.clipboard.writeText(String(t)); return J({ ok: true }); } catch { return J({ ok: false, error: "Не удалось скопировать" }); } },
    openExternal: (url) => { try { const u = new URL(url); if (u.protocol === "https:" || u.protocol === "tel:" || u.protocol === "mailto:") window.open(u.href, "_blank", "noopener"); } catch { /* неверная ссылка */ } return J({ ok: true }); },
    notify: () => J({ ok: true }),
    updateCheck: (id) => cb(id, { ok: true, available: false, current: VERSION }),
    updateNeedsPermission: () => J({ ok: true, need: false }),
    updateInstall: (id) => cb(id, { ok: true }),
    ownerKeyStatus: () => J({ ok: true, present: false }),
    ownerKeyImport: () => no("Ключ владельца"), ownerKeyRemove: () => J({ ok: true }), ownerSign: () => no("Подпись ключом владельца"),
  };

  if ("serviceWorker" in navigator) addEventListener("load", () => navigator.serviceWorker.register("sw.js").catch(() => {}));
})();
