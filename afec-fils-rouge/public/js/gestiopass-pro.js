/* gestiopass.pro.optimized.js — version améliorée
    - Forcage d'au moins un caractère par classe sélectionnée
    - Multi-delete (checkbox + bouton au-dessus du tableau)
    - Event delegation pour actions table
    - Nettoyage des doublons, meilleure organisation
    - Argon2 fallback PBKDF2
    - Clipboard clear retries, session & inactivity lock
*/
document.addEventListener('DOMContentLoaded', async () => {
    // ====== CONFIG ======
    const STORAGE_DB = 'bbh_coffre';
    const STORE_NAME = 'accounts';
    const VERIFIER_KEY = 'pm_verifier_v1';
    const ATTEMPTS_KEY = 'pm_attempts_v1';
    const LOCK_UNTIL_KEY = 'pm_lock_until_v1';

    const ARGON2_PARAMS = { time: 3, mem: 65536, parallelism: 1, hashLen: 32 }; // mem in KiB (64MiB)
    const PBKDF2_ITERATIONS = 100000;
    const AES_ALGO = 'AES-GCM';
    const AES_KEY_LENGTH = 256;

    const MAX_ATTEMPTS = 5;
    const INITIAL_LOCK_MS = 5 * 60 * 1000; // 5 min
    const SESSION_TIMEOUT_MS = 5 * 60 * 1000;
    const INACTIVITY_LOCK_MS = 2 * 60 * 1000;
    const AUTO_HIDE_MS = 5000;
    const CLIP_CLEAR_MS = 4000;
    const CLIP_CLEAR_RETRIES = 3;
    const CLIP_CLEAR_RETRY_MS = 600;

    // ====== DOM refs ======
    const $ = id => document.getElementById(id);
    const lockModal = $('lockModal');
    const masterInput = $('masterInput');
    const unlockBtn = $('unlockBtn');
    const setMasterBtn = $('setMasterBtn');
    const masterMsg = $('masterMsg');

    const tableBody = $('tableBody');
    const emptyHint = $('emptyHint');
    const paginationContainer = $('pagination');
    const multiDeleteBtn = $('multiDeleteBtn'); // bouton ajouté au-dessus du tableau
    const selectAllCheckbox = $('selectAllCheckbox'); // checkbox dans l'entête

    const generateBtn = $('generateBtn');
    const addBtn = $('addBtn');
    const generatedPassword = $('generatedPassword');
    const lengthRange = $('lengthRange');
    const lenLabel = $('lenLabel');

    const strengthText = $('strengthText');
    const strengthBar = $('strengthBar');

    const search = $('search');
    const exportBtn = $('exportBtn');
    const importFile = $('importFile');
    const logoutBtn = $('logoutBtn');

    const togglePwdBtn = $('togglePwd');
    const iconEye = $('iconEye');
    const iconEyeOff = $('iconEyeOff');

    const optLower = $('optLower');
    const optUpper = $('optUpper');
    const optDigits = $('optDigits');
    const optSymbols = $('optSymbols');

    const siteInput = $('site');
    const emailInput = $('email');
    const toastContainer = $('toastContainer') || document.body;

    // ====== STATE ======
    let MASTER_KEY = null;
    let db = null;
    let accountsCache = [];
    let currentPage = 1;
    let argon2Loaded = false, argon2Available = false;
    const enc = new TextEncoder(), dec = new TextDecoder();

    // ====== helpers ======
    const bufToB64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
    const b64ToBuf = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
    const toast = msg => {
        try {
            const t = document.createElement('div');
            t.textContent = msg;
            t.role = 'alert'
            t.className = 'fixed bottom-6 right-6 bg-slate-700 text-slate-100 px-4 py-2 rounded shadow z-50';
            toastContainer.appendChild(t);
            setTimeout(() => t.remove(), 2200);
        } catch { /* ignore */ }
    };
    const mask = s => (typeof s === 'string' ? '*'.repeat(Math.max(6, s.length)) : '—');
    const escapeHtml = s => String(s || '').replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[m]));

    // ====== load argon2 async ======
    (function loadArgon2Async() {
        if (window.argon2) { argon2Loaded = argon2Available = true; return; }
        const s = document.createElement('script');
        s.src = 'https://cdn.jsdelivr.net/npm/argon2-browser/dist/argon2.min.js';
        s.onload = () => { argon2Loaded = true; argon2Available = !!window.argon2; };
        s.onerror = () => { argon2Loaded = true; argon2Available = false; };
        document.head.appendChild(s);
    })();

    // ====== crypto helpers ======
    async function importRawKey(raw) {
        return crypto.subtle.importKey('raw', raw, { name: AES_ALGO }, false, ['encrypt', 'decrypt']);
    }

    async function deriveKeyArgon2(masterStr, saltBuf) {
        if (!argon2Loaded) await new Promise(r => setTimeout(r, 50));
        if (!argon2Available) throw new Error('argon2 not available');
        const saltU8 = new Uint8Array(saltBuf);
        const res = await window.argon2.hash({
            pass: masterStr,
            salt: saltU8,
            time: ARGON2_PARAMS.time,
            mem: ARGON2_PARAMS.mem,
            hashLen: ARGON2_PARAMS.hashLen,
            parallelism: ARGON2_PARAMS.parallelism,
            type: window.argon2.ArgonType.Argon2id
        });
        return importRawKey(res.hash.buffer);
    }

    async function deriveKeyPBKDF2(masterStr, saltBuf) {
        const base = await crypto.subtle.importKey('raw', enc.encode(masterStr), { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']);
        return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: saltBuf, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' }, base, { name: AES_ALGO, length: AES_KEY_LENGTH }, false, ['encrypt', 'decrypt']);
    }

    async function deriveKey(masterStr, saltBuf) {
        if (argon2Available) {
            try { return await deriveKeyArgon2(masterStr, saltBuf); } catch { /* fallback */ }
        }
        return deriveKeyPBKDF2(masterStr, saltBuf);
    }

    async function aesEncryptWithKey(cryptoKey, plaintext) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ct = await crypto.subtle.encrypt({ name: AES_ALGO, iv }, cryptoKey, enc.encode(plaintext));
        return { iv: bufToB64(iv.buffer), data: bufToB64(ct) };
    }
    async function aesDecryptWithKey(cryptoKey, ivB64, dataB64) {
        try {
            const iv = new Uint8Array(b64ToBuf(ivB64));
            const ct = b64ToBuf(dataB64);
            const pt = await crypto.subtle.decrypt({ name: AES_ALGO, iv }, cryptoKey, ct);
            return dec.decode(pt);
        } catch { return null; }
    }

    // ====== IndexedDB ======
    const openDB = () => new Promise((resolve, reject) => {
        const req = indexedDB.open(STORAGE_DB, 1);
        req.onupgradeneeded = e => {
            db = e.target.result;
            if (!db.objectStoreNames.contains(STORE_NAME)) db.createObjectStore(STORE_NAME, { keyPath: 'id' });
        };
        req.onsuccess = e => { db = e.target.result; resolve(db); };
        req.onerror = e => reject(e);
    });

    const saveAccountDB = account => new Promise((res, rej) => {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        const r = store.put(account);
        r.onsuccess = () => res();
        r.onerror = rej;
    });

    const deleteAccountDB = id => new Promise((res, rej) => {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const r = tx.objectStore(STORE_NAME).delete(id);
        r.onsuccess = () => res();
        r.onerror = rej;
    });

    const loadAccountsDB = () => new Promise((res) => {
        const tx = db.transaction(STORE_NAME, 'readonly');
        const req = tx.objectStore(STORE_NAME).getAll();
        req.onsuccess = e => res(e.target.result || []);
        req.onerror = () => res([]);
    });

    await openDB();

    // ====== verifier handling ======
    // verifier JSON: { salt: b64, iv: b64, data: b64, alg: 'argon2id'|'pbkdf2' }
    async function createVerifier(masterStr) {
        const salt = crypto.getRandomValues(new Uint8Array(16)).buffer;
        const key = await deriveKey(masterStr, salt);
        const encRes = await aesEncryptWithKey(key, 'verifier-token-v2');
        const alg = argon2Available ? 'argon2id' : 'pbkdf2';
        localStorage.setItem(VERIFIER_KEY, JSON.stringify({ salt: bufToB64(salt), iv: encRes.iv, data: encRes.data, alg }));
    }

    async function checkVerifierAndReturnKey(masterStr) {
        try {
            const raw = localStorage.getItem(VERIFIER_KEY);
            if (!raw) return null;
            const obj = JSON.parse(raw);
            const saltBuf = b64ToBuf(obj.salt);
            const key = await deriveKey(masterStr, saltBuf);
            const txt = await aesDecryptWithKey(key, obj.iv, obj.data);
            if (txt === 'verifier-token-v2') return key;
            return null;
        } catch { return null; }
    }

    // ====== lockout/attempts ======
    const getAttempts = () => Number(localStorage.getItem(ATTEMPTS_KEY) || '0');
    const setAttempts = n => localStorage.setItem(ATTEMPTS_KEY, String(n));
    const resetAttempts = () => { localStorage.removeItem(ATTEMPTS_KEY); localStorage.removeItem(LOCK_UNTIL_KEY); };
    const getLockUntil = () => Number(localStorage.getItem(LOCK_UNTIL_KEY) || '0');
    const setLockUntil = ts => localStorage.setItem(LOCK_UNTIL_KEY, String(ts));
    const isLocked = () => { const u = getLockUntil(); return u && Date.now() < u; };
    const computeNextLock = () => {
        const current = getLockUntil();
        if (!current || Date.now() >= current) return Date.now() + INITIAL_LOCK_MS;
        const remaining = current - Date.now();
        return Date.now() + Math.min(remaining * 2, 24 * 60 * 60 * 1000);
    };
    const jitter = baseMs => baseMs + Math.floor(Math.random() * Math.min(500, baseMs));

    // ====== UI enable/disable ======
    const disableSensitiveUI = () => {
        if (addBtn) addBtn.disabled = true;
        if (generateBtn) generateBtn.disabled = true;
        if (exportBtn) exportBtn.disabled = true;
        if (importFile) importFile.disabled = true;
        if (multiDeleteBtn) multiDeleteBtn.disabled = true;
        for (const el of document.querySelectorAll('.showBtn, .copyBtn, .delBtn, .row-checkbox')) el.disabled = true;
    };
    const enableSensitiveUI = () => {
        if (addBtn) addBtn.disabled = false;
        if (generateBtn) generateBtn.disabled = false;
        if (exportBtn) exportBtn.disabled = false;
        if (importFile) importFile.disabled = false;
        if (multiDeleteBtn) multiDeleteBtn.disabled = false;
        for (const el of document.querySelectorAll('.showBtn, .copyBtn, .delBtn, .row-checkbox')) el.disabled = false;
    };

    const disableUnlockUI = (ms) => {
        if (!unlockBtn) return;
        unlockBtn.disabled = true;
        if (masterInput) masterInput.disabled = true;
        setTimeout(() => {
            if (unlockBtn) unlockBtn.disabled = false;
            if (masterInput) masterInput.disabled = false;
            if (masterInput) masterInput.focus();
        }, ms);
    };

    // ====== session / inactivity handling ======
    let sessionTimer = null, inactivityTimer = null;
    const resetSessionTimer = () => {
        if (sessionTimer) clearTimeout(sessionTimer);
        sessionTimer = setTimeout(() => hardLock('Session expirée — reconnectez-vous'), SESSION_TIMEOUT_MS);
    };
    const resetInactivityTimer = () => {
        if (inactivityTimer) clearTimeout(inactivityTimer);
        inactivityTimer = setTimeout(() => hardLock('Inactivité détectée — verrouillage'), INACTIVITY_LOCK_MS);
    };

    // ====== clipboard clear with retries ======
    async function clearClipboardOnce() {
        try { await navigator.clipboard.writeText(''); return true; } catch { return false; }
    }
    async function clearClipboardRetriesImpl() {
        for (let i = 0; i < CLIP_CLEAR_RETRIES; i++) {
            try { await navigator.clipboard.writeText(''); return; } catch { await new Promise(r => setTimeout(r, CLIP_CLEAR_RETRY_MS)); }
        }
    }
    async function scheduleClipboardClear() {
        if (navigator.clipboard == null) return;
        if (typeof clipboardClearTimer !== 'undefined' && clipboardClearTimer) clearTimeout(clipboardClearTimer);
        clipboardClearTimer = setTimeout(async () => { try { await clearClipboardRetriesImpl(); toast('Presse-papiers effacé'); } catch { } }, CLIP_CLEAR_MS);
    }
    window.addEventListener('beforeunload', async () => { try { await clearClipboardRetriesImpl(); } catch { } });

    // ====== hard lock ======
    async function hardLock(msg) {
        try { await clearClipboardRetriesImpl(); } catch { }
        MASTER_KEY = null;
        accountsCache = [];
        currentPage = 1;
        if (tableBody) tableBody.innerHTML = '';
        if (lockModal) lockModal.style.display = 'flex';
        disableSensitiveUI();
        if (msg) toast(msg);
    }

    // auto-lock on visibility change
    document.addEventListener('visibilitychange', () => { if (document.hidden) hardLock('Page masquée — verrouillage'); });
    window.addEventListener('blur', () => { resetInactivityTimer(); });
    window.addEventListener('focus', () => { resetInactivityTimer(); resetSessionTimer(); });
    ['mousemove', 'keydown', 'touchstart', 'click'].forEach(evt => window.addEventListener(evt, () => { resetInactivityTimer(); resetSessionTimer(); }));

    // ====== unlock flow ======
    async function handleUnlock() {
        if (!masterInput) return;
        if (isLocked()) {
            const until = getLockUntil();
            const sec = Math.ceil((until - Date.now()) / 1000);
            if (masterMsg) masterMsg.textContent = `Verrouillé — réessayez dans ${sec}s.`;
            disableUnlockUI(Math.min(sec * 1000, 60 * 1000));
            return;
        }
        const masterStr = masterInput.value || '';
        if (!masterStr) return;
        const derivedKey = await checkVerifierAndReturnKey(masterStr);
        masterInput.value = '';
        if (derivedKey) {
            MASTER_KEY = derivedKey;
            if (lockModal) lockModal.style.display = 'none';
            resetAttempts();
            await unlockSession();
            enableSensitiveUI();
            resetSessionTimer();
            resetInactivityTimer();
            toast('Coffre déverrouillé');
        } else {
            const attempts = getAttempts() + 1;
            setAttempts(attempts);
            const delay = jitter(500 * attempts);
            if (attempts >= MAX_ATTEMPTS) {
                const until = computeNextLock();
                setLockUntil(until);
                masterMsg.textContent = `Trop d'essais. Verrouillé jusqu'à ${new Date(until).toLocaleString()}.`;
                disableUnlockUI(Math.min(until - Date.now(), 60 * 60 * 1000));
            } else {
                masterMsg.textContent = `Mot de passe maître incorrect. (${attempts}/${MAX_ATTEMPTS})`;
                disableUnlockUI(delay);
            }
        }
    }

    unlockBtn?.addEventListener('click', handleUnlock);
    masterInput?.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); handleUnlock(); } });

    setMasterBtn?.addEventListener('click', async () => {
        const m = masterInput?.value?.trim?.() || '';
        if (m.length < 12 || !/[A-Z]/.test(m) || !/[a-z]/.test(m) || !/\d/.test(m) || !/[^A-Za-z0-9]/.test(m)) {
            masterMsg.textContent = 'Mot de passe maître min 12 car., maj, min, chiffres et symboles.';
            return;
        }
        await createVerifier(m);
        const k = await checkVerifierAndReturnKey(m);
        masterInput.value = '';
        if (!k) { masterMsg.textContent = 'Erreur création vérificateur'; return; }
        MASTER_KEY = k;
        if (lockModal) lockModal.style.display = 'none';
        await unlockSession();
        enableSensitiveUI();
        resetSessionTimer();
        resetInactivityTimer();
        toast('Mot de passe maître créé (clé dérivée en mémoire)');
    });

    logoutBtn?.addEventListener('click', async () => {
        await clearClipboardRetriesImpl();
        MASTER_KEY = null;
        accountsCache = [];
        if (tableBody) tableBody.innerHTML = '';
        if (lockModal) lockModal.style.display = 'flex';
        disableSensitiveUI();
        toast('Verrouillé');
    });

    // ====== unlockSession & per-account wrapping ======
    const randId = () => Array.from(crypto.getRandomValues(new Uint8Array(12))).map(b => b.toString(16).padStart(2, '0')).join('');

    async function unlockSession() {
        if (!MASTER_KEY) return;
        const raw = await loadAccountsDB();
        accountsCache = [];
        for (const a of raw) {
            try {
                if (a.wrappedKey) {
                    const perKeyRawB64 = await aesDecryptWithKey(MASTER_KEY, a.wrappedKey.iv, a.wrappedKey.data);
                    if (!perKeyRawB64) { accountsCache.push({ ...a, password: null }); continue; }
                    const perKeyBuf = b64ToBuf(perKeyRawB64);
                    const perKey = await crypto.subtle.importKey('raw', perKeyBuf, { name: AES_ALGO }, false, ['decrypt']);
                    const pwd = await aesDecryptWithKey(perKey, a.iv, a.data);
                    accountsCache.push({ ...a, password: pwd });
                } else {
                    // legacy
                    accountsCache.push({ ...a, password: null });
                }
            } catch {
                accountsCache.push({ ...a, password: null });
            }
        }
        currentPage = 1;
        renderTable(search?.value?.toLowerCase() || '');
        resetSessionTimer();
        resetInactivityTimer();
    }

    async function addAccount(site, email, pwd) {
        if (!MASTER_KEY) throw new Error('locked');
        const id = randId();
        const perKeyRaw = crypto.getRandomValues(new Uint8Array(32));
        const perKey = await crypto.subtle.importKey('raw', perKeyRaw.buffer, { name: AES_ALGO }, false, ['encrypt', 'decrypt']);
        const encRes = await aesEncryptWithKey(perKey, pwd);
        const perKeyB64 = bufToB64(perKeyRaw.buffer);
        const wrapped = await aesEncryptWithKey(MASTER_KEY, perKeyB64);
        const account = {
            id, site, email,
            iv: encRes.iv, data: encRes.data,
            created: Date.now(),
            wrappedKey: { iv: wrapped.iv, data: wrapped.data }
        };
        await saveAccountDB(account);
        accountsCache.push({ ...account, password: pwd });
        renderTable(search?.value?.toLowerCase() || '');
        resetSessionTimer();
    }

    async function deleteAccount(id) {
        await deleteAccountDB(id);
        accountsCache = accountsCache.filter(a => a.id !== id);
        renderTable(search?.value?.toLowerCase() || '');
        resetSessionTimer();
    }

    async function deleteAccountsBatch(ids) {
        const tx = db.transaction(STORE_NAME, 'readwrite');
        const store = tx.objectStore(STORE_NAME);
        for (const id of ids) store.delete(id);
        await new Promise((res, rej) => { tx.oncomplete = res; tx.onerror = rej; });
        accountsCache = accountsCache.filter(a => !ids.includes(a.id));
        renderTable(search?.value?.toLowerCase() || '');
    }

    // ====== rendering & event delegation ======
    const ITEMS_PER_PAGE = 9;

    function createTableRow(entry) {
        const tr = document.createElement('tr');
        tr.dataset.id = entry.id;
        tr.innerHTML = `
            <td class="px-3 py-3">${escapeHtml(entry.site) || '—'}</td>
            <td class="px-3 py-3">${escapeHtml(entry.email) || '—'}</td>
            <td class="px-3 py-3 break-all"><span class="pw-span" data-id="${entry.id}">${mask(entry.password)}</span></td>
            <td class="px-3 py-3">
                <div class="flex gap-2">
                    <button class="showBtn px-2 py-1 rounded bg-slate-700 hover:bg-slate-600 text-xs" data-action="show" data-id="${entry.id}" aria-label="Bouton afficher">Afficher</button>
                    <button class="copyBtn px-2 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-xs" data-action="copy" data-id="${entry.id}" aria-label="Bouton copier pour 5 secondes">Copier</button>
                    <button class="delBtn px-2 py-1 rounded bg-rose-600 hover:bg-rose-500 text-xs" data-action="del" data-id="${entry.id}" aria-label="Bouton supprimer">Suppr</button>
                </div>
            </td>
        `;
        return tr;
    }

    function renderTable(filter = '') {
        if (!tableBody) return;
        tableBody.innerHTML = '';
        const q = (filter || '').toLowerCase();
        const filtered = accountsCache
            .map((a, i) => ({ ...a, _idx: i }))
            .filter(a => (a.site || '').toLowerCase().includes(q) || (a.email || '').toLowerCase().includes(q));
        const totalItems = filtered.length;
        const totalPages = Math.max(1, Math.ceil(totalItems / ITEMS_PER_PAGE));
        if (currentPage > totalPages) currentPage = totalPages;
        const start = (currentPage - 1) * ITEMS_PER_PAGE;
        const visible = filtered.slice(start, start + ITEMS_PER_PAGE);
        if (emptyHint) emptyHint.style.display = visible.length === 0 ? 'block' : 'none';
        for (const entry of visible) tableBody.appendChild(createTableRow(entry));
        renderPagination(totalPages);
    }

    function renderPagination(totalPages) {
        if (!paginationContainer) return;
        paginationContainer.innerHTML = '';

        const wrapper = document.createElement('div');
        wrapper.className = 'flex justify-center items-center gap-2 mt-4 p-2 bg-slate-800 rounded shadow max-h-12';

        const btnPrev = document.createElement('button');
        btnPrev.className = 'px-3 py-1 bg-slate-700 text-slate-100 rounded hover:bg-slate-600 disabled:opacity-50';
        btnPrev.textContent = 'Prev';
        btnPrev.disabled = currentPage <= 1;
        btnPrev.onclick = () => { currentPage = Math.max(1, currentPage - 1); renderTable(search?.value || ''); };

        const btnNext = document.createElement('button');
        btnNext.className = 'px-3 py-1 bg-slate-700 text-slate-100 rounded hover:bg-slate-600 disabled:opacity-50';
        btnNext.textContent = 'Next';
        btnNext.disabled = currentPage >= totalPages;
        btnNext.onclick = () => { currentPage = Math.min(totalPages, currentPage + 1); renderTable(search?.value || ''); };

        const info = document.createElement('span');
        info.className = 'text-slate-200 font-medium';
        info.textContent = `Page ${currentPage}/${totalPages}`;

        wrapper.appendChild(btnPrev);
        wrapper.appendChild(info);
        wrapper.appendChild(btnNext);

        // Tailwind fixed at bottom of the table
        wrapper.classList.add('sticky', 'bottom-0', 'bg-slate-900');
        paginationContainer.appendChild(wrapper);
    }


    // event delegation for table actions
    tableBody?.addEventListener('click', async (e) => {
        const btn = e.target.closest('button');
        if (!btn) return;
        const action = btn.dataset.action;
        const id = btn.dataset.id;
        if (!action || !id) return;

        // find account
        const account = accountsCache.find(a => a.id === id);
        if (!account) { toast('Élément introuvable'); return; }

        if (action === 'show') {
            const span = btn.closest('tr')?.querySelector('.pw-span');
            if (!span) return;
            if (!account.password) { toast('Impossible de déchiffrer (reconnectez-vous)'); return; }
            if (span.textContent.includes('*')) {
                span.textContent = account.password;
                setTimeout(() => { span.textContent = mask(account.password); }, AUTO_HIDE_MS);
            } else {
                span.textContent = mask(account.password);
            }
            resetSessionTimer(); resetInactivityTimer();
            return;
        }

        if (action === 'copy') {
            if (!account.password) { toast('Impossible de copier (reconnectez-vous)'); return; }
            try {
                await navigator.clipboard.writeText(account.password);
                toast('Mot de passe copié — effacement automatique');
                scheduleClipboardClear();
            } catch { toast('Impossible de copier'); }
            resetSessionTimer(); resetInactivityTimer();
            return;
        }

        if (action === 'del') {
            if (confirm('Supprimer cet élément ?')) {
                await deleteAccount(id);
                toast('Supprimé');
            }
            resetSessionTimer(); resetInactivityTimer();
            return;
        }
    });

    // row checkbox clicks handled by event delegation on tableBody
    tableBody?.addEventListener('change', (e) => {
        const cb = e.target.closest('.row-checkbox');
        if (!cb) return;
        // update selectAllCheckbox state
        const all = Array.from(tableBody.querySelectorAll('.row-checkbox'));
        const checked = all.filter(x => x.checked).length;
        if (selectAllCheckbox) {
            selectAllCheckbox.checked = checked > 0 && checked === all.length;
            selectAllCheckbox.indeterminate = checked > 0 && checked < all.length;
        }
    });

    // selectAllCheckbox logic
    selectAllCheckbox?.addEventListener('change', (e) => {
        const on = e.target.checked;
        for (const cb of tableBody.querySelectorAll('.row-checkbox')) cb.checked = on;
    });

    // multi-delete button
    multiDeleteBtn?.addEventListener('click', async () => {
        const selected = Array.from(tableBody.querySelectorAll('.row-checkbox')).filter(cb => cb.checked).map(cb => cb.dataset.id);
        if (selected.length === 0) { toast('Aucune sélection'); return; }
        if (!confirm(`Supprimer ${selected.length} éléments ?`)) return;
        await deleteAccountsBatch(selected);
        toast(`${selected.length} éléments supprimés`);
    });

    // ====== generator improved (force classes) ======
    const secureRandomInt = max => crypto.getRandomValues(new Uint32Array(1))[0] % max;
    function generatePassword(len = 16, opts = { lower: true, upper: true, digits: true, symbols: true }) {
        const lower = 'abcdefghijklmnopqrstuvwxyz';
        const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const digits = '0123456789';
        const symbols = '!@#$%^&*()-_=+[]{};:,.<>?/~`';
        const classes = [];
        if (opts.lower) classes.push(lower);
        if (opts.upper) classes.push(upper);
        if (opts.digits) classes.push(digits);
        if (opts.symbols) classes.push(symbols);
        if (classes.length === 0) classes.push(lower, digits);

        const out = [];
        // ensure at least one char from each selected class
        for (const cls of classes) {
            out.push(cls[secureRandomInt(cls.length)]);
        }
        // fill the rest
        const pool = classes.join('');
        while (out.length < len) out.push(pool[secureRandomInt(pool.length)]);
        // shuffle (Fisher-Yates)
        for (let i = out.length - 1; i > 0; i--) {
            const j = secureRandomInt(i + 1);
            [out[i], out[j]] = [out[j], out[i]];
        }
        return out.slice(0, len).join('');
    }

    lengthRange?.addEventListener('input', () => { if (lenLabel) lenLabel.textContent = lengthRange.value; });

    generateBtn?.addEventListener('click', () => {
        const len = Number(lengthRange?.value || 16);
        const opts = { lower: optLower?.checked ?? true, upper: optUpper?.checked ?? true, digits: optDigits?.checked ?? true, symbols: optSymbols?.checked ?? true };
        const pwd = generatePassword(len, opts);
        if (generatedPassword) generatedPassword.value = pwd;
        updateStrength(pwd);
        resetSessionTimer(); resetInactivityTimer();
    });

    // eye for generated password (5s)
    let eyeTimer = null;
    togglePwdBtn?.addEventListener('click', () => {
        if (!generatedPassword) return;
        const hidden = generatedPassword.type === 'password';
        generatedPassword.type = hidden ? 'text' : 'password';
        iconEye?.classList.toggle('hidden'); iconEyeOff?.classList.toggle('hidden');
        if (hidden) {
            if (eyeTimer) clearTimeout(eyeTimer);
            eyeTimer = setTimeout(() => {
                generatedPassword.type = 'password';
                iconEye?.classList.remove('hidden');
                iconEyeOff?.classList.add('hidden');
                eyeTimer = null;
            }, 5000);
        } else {
            if (eyeTimer) { clearTimeout(eyeTimer); eyeTimer = null; }
        }
    });

    // strength
    function updateStrength(pwd) {
        if (!strengthText || !strengthBar) return;
        if (!pwd) {
            strengthText.textContent = '—';
            for (const seg of strengthBar.children) seg.classList.add('opacity-30');
            return;
        }
        let score = 0;
        if (pwd.length >= 8) score++;
        if (pwd.length >= 12) score++;
        if (/[a-z]/.test(pwd) && /[A-Z]/.test(pwd)) score++;
        if (/\d/.test(pwd)) score++;
        if (/[^A-Za-z0-9]/.test(pwd)) score++;
        const labels = ['Très faible', 'Faible', 'Moyen', 'Bon', 'Fort', 'Excellent'];
        strengthText.textContent = labels[Math.min(score, labels.length - 1)];
        Array.from(strengthBar.children).forEach((seg, idx) => score > idx ? seg.classList.remove('opacity-30') : seg.classList.add('opacity-30'));
    }
    generatedPassword?.addEventListener('input', e => updateStrength(e.target.value));

    // ====== add account UI ======
    addBtn?.addEventListener('click', async () => {
        if (!MASTER_KEY) { alert('Déverrouillez le coffre.'); return; }
        clearError(siteInput); clearError(emailInput);
        const site = siteInput?.value?.trim() || '', email = emailInput?.value?.trim() || '', pwd = generatedPassword?.value || '';
        if (!site) { showError(siteInput, 'Site requis'); return; }
        if (!email) { showError(emailInput, 'Email requis'); return; }
        if (!pwd) { toast('Mot de passe requis'); return; }
        await addAccount(site, email, pwd);
        if (siteInput) siteInput.value = ''; if (emailInput) emailInput.value = ''; if (generatedPassword) generatedPassword.value = '';
        updateStrength(''); toast('Ajouté au coffre');
        resetSessionTimer(); resetInactivityTimer();
    });

    function showError(input, msg) { if (!input) return; let e = input.nextElementSibling; if (!e || !e.classList.contains('input-error')) { e = document.createElement('div'); e.className = 'input-error text-rose-400 text-xs mt-1'; input.parentNode.insertBefore(e, input.nextSibling); } e.textContent = msg; }
    function clearError(input) { if (!input) return; const e = input.nextElementSibling; if (e && e.classList.contains('input-error')) e.remove(); }

    // ====== export / import ======
    exportBtn?.addEventListener('click', async () => {
        const pwd = prompt('Confirmation: entrez votre mot de passe maître pour exporter (ne sera pas stocké).');
        if (!pwd) return;
        const key = await checkVerifierAndReturnKey(pwd);
        if (!key) { alert('Mot de passe maître incorrect'); return; }
        const all = await loadAccountsDB();
        const blob = new Blob([JSON.stringify(all)], { type: 'application/json' });
        const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'bbh-coffre.json'; a.click(); URL.revokeObjectURL(a.href);
        await clearClipboardRetriesImpl();
        toast('Export terminé (les données exportées restent chiffrées)');
    });

    importFile?.addEventListener('change', async e => {
        const f = e.target.files[0]; if (!f) return;
        const pwd = prompt('Confirmation: entrez votre mot de passe maître pour importer (ne sera pas stocké).');
        if (!pwd) { importFile.value = ''; return; }
        const key = await checkVerifierAndReturnKey(pwd);
        if (!key) { alert('Mot de passe maître incorrect'); importFile.value = ''; return; }
        try {
            const content = await f.text();
            const parsed = JSON.parse(content);
            if (!Array.isArray(parsed)) throw new Error('invalid');
            if (!confirm('Importer va remplacer le coffre actuel. Continuer ?')) { importFile.value = ''; return; }
            const tx = db.transaction(STORE_NAME, 'readwrite'); const store = tx.objectStore(STORE_NAME);
            store.clear();
            for (const a of parsed) store.put(a);
            tx.oncomplete = () => { unlockSession(); toast('Import terminé'); };
        } catch {
            alert('Fichier invalide');
        } finally { if (importFile) importFile.value = ''; }
    });

    // ====== small UI helpers & init ======
    if (strengthBar && strengthBar.children.length === 0) {
        for (let i = 0; i < 5; i++) {
            const seg = document.createElement('div');
            seg.className = 'flex-1 rounded opacity-30';
            strengthBar.appendChild(seg);
        }
    }

    function checkArgon2Ready() { if (!argon2Loaded) return new Promise(r => setTimeout(() => r(argon2Available), 100)); return Promise.resolve(argon2Available); }

    // initial modal display
    if (!localStorage.getItem(VERIFIER_KEY)) {
        if (lockModal) lockModal.style.display = 'flex';
        if (masterMsg) masterMsg.textContent = 'Créez un mot de passe maître';
        disableSensitiveUI();
    } else {
        if (lockModal) lockModal.style.display = 'flex';
        disableSensitiveUI();
    }

    // expose debug helpers
    window.__gestiopass = {
        isLocked: () => !MASTER_KEY,
        clearClipboardNow: async () => { try { await clearClipboardRetriesImpl(); } catch { } },
        getAttempts: () => Number(localStorage.getItem(ATTEMPTS_KEY) || '0')
    };

    // ====== search input ======
    search?.addEventListener('input', e => { currentPage = 1; renderTable(e.target.value || ''); });

    // ====== keyboard shortcut: Ctrl+Shift+L -> lock ======
    window.addEventListener('keydown', (e) => {
        if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === 'l') { hardLock('Verrouillage manuel'); }
    });

});
