// gestiopass.webcrypto.fixed.js — WebCrypto (PBKDF2 100k + AES-GCM per-account) with fixed password generator
document.addEventListener('DOMContentLoaded', async () => {
    // ===== Constants =====
    const STORAGE_DB = 'bbh_coffre';
    const STORE_NAME = 'accounts';
    const VERIFIER_KEY = 'pm_verifier_v1'; // JSON { salt:b64, iv:b64, cipher:b64 }
    const ATTEMPTS_KEY = 'pm_attempts_v1';
    const LOCK_UNTIL_KEY = 'pm_lock_until_v1';
    const PBKDF2_ITERATIONS = 100000;
    const PBKDF2_HASH = 'SHA-256';
    const AES_ALGO = 'AES-GCM';
    const AES_KEY_LENGTH = 256;
    const MAX_ATTEMPTS = 5;
    const INITIAL_LOCK_MS = 5 * 60 * 1000;
    const ITEMS_PER_PAGE = 10;
    const AUTO_HIDE_MS = 5000;
    const SESSION_TIMEOUT_MS = 10 * 60 * 1000;
    const CLIP_CLEAR_MS = 5000;

    // ===== DOM helpers =====
    const $ = id => document.getElementById(id);
    const lockModal = $('lockModal');
    const masterInput = $('masterInput');
    const unlockBtn = $('unlockBtn');
    const setMasterBtn = $('setMasterBtn');
    const masterMsg = $('masterMsg');

    const tableBody = $('tableBody');
    const emptyHint = $('emptyHint');
    const paginationContainer = $('pagination');

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

    // ===== State =====
    let MASTER = null;
    let accountsCache = [];
    let currentPage = 1;
    const showTimers = new Map();
    let clipboardClearTimer = null;
    let sessionTimer = null;
    let db = null;

    // ===== Text encoder/decoder =====
    const enc = new TextEncoder();
    const dec = new TextDecoder();

    // ===== B64 helpers =====
    const bufToB64 = buf => {
        const bytes = new Uint8Array(buf);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary);
    };
    const b64ToBuf = b64 => {
        const binary = atob(b64);
        const len = binary.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
        return bytes.buffer;
    };

    // ===== WebCrypto primitives =====
    async function deriveKey(masterStr, saltBuf) {
        const masterKey = await crypto.subtle.importKey('raw', enc.encode(masterStr), { name: 'PBKDF2' }, false, ['deriveKey']);
        return crypto.subtle.deriveKey(
            { name: 'PBKDF2', salt: saltBuf, iterations: PBKDF2_ITERATIONS, hash: PBKDF2_HASH },
            masterKey,
            { name: AES_ALGO, length: AES_KEY_LENGTH },
            false,
            ['encrypt', 'decrypt']
        );
    }

    async function aesGcmEncrypt(key, plaintextStr) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const cipherBuf = await crypto.subtle.encrypt({ name: AES_ALGO, iv }, key, enc.encode(plaintextStr));
        return { iv: bufToB64(iv.buffer), cipher: bufToB64(cipherBuf) };
    }

    async function aesGcmDecrypt(key, ivB64, cipherB64) {
        try {
            const ivBuf = b64ToBuf(ivB64);
            const cipherBuf = b64ToBuf(cipherB64);
            const plainBuf = await crypto.subtle.decrypt({ name: AES_ALGO, iv: new Uint8Array(ivBuf) }, key, cipherBuf);
            return dec.decode(plainBuf);
        } catch {
            return null;
        }
    }

    // ===== IndexedDB =====
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
        const store = tx.objectStore(STORE_NAME);
        const r = store.delete(id);
        r.onsuccess = () => res();
        r.onerror = rej;
    });

    const loadAccountsDB = () => new Promise(res => {
        const tx = db.transaction(STORE_NAME, 'readonly');
        const req = tx.objectStore(STORE_NAME).getAll();
        req.onsuccess = e => res(e.target.result || []);
        req.onerror = () => res([]);
    });

    // ===== UI helpers =====
    const toast = msg => {
        try {
            const t = document.createElement('div');
            t.textContent = msg;
            t.className = 'fixed bottom-6 right-6 bg-slate-700 text-slate-100 px-4 py-2 rounded shadow z-50';
            toastContainer.appendChild(t);
            setTimeout(() => t.remove(), 2200);
        } catch { /* ignore */ }
    };
    const mask = s => (typeof s === 'string' ? '*'.repeat(Math.max(6, s.length)) : '—');
    const escapeHtml = s => String(s || '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#039;');

    const showError = (input, msg) => {
        if (!input) return;
        let e = input.nextElementSibling;
        if (!e || !e.classList.contains('input-error')) {
            e = document.createElement('div');
            e.className = 'input-error text-rose-400 text-xs mt-1';
            input.parentNode.insertBefore(e, input.nextSibling);
        }
        e.textContent = msg;
    };
    const clearError = input => { if (!input) return; const e = input.nextElementSibling; if (e && e.classList.contains('input-error')) e.remove(); };

    // ===== Lockout/session/clipboard =====
    const getAttempts = () => Number(localStorage.getItem(ATTEMPTS_KEY) || '0');
    const setAttempts = n => localStorage.setItem(ATTEMPTS_KEY, String(n));
    const resetAttempts = () => { localStorage.removeItem(ATTEMPTS_KEY); localStorage.removeItem(LOCK_UNTIL_KEY); };

    const getLockUntil = () => Number(localStorage.getItem(LOCK_UNTIL_KEY) || '0');
    const setLockUntil = ts => localStorage.setItem(LOCK_UNTIL_KEY, String(ts));
    const isLocked = () => { const u = getLockUntil(); return u && Date.now() < u; };
    const computeNextLock = () => {
        const cur = getLockUntil();
        if (!cur || Date.now() >= cur) return Date.now() + INITIAL_LOCK_MS;
        const remaining = cur - Date.now();
        return Date.now() + Math.min(remaining * 2, 24 * 60 * 60 * 1000);
    };
    const disableUnlockUI = ms => {
        if (!unlockBtn) return;
        unlockBtn.disabled = true;
        if (masterInput) masterInput.disabled = true;
        setTimeout(() => { if (unlockBtn) unlockBtn.disabled = false; if (masterInput) masterInput.disabled = false; if (masterInput) masterInput.focus(); }, ms);
    };

    const scheduleClipboardClear = () => {
        if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
        clipboardClearTimer = setTimeout(async () => {
            try { await navigator.clipboard.writeText(''); } catch { /* best-effort */ }
            clipboardClearTimer = null;
        }, CLIP_CLEAR_MS);
    };

    const resetSessionTimer = () => {
        if (sessionTimer) clearTimeout(sessionTimer);
        sessionTimer = setTimeout(async () => {
            MASTER = null;
            accountsCache = [];
            if (tableBody) tableBody.innerHTML = '';
            if (lockModal) lockModal.style.display = 'flex';
            disableSensitiveUI();
            try { await navigator.clipboard.writeText(''); } catch { }
            toast('Session expirée — reconnectez-vous');
        }, SESSION_TIMEOUT_MS);
    };

    const disableSensitiveUI = () => {
        if (addBtn) addBtn.disabled = true;
        if (generateBtn) generateBtn.disabled = true;
        for (const el of document.querySelectorAll('.showBtn, .copyBtn, .delBtn')) el.disabled = true;
    };
    const enableSensitiveUI = () => {
        if (addBtn) addBtn.disabled = false;
        if (generateBtn) generateBtn.disabled = false;
        for (const el of document.querySelectorAll('.showBtn, .copyBtn, .delBtn')) el.disabled = false;
    };

    // ===== Master verifier (localStorage JSON) =====
    async function createVerifier(masterStr) {
        const salt = crypto.getRandomValues(new Uint8Array(16)).buffer;
        const key = await deriveKey(masterStr, salt);
        const { iv, cipher } = await aesGcmEncrypt(key, 'verifier-token-v1');
        localStorage.setItem(VERIFIER_KEY, JSON.stringify({ salt: bufToB64(salt), iv, cipher }));
    }
    async function checkVerifier(masterStr) {
        try {
            const raw = localStorage.getItem(VERIFIER_KEY);
            if (!raw) return false;
            const obj = JSON.parse(raw);
            const saltBuf = b64ToBuf(obj.salt);
            const key = await deriveKey(masterStr, saltBuf);
            const txt = await aesGcmDecrypt(key, obj.iv, obj.cipher);
            return txt === 'verifier-token-v1';
        } catch {
            return false;
        }
    }

    // ===== Init DB =====
    await openDB();

    // ===== Master modal logic =====
    const hasMaster = () => !!localStorage.getItem(VERIFIER_KEY);
    const validateMaster = pwd => pwd && pwd.length >= 12 && /[A-Z]/.test(pwd) && /[a-z]/.test(pwd) && /\d/.test(pwd) && /[^A-Za-z0-9]/.test(pwd);

    async function setMaster(masterStr) {
        await createVerifier(masterStr);
        MASTER = masterStr;
        resetAttempts();
    }

    async function handleUnlock() {
        if (!masterInput) return;
        if (isLocked()) {
            const sec = Math.ceil((getLockUntil() - Date.now()) / 1000);
            if (masterMsg) masterMsg.textContent = `Verrouillé — réessayez dans ${sec}s.`;
            disableUnlockUI(Math.min(sec * 1000, 60000));
            return;
        }
        const m = masterInput.value?.trim?.();
        if (!m) return;
        const ok = await checkVerifier(m);
        if (ok) {
            MASTER = m;
            masterInput.value = '';
            if (lockModal) lockModal.style.display = 'none';
            resetAttempts();
            await unlockSession();
            enableSensitiveUI();
            toast('Coffre déverrouillé');
        } else {
            const attempts = getAttempts() + 1;
            setAttempts(attempts);
            if (attempts >= MAX_ATTEMPTS) {
                const until = computeNextLock();
                setLockUntil(until);
                if (masterMsg) masterMsg.textContent = `Trop d'essais. Verrouillé jusqu'à ${new Date(until).toLocaleString()}.`;
                disableUnlockUI(Math.min(until - Date.now(), 3600000));
            } else {
                if (masterMsg) masterMsg.textContent = `Mot de passe maître incorrect. (${attempts}/${MAX_ATTEMPTS})`;
                disableUnlockUI(500 * attempts);
            }
        }
    }

    setMasterBtn?.addEventListener('click', async () => {
        const m = masterInput?.value?.trim?.() || '';
        if (!validateMaster(m)) {
            if (masterMsg) masterMsg.textContent = 'Mot de passe maître min 12 car., maj, min, chiffre, symbole.';
            return;
        }
        await setMaster(m);
        if (lockModal) lockModal.style.display = 'none';
        await unlockSession();
        enableSensitiveUI();
        toast('Mot de passe maître créé');
    });

    unlockBtn?.addEventListener('click', handleUnlock);
    masterInput?.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); handleUnlock(); } });

    logoutBtn?.addEventListener('click', async () => {
        MASTER = null;
        accountsCache = [];
        if (tableBody) tableBody.innerHTML = '';
        if (lockModal) lockModal.style.display = 'flex';
        disableSensitiveUI();
        if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
        try { await navigator.clipboard.writeText(''); } catch { }
        toast('Verrouillé');
    });

    if (!hasMaster()) {
        if (lockModal) lockModal.style.display = 'flex';
        if (masterMsg) masterMsg.textContent = 'Créez un mot de passe maître';
        disableSensitiveUI();
    } else {
        if (lockModal) lockModal.style.display = 'flex';
        disableSensitiveUI();
    }

    // ===== Core: unlockSession, CRUD =====
    const cryptoRandomId = () => Array.from(crypto.getRandomValues(new Uint8Array(12))).map(b => b.toString(16).padStart(2, '0')).join('');

    async function unlockSession() {
        if (!MASTER) return;
        const raw = await loadAccountsDB();
        accountsCache = [];
        for (const a of raw) {
            try {
                const saltBuf = b64ToBuf(a.salt);
                const key = await deriveKey(MASTER, saltBuf);
                const pwd = await aesGcmDecrypt(key, a.iv, a.cipher);
                accountsCache.push({ id: a.id, site: a.site, email: a.email, password: pwd, salt: a.salt, created: a.created });
            } catch {
                accountsCache.push({ id: a.id, site: a.site, email: a.email, password: null, salt: a.salt, created: a.created });
            }
        }
        currentPage = 1;
        renderTable();
        resetSessionTimer();
        enableSensitiveUI();
    }

    async function addAccount(site, email, pwd) {
        if (!MASTER) throw new Error('locked');
        const id = cryptoRandomId();
        const saltBuf = crypto.getRandomValues(new Uint8Array(16)).buffer;
        const saltB64 = bufToB64(saltBuf);
        const key = await deriveKey(MASTER, saltBuf);
        const encRes = await aesGcmEncrypt(key, pwd);
        const account = { id, site, email, cipher: encRes.cipher, iv: encRes.iv, salt: saltB64, created: Date.now() };
        await saveAccountDB(account);
        accountsCache.push({ id, site, email, password: pwd, salt: saltB64, created: account.created });
        renderTable(search?.value?.toLowerCase() || '');
        resetSessionTimer();
    }

    async function deleteAccount(id) {
        await deleteAccountDB(id);
        accountsCache = accountsCache.filter(a => a.id !== id);
        renderTable(search?.value?.toLowerCase() || '');
        resetSessionTimer();
    }

    // ===== Rendering / listeners =====
    function renderRow(entry) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td class="px-3 py-3">${escapeHtml(entry.site) || '—'}</td>
            <td class="px-3 py-3">${escapeHtml(entry.email) || '—'}</td>
            <td class="px-3 py-3 break-all"><span class="pw-span" data-id="${entry.id}">${mask(entry.password)}</span></td>
            <td class="px-3 py-3">
                <div class="flex gap-2">
                    <button class="showBtn px-2 py-1 rounded bg-slate-700 hover:bg-slate-600 text-xs" data-id="${entry.id}">Afficher</button>
                    <button class="copyBtn px-2 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-xs" data-id="${entry.id}">Copier</button>
                    <button class="delBtn px-2 py-1 rounded bg-rose-600 hover:bg-rose-500 text-xs" data-id="${entry.id}">Suppr</button>
                </div>
            </td>
        `;
        tableBody?.appendChild(tr);
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
        for (const entry of visible) renderRow(entry);
        renderPagination(totalItems);
        attachRowListeners();
    }

    function renderPagination(totalItems) {
        if (!paginationContainer) return;
        paginationContainer.innerHTML = '';
        const totalPages = Math.ceil(Math.max(1, totalItems) / ITEMS_PER_PAGE);
        if (totalPages <= 1) return;
        for (let i = 1; i <= totalPages; i++) {
            const btn = document.createElement('button');
            btn.textContent = String(i);
            btn.className = `px-2 py-1 rounded ${i === currentPage ? 'bg-cyan-500 text-slate-900' : 'bg-slate-700 text-slate-200'} hover:bg-cyan-400`;
            btn.addEventListener('click', () => { currentPage = i; renderTable(search?.value?.toLowerCase() || ''); });
            paginationContainer.appendChild(btn);
        }
    }

    function showPassword(spanEl, pwd, id) {
        if (!pwd) return;
        const existing = showTimers.get(id);
        if (existing) clearTimeout(existing);
        spanEl.textContent = pwd;
        const t = setTimeout(() => { spanEl.textContent = mask(pwd); showTimers.delete(id); }, AUTO_HIDE_MS);
        showTimers.set(id, t);
    }

    function attachRowListeners() {
        for (const b of document.querySelectorAll('.showBtn')) {
            b.onclick = e => {
                const id = e.currentTarget.dataset.id;
                const span = e.currentTarget.closest('tr')?.querySelector('.pw-span');
                const pwd = accountsCache.find(a => a.id === id)?.password;
                if (!span || !pwd) return;
                if (span.textContent.includes('*')) showPassword(span, pwd, id);
                else { clearTimeout(showTimers.get(id)); showTimers.delete(id); span.textContent = mask(pwd); }
                resetSessionTimer();
            };
        }
        for (const b of document.querySelectorAll('.copyBtn')) {
            b.onclick = async e => {
                const id = e.currentTarget.dataset.id;
                const pwd = accountsCache.find(a => a.id === id)?.password || '';
                try {
                    await navigator.clipboard.writeText(pwd);
                    toast('Mot de passe copié — effacement automatique dans 5s');
                    scheduleClipboardClear();
                } catch {
                    toast('Impossible de copier');
                }
                resetSessionTimer();
            };
        }
        for (const b of document.querySelectorAll('.delBtn')) {
            b.onclick = async e => {
                const id = e.currentTarget.dataset.id;
                if (confirm('Supprimer cet élément ?')) { await deleteAccount(id); toast('Supprimé'); }
                resetSessionTimer();
            };
        }
    }

    // ===== Generator (fixed) + strength =====
    const secureRandomInt = max => crypto.getRandomValues(new Uint32Array(1))[0] % max;

    // Improved generator: ensures at least one char from each selected class when length permits
    function generatePassword(len = 16, opts = { lower: true, upper: true, digits: true, symbols: true }) {
        const classes = [];
        const lower = 'abcdefghijklmnopqrstuvwxyz';
        const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const digits = '0123456789';
        const symbols = '!@#$%^&*()-_=+[]{};:,.<>?/~`';

        if (opts.lower) classes.push(lower);
        if (opts.upper) classes.push(upper);
        if (opts.digits) classes.push(digits);
        if (opts.symbols) classes.push(symbols);
        // fallback
        if (classes.length === 0) classes.push(lower, digits);

        // ensure at least one from each selected class if possible
        const out = [];
        for (const cls of classes) {
            if (out.length < len) out.push(cls[secureRandomInt(cls.length)]);
        }
        // fill remaining from the concatenated pool
        const pool = classes.join('');
        while (out.length < len) out.push(pool[secureRandomInt(pool.length)]);
        // shuffle (Fisher-Yates)
        for (let i = out.length - 1; i > 0; i--) {
            const j = secureRandomInt(i + 1);
            const tmp = out[i]; out[i] = out[j]; out[j] = tmp;
        }
        return out.join('');
    }

    lengthRange?.addEventListener('input', () => { if (lenLabel) lenLabel.textContent = lengthRange.value; });

    generateBtn?.addEventListener('click', () => {
        const len = Number(lengthRange?.value || 16);
        const opts = {
            lower: optLower?.checked ?? true,
            upper: optUpper?.checked ?? true,
            digits: optDigits?.checked ?? true,
            symbols: optSymbols?.checked ?? true
        };
        const pwd = generatePassword(len, opts);
        if (generatedPassword) generatedPassword.value = pwd;
        updateStrength(pwd);
        resetSessionTimer();
    });

    generatedPassword?.addEventListener('input', e => updateStrength(e.target.value));

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
        const segments = Array.from(strengthBar.children);
        for (const [idx, seg] of segments.entries()) {
            if (score > idx) seg.classList.remove('opacity-30'); else seg.classList.add('opacity-30');
        }
    }

    // ===== Add account UI =====
    addBtn?.addEventListener('click', async () => {
        if (!MASTER) { alert('Déverrouillez le coffre.'); return; }
        clearError(siteInput); clearError(emailInput);
        const site = siteInput?.value?.trim() || '';
        const email = emailInput?.value?.trim() || '';
        const pwd = generatedPassword?.value || '';
        if (!site) { showError(siteInput, 'Site requis'); return; }
        if (!email) { showError(emailInput, 'Email requis'); return; }
        if (!pwd) { toast('Mot de passe requis'); return; }
        await addAccount(site, email, pwd);
        if (siteInput) siteInput.value = '';
        if (emailInput) emailInput.value = '';
        if (generatedPassword) generatedPassword.value = '';
        updateStrength('');
        toast('Ajouté au coffre');
    });

    // ===== Export / Import =====
    exportBtn?.addEventListener('click', async () => {
        try {
            const all = await loadAccountsDB();
            const blob = new Blob([JSON.stringify(all)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url; a.download = 'bbh-coffre.json';
            document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
            toast('Export terminé');
        } catch {
            toast('Export impossible');
        }
    });

    importFile?.addEventListener('change', async e => {
        const f = e.target.files[0]; if (!f) return;
        try {
            const content = await f.text();
            const parsed = JSON.parse(content);
            if (!Array.isArray(parsed)) throw new Error('invalid');
            if (confirm('Importer va remplacer le coffre actuel. Continuer ?')) {
                const tx = db.transaction(STORE_NAME, 'readwrite'); const store = tx.objectStore(STORE_NAME);
                store.clear();
                for (const a of parsed) store.put(a);
                tx.oncomplete = () => { unlockSession(); toast('Import terminé'); };
            }
        } catch {
            alert('Fichier invalide');
        } finally { if (importFile) importFile.value = ''; }
    });

    // ===== Init UI =====
    if (strengthBar && strengthBar.children.length === 0) {
        for (let i = 0; i < 5; i++) {
            const seg = document.createElement('div');
            seg.className = 'flex-1 rounded opacity-30';
            strengthBar.appendChild(seg);
        }
    }

    if (MASTER) await unlockSession();

    window.addEventListener('beforeunload', async () => {
        if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
        try { await navigator.clipboard.writeText(''); } catch { }
    });

    // ===== Expose debug helpers =====
    window.__gestiopass = {
        resetAttempts,
        getAttempts: () => Number(localStorage.getItem(ATTEMPTS_KEY) || '0'),
        clearClipboardNow: async () => { try { await navigator.clipboard.writeText(''); } catch { } }
    };
});
