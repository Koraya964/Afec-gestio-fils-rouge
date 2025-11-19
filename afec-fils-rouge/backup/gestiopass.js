// gestiopass.js — version sécurisée avec limitation de tentatives, PBKDF2 renforcé et effacement auto du presse-papier
document.addEventListener("DOMContentLoaded", () => {
    // ===============================
    // ⚙️ Constantes
    // ===============================
    const STORAGE_KEY = 'pm_v1';
    const SALT_KEY = 'pm_salt_v1';
    const VERIFIER_KEY = 'pm_verifier_v1';

    // tentative / lockout
    const ATTEMPTS_KEY = 'pm_attempts_v1';
    const LOCK_UNTIL_KEY = 'pm_lock_until_v1';
    const INITIAL_LOCK_MS = 5 * 60 * 1000; // 5 minutes
    const MAX_ATTEMPTS = 5;

    const ITEMS_PER_PAGE = 10;
    const AUTO_HIDE_MS = 5000; // délai pour remasquer mot de passe affiché
    const CLIP_CLEAR_MS = 5000; // délai pour effacer le presse-papier après copie

    // PBKDF2 -> augmenter les itérations
    const PBKDF2_ITERATIONS = 10000;

    // ===============================
    // 🧩 DOM Elements
    // ===============================
    const lockModal = document.getElementById('lockModal');
    const masterInput = document.getElementById('masterInput');
    const unlockBtn = document.getElementById('unlockBtn');
    const setMasterBtn = document.getElementById('setMasterBtn');
    const masterMsg = document.getElementById('masterMsg');

    const tableBody = document.getElementById('tableBody');
    const emptyHint = document.getElementById('emptyHint');
    const paginationContainer = document.getElementById('pagination');

    const generateBtn = document.getElementById('generateBtn');
    const addBtn = document.getElementById('addBtn');
    const generatedPassword = document.getElementById('generatedPassword');
    const lengthRange = document.getElementById('lengthRange');
    const lenLabel = document.getElementById('lenLabel');

    const strengthText = document.getElementById('strengthText');
    const strengthBar = document.getElementById('strengthBar');

    const search = document.getElementById('search');
    const exportBtn = document.getElementById('exportBtn');
    const importFile = document.getElementById('importFile');
    const logoutBtn = document.getElementById('logoutBtn');

    const togglePwdBtn = document.getElementById('togglePwd');
    const iconEye = document.getElementById('iconEye');
    const iconEyeOff = document.getElementById('iconEyeOff');

    const optLower = document.getElementById('optLower');
    const optUpper = document.getElementById('optUpper');
    const optDigits = document.getElementById('optDigits');
    const optSymbols = document.getElementById('optSymbols');

    const siteInput = document.getElementById('site');
    const emailInput = document.getElementById('email');
    const toastContainer = document.getElementById('toastContainer') || document.body;

    // ===============================
    // 🔐 Variables globales
    // ===============================
    let MASTER = null;
    let accounts = []; // tableau en mémoire (décrypté)
    let currentPage = 1;
    const showTimers = new Map(); // timers par index pour masquer les passwords affichés
    let clipboardClearTimer = null;

    // ===============================
    // 🔑 Crypto utils (PBKDF2 renforcé)
    // ===============================
    const deriveKey = (master, salt) =>
        CryptoJS.PBKDF2(master, salt, { keySize: 256 / 32, iterations: PBKDF2_ITERATIONS }).toString();

    const encryptWithMaster = plain => {
        const salt = localStorage.getItem(SALT_KEY) || '';
        return CryptoJS.AES.encrypt(plain, deriveKey(MASTER, salt)).toString();
    };

    const decryptWithMaster = cipher => {
        try {
            const salt = localStorage.getItem(SALT_KEY) || '';
            const bytes = CryptoJS.AES.decrypt(cipher, deriveKey(MASTER, salt));
            return bytes.toString(CryptoJS.enc.Utf8);
        } catch {
            return null;
        }
    };

    const loadRaw = () => {
        try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]'); } catch { return []; }
    };
    const saveRaw = raw => localStorage.setItem(STORAGE_KEY, JSON.stringify(raw));

    // ===============================
    // 🧹 Helpers
    // ===============================
    const escapeHtml = s => String(s)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');

    const mask = s => (typeof s === 'string' ? '*'.repeat(Math.max(6, s.length)) : '—');

    function toast(msg) {
        try {
            const t = document.createElement('div');
            t.textContent = msg;
            t.className = 'fixed bottom-6 right-6 bg-slate-700 text-slate-100 px-4 py-2 rounded shadow z-50';
            toastContainer.appendChild(t);
            setTimeout(() => t.remove(), 2200);
        } catch { /* silent */ }
    }

    const showError = (input, msg) => {
        let error = input.nextElementSibling;
        if (!error || !error.classList.contains('input-error')) {
            error = document.createElement('div');
            error.className = 'input-error text-rose-400 text-xs mt-1';
            input.parentNode.insertBefore(error, input.nextSibling);
        }
        error.textContent = msg;
    };
    const clearError = input => {
        const error = input.nextElementSibling;
        if (error && error.classList.contains('input-error')) error.remove();
    };

    // ===============================
    // 🔒 Gestion des tentatives / lockout
    // ===============================
    const getAttempts = () => Number(localStorage.getItem(ATTEMPTS_KEY) || '0');
    const setAttempts = n => localStorage.setItem(ATTEMPTS_KEY, String(n));
    const resetAttempts = () => { localStorage.removeItem(ATTEMPTS_KEY); localStorage.removeItem(LOCK_UNTIL_KEY); };

    const getLockUntil = () => Number(localStorage.getItem(LOCK_UNTIL_KEY) || '0');
    const setLockUntil = (ts) => localStorage.setItem(LOCK_UNTIL_KEY, String(ts));

    const isLocked = () => {
        const until = getLockUntil();
        return until && Date.now() < until;
    };

    const computeNextLock = () => {
        // si déjà verrouillé, doubler la durée (à la volée)
        const currentUntil = getLockUntil();
        if (!currentUntil || Date.now() >= currentUntil) {
            return Date.now() + INITIAL_LOCK_MS;
        }
        // durée restante doublée
        const remaining = currentUntil - Date.now();
        const next = Date.now() + Math.min(remaining * 2, 24 * 60 * 60 * 1000); // cap 24h
        return next;
    };

    const disableUnlockUI = (ms) => {
        if (!unlockBtn) return;
        unlockBtn.disabled = true;
        masterInput.disabled = true;
        setTimeout(() => {
            unlockBtn.disabled = false;
            masterInput.disabled = false;
            masterInput.focus();
        }, ms);
    };

    // ===============================
    // 🧾 Master password
    // ===============================
    const hasMaster = () => !!localStorage.getItem(SALT_KEY) && !!localStorage.getItem(VERIFIER_KEY);

    const setMaster = master => {
        const salt = CryptoJS.lib.WordArray.random(16).toString();
        localStorage.setItem(SALT_KEY, salt);
        MASTER = master;
        const verifier = CryptoJS.AES.encrypt('verifier', deriveKey(master, salt)).toString();
        localStorage.setItem(VERIFIER_KEY, verifier);
        resetAttempts();
    };

    const verifyMaster = master => {
        try {
            // lock check
            if (isLocked()) return false;
            const salt = localStorage.getItem(SALT_KEY);
            const dec = CryptoJS.AES.decrypt(localStorage.getItem(VERIFIER_KEY), deriveKey(master, salt))
                .toString(CryptoJS.enc.Utf8);
            return dec === 'verifier';
        } catch {
            return false;
        }
    };

    const handleUnlock = () => {
        if (isLocked()) {
            const until = getLockUntil();
            const sec = Math.ceil((until - Date.now()) / 1000);
            masterMsg.textContent = `Verrouillé — réessayez dans ${sec}s.`;
            disableUnlockUI(Math.min(sec * 1000, 60 * 1000));
            return;
        }

        const m = masterInput.value.trim();
        if (!m) return;

        // tentative de vérification, appliquer délai minimal sur échec pour ralentir brute-force
        if (verifyMaster(m)) {
            MASTER = m;
            masterInput.value = '';
            lockModal.style.display = 'none';
            resetAttempts();
            unlockSession();
        } else {
            // incrémenter tentatives et calculer lock si besoin
            const attempts = getAttempts() + 1;
            setAttempts(attempts);
            if (attempts >= MAX_ATTEMPTS) {
                const until = computeNextLock();
                setLockUntil(until);
                masterMsg.textContent = `Trop d'essais. Verrouillé jusqu'à ${new Date(until).toLocaleString()}.`;
                disableUnlockUI(Math.min(until - Date.now(), 60 * 60 * 1000));
            } else {
                masterMsg.textContent = `Mot de passe maître incorrect. (${attempts}/${MAX_ATTEMPTS})`;
                // petit délai progressif pour ralentir essais automatisés
                disableUnlockUI(500 * attempts);
            }
        }
    };

    if (setMasterBtn) {
        setMasterBtn.addEventListener('click', () => {
            const m = masterInput.value.trim();
            if (m.length < 8) {
                masterMsg.textContent = 'Minimum 8 caractères.';
                return;
            }
            setMaster(m);
            masterInput.value = '';
            lockModal.style.display = 'none';
            unlockSession();
            toast('Mot de passe maître créé');
        });
    }

    if (unlockBtn) unlockBtn.addEventListener('click', handleUnlock);
    if (masterInput) masterInput.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); handleUnlock(); } });

    if (logoutBtn) logoutBtn.addEventListener('click', () => {
        MASTER = null;
        tableBody.innerHTML = '';
        lockModal.style.display = 'flex';
    });

    if (!hasMaster()) {
        if (lockModal) lockModal.style.display = 'flex';
        if (masterMsg) masterMsg.textContent = 'Créez un mot de passe maître';
    } else {
        if (lockModal) lockModal.style.display = 'flex';
        if (masterMsg) masterMsg.textContent = '';
    }

    // ===============================
    // 🚀 Coffre
    // ===============================
    const unlockSession = () => {
        const raw = loadRaw();
        accounts = raw.map(r => ({ ...r, password: decryptWithMaster(r.password) ?? null }));
        currentPage = 1;
        renderTable();
    };

    const cryptoRandomId = () => {
        const arr = new Uint8Array(12);
        crypto.getRandomValues(arr);
        // hex
        return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
    };

    const addAccount = (site, email, pwd) => {
        const raw = loadRaw();
        const entry = { id: cryptoRandomId(), site, email, password: encryptWithMaster(pwd), created: Date.now() };
        raw.push(entry);
        saveRaw(raw);
        accounts.push({ ...entry, password: pwd });
        renderTable(search?.value?.toLowerCase?.() || '');
    };

    const deleteAccount = idx => {
        const raw = loadRaw();
        raw.splice(idx, 1);
        saveRaw(raw);
        accounts.splice(idx, 1);
        renderTable(search?.value?.toLowerCase?.() || '');
    };

    // ===============================
    // 📋 Tableau + pagination + recherche
    // ===============================
    const renderTable = (filter = '') => {
        if (!tableBody) return;
        tableBody.innerHTML = '';
        const withIndex = accounts.map((a, i) => ({ ...a, _idx: i }));
        const filtered = withIndex.filter(a =>
            (a.site || '').toLowerCase().includes(filter) ||
            (a.email || '').toLowerCase().includes(filter)
        );

        const totalItems = filtered.length;
        const totalPages = Math.max(1, Math.ceil(totalItems / ITEMS_PER_PAGE));
        if (currentPage > totalPages) currentPage = totalPages;

        const start = (currentPage - 1) * ITEMS_PER_PAGE;
        const visible = filtered.slice(start, start + ITEMS_PER_PAGE);

        if (emptyHint) emptyHint.style.display = visible.length === 0 ? 'block' : 'none';

        for (const entry of visible) {
            const idx = entry._idx;
            const tr = document.createElement('tr');

            const siteTd = document.createElement('td');
            siteTd.className = 'px-3 py-3';
            siteTd.textContent = entry.site || '—';

            const emailTd = document.createElement('td');
            emailTd.className = 'px-3 py-3';
            emailTd.textContent = entry.email || '—';

            const pwdTd = document.createElement('td');
            pwdTd.className = 'px-3 py-3 break-all';
            const span = document.createElement('span');
            span.className = 'pw-span';
            span.dataset.idx = String(idx);
            span.textContent = entry.password ? mask(entry.password) : '—';
            pwdTd.appendChild(span);

            const actionsTd = document.createElement('td');
            actionsTd.className = 'px-3 py-3';
            const flexDiv = document.createElement('div');
            flexDiv.className = 'flex gap-2';

            const showBtn = document.createElement('button');
            showBtn.className = 'showBtn px-2 py-1 rounded bg-slate-700 hover:bg-slate-600 text-xs';
            showBtn.setAttribute('aria-label', 'Afficher le mot de passe');
            showBtn.dataset.idx = String(idx);
            showBtn.textContent = 'Afficher';

            const copyBtn = document.createElement('button');
            copyBtn.className = 'copyBtn px-2 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-xs';
            copyBtn.setAttribute('aria-label', 'Copier le mot de passe');
            copyBtn.dataset.idx = String(idx);
            copyBtn.textContent = 'Copier';

            const delBtn = document.createElement('button');
            delBtn.className = 'delBtn px-2 py-1 rounded bg-rose-600 hover:bg-rose-500 text-xs';
            delBtn.setAttribute('aria-label', 'Supprimer');
            delBtn.dataset.idx = String(idx);
            delBtn.textContent = 'Suppr';

            flexDiv.append(showBtn, copyBtn, delBtn);
            actionsTd.appendChild(flexDiv);

            tr.append(siteTd, emailTd, pwdTd, actionsTd);
            tableBody.appendChild(tr);
        }

        renderPagination(totalItems);
        attachRowListeners();
    };

    const renderPagination = totalItems => {
        if (!paginationContainer) return;
        paginationContainer.innerHTML = '';
        const totalPages = Math.ceil(Math.max(1, totalItems) / ITEMS_PER_PAGE);
        if (totalPages <= 1) return;
        for (let i = 1; i <= totalPages; i++) {
            const btn = document.createElement('button');
            btn.textContent = String(i);
            btn.className = `px-2 py-1 rounded ${i === currentPage ? 'bg-cyan-500 text-slate-900' : 'bg-slate-700 text-slate-200'} hover:bg-cyan-400`;
            btn.addEventListener('click', () => { currentPage = i; renderTable(search?.value?.toLowerCase?.() || ''); });
            paginationContainer.appendChild(btn);
        }
    };

    // remasque après AUTO_HIDE_MS et gère copie/suppression
    const showPassword = (spanEl, pwd, idx) => {
        if (!pwd) return;
        const existing = showTimers.get(idx);
        if (existing) clearTimeout(existing);

        spanEl.textContent = pwd;
        const t = setTimeout(() => { spanEl.textContent = mask(pwd); showTimers.delete(idx); }, AUTO_HIDE_MS);
        showTimers.set(idx, t);
    };

    const attachRowListeners = () => {
        document.querySelectorAll('.showBtn').forEach(b => {
            b.onclick = e => {
                const idx = Number(e.currentTarget.dataset.idx);
                const span = e.currentTarget.closest('tr')?.querySelector('.pw-span');
                if (!span) return;
                const pwd = accounts[idx]?.password;
                if (!pwd) return;
                if (span.textContent.includes('*')) showPassword(span, pwd, idx);
                else { clearTimeout(showTimers.get(idx)); showTimers.delete(idx); span.textContent = mask(pwd); }
            };
        });

        document.querySelectorAll('.copyBtn').forEach(b => {
            b.onclick = async e => {
                const idx = Number(e.currentTarget.dataset.idx);
                const pwd = accounts[idx]?.password || '';
                try {
                    await navigator.clipboard.writeText(pwd);
                    toast('Mot de passe copié');
                    // effacer le presse-papier après CLIP_CLEAR_MS (best-effort)
                    if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
                    clipboardClearTimer = setTimeout(async () => {
                        try { await navigator.clipboard.writeText(''); } catch { /* ignore */ }
                        clipboardClearTimer = null;
                    }, CLIP_CLEAR_MS);
                } catch {
                    toast('Impossible de copier');
                }
            };
        });

        document.querySelectorAll('.delBtn').forEach(b => {
            b.onclick = e => {
                const idx = Number(e.currentTarget.dataset.idx);
                if (confirm('Supprimer cet élément ?')) { deleteAccount(idx); toast('Supprimé'); }
            };
        });
    };

    if (search) search.addEventListener('input', () => { currentPage = 1; renderTable(search.value.toLowerCase()); });

    // ===============================
    // ➕ Générateur mot de passe + toggle
    // ===============================
    const secureRandomInt = max => { const arr = new Uint32Array(1); crypto.getRandomValues(arr); return arr[0] % max; };

    const generatePassword = (len, opts) => {
        const lower = 'abcdefghijklmnopqrstuvwxyz';
        const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const digits = '0123456789';
        const symbols = '!@#$%^&*()-_=+[]{};:,.<>?/~`';
        let pool = '';
        if (opts.lower) pool += lower;
        if (opts.upper) pool += upper;
        if (opts.digits) pool += digits;
        if (opts.symbols) pool += symbols;
        if (!pool) pool = lower + digits;
        return Array.from({ length: len }, () => pool[secureRandomInt(pool.length)]).join('');
    };

    if (lengthRange) lengthRange.addEventListener('input', () => { if (lenLabel) lenLabel.textContent = lengthRange.value; });

    if (generateBtn) generateBtn.addEventListener('click', () => {
        const pwd = generatePassword(
            Number(lengthRange?.value || 16),
            { lower: optLower?.checked, upper: optUpper?.checked, digits: optDigits?.checked, symbols: optSymbols?.checked }
        );
        if (generatedPassword) generatedPassword.value = pwd;
        updateStrength(pwd);
    });

    if (togglePwdBtn) togglePwdBtn.addEventListener('click', () => {
        if (!generatedPassword) return;
        const hidden = generatedPassword.type === 'password';
        generatedPassword.type = hidden ? 'text' : 'password';
        if (iconEye) iconEye.classList.toggle('hidden');
        if (iconEyeOff) iconEyeOff.classList.toggle('hidden');
    });

    // ===============================
    // ➕ Barre de force visuelle (accessible)
    // ===============================
    const updateStrength = pwd => {
        if (!strengthText || !strengthBar) return;
        if (!pwd) {
            strengthText.textContent = '—';
            strengthBar.setAttribute('aria-valuenow', '0');
            Array.from(strengthBar.children).forEach(seg => { seg.className = 'flex-1 rounded-sm opacity-30'; seg.style.backgroundColor = ''; });
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

        const colors = ['#ef4444', '#f59e0b', '#f59e0b', '#84cc16', '#22c55e'];
        const segments = Array.from(strengthBar.children);
        strengthBar.setAttribute('aria-valuenow', String(score));

        segments.forEach((seg, idx) => {
            const segIndex = idx + 1;
            if (score >= segIndex) {
                const color = colors[Math.min(segIndex - 1, colors.length - 1)];
                seg.className = 'flex-1 rounded-sm';
                seg.style.backgroundColor = color;
                seg.style.opacity = '1';
                seg.style.transition = 'background-color 220ms, opacity 220ms';
            } else {
                seg.className = 'flex-1 rounded-sm opacity-30';
                seg.style.backgroundColor = '';
            }
        });
    };

    if (generatedPassword) generatedPassword.addEventListener('input', e => updateStrength(e.target.value));

    // ===============================
    // ➕ Validation UX (feedback inline) + Ajouter
    // ===============================
    if (addBtn) {
        addBtn.addEventListener('click', () => {
            if (!MASTER) { alert('Déverrouillez le coffre.'); return; }

            if (siteInput) clearError(siteInput);
            if (emailInput) clearError(emailInput);

            const site = siteInput?.value?.trim?.() || '';
            const email = emailInput?.value?.trim?.() || '';
            const pwd = generatedPassword?.value || '';

            if (!site) { if (siteInput) showError(siteInput, 'Site requis'); return; }
            if (!email) { if (emailInput) showError(emailInput, 'Email requis'); return; }
            if (!pwd) { toast('Mot de passe requis'); return; }

            addAccount(site, email, pwd);

            if (siteInput) siteInput.value = '';
            if (emailInput) emailInput.value = '';
            if (generatedPassword) generatedPassword.value = '';
            updateStrength('');
            toast('Ajouté au coffre');
        });
    }

    // ===============================
    // 🔄 Export / Import (sécurisé)
    // ===============================
    if (exportBtn) {
        exportBtn.addEventListener('click', () => {
            try {
                const raw = localStorage.getItem(STORAGE_KEY) || '[]';
                const blob = new Blob([raw], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a'); a.href = url; a.download = 'bbh-coffre.json';
                document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
                toast('Export terminé');
            } catch { toast('Export impossible'); }
        });
    }

    if (importFile) {
        importFile.addEventListener('change', async e => {
            const f = e.target.files[0]; if (!f) return;
            try {
                const content = await f.text();
                const parsed = JSON.parse(content);
                if (confirm('Importer va remplacer le coffre actuel. Continuer ?')) {
                    localStorage.setItem(STORAGE_KEY, JSON.stringify(parsed));
                    unlockSession(); toast('Import terminé');
                }
            } catch { alert('Fichier invalide'); }
            finally { importFile.value = ''; }
        });
    }

    // ===============================
    // 🚀 Init
    // ===============================
    // Ensure strengthBar exists and has 5 segments if not provided by HTML
    if (strengthBar && strengthBar.children.length === 0) {
        for (let i = 0; i < 5; i += 1) {
            const seg = document.createElement('div');
            seg.className = 'flex-1 rounded-sm opacity-30';
            strengthBar.appendChild(seg);
        }
    }

    // Si déjà connecté (rare) -> charger
    if (MASTER) unlockSession();

    // tidy on unload: clear clipboard timer
    window.addEventListener('beforeunload', () => {
        if (clipboardClearTimer) {
            clearTimeout(clipboardClearTimer);
            clipboardClearTimer = null;
            try { navigator.clipboard.writeText(''); } catch { /* best-effort */ }
        }
    });
});
