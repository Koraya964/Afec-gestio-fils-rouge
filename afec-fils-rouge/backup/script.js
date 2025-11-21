document.addEventListener("DOMContentLoaded", () => {

  // ============================================================
  // 1. SIDEBAR & NAVIGATION
  // ============================================================
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebar-overlay');
  const openSidebarBtn = document.getElementById('openLoginSidebar');
  const closeSidebarBtn = document.getElementById('closeSidebar');

  const openSidebar = () => {
    if (!sidebar || !overlay) return;
    sidebar.style.right = '0';
    overlay.classList.add('opacity-100', 'visible');
    overlay.classList.remove('opacity-0', 'invisible');
  };

  const closeSidebar = () => {
    if (!sidebar || !overlay) return;
    sidebar.style.right = '-100%';
    overlay.classList.remove('opacity-100', 'visible');
    overlay.classList.add('opacity-0', 'invisible');
  };

  if (openSidebarBtn) openSidebarBtn.addEventListener('click', openSidebar);
  if (closeSidebarBtn) closeSidebarBtn.addEventListener('click', closeSidebar);
  if (overlay) overlay.addEventListener('click', closeSidebar);


  // ============================================================
  // 2. SYSTÈME DE NOTATION (ÉTOILES)
  // ============================================================
  function setupStars(starContainerId, inputId) {
    const container = document.getElementById(starContainerId);
    const hiddenInput = document.getElementById(inputId);

    // SÉCURITÉ : Si les éléments n'existent pas, on arrête la fonction
    if (!container || !hiddenInput) return;

    const stars = container.querySelectorAll("span");

    // Gestion du clic (mise à jour input caché)
    stars.forEach(star => {
      star.addEventListener('click', () => {
        hiddenInput.value = star.dataset.value;
        stars.forEach(s => {
          if (s.dataset.value <= star.dataset.value) {
            s.classList.add('text-yellow-400');
          } else {
            s.classList.remove('text-yellow-400');
          }
        });
      });
    });

    // Gestion survol (effet visuel)
    let selectedRating = 0;
    stars.forEach((star, index) => {
      star.addEventListener("mouseover", () => {
        stars.forEach((s, i) => {
          s.style.color = i <= index ? "#0ea5e9" : "#64748b";
          s.style.transform = i <= index ? "scale(1.15)" : "scale(1)";
        });
      });
      star.addEventListener("mouseout", () => {
        stars.forEach((s, i) => {
          // On revient à la couleur jaune si cliqué, sinon gris
          if (hiddenInput.value && i < hiddenInput.value) {
            s.style.color = "#facc15"; // text-yellow-400
          } else {
            s.style.color = "#64748b";
          }
          s.style.transform = "scale(1)";
        });
      });
    });
  }

  // Initialisation sécurisée
  setupStars('ergonomie-stars', 'ergonomie-rating');
  setupStars('design-stars', 'design-rating');
  setupStars('contenu-stars', 'contenu-rating');

  // Formulaire Feedback Netlify (SÉCURISÉ)
  const ratingForm = document.getElementById('multi-rating-form');
  if (ratingForm) {
    ratingForm.addEventListener('submit', function (e) {
      // Note: Netlify gère le submit, on affiche juste le message visuel
      const messageEl = document.getElementById('message');
      if (messageEl) {
        setTimeout(() => {
          messageEl.textContent = "Merci pour votre feedback !";
          this.reset();
          document.querySelectorAll('#ergonomie-stars span, #design-stars span, #contenu-stars span')
            .forEach(s => {
              s.classList.remove('text-yellow-400');
              s.style.color = "#64748b";
            });
        }, 100);
      }
    });
  }


  // ============================================================
  // 3. TABS PARAMÈTRES
  // ============================================================
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  if (tabButtons.length > 0) {
    tabButtons.forEach(btn => {
      btn.addEventListener("click", () => {
        const tab = btn.getAttribute("data-tab");
        tabButtons.forEach(b => b.classList.remove("active", "bg-bbh-accent", "text-bbh-dark"));
        tabContents.forEach(c => c.classList.add("hidden"));

        btn.classList.add("active", "bg-bbh-accent", "text-bbh-dark");
        const targetTab = document.getElementById(tab);
        if (targetTab) targetTab.classList.remove("hidden");
      });
    });
  }


  // ============================================================
  // 4. 2FA: QR + OTP
  // ============================================================
  const twofaCheckbox = document.getElementById("twofa");
  const twofaSetup = document.getElementById("twofa-setup");
  const qrCanvas = document.getElementById("qrCodeCanvas");
  const otpCodeElement = document.getElementById("otpCode");
  const otpTimerElement = document.getElementById("otpTimer");

  let otpTimer = 30;
  let otpSecret = "BBH-2FA-SECRET";
  let intervalOTP;

  if (twofaCheckbox && twofaSetup) {
    twofaCheckbox.addEventListener("change", () => {
      if (twofaCheckbox.checked) {
        twofaSetup.classList.remove("hidden");
        // Vérification que la lib QRCode est chargée
        if (typeof QRCode !== 'undefined' && qrCanvas) {
          QRCode.toCanvas(qrCanvas, "otpauth://totp/BBH?secret=" + otpSecret);
        }
        generateOTP();
        startOtpTimer();
      } else {
        twofaSetup.classList.add("hidden");
        stopOtpTimer();
      }
    });
  }

  function generateOTP() {
    if (!otpCodeElement) return;
    const otp = Math.floor(100000 + Math.random() * 900000);
    otpCodeElement.textContent = otp;
  }

  function startOtpTimer() {
    if (!otpTimerElement) return;
    otpTimer = 30;
    otpTimerElement.textContent = otpTimer;
    clearInterval(intervalOTP); // Reset interval prevent doubles
    intervalOTP = setInterval(() => {
      otpTimer--;
      otpTimerElement.textContent = otpTimer;
      if (otpTimer <= 0) {
        generateOTP();
        otpTimer = 30;
      }
    }, 1000);
  }

  function stopOtpTimer() {
    clearInterval(intervalOTP);
  }


  // ============================================================
  // 5. WIZARD MULTI-ÉTAPES (CORRIGÉ & SÉCURISÉ)
  // ============================================================
  const steps = document.querySelectorAll(".step");
  const nextBtns = document.querySelectorAll(".next");
  const prevBtns = document.querySelectorAll(".prev");
  const progress = document.getElementById("progress");

  let currentStep = 0;
  const CLICK_DELAY = 800;
  let lastClick = 0;

  // Fonctions utilitaires Wizard
  function showStep(n) {
    steps.forEach((step, i) => step.classList.toggle("hidden", i !== n));
    if (progress && steps.length > 0) {
      progress.style.width = ((n + 1) / steps.length) * 100 + "%";
    }
  }

  function showError(field, message) {
    let span = field.previousElementSibling;
    if (!span || !span.classList.contains("error-msg")) {
      span = document.createElement("span");
      span.className = "error-msg text-red-500 text-xs block mb-1";
      field.parentNode.insertBefore(span, field);
    }
    span.textContent = message;
  }

  function clearError(field) {
    let span = field.previousElementSibling;
    if (span && span.classList.contains("error-msg")) {
      span.textContent = "";
    }
  }

  // Initialiser l'affichage si des étapes existent
  if (steps.length > 0) {
    showStep(currentStep);

    // Feedback live sur input
    steps.forEach(step => {
      const fields = step.querySelectorAll('input[required]');
      fields.forEach(field => {
        field.addEventListener('input', () => {
          if (field.checkValidity()) clearError(field);
        });
      });
    });
  }

  // Logique Bouton SUIVANT (Corrigée)
  nextBtns.forEach(btn =>
    btn.addEventListener("click", (e) => {
      e.preventDefault(); // Empêche le submit auto

      const now = Date.now();
      if (now - lastClick < CLICK_DELAY) return;
      lastClick = now;

      // Validation scoped : Uniquement les champs de l'étape visible
      const currentFields = steps[currentStep].querySelectorAll("input[required]");
      let allValid = true;

      currentFields.forEach(field => {
        if (!field.checkValidity()) {
          allValid = false;
          showError(field, field.title || field.validationMessage || "Champ requis");
        } else {
          clearError(field);
        }
      });

      // Validation Mot de passe (Uniquement si présent à l'étape courante)
      const pwInput = steps[currentStep].querySelector("#masterPassword");
      const confirmInput = steps[currentStep].querySelector("#confirmPassword");
      const confirmMsg = document.getElementById("confirm-msg");

      if (pwInput && confirmInput) {
        if (pwInput.value !== confirmInput.value) {
          allValid = false;
          showError(confirmInput, "Les mots de passe ne correspondent pas");
          if (confirmMsg) confirmMsg.textContent = "❌ Différents";
        } else {
          clearError(confirmInput);
          if (confirmMsg) confirmMsg.textContent = "✅ Identiques";
        }
      }

      if (!allValid) {
        // Animation d'erreur
        btn.classList.add('shake');
        setTimeout(() => btn.classList.remove('shake'), 300);
      } else {
        // Succès : Préparation Résumé (Si étape 1 finie)
        if (currentStep === 0) {
          const dName = document.getElementById("displayName");
          const dMail = document.getElementById("email");
          const dPhone = document.getElementById("phoneNumber");

          const rName = document.getElementById("review-displayName");
          const rMail = document.getElementById("review-email");
          const rPhone = document.getElementById("review-phoneNumber");

          if (rName && dName) rName.textContent = dName.value;
          if (rMail && dMail) rMail.textContent = dMail.value;
          if (rPhone && dPhone) rPhone.textContent = dPhone.value;
        }

        // Changement d'étape
        if (currentStep < steps.length - 1) {
          currentStep++;
          showStep(currentStep);
        }
      }
    })
  );

  // Logique Bouton PRÉCÉDENT
  prevBtns.forEach(btn =>
    btn.addEventListener("click", () => {
      if (currentStep > 0) {
        currentStep--;
        showStep(currentStep);
      }
    })
  );


  // ============================================================
  // 6. FORMULAIRE HELP / CONTACT
  // ============================================================
  const helpForm = document.getElementById("help-form");

  function showMessage(el, message, type = "success") {
    if (!el) return;
    el.textContent = message;
    el.classList.add("animate-pulse", "transition-all", "duration-500");
    if (type === "error") el.classList.add("text-red-400");
    else el.classList.add("text-green-400");

    setTimeout(() => {
      el.textContent = "";
      el.classList.remove("animate-pulse", "text-green-400", "text-red-400");
    }, 4000);
  }

  if (helpForm) {
    helpForm.addEventListener("submit", (e) => {
      e.preventDefault(); // On empêche le rechargement pour la démo
      showMessage(document.getElementById("sos-message"), "✅ Votre message a bien été envoyé !");
      helpForm.reset();
    });
  }


  // ============================================================
  // 7. PASSWORD METER & GENERATOR
  // ============================================================
  const mainPwInput = document.getElementById("masterPassword");
  // Note: On utilise mainPwInput pour vérifier si on doit lancer ce module

  if (mainPwInput) {
    let pwMeter = document.getElementById("pw-meter");
    let pwMsg = document.getElementById("pw-msg");
    const confirmInput = document.getElementById("confirmPassword");

    // Création dynamique du meter si absent du HTML
    if (!pwMeter) {
      const meterWrapper = document.createElement("div");
      meterWrapper.className = "h-2 w-full bg-slate-700 rounded mt-2";
      pwMeter = document.createElement("div");
      pwMeter.id = "pw-meter";
      pwMeter.className = "h-2 w-0 bg-red-500 rounded-full transition-all duration-300";
      meterWrapper.appendChild(pwMeter);
      mainPwInput.insertAdjacentElement("afterend", meterWrapper);

      pwMsg = document.createElement("p");
      pwMsg.id = "pw-msg";
      pwMsg.className = "text-xs text-slate-400 mt-1";
      pwMsg.textContent = "Force : —";
      meterWrapper.insertAdjacentElement("afterend", pwMsg);
    }

    // Toolbar (Générer / Copier / Voir)
    const toolbar = document.createElement("div");
    toolbar.className = "flex gap-2 mt-3";

    const genBtn = document.createElement("button");
    genBtn.type = "button";
    genBtn.className = "bg-sky-500 hover:bg-sky-600 text-slate-900 font-semibold rounded px-3 py-2 cursor-pointer text-xs";
    genBtn.textContent = "Générer";

    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.id = "copy-pw";
    copyBtn.className = "bg-slate-600 text-slate-200 rounded px-3 py-2 cursor-pointer hover:bg-sky-500 text-xs";
    copyBtn.textContent = "Copier";
    copyBtn.disabled = true;

    const toggleBtn = document.createElement("button");
    toggleBtn.type = "button";
    toggleBtn.className = "bg-slate-700 text-slate-200 rounded px-3 py-2 cursor-pointer hover:bg-sky-500 text-xs";
    toggleBtn.textContent = "Afficher";

    toolbar.appendChild(genBtn);
    toolbar.appendChild(copyBtn);
    toolbar.appendChild(toggleBtn);

    // Insertion après le message de force
    pwMsg.insertAdjacentElement("afterend", toolbar);

    // Logique Toolbar
    genBtn.addEventListener("click", () => {
      const pwd = generatePassword({ length: 16 });
      mainPwInput.value = pwd;
      updatePwMeter(checkStrength(pwd));
      copyBtn.disabled = false;
      if (confirmInput) confirmInput.value = ''; // Reset confirm
    });

    copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(mainPwInput.value);
        copyBtn.textContent = "Copié ✓";
        setTimeout(() => copyBtn.textContent = "Copier", 1400);
      } catch {
        copyBtn.textContent = "Erreur";
        setTimeout(() => copyBtn.textContent = "Copier", 1400);
      }
    });

    toggleBtn.addEventListener("click", () => {
      if (mainPwInput.type === "password") {
        mainPwInput.type = "text";
        toggleBtn.textContent = "Masquer";
      } else {
        mainPwInput.type = "password";
        toggleBtn.textContent = "Afficher";
      }
    });

    mainPwInput.addEventListener("input", () => updatePwMeter(checkStrength(mainPwInput.value || "")));
  }

  // Fonctions utilitaires Password
  function generatePassword(opts = {}) {
    const length = opts.length || 16;
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.<>?";
    let pwd = [];
    for (let i = 0; i < length; i++) pwd.push(chars.charAt(Math.floor(Math.random() * chars.length)));
    return shuffleArray(pwd).join('');
  }
  function shuffleArray(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  }
  function checkStrength(pw) {
    let s = 0;
    if (pw.length >= 12) s++;
    if (/[A-Z]/.test(pw)) s++;
    if (/[a-z]/.test(pw)) s++;
    if (/[0-9]/.test(pw)) s++;
    if (/[^A-Za-z0-9]/.test(pw)) s++;
    return s;
  }
  function updatePwMeter(strength) {
    const m = document.getElementById("pw-meter"), msg = document.getElementById("pw-msg");
    if (!m || !msg) return;
    let color = "bg-red-500", text = "Très faible";
    if (strength >= 4) { color = "bg-green-500"; text = "Fort"; }
    else if (strength === 3) { color = "bg-yellow-500"; text = "Moyen"; }
    else if (strength === 2) { color = "bg-orange-500"; text = "Faible"; }
    m.className = `${color} h-2 rounded-full transition-all duration-300`;
    m.style.width = (strength / 5) * 100 + "%";
    msg.textContent = `Force : ${text}`;
  }


  // ============================================================
  // 8. GESTION COMPTES LOCAUX
  // ============================================================
  const MASTER_KEY = "bbhMasterKey123";
  const accountForm = document.getElementById("addAccountForm");
  const siteInput = document.getElementById("site");
  const userInput = document.getElementById("username"); // Attention conflit possible ID avec login sidebar
  const passwordInput = document.getElementById("password"); // Attention conflit possible
  const togglePasswordBtn = document.getElementById("togglePassword");
  const accountList = document.getElementById("accountList");

  // On vérifie que le formulaire existe avant de lancer la logique
  if (accountForm && accountList) {

    if (togglePasswordBtn && passwordInput) {
      togglePasswordBtn.addEventListener("click", () => {
        passwordInput.type = passwordInput.type === "password" ? "text" : "password";
      });
    }

    let accounts = JSON.parse(localStorage.getItem("accounts") || "[]");
    renderAccounts();

    accountForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const site = siteInput.value.trim();
      // Note: utilise .value sur l'input trouvé dans CETTE section
      const username = userInput ? userInput.value.trim() : "";
      const password = passwordInput ? passwordInput.value : "";

      if (!site || !username || !password) return;

      // Vérif CryptoJS
      if (typeof CryptoJS !== 'undefined') {
        const encryptedPassword = CryptoJS.AES.encrypt(password, MASTER_KEY).toString();
        accounts.push({ site, username, password: encryptedPassword });
        localStorage.setItem("accounts", JSON.stringify(accounts));
        accountForm.reset();
        renderAccounts();
      } else {
        alert("Erreur : Librairie de cryptage non chargée");
      }
    });

    function renderAccounts() {
      if (!accountList) return;
      accountList.innerHTML = "";
      accounts.forEach((acc, index) => {
        let decrypted = "Erreur";
        if (typeof CryptoJS !== 'undefined') {
          try {
            decrypted = CryptoJS.AES.decrypt(acc.password, MASTER_KEY).toString(CryptoJS.enc.Utf8);
          } catch (e) { decrypted = "???"; }
        }

        const card = document.createElement("div");
        card.classList.add("card"); // Assure-toi d'avoir du CSS pour .card
        card.innerHTML = `
            <h3>${acc.site}</h3>
            <p><strong>Utilisateur :</strong> ${acc.username}</p>
            <p><strong>Mot de passe :</strong> <span class="masked">${"*".repeat(decrypted.length)}</span>
            <button class="btn-icon show-password" type="button">👁️</button></p>
            <button class="btn" data-index="${index}" type="button">Supprimer</button>
          `;
        accountList.appendChild(card);

        const showBtn = card.querySelector(".show-password");
        const pwdSpan = card.querySelector(".masked");
        showBtn.addEventListener("click", () => {
          if (pwdSpan.textContent.includes("*")) pwdSpan.textContent = decrypted;
          else pwdSpan.textContent = "*".repeat(decrypted.length);
        });

        const delBtn = card.querySelector(".btn");
        delBtn.addEventListener("click", () => {
          accounts.splice(index, 1);
          localStorage.setItem("accounts", JSON.stringify(accounts));
          renderAccounts();
        });
      });
    }
  }

});