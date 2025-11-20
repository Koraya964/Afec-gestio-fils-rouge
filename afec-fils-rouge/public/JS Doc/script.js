document.addEventListener("DOMContentLoaded", () => {

  // ===============================
  // Sidebar utilisateur
  // ===============================
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

  // setup étoile pour netlify

  function setupStars(starContainerId, inputId) {
    const stars = document.querySelectorAll(`#${starContainerId} span`);
    const hiddenInput = document.getElementById(inputId);

    stars.forEach(star => {
      star.addEventListener('click', () => {
        hiddenInput.value = star.dataset.value;

        // Mettre à jour le style des étoiles sélectionnées
        stars.forEach(s => {
          if (s.dataset.value <= star.dataset.value) {
            s.classList.add('text-yellow-400');
          } else {
            s.classList.remove('text-yellow-400');
          }
        });
      });
    });
  }

  // Initialisation
  setupStars('ergonomie-stars', 'ergonomie-rating');
  setupStars('design-stars', 'design-rating');
  setupStars('contenu-stars', 'contenu-rating');

  // Message de confirmation Netlify
  document.getElementById('multi-rating-form').addEventListener('submit', function (e) {
    const messageEl = document.getElementById('message');
    setTimeout(() => {
      messageEl.textContent = "Merci pour votre feedback !";
      this.reset();
      // Reset des étoiles
      document.querySelectorAll('#ergonomie-stars span, #design-stars span, #contenu-stars span').forEach(s => s.classList.remove('text-yellow-400'));
    }, 100); // délai pour que Netlify capture le submit
  });




  /* ============================
    TABS PARAMÈTRES
  ============================ */
  const tabButtons = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
      const tab = btn.getAttribute("data-tab");

      tabButtons.forEach(b => b.classList.remove("active", "bg-bbh-accent", "text-bbh-dark"));
      tabContents.forEach(c => c.classList.add("hidden"));

      btn.classList.add("active", "bg-bbh-accent", "text-bbh-dark");
      document.getElementById(tab).classList.remove("hidden");
    });
  });



  /* ============================
     2FA: QR + OTP
  ============================ */
  const twofaCheckbox = document.getElementById("twofa");
  const twofaSetup = document.getElementById("twofa-setup");
  const qrCanvas = document.getElementById("qrCodeCanvas");
  const otpCodeElement = document.getElementById("otpCode");
  const otpTimerElement = document.getElementById("otpTimer");

  let otpTimer = 30;
  let otpSecret = "BBH-2FA-SECRET";
  let intervalOTP;

  if (twofaCheckbox) {
    twofaCheckbox.addEventListener("change", () => {
      if (twofaCheckbox.checked) {
        twofaSetup.classList.remove("hidden");
        QRCode.toCanvas(qrCanvas, "otpauth://totp/BBH?secret=" + otpSecret);
        generateOTP();
        startOtpTimer();
      } else {
        twofaSetup.classList.add("hidden");
        stopOtpTimer();
      }
    });
  }


  function generateOTP() {
    const otp = Math.floor(100000 + Math.random() * 900000);
    otpCodeElement.textContent = otp;
  }

  function startOtpTimer() {
    otpTimer = 30;
    otpTimerElement.textContent = otpTimer;
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




  // ===============================
  // Wizard multi-étapes
  // ===============================
  const steps = document.querySelectorAll(".step");
  const nextBtns = document.querySelectorAll(".next");
  const prevBtns = document.querySelectorAll(".prev");
  const progress = document.getElementById("progress");
  let currentStep = 0;
  const CLICK_DELAY = 800;
  let lastClick = 0;

  function showStep(n) {
    steps.forEach((step, i) => step.classList.toggle("hidden", i !== n));
    if (progress) progress.style.width = ((n + 1) / steps.length) * 100 + "%";
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

  nextBtns.forEach(btn => btn.addEventListener("click", () => {
    const now = Date.now();
    if (now - lastClick < CLICK_DELAY) return;
    lastClick = now;

    const currentFields = steps[currentStep].querySelectorAll("input[required]");
    let allValid = true;

    currentFields.forEach(field => {
      if (!field.checkValidity()) {
        allValid = false;
        showError(field, field.title || "Champ requis ou invalide");
        field.reportValidity();
      } else {
        clearError(field);
      }
    });

    // Vérification mot de passe
    const pwInput = document.getElementById("masterPassword");
    const confirmInput = document.getElementById("confirmPassword");
    const confirmMsg = document.getElementById("confirm-msg");
    if (pwInput && confirmInput && !steps[currentStep].classList.contains("hidden")) {
      if (pwInput.value !== confirmInput.value) {
        allValid = false;
        showError(confirmInput, "Les mots de passe ne correspondent pas");
        if (confirmMsg) confirmMsg.textContent = "❌ Les mots de passe ne correspondent pas";
      } else {
        clearError(confirmInput);
        if (confirmMsg) confirmMsg.textContent = "✅ Les mots de passe correspondent";
      }
    }

    if (!allValid) {
      btn.classList.add('shake');
      setTimeout(() => btn.classList.remove('shake'), 300);
    }

    // Remplir le résumé avant de passer à l'étape 3
    if (currentStep === 1 && allValid) {
      document.getElementById("review-displayName").textContent =
        document.getElementById("displayName").value;

      document.getElementById("review-email").textContent =
        document.getElementById("email").value;

      document.getElementById("review-phoneNumber").textContent =
        document.getElementById("phoneNumber").value;
    }

    if (allValid && currentStep < steps.length - 1) {
      currentStep++;
      showStep(currentStep);
    }
  }));

  prevBtns.forEach(btn => btn.addEventListener("click", () => {
    if (currentStep > 0) {
      currentStep--;
      showStep(currentStep);
    }
  }));

  showStep(currentStep);

  // ===============================
  // Feedback live sur champs
  // ===============================
  steps.forEach(step => {
    const fields = step.querySelectorAll('input[required]');
    fields.forEach(field => {
      field.addEventListener('input', () => {
        if (field.checkValidity()) clearError(field);
      });
    });
  });

  // ===============================
  // Formulaires Contact et Feedback
  // ===============================
  const helpForm = document.getElementById("help-form");
  const feedbackForm = document.getElementById("multi-rating-form");

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
      showMessage(document.getElementById("sos-message"), "✅ Votre message a bien été envoyé !");
      helpForm.reset();
    });
  }

  if (feedbackForm) {
    feedbackForm.addEventListener("submit", (e) => {
      showMessage(document.getElementById("message"), "✅ Merci pour votre feedback !");
      feedbackForm.reset();
    });
  }

  // ===============================
  // Étoiles interactives
  // ===============================
  ["ergonomie-stars", "design-stars", "contenu-stars"].forEach(groupId => {
    const container = document.getElementById(groupId);
    if (!container) return;

    const stars = container.querySelectorAll("span");
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
          s.style.color = i < selectedRating ? "#0ea5e9" : "#64748b";
          s.style.transform = "scale(1)";
        });
      });
      star.addEventListener("click", () => {
        selectedRating = index + 1;
        stars.forEach((s, i) => s.style.color = i < selectedRating ? "#0ea5e9" : "#64748b");
        const feedbackText = container.nextElementSibling;
        if (feedbackText) feedbackText.textContent = ["Très mauvais", "Mauvais", "Moyen", "Bien", "Excellent"][selectedRating - 1];
      });
    });
  });

  // ===============================
  // Password Meter + Générer / Copier / Toggle
  // ===============================
  const pwInput = document.getElementById("masterPassword");
  const confirmInput = document.getElementById("confirmPassword");
  if (pwInput) {
    let pwMeter = document.getElementById("pw-meter");
    let pwMsg = document.getElementById("pw-msg");

    if (!pwMeter) {
      const meterWrapper = document.createElement("div");
      meterWrapper.className = "h-2 w-full bg-slate-700 rounded mt-2";
      pwMeter = document.createElement("div");
      pwMeter.id = "pw-meter";
      pwMeter.className = "h-2 w-0 bg-red-500 rounded-full transition-all duration-300";
      meterWrapper.appendChild(pwMeter);
      pwInput.insertAdjacentElement("afterend", meterWrapper);

      pwMsg = document.createElement("p");
      pwMsg.id = "pw-msg";
      pwMsg.className = "text-xs text-slate-400 mt-1";
      pwMsg.textContent = "Force : —";
      meterWrapper.insertAdjacentElement("afterend", pwMsg);
    }

    const toolbar = document.createElement("div");
    toolbar.className = "flex gap-2 mt-3";

    const genBtn = document.createElement("button");
    genBtn.type = "button";
    genBtn.className = "bg-sky-500 hover:bg-sky-600 text-slate-900 font-semibold rounded px-3 py-2 cursor-pointer";
    genBtn.textContent = "Générer";

    const copyBtn = document.createElement("button");
    copyBtn.type = "button";
    copyBtn.id = "copy-pw";
    copyBtn.className = "bg-slate-600 text-slate-200 rounded px-3 py-2 cursor-pointer hover:bg-sky-500";
    copyBtn.textContent = "Copier";
    copyBtn.disabled = true;

    const toggleBtn = document.createElement("button");
    toggleBtn.type = "button";
    toggleBtn.className = "bg-slate-700 text-slate-200 rounded px-3 py-2 cursor-pointer hover:bg-sky-500";
    toggleBtn.textContent = "Afficher";

    toolbar.appendChild(genBtn);
    toolbar.appendChild(copyBtn);
    toolbar.appendChild(toggleBtn);
    pwMsg.insertAdjacentElement("afterend", toolbar);

    genBtn.addEventListener("click", () => {
      const pwd = generatePassword({ length: 16 });
      pwInput.value = pwd;
      updatePwMeter(checkStrength(pwd));
      copyBtn.disabled = false;
      if (confirmInput) confirmInput.value = '';
    });

    copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(pwInput.value);
        copyBtn.textContent = "Copié ✓";
        setTimeout(() => copyBtn.textContent = "Copier", 1400);
      } catch {
        copyBtn.textContent = "Erreur";
        setTimeout(() => copyBtn.textContent = "Copier", 1400);
      }
    });

    toggleBtn.addEventListener("click", () => {
      if (pwInput.type === "password") { pwInput.type = "text"; toggleBtn.textContent = "Masquer"; }
      else { pwInput.type = "password"; toggleBtn.textContent = "Afficher"; }
    });

    pwInput.addEventListener("input", () => updatePwMeter(checkStrength(pwInput.value || "")));
  }

  function generatePassword(opts = {}) { const length = opts.length || 16; const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.<>?"; let pwd = []; for (let i = 0; i < length; i++)pwd.push(chars.charAt(Math.floor(Math.random() * chars.length))); return shuffleArray(pwd).join(''); }
  function shuffleArray(arr) { for (let i = arr.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1));[arr[i], arr[j]] = [arr[j], arr[i]]; } return arr; }
  function checkStrength(pw) { let s = 0; if (pw.length >= 12) s++; if (/[A-Z]/.test(pw)) s++; if (/[a-z]/.test(pw)) s++; if (/[0-9]/.test(pw)) s++; if (/[^A-Za-z0-9]/.test(pw)) s++; return s; }
  function updatePwMeter(strength) { const m = document.getElementById("pw-meter"), msg = document.getElementById("pw-msg"); if (!m || !msg) return; let color = "bg-red-500", text = "Très faible"; if (strength >= 4) { color = "bg-green-500"; text = "Fort"; } else if (strength === 3) { color = "bg-yellow-500"; text = "Moyen"; } else if (strength === 2) { color = "bg-orange-500"; text = "Faible"; } m.className = `${color} h-2 rounded-full transition-all duration-300`; m.style.width = (strength / 5) * 100 + "%"; msg.textContent = `Force : ${text}`; }

  // ===============================
  // Gestion comptes locaux
  // ===============================
  const MASTER_KEY = "bbhMasterKey123";
  const form = document.getElementById("addAccountForm");
  const siteInput = document.getElementById("site");
  const userInput = document.getElementById("username");
  const passwordInput = document.getElementById("password");
  const togglePasswordBtn = document.getElementById("togglePassword");
  const accountList = document.getElementById("accountList");

  if (togglePasswordBtn && passwordInput) {
    togglePasswordBtn.addEventListener("click", () => {
      passwordInput.type = passwordInput.type === "password" ? "text" : "password";
    });
  }

  let accounts = JSON.parse(localStorage.getItem("accounts") || "[]");
  renderAccounts();

  if (form) {
    form.addEventListener("submit", (e) => {
      e.preventDefault();
      const site = siteInput.value.trim();
      const username = userInput.value.trim();
      const password = passwordInput.value;
      if (!site || !username || !password) return;
      const encryptedPassword = CryptoJS.AES.encrypt(password, MASTER_KEY).toString();
      accounts.push({ site, username, password: encryptedPassword });
      localStorage.setItem("accounts", JSON.stringify(accounts));
      form.reset();
      renderAccounts();
    });
  }

  function renderAccounts() {
    if (!accountList) return;
    accountList.innerHTML = "";
    accounts.forEach((acc, index) => {
      const decrypted = CryptoJS.AES.decrypt(acc.password, MASTER_KEY).toString(CryptoJS.enc.Utf8);
      const card = document.createElement("div");
      card.classList.add("card");
      card.innerHTML = `
        <h3>${acc.site}</h3>
        <p><strong>Utilisateur :</strong> ${acc.username}</p>
        <p><strong>Mot de passe :</strong> <span class="masked">${"*".repeat(decrypted.length)}</span>
        <button class="btn-icon show-password">👁️</button></p>
        <button class="btn" data-index="${index}">Supprimer</button>
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

});
