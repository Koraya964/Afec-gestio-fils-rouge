<!doctype html>
<html lang="fr">

<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>BBH Password Manager — Prototype</title>
    <link rel="icon" type="image/png" sizes="32x32" href="images/BBH-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="images/BBH-16x16.png">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js"></script>
    <script src="JS Doc/gestiopass-pro.js" defer></script>
    <script src="JS Doc/script.js"></script>
    <link href="ressources graphique/css/styletailwind.css" rel="stylesheet">
    
</head>

<body class="bg-slate-900 text-slate-100 min-h-screen antialiased">
    <!-- Header -->
    <header class="bg-slate-800/60 backdrop-blur-md sticky top-0 z-40 shadow-md">
        <div class="max-w-6xl mx-auto px-4 py-3 flex flex-wrap items-center justify-between gap-3">

            <!-- Logo + Titre -->
            <div class="flex items-center gap-2 flex-shrink-0">
                <a href="index.html" class="flex items-center gap-2">
                    <img src="images/BBH-45x45.png" alt="BBH" class="w-9 h-9 sm:w-10 sm:h-10" />
                    <h1 class="text-base sm:text-lg font-semibold text-cyan-300">BBH Password Manager</h1>
                </a>
                <span class="hidden sm:inline text-xs sm:text-sm text-slate-400 ml-1">Prototype</span>
            </div>

            <!-- Zone droite -->
            <div class="flex items-center gap-2 w-full sm:w-auto">
                <!-- Barre de recherche -->
                <input id="search" type="search" placeholder="Rechercher site / email..."
                    class="flex-1 sm:flex-none w-full sm:w-64 px-3 py-2 rounded-lg bg-slate-700/40 placeholder-slate-400 text-slate-100 focus:outline-none focus:ring-2 focus:ring-cyan-400 transition-all" />

                <!-- Bouton verrouiller -->
                <button id="logoutBtn"
                    class="whitespace-nowrap px-3 py-2 rounded-lg bg-rose-500 text-white text-sm hover:bg-rose-600 transition-colors">
                    Verrouiller
                </button>
            </div>
        </div>
    </header>

    <main class="max-w-6xl mx-auto px-4 py-8">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6" id="generatorContent">
            <!-- Formulaire / Générateur -->
            <section class="md:col-span-1 bg-slate-800 rounded-lg p-6 shadow flex-none max-h-[650px] overflow-y-auto">
                <h2 class="text-cyan-300 font-semibold text-lg mb-4">Générateur & Ajouter</h2>

                <div class="space-y-3">
                    <label class="block text-sm text-slate-300" for="Site et App">Site / App</label>
                    <input id="site" name="Site et App" class="w-full px-3 py-2 rounded bg-slate-700 text-slate-100" />

                    <label class="block text-sm text-slate-300" for="Email ou Identifiant">Email / Identifiant</label>
                    <input id="email" name="Email ou Identifiant "
                        class="w-full px-3 py-2 rounded bg-slate-700 text-slate-100" />

                    <label class="block text-sm text-slate-300" for="Mot de passe">Mot de passe</label>
                    <div class="flex gap-2 items-center">
                        <div class="relative flex-1">
                            <input id="generatedPassword" type="password" name="Mot de passe"
                                class="w-full px-3 py-2 rounded bg-slate-700 text-slate-100 pr-10"
                                placeholder="Mot de passe généré" />

                            <!-- Bouton œil SVG -->
                            <button id="togglePwd" type="button"
                                class="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-cyan-400 transition">
                                <svg id="iconEye" xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" fill="none"
                                    viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8"
                                        d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                                    <circle cx="12" cy="12" r="3" />
                                </svg>

                                <svg id="iconEyeOff" xmlns="http://www.w3.org/2000/svg" class="w-5 h-5 hidden"
                                    fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8"
                                        d="M3 3l18 18M10.58 10.59A3 3 0 0113.4 13.4M9.88 9.88a3 3 0 014.24 4.24M21 12c-.878 2.675-3.89 6-9 6-5.11 0-8.122-3.325-9-6a9.77 9.77 0 012.528-3.568M9.882 9.882L4.7 4.7" />
                                </svg>
                            </button>
                        </div>

                        <button id="generateBtn" type="button"
                            class="px-3 py-2 rounded bg-cyan-500 text-slate-900 font-semibold hover:bg-cyan-400 transition cursor-pointer">
                            Générer
                        </button>
                    </div>

                    <div class="grid grid-cols-2 gap-2 text-sm text-slate-300">
                        <label class="flex items-center gap-2"><input id="optLower" type="checkbox" checked
                                class="accent-cyan-400" /> minuscules</label>
                        <label class="flex items-center gap-2"><input id="optUpper" type="checkbox" checked
                                class="accent-cyan-400" /> MAJ</label>
                        <label class="flex items-center gap-2"><input id="optDigits" type="checkbox" checked
                                class="accent-cyan-400" /> chiffres</label>
                        <label class="flex items-center gap-2"><input id="optSymbols" type="checkbox" checked
                                class="accent-cyan-400" /> symboles</label>
                    </div>

                    <label class="block text-sm text-slate-300 mt-2" for="Longueur">Longueur: <span id="lenLabel"
                            class="font-medium text-cyan-300">16</span></label>
                    <input id="lengthRange" type="range" min="8" max="64" value="16" class="w-full" name="Longueur" class="cursor-pointer" />

                    <div class="flex gap-2 mt-3">
                        <button id="addBtn"
                            class="w-full px-3 py-2 rounded bg-emerald-500 text-slate-900 font-semibold hover:bg-emerald-400 cursor-pointer">Ajouter
                            au coffre</button>
                    </div>
                    <div class="mt-3">
                        <div class="flex items-center justify-between text-sm text-slate-300">
                            <span>Force:</span>
                            <span id="strengthText" class="font-medium">—</span>
                        </div>
                        <div id="strengthBar" class="flex gap-1 mt-1 h-2 rounded">
                            <!-- 5 segments générés par JS -->
                            <div class="flex-1 rounded opacity-30 bg-red-500"></div>
                            <div class="flex-1 rounded opacity-30 bg-orange-500"></div>
                            <div class="flex-1 rounded opacity-30 bg-yellow-400"></div>
                            <div class="flex-1 rounded opacity-30 bg-lime-500"></div>
                            <div class="flex-1 rounded opacity-30 bg-green-500"></div>
                        </div>
                        <div class="mt-3 text-sm text-slate-400">
                            <div class="text-xs text-slate-500 mt-1">Les mots de passe sont chiffrés côté client avec
                                une
                                clé dérivée de votre mot de passe maître. (Prototype)</div>
                        </div>
                    </div>

                </div>
            </section>

            <!-- Tableau des mots de passe -->
            <section class="md:col-span-2 bg-slate-800 rounded-lg p-4 shadow flex flex-col">
                <div class="flex items-center justify-between mb-4">
                    <h2 class="text-cyan-300 font-semibold">Votre coffre fort</h2>
                    <div class="flex items-center gap-2">

                        </label>
                    </div>
                </div>

                <!-- Tableau scrollable -->

                <div class="overflow-y-auto max-h-[600px] mb-2">
                    <table class="w-full text-sm table-auto">
                        <thead class="text-slate-400 text-xs uppercase sticky top-0 bg-slate-800">
                            <tr>
                                <th class="text-left px-3 py-2">Site</th>
                                <th class="text-left px-3 py-2">Email</th>
                                <th class="text-left px-3 py-2">Mot de passe</th>
                                <th class="px-3 py-2">Actions</th>
                            </tr>
                        </thead>
                        <tbody id="tableBody" class="align-top">
                            <!-- lignes dynamiques -->
                        </tbody>
                    </table>
                </div>
                <!-- Pagination -->
                <div id="pagination" class="flex gap-2 justify-center order-2 mt-4 "></div>

                <div id="emptyHint" class="text-slate-400 mt-4 text-sm order-1">Aucun mot de passe dans le coffre —
                    générez-en
                    un puis cliquez sur «Ajouter au coffre».</div>

            </section>
        </div>
    </main>
    <!-- Modal master password -->
    <div id="lockModal" class="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
        <div class="bg-slate-800 rounded-lg w-full max-w-md p-6 shadow-lg">
            <h3 class="text-cyan-300 text-lg font-semibold mb-2">Déverrouiller le coffre</h3>
            <p class="text-sm text-slate-400 mb-4">Entrez votre mot de passe maître pour accéder à vos mots de passe. Si
                c'est la première utilisation, choisissez un mot de passe maître sûr.</p>
            <div class="space-y-3">
                <input id="masterInput" type="password" placeholder="Mot de passe maître"
                    class="w-full px-3 py-2 rounded bg-slate-700 text-slate-100" />
                <div class="flex gap-2">
                    <button id="unlockBtn"
                        class="flex-1 px-3 py-2 rounded bg-cyan-500 text-slate-900 font-semibold cursor-pointer">Déverrouiller</button>
                    <button id="setMasterBtn"
                        class="flex-1 px-3 py-2 rounded bg-amber-500 text-slate-900 font-semibold cursor-pointer">Créer
                        /
                        Réinitialiser</button>
                </div>
                <div id="masterMsg" class="text-sm text-rose-400"></div>
            </div>
        </div>
    </div>

</body>

</html>