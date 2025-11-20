<!DOCTYPE html>
<html lang="fr">

<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>BBH Network Dashboard</title>
    <link rel="icon" type="image/png" sizes="32x32" href="images/BBH-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="images/BBH-16x16.png">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://unpkg.com/lucide@latest"></script>
    <link href="ressources graphique/css/styletailwind.css" rel="stylesheet">

</head>

<body class="bg-[#0d1117] text-gray-200 min-h-screen flex flex-col items-center justify-start p-6">

    <div class="max-w-4xl w-full bg-[#161b22] border border-gray-700 rounded-2xl p-6 shadow-lg space-y-6">
        <header class="flex flex-col items-center gap-2">
            <div class="flex items-center gap-2">
                <i data-lucide="bar-chart-3" class="w-6 h-6 text-cyan-400"></i>
                <h1 class="text-2xl font-bold text-cyan-400">BBH Network Dashboard</h1>
            </div>
            <p class="text-gray-400 text-sm italic">Analyse des tests réalisés localement sur votre navigateur</p>
        </header>

        <div id="statsContainer"
            class="grid md:grid-cols-2 gap-4 text-sm bg-[#0d1117] border border-gray-700 p-4 rounded-xl">
            <div>
                <h2 class="text-cyan-300 font-semibold mb-2">Latence & Stabilité</h2>
                <p>Ping moyen : <span id="avgPing">–</span> ms</p>
                <p>Ping min : <span id="minPing">–</span> ms</p>
                <p>Ping max : <span id="maxPing">–</span> ms</p>
                <p>Jitter moyen : <span id="avgJitter">–</span> ms</p>
                <p>Perte moyenne : <span id="avgLoss">–</span>%</p>
            </div>

            <div>
                <h2 class="text-green-300 font-semibold mb-2">Débits</h2>
                <p>Download moyen : <span id="avgDown">–</span> Mbps</p>
                <p>Upload moyen : <span id="avgUp">–</span> Mbps</p>
                <p>Dernier test : <span id="lastDate">–</span></p>
                <p>Nombre total de tests : <span id="count">–</span></p>
            </div>
        </div>

        <canvas id="chart" class="w-full h-64"></canvas>

        <div class="flex flex-wrap items-center justify-between gap-4">
            <button id="exportCSV"
                class="bg-cyan-400 text-[#0d1117] font-semibold px-5 py-2 rounded-xl hover:bg-cyan-500 transition">
                ⬇️ Exporter en CSV
            </button>
            <a href="monitoring.html" class="text-sm text-gray-400 hover:text-cyan-400 underline">← Retour au test</a>
        </div>
    </div>

    <footer class="text-xs text-gray-500 mt-6">© 2025 BBH — Monitoring local</footer>

    <script>
        const STORAGE_KEY = "bbh_net_history";
        const ctx = document.getElementById("chart").getContext("2d");
        let history = loadHistory();

        // === Charger les données ===
        function loadHistory() {
            const raw = localStorage.getItem(STORAGE_KEY);
            return raw ? JSON.parse(atob(raw)) : [];
        }

        // === Calcul statistiques ===
        function calcStats() {
            if (!history.length) return null;
            const avgPing = (history.reduce((a, h) => a + h.ping, 0) / history.length).toFixed(2);
            const minPing = Math.min(...history.map(h => h.ping)).toFixed(2);
            const maxPing = Math.max(...history.map(h => h.ping)).toFixed(2);
            const avgJitter = (history.reduce((a, h) => a + h.jitter, 0) / history.length).toFixed(2);
            const avgLoss = (history.reduce((a, h) => a + +h.packetLoss, 0) / history.length).toFixed(1);
            const avgDown = (history.reduce((a, h) => a + h.download, 0) / history.length).toFixed(2);
            const avgUp = (history.reduce((a, h) => a + h.upload, 0) / history.length).toFixed(2);
            const lastDate = new Date(history.at(-1).ts).toLocaleString();

            return { avgPing, minPing, maxPing, avgJitter, avgLoss, avgDown, avgUp, lastDate, count: history.length };
        }

        // === Afficher stats ===
        function renderStats() {
            const stats = calcStats();
            const els = {
                avgPing: document.getElementById("avgPing"),
                minPing: document.getElementById("minPing"),
                maxPing: document.getElementById("maxPing"),
                avgJitter: document.getElementById("avgJitter"),
                avgLoss: document.getElementById("avgLoss"),
                avgDown: document.getElementById("avgDown"),
                avgUp: document.getElementById("avgUp"),
                lastDate: document.getElementById("lastDate"),
                count: document.getElementById("count"),
            };

            if (!stats) {
                document.getElementById("statsContainer").innerHTML =
                    "<p class='text-center text-gray-400 italic w-full'>Aucun test enregistré pour le moment.<br>Réalisez un test sur la page <a href='monitoring.html' class='text-cyan-400 underline'>Monitoring</a>.</p>";
                return;
            }

            for (const k in stats) els[k].textContent = stats[k];
        }

        // === Graphique ===
        const chart = new Chart(ctx, {
            type: "line",
            data: {
                labels: history.map(h => new Date(h.ts).toLocaleTimeString()),
                datasets: [
                    {
                        label: "Ping (ms)",
                        data: history.map(h => h.ping),
                        borderColor: "#00d8ff",
                        backgroundColor: "rgba(0,216,255,0.2)",
                        tension: 0.3,
                    },
                    {
                        label: "Download (Mbps)",
                        data: history.map(h => h.download),
                        borderColor: "#22c55e",
                        backgroundColor: "rgba(34,197,94,0.2)",
                        tension: 0.3,
                    },
                    {
                        label: "Upload (Mbps)",
                        data: history.map(h => h.upload),
                        borderColor: "#facc15",
                        backgroundColor: "rgba(250,204,21,0.2)",
                        tension: 0.3,
                    },
                ]
            },
            options: {
                responsive: true,
                plugins: { legend: { labels: { color: "#ccc" } } },
                scales: {
                    x: { ticks: { color: "#aaa" } },
                    y: { beginAtZero: true, ticks: { color: "#aaa" } }
                }
            }
        });

        // === Export CSV ===
        function exportCSV() {
            if (!history.length) return alert("Aucune donnée à exporter !");
            const headers = ["Horodatage", "Ping (ms)", "Jitter (ms)", "Pertes (%)", "Download (Mbps)", "Upload (Mbps)"];
            const rows = history.map(h => [h.ts, h.ping, h.jitter, h.packetLoss, h.download, h.upload]);
            const csv = [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
            const blob = new Blob([csv], { type: "text/csv" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "bbh_network_data.csv";
            a.click();
            URL.revokeObjectURL(url);
        }

        document.getElementById("exportCSV").addEventListener("click", exportCSV);

        lucide.createIcons();
        renderStats();
    </script>

</body>

</html>