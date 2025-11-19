const express = require('express');
const path = require('path');
const app = express();
const PORT = 3000;

// Servir le dossier public
app.use(express.static(path.join(__dirname, 'public')));

// Route principale
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public/', 'index.html'));
});

const fs = require('fs');

console.log('Chemin de l’index.html :', path.join(__dirname, 'public', 'index.html'));
console.log('Existe-t-il ?', fs.existsSync(path.join(__dirname, 'public', 'index.html')));


app.listen(PORT, () => console.log(`Serveur démarré sur http://localhost:${PORT}`));
