# Projet BBH

## Nom du projet

### BBH — Bug Bounty Hero

Plateforme web complète permettant la création de compte, la gestion sécurisée des informations et l’accès à plusieurs outils intégrés.

# Frameworks & technologies utilisées

Le projet utilise les technologies et outils suivants :

Front-end :

HTML5 / CSS3

TailwindCSS (Design System du projet BBH)

JavaScript Vanilla

Accessibilité ARIA (menus, sidebar, formulaires multi-étapes)

Responsive design (mobile → desktop)

### Back-end :

- PHP (très peu)

- JSON ou fichier local (pour l'import export des MDP mais encore en développement)

### Autres outils

- Netlify pour l’hébergement statique

- GitHub pour le versioning

- Figma pour l’identité visuelle

# Objectif final du fil rouge

- Créer un site web complet et professionnel permettant :

- La création d’un compte via un formulaire en 3 étapes (wizard)

- La connexion utilisateur via une sidebar dynamique

- L’accès à plusieurs pages informatives (Contact, Téléchargement, À propos, Certification…)

- Un design cohérent basé sur la charte graphique BBH

- Une expérience utilisateur fluide et moderne, adaptée aux débutants comme aux utilisateurs expérimentés.

# Fonctionnalités finales prévues pour la fin du fil rouge

### Authentification

- Sidebar de connexion avec transitions

- Page de création de compte en plusieurs étapes :

- Étape 1 : Informations de compte

- Étape 2 : Sécurité (mot de passe maître, validation, téléphone)

- Étape 3 : Récapitulatif + validation finale

- Contrôles de validité en direct

- Messages d’erreurs automatiquement générés

- Progression visuelle avec barre d’avancement

### Navigation générale

- Header responsive avec burger menu

- Navigation desktop et mobile

- Footer complet avec liens légaux et sociaux

### Accessibilité

- Attributs aria-label, aria-hidden, aria-live pour améliorer la navigation clavier

- Sidebar facilement utilisable via tabulation

### Mobile friendly

- Sidebar adaptative

- Formulaire optimisé mobile

- Cartes et boutons redimensionnés

### Section Téléchargements

- Redirection vers fichiers ou installateurs BBH

- Présentation claire des outils

### Divers

- Pages informatives :

- Contact

- À propos

- Certification

- Mentions légales

- Politique de confidentialité

# Structure du projet
/public
    /assets
        /css
            styletailwind.css
            register.css
            style.css
    /js
        script.js
        gestiopass-pro.js
    /images
    /vidéo
index.html
register.html
contact.html
Téléchargement.html
certification.html
settings.html
mentions_legales.html
politique_de_confidentialité.html
mot_espace.html
mot_de_passe.html
ETC...
README.md

# AUTEUR 

Projet réalisé par Julien R. (alias Koraya964)
Étudiant à l'AFEC
Formation développement web – 2025.

