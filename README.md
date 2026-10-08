# pxetrace

Audit PXE depuis Linux, sans redémarrer : récupérer les fichiers de démarrage et les stratégies ConfigMgr accessibles, puis montrer les secrets exposés avec leur source. À utiliser sur un réseau que vous êtes autorisé à auditer.

## Installation

Linux, Python 3.11+. Sur Debian/Ubuntu :

```bash
sudo apt install pipx git openssl wimtools p7zip-full
pipx ensurepath
pipx install 'git+https://github.com/VOTRE_COMPTE/pxetrace.git'
```

Remplacez l'URL par celle du dépôt. Si pipx vient d'être installé, ouvrez un nouveau terminal. Depuis un clone local : `pipx install .`.

## Utilisation

```bash
# Audit sur l'interface réseau
sudo "$(command -v pxetrace)" enp0s31f6

# Démo hors ligne, avec des données fictives et sans root
pxetrace --demo

# Réanalyser une capture sans contacter le serveur
pxetrace --offline pxetrace-output/ma-capture
```

L'interface est détectée si elle n'est pas précisée. `-q` réduit les messages pendant la collecte. Les rapports sont dans `pxetrace-output/` : `audit-report.txt` pour la synthèse, `audit-details.json` pour les preuves. Ils contiennent des secrets en clair : ne les publiez pas.

## Exemple de sortie

Extrait, avec des identifiants fictifs :

```text
PXETRACE — AUDIT PXE
Serveur : pxe.example.test

2 secret(s) extrait(s) en clair
+-------------+-------------------+-----------------------+--------+
| Compte      | Secret en clair   | Champ                 | Source |
+-------------+-------------------+-----------------------+--------+
| DEMO\naa    | Demo-NAA-Only!    | NetworkAccessPassword | 1      |
| DEMO\deploy | Demo-Deploy-Only! | UserPassword          | 2      |
+-------------+-------------------+-----------------------+--------+
  [1] ConfigMgr #1 NAAConfig
  [2] boot.wim / image 1 / Deploy/Bootstrap.ini

Alertes de sécurité
  CRITIQUE  média PXE sans mot de passe
  CRITIQUE  secret dans un fichier de déploiement
```

La recherche cible les configurations de déploiement, pas toutes les chaînes du WIM. Les comptes trouvés ne sont pas testés. Aucun secret extrait ne veut pas dire serveur sécurisé.

Pour en savoir plus sur les échanges DHCP, le démarrage UEFI et ConfigMgr : [EXPLANATION.md](EXPLANATION.md).

Pour savoir quoi vérifier et comment protéger le déploiement : [guide d'audit et bonnes pratiques](AUDIT.md).

Les PR et retours de terrain sont les bienvenus. Merci de ne pas joindre de captures contenant des secrets. Licence [MIT](LICENSE).
