# Quoi vérifier sur une chaîne PXE

Le but est de répondre à une question : **qu'est-ce qu'un poste branché sur ce réseau peut récupérer avant même d'avoir un OS ?**

On part des fichiers annoncés par DHCP, WDS, le BCD et ConfigMgr. On suit leurs références, dans le périmètre autorisé. Pas de recherche à l'aveugle dans tout le WIM ni de téléchargement de tous les partages du réseau.

## Les éléments intéressants

| Élément | Ce qu'il faut regarder | Ce que ça peut révéler |
| --- | --- | --- |
| DHCP / ProxyDHCP / WDS | Serveur et chargeur annoncés, option 252 pour le BCD, option 243 pour les variables ConfigMgr. | Les points d'entrée et les chemins réels. Ce ne sont pas des mots de passe à eux seuls. |
| BCD et scripts iPXE | Références vers les images, scripts, URL et paramètres. | Les étapes suivantes ; parfois des identifiants intégrés à une URL ou une commande. |
| WIM, ISO, CAB et autres images annoncées | Configurations de déploiement, scripts appelés au démarrage et fichiers de réponse. | Des secrets embarqués dans l'image ou une référence vers leur emplacement. |
| `Bootstrap.ini` — MDT | `DeployRoot`, `UserDomain`, `UserID`, `UserPassword`. | Le compte d'accès au partage de déploiement, s'il est enregistré dans le fichier. |
| `CustomSettings.ini` — MDT | `DomainAdmin`, `DomainAdminDomain`, `DomainAdminPassword`, `AdminPassword`, `DBID`, `DBPwd`. | Compte de jonction au domaine, mot de passe administrateur local ou accès à une base. |
| `Unattend.xml`, `Autounattend.xml`, `sysprep.inf` | AutoLogon, comptes locaux, jonction au domaine, commandes personnalisées. | Des identifiants de déploiement. Le format dépend de la version et du fichier. |
| `.boot.var` / `variables.dat` | Variables du média, Management Points et références aux stratégies. | Des variables sensibles et éventuellement le PFX du média, une fois le format correctement décodé. |
| `_SMSTSMediaPFX` | Présence d'une clé privée, certificat associé, validité et usage. | Une identité de média ConfigMgr. Ce n'est pas un mot de passe NAA, ni automatiquement un accès administrateur au domaine. |
| Stratégie `NAAConfig` | `NetworkAccessUsername`, `NetworkAccessPassword`, après décodage. | Les identifiants NAA distribués à cette identité, s'ils sont présents. |
| `TaskSequence` / `CollectionSettings` | Variables, comptes d'exécution, jonction au domaine et commandes de déploiement. | D'autres secrets que le NAA : comptes techniques, mots de passe ou jetons. |
| Scripts et journaux de déploiement accessibles | Scripts réellement référencés, paramètres de commandes, copies de configuration, traces personnalisées. | Des secrets oubliés ou écrits dans les logs. À examiner dans leur contexte, pas comme une liste de chaînes. |

Les propriétés MDT sont décrites dans la [référence Microsoft](https://learn.microsoft.com/en-us/intune/configmgr/mdt/properties). Les chemins varient : `Deploy`, `Control`, `Scripts`, `Panther` et les répertoires indiqués par le déploiement sont des pistes, pas une liste de fichiers obligatoires.

`win.ini`, un chargeur EFI ou `boot.sdi` ne sont pas des cibles prioritaires pour les mots de passe. Leur présence seule ne justifie aucune alerte.

## Ne pas confondre indice et preuve

- Un compte et un mot de passe doivent venir du même objet XML ou de la même section INI. Ne pas associer deux lignes trouvées au hasard.
- `RequirePassword=true`, un nom de variable ou `%RuntimePassword%` ne sont pas des secrets récupérés.
- Un bloc chiffré ou une sortie binaire illisible reste **non décodé**. On ne le présente pas comme un mot de passe.
- Dans un fichier de réponse Windows, `PlainText=false` signifie que la valeur est masquée, pas nécessairement protégée par un chiffrement sûr. Il faut identifier le format avant de conclure. Voir [Hide Sensitive Data in an Answer File](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/wsim/hide-sensitive-data-in-an-answer-file).
- Un PFX contenant une clé privée est une preuve distincte d'un certificat public. Son impact dépend de ce que le serveur accepte avec cette identité.
- Un secret peut être ancien ou révoqué. Son extraction prouve son exposition, pas sa validité actuelle. Ne pas essayer les comptes hors du périmètre prévu.

Pour une preuve exploitable, garder le serveur, la date, le chemin, l'index de l'image si nécessaire, le champ et l'empreinte du contenu analysé. Une ligne compte / secret / source suffit à l'écran ; les occurrences répétées restent dans le rapport détaillé.

Ce guide couvre aussi les vérifications manuelles. pxetrace n'interprète pas les scripts et ne décode pas tous les formats. « Aucun secret extrait » n'est donc pas un résultat exhaustif. Un fichier absent, un fichier illisible et une stratégie non déchiffrée sont trois résultats différents.

## Best practices

### 1. Limiter qui peut atteindre le déploiement

- Placer les services de déploiement dans un VLAN dédié et réserver l'accès aux postes ou VLAN de préparation autorisés.
- Ajouter des ACL / règles de pare-feu entre les VLAN. Déplacer uniquement le serveur ne sert pas si tout le réseau peut encore le joindre.
- Restreindre les relais DHCP / IP helpers aux segments qui doivent démarrer en PXE. Cela ne remplace pas le filtrage des accès directs TFTP, WDS, HTTP(S) et SMB.
- N'ouvrir que les flux nécessaires au fonctionnement retenu. Pour TFTP, tenir compte des ports de transfert négociés, pas seulement d'UDP 69.
- Contrôler les prises et les équipements autorisés sur le réseau de préparation. Selon l'infrastructure, utiliser NAC / 802.1X et DHCP snooping ; vérifier leur compatibilité avec le démarrage réseau.

### 2. Protéger le démarrage et les archives

- Exiger le mot de passe PXE prévu par ConfigMgr. Limiter les interfaces d'écoute et les déploiements proposés aux machines inconnues.
- Protéger les médias de démarrage et les exports PFX par un mot de passe fort. Cela ne chiffre pas tous les fichiers de la chaîne et ne remplace pas les restrictions réseau. Microsoft détaille ces protections dans ses [recommandations OSD](https://learn.microsoft.com/en-us/intune/configmgr/osd/plan-design/security-and-privacy-for-operating-system-deployment).
- Pour les **archives de sauvegarde, d'export et les rapports d'audit**, utiliser un chiffrement robuste, par exemple une [archive 7z chiffrée en AES-256](https://www.7-zip.org/7z.html). Garder le mot de passe dans un coffre, transmis séparément ; pas dans le même dossier ou un script de déploiement.
- Ne pas confondre archive chiffrée et WIM de démarrage : compresser le WIM ne protège pas ses secrets. Une archive que le poste ouvre automatiquement avec une clé fournie dans la même chaîne ne résout pas l'exposition.
- Conserver Secure Boot pour vérifier les composants de démarrage pris en charge. Il ne rend pas confidentiels les fichiers téléchargés.

### 3. Retirer les secrets des images

- Éviter les comptes partagés intégrés dans Bootstrap.ini, les fichiers de réponse et les scripts. Pour MDT, la [procédure Microsoft](https://learn.microsoft.com/en-us/windows/deployment/deploy-windows-mdt/deploy-a-windows-10-image-using-mdt) prévoit notamment de retirer `UserID` et `UserPassword` de Bootstrap.ini pour demander les identifiants à l'opérateur.
- Ne pas considérer « masquer cette variable » comme une protection suffisante si le client doit pouvoir la relire.
- Préférer des secrets temporaires et limités à la tâche lorsque le workflow le permet. Ne pas remplacer un mot de passe en dur par un jeton permanent tout aussi exposé.
- Après nettoyage, régénérer et redistribuer les images et médias concernés. Retirer les anciennes versions accessibles : corriger le fichier source ne modifie pas les copies déjà distribuées.
- Vérifier les images avant publication et après chaque modification importante, y compris les scripts et logs ajoutés par l'équipe de déploiement.

### 4. Réduire les droits des comptes

- Vérifier si le NAA est encore nécessaire. HTTPS / Enhanced HTTP permettent de s'en passer dans plusieurs scénarios, mais pas tous. S'il reste nécessaire, limiter ses droits à la lecture du contenu requis, sans droits administrateur ni connexion interactive. Voir les [comptes ConfigMgr](https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/accounts#network-access-account).
- Séparer les comptes d'accès au contenu, de jonction au domaine et d'exécution des tâches. Déléguer la jonction sur les seules OU concernées ; ne pas utiliser un Domain Admin.
- Éviter un mot de passe administrateur local identique sur tous les postes. Prévoir une gestion par machine et une rotation après le déploiement.
- Lors d'une rotation NAA, organiser le remplacement et le retrait de l'ancien compte pour éviter les blocages de clients. En cas de compromission, traiter aussi l'urgence de couper son accès, pas seulement la mise à jour de ConfigMgr.

### 5. Protéger l'infrastructure

- Utiliser HTTPS avec validation du certificat là où le rôle le permet. Vérifier les flux restants : [Enhanced HTTP ne sécurise pas toutes les communications](https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/hierarchy/enhanced-http#unsupported-scenarios), et ne transforme pas TFTP en protocole chiffré.
- Restreindre les droits SMB, NTFS et ConfigMgr : un client de déploiement ne doit pas pouvoir modifier les images ou les scripts qu'utiliseront les autres postes. Séparer l'administration du trafic de démarrage.
- Maintenir les serveurs, ConfigMgr et les images de démarrage à jour. Pour WDS, vérifier aussi le [durcissement du déploiement sans intervention publié par Microsoft](https://support.microsoft.com/en-us/servicing/os/windows/2025/12/windows-deployment-services-wds-hands-free-deployment-hardening-guidance-related-to-cve-2026-0386), selon le workflow utilisé.
- Journaliser les demandes PXE/WDS, les accès aux fichiers et les téléchargements de stratégies. Rechercher les clients inhabituels et les collectes répétées, sans recopier les secrets dans les alertes.

### 6. Si quelque chose a déjà été exposé

- Identifier les comptes, certificats, images et anciennes copies concernés. Conserver les preuves dans un emplacement à accès restreint.
- Révoquer ou remplacer les secrets encore utilisables. Pour le certificat du média, le bloquer dans ConfigMgr ; s'il vient d'une PKI, le révoquer aussi. Supprimer seulement le PFX du partage ne neutralise pas une copie déjà récupérée. Voir les [consignes Microsoft sur les certificats compromis](https://learn.microsoft.com/en-us/intune/configmgr/osd/plan-design/security-and-privacy-for-operating-system-deployment#block-or-revoke-any-compromised-certificates).
- Refaire le contrôle depuis un réseau utilisateur non autorisé **et** depuis le réseau de déploiement. Vérifier que l'exposition est fermée et que le déploiement normal fonctionne toujours.
- Garder les rapports hors de Git, des tickets publics et des captures d'écran diffusées. Définir leur durée de conservation avec le client.
