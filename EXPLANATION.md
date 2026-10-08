# Comment ça marche

Un serveur PXE doit fournir de quoi démarrer à une machine qui n'a pas encore d'OS. On reproduit les échanges réseau de ce démarrage depuis Linux. Pas besoin de lancer WinPE pour demander les fichiers que le serveur accepte déjà de transmettre.

```text
DHCP / ProxyDHCP → chargeur EFI → WDS → BCD → WIM et .boot.var
                                                        ↓
                                  ConfigMgr → stratégies → secrets
```

## 1. Se présenter comme un client PXE

On envoie un DHCPDISCOVER de `0.0.0.0:68` vers `255.255.255.255:67`. Le champ BOOTP `flags=0x8000` demande une réponse broadcast : à ce stade, un client de démarrage n'a pas encore son adresse. Ce flag ne donne aucun droit, il indique comment répondre. Voir la [RFC 2131, §4.1](https://www.rfc-editor.org/rfc/rfc2131#section-4.1).

Ce qui distingue notre requête d'un DHCP classique, ce sont surtout les options PXE :

| Champ / option | Ce qu'on envoie et pourquoi |
| --- | --- |
| `chaddr` et 61 | MAC de la machine ; on privilégie la MAC matérielle quand elle est disponible, même si Linux utilise une MAC aléatoire. |
| 60 | `PXEClient:Arch:00007:UNDI:003016` pour le profil UEFI x64 par défaut : le serveur sait qu'on demande un démarrage réseau. |
| 93 | Architecture du client, `7` pour notre profil UEFI x64. Le serveur peut choisir le chargeur adapté. |
| 94 | Interface UNDI, version `3.16` par défaut. |
| 97 | UUID SMBIOS, avec son ordre d'octets, pour conserver l'identité annoncée par le firmware. |
| 55 | Paramètres demandés, notamment les options PXE et les informations de démarrage. |

Les options 93, 94 et 97 sont décrites dans la [RFC 4578](https://www.rfc-editor.org/rfc/rfc4578). Sa table d'origine diffère de la [spécification UEFI](https://uefi.org/sites/default/files/resources/UEFI_Spec_2_1_D.pdf), qui donne `7` pour x64 EFI. Le code garde aussi un profil alternatif à `9`.

Le serveur DHCP peut donner l'IP et un autre serveur, le ProxyDHCP, les informations PXE. On garde les deux réponses, puis on confirme le bail par DHCPREQUEST avec les options 50 et 54. Le premier fichier vient de l'option 67 ou du champ BOOTP `file` ; le serveur de démarrage est résolu depuis les informations reçues.

On ne reconfigure pas l'interface Linux. Le bail demandé peut donc différer de l'IP réellement utilisée ensuite. Ce n'est pas une capture passive : les serveurs voient les requêtes et peuvent les journaliser.

## 2. Continuer le dialogue WDS

Avec WDS/ConfigMgr, récupérer `wdsmgfw.efi` ne suffit pas. Ce chargeur demande ensuite sa configuration au serveur sur UDP 4011. On reproduit cette requête, sans exécuter le binaire EFI.

Elle est différente du Discover : DHCPREQUEST unicast, `flags=0`, `ciaddr` renseigné, option 60 réduite à `PXEClient`. L'option privée 250 contient les sous-options WDS : architecture, version du chargeur, état du dialogue. Le constructeur reprend aussi les constantes du profil WDS implémenté (`xid=0x40e20100` sur le réseau, `secs=0xffff`) ; ce ne sont pas des exigences du DHCP standard.

Le serveur peut demander d'attendre pendant qu'il prépare le déploiement. On respecte son délai, dans une attente bornée. Les réponses utiles sont :

- option 252 : chemin du BCD généré ;
- option 243 : chemin du `.boot.var` et informations de clé ConfigMgr, selon la protection du média.

Ces options sont propres à cette chaîne WDS/ConfigMgr. Un autre serveur PXE peut fonctionner autrement. Si le chargeur annoncé est iPXE, un second échange avec la classe utilisateur `iPXE` peut fournir son script de démarrage.

## 3. Lire les fichiers annoncés

On télécharge par TFTP, ou HTTP si une URL est fournie. TFTP démarre sur UDP 69 puis utilise le port choisi par le serveur. Le BCD est une ruche de registre : on en lit les références vers le WIM et `boot.sdi`, au lieu de deviner leurs noms.

Pour le WIM, on liste les chemins avec `wimlib-imagex`, puis on lit uniquement les fichiers ciblés : Bootstrap.ini, CustomSettings.ini, Unattend.xml et configurations des dossiers de déploiement. Pas de `grep` sur l'image, pas de recherche de chaînes dans les binaires, pas de montage. Les autres conteneurs pris en charge passent par `7z` ; on ne descend pas récursivement dans les archives imbriquées.

Les configurations connues passent en premier. Limites par passe : 256 fichiers, 64 Mio, 120 secondes et 8 index par WIM. Un fichier est limité à 16 Mio. L'ancien `--full-audit` est distinct et reste désactivé par défaut.

On analyse les champs XML et les sections INI. `RequirePassword=true` n'est pas un mot de passe ; le nom d'une stratégie n'est pas un compte. Les scripts sont repérés mais non interprétés. Une valeur chiffrée, un fichier illisible ou une limite atteinte reste signalé comme non vérifié. L'absence de configuration connue n'est annoncée qu'après un inventaire réussi.

## 4. Ouvrir les variables ConfigMgr

Le `.boot.var` est chiffré. Pour le format sans mot de passe pris en charge, les données reçues dans l'option 243 permettent de retrouver la clé de session. On vérifie l'enveloppe, les longueurs et le padding, puis on déchiffre l'AES et on lit le XML. On ne force pas les médias protégés par mot de passe.

Ces variables peuvent donner le Management Point et `_SMSTSMediaPFX`. Ce dernier est un PKCS#12 : certificat du média et, selon son contenu, clé privée. Dans le format géré, `_SMSMediaGuid` intervient dans son ouverture.

Le point important : du chiffrement ne suffit pas si le même client récupère aussi de quoi déchiffrer. Une clé privée de média accessible est du matériel d'authentification exposé, pas automatiquement un compte administrateur du domaine. Microsoft décrit ces certificats et leur usage dans les [contrôles cryptographiques ConfigMgr](https://learn.microsoft.com/en-us/intune/configmgr/core/plan-design/security/cryptographic-controls-technical-reference).

## 5. Demander et décoder les stratégies

On utilise le certificat du média pour signer les requêtes au Management Point. Le code demande les affectations pour l'identité Unknown Computer annoncée par celui-ci : ce n'est pas un inventaire de toutes les stratégies du site.

Les réponses passent par les couches nécessaires : enveloppe CMS, XML, décompression zlib, puis désobfuscation 3DES des champs secrets reconnus. Un bloc hexadécimal quelconque ne déclenche pas un déchiffrement au hasard. Le padding et le texte obtenu sont contrôlés.

Dans NAAConfig, on cherche notamment `NetworkAccessUsername` et `NetworkAccessPassword`. TaskSequence et CollectionSettings peuvent aussi porter des secrets de déploiement. Le compte est associé au mot de passe dans le même objet XML ou la même section INI ; les connexions avec ces comptes ne sont jamais testées.

Un échec CMS reste un échec d'analyse, pas la preuve que WinPE ne peut pas démarrer. Il faut la réponse chiffrée originale et le PFX correspondant pour l'examiner. Les nouvelles captures conservent ces réponses dans `configmgr-diagnostics/` ; une empreinte SHA-256 seule ne suffit pas.

## 6. Lire le résultat

L'écran montre chaque compte/secret une seule fois, une source et les alertes regroupées. Toutes les occurrences restent dans `audit-details.json` ; `configmgr-report.txt` garde les détails ConfigMgr. Les fichiers de rapport sont en `0600`, mais contiennent des secrets en clair : ils ne doivent pas partir sur GitHub.

`--offline` relit une capture locale sans contacter le serveur. `--demo` génère des données fictives, teste les décodeurs et une petite image, puis supprime son dossier temporaire. Ce n'est ni un site ConfigMgr complet ni un effacement sécurisé.

Si un secret est récupéré, il faut vérifier son usage et le changer s'il est encore valide. Pour un média compromis, ConfigMgr permet de bloquer son certificat. Revoir aussi l'accès au déploiement et les droits des comptes exposés : [sécurité du déploiement OS, Microsoft](https://learn.microsoft.com/en-us/intune/configmgr/osd/plan-design/security-and-privacy-for-operating-system-deployment).
