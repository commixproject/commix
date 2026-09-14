<p align="center">
  <img alt="CommixProject" src="https://commixproject.com/images/logo-header.png" height="120" />
</p>

<div align="center">

[`English`](../../README.md) • [`Ελληνικά`](README-gr-GR.md) • [`Español`](README-es-ES.md) • `Français` • [`فارسی`](README-fa-FA.md) • [`Bahasa Indonesia`](README-idn-IDN.md) • [`Türkçe`](README-tr-TR.md)

</div>

<p align="center">
  <a href="https://github.com/commixproject/commix/actions/workflows/builds.yml"><img alt="Builds Tests" src="https://github.com/commixproject/commix/actions/workflows/builds.yml/badge.svg"></a>
  <a href="https://www.python.org/downloads/"><img alt="Python 3.7+" src="https://img.shields.io/badge/python-3.7+-yellow.svg"></a>
  <a href="https://github.com/commixproject/commix/blob/master/LICENSE.txt"><img alt="GPLv3 License" src="https://img.shields.io/badge/license-GPLv3-red.svg"></a>
  <a href="https://x.com/commixproject"><img alt="X" src="https://img.shields.io/badge/x-@commixproject-blue.svg"></a>
</p>

**Commix** (abréviation de [**comm**]and [**i**]njection e[**x**]ploiter) est un outil open source de test d'intrusion, écrit par [**Anastasios Stasinopoulos**](https://github.com/stasinopoulos) ([**@ancst**](https://x.com/ancst)), qui automatise la détection et l'exploitation des vulnérabilités de type [**command**](https://owasp.org/www-community/attacks/Command_Injection) (et [**code**](https://owasp.org/www-community/attacks/Code_Injection)) injection.

![Screenshot](https://commixproject.com/images/background.png)

Vous pouvez consulter la [**collection de captures d'écran**](https://github.com/commixproject/commix/wiki/Screenshots) présentant certaines fonctionnalités sur le wiki.

> [!IMPORTANT]
> **Ce projet est en développement actif.** Attendez-vous à des changements incompatibles d'une
> révision à l'autre. Consultez le
> [journal des modifications](https://github.com/commixproject/commix/blob/master/doc/CHANGELOG.md)
> avant toute mise à jour.
>
> Commix est conçu avant tout comme un outil autonome en ligne de commande, et il exécute des
> commandes système sur les cibles qu'il teste. **Exécuter commix en tant que service peut présenter
> des risques de sécurité.** Il est recommandé de l'utiliser avec prudence, et uniquement contre des
> systèmes qui vous appartiennent ou pour lesquels vous disposez d'une autorisation explicite.

## Fonctionnalités

* **Quatre techniques d'injection** - classic (basée sur les résultats), time-based (à l'aveugle), file-based (semi-aveugle, avec une variante tempfile-based pour les cibles à écriture restreinte) et out-of-band (OAST) via HTTP/S et DNS.
* **Injection de code** - `--eval` teste la chaîne que la cible évalue comme du code, en PHP ou Python, avec les quatre mêmes techniques.
* **Large surface d'injection** - paramètres GET/POST, en-têtes HTTP, cookies et corps de requête JSON/XML, ainsi que le module `shellshock` pour les cibles CGI.
* **Shells interactifs** - un `os_shell` sur la cible, les modes intégrés `reverse_tcp` et `bind_tcp`, et le transfert de fichiers (`download`/`upload`) via le shell établi.
* **Énumération et accès aux fichiers** - utilisateur courant, nom d'hôte, privilèges, informations système, utilisateurs et empreintes de mots de passe ; lecture et écriture de fichiers sur la cible.
* **Contournement des filtres et des WAF** - Plusieurs scripts de falsification (tamper) combinables, appliqués dans un ordre déterministe.
* **Ciblage flexible** - une URL unique, une exploration du site, des formulaires HTML, un sitemap, un journal de proxy, un fichier de cibles multiples, un fichier de requête HTTP brute ou une entrée `stdin`.
* **Analyses reprenables** - les résultats sont stockés par cible dans un fichier de session et peuvent être exportés en JSON.
* **Large prise en charge des back-ends** - PHP, Python, Perl, Ruby, ASP.NET, JSP et CGI.

## Installation

Vous pouvez télécharger commix sur n'importe quelle plateforme en clonant le dépôt Git officiel :

```
$ git clone https://github.com/commixproject/commix.git commix
```

Vous pouvez également télécharger la dernière [**archive tarball**](https://github.com/commixproject/commix/tarball/master) ou [**archive zipball**](https://github.com/commixproject/commix/zipball/master).

> [!NOTE]
> [**Python**](https://www.python.org/downloads/) (version **3.7** ou ultérieure) est requis pour
> exécuter commix. Toutes les autres dépendances sont fournies avec le programme, aucune étape
> d'installation supplémentaire n'est donc nécessaire.

## Utilisation

Pour obtenir la liste de toutes les options et de tous les paramètres disponibles :

```
$ python3 commix.py -h
```

Tester un seul paramètre injectable, puis ouvrir un shell sur la cible :

```
$ python3 commix.py --url="http://www.target.com/vuln.php?addr=127.0.0.1" --os-shell
```

Prouver l'exécution hors bande, lorsque la réponse ne renvoie rien :

```
$ python3 commix.py --url="http://www.target.com/vuln.php" --data="addr=127.0.0.1" --oob
```

> [!NOTE]
> La détection hors bande (OAST) avec `--oob` utilise par défaut le serveur interactsh public
> `oast.fun` : les métadonnées des interactions avec votre cible sortent donc de votre réseau.
> Pointez `--oob-server` vers une instance auto-hébergée pour les garder en interne. Pour un guide
> détaillé, consultez la page
> [**`techniques`**](https://github.com/commixproject/commix/wiki/Techniques) du wiki.

Analyser une liste de cibles sans surveillance et enregistrer les résultats dans un fichier :

```
$ python3 commix.py -m targets.txt --batch --report-json=results.json
```

Pour obtenir un aperçu des options, paramètres et concepts de base de commix, consultez les pages du wiki [**Utilisation**](https://github.com/commixproject/commix/wiki/Usage), [**Exemples d'utilisation**](https://github.com/commixproject/commix/wiki/Usage-examples) et [**Contournement des filtres**](https://github.com/commixproject/commix/wiki/Filters-bypass-examples).

## Liens

- Manuel utilisateur : [https://github.com/commixproject/commix/wiki](https://github.com/commixproject/commix/wiki)
- Suivi des problèmes : [https://github.com/commixproject/commix/issues](https://github.com/commixproject/commix/issues)
