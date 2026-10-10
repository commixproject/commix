<p align="center">
  <img alt="CommixProject" src="https://commixproject.com/images/logo-header.png" height="120" />
</p>

<div align="center">

[`English`](../../README.md) • [`Ελληνικά`](README-gr-GR.md) • [`Español`](README-es-ES.md) • `Français` • [`فارسی`](README-fa-FA.md) • [`Bahasa Indonesia`](README-idn-IDN.md) • [`Türkçe`](README-tr-TR.md)

</div>

<p align="center">
  <a href="https://github.com/commixproject/commix/actions/workflows/builds.yml"><img alt="Builds Tests" src="https://img.shields.io/github/actions/workflow/status/commixproject/commix/builds.yml?branch=master&label=Builds%20Tests&style=for-the-badge&logo=githubactions&logoColor=white"></a>
  <a href="https://www.python.org/downloads/"><img alt="Python 3.7+" src="https://img.shields.io/badge/Python-3.7%2B-3776AB.svg?style=for-the-badge&logo=python&logoColor=white"></a>
  <a href="https://github.com/commixproject/commix/blob/master/LICENSE.txt"><img alt="GPLv3 License" src="https://img.shields.io/badge/License-GPLv3-6A1B9A.svg?style=for-the-badge&logo=gnu&logoColor=white"></a>
  <a href="https://x.com/commixproject"><img alt="Follow @commixproject" src="https://img.shields.io/badge/Follow-@commixproject-000000.svg?style=for-the-badge&logo=x&logoColor=white"></a>
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

* **Quatre techniques d'injection** - results-based, boolean-based, time-based et file-based, choisies avec `--technique` ou selon le type sous lequel elles sont rapportées avec `--type` - voir [techniques](https://github.com/commixproject/commix/wiki/Techniques) pour ce que chacune exige d'une cible.
* **Out-of-band, quand rien ne revient** - `--oob` prouve l'exécution et rapporte la sortie de la commande via HTTP/S ou DNS, en atteignant le serveur par le client dont la cible dispose - voir [out-of-band client](https://github.com/commixproject/commix/wiki/Usage#out-of-band-client) pour ceux qu'il essaie et comment en fixer un.
* **Injection de code** - [`--eval`](https://github.com/commixproject/commix/wiki/Usage#test-for-code-injection) teste ce que la cible évalue comme du code, en PHP, Python, Ruby, JavaScript ou PowerShell, avec ces mêmes techniques.
* **Partout où l'entrée aboutit** - paramètres GET/POST, [en-têtes HTTP et cookies](https://github.com/commixproject/commix/wiki/Usage#request-options), corps JSON/XML/GraphQL, ainsi que le module `shellshock` pour les cibles CGI.
* **De la preuve au shell** - [`--os-shell`](https://github.com/commixproject/commix/wiki/Getting-shells), les modes intégrés `reverse_tcp` et `bind_tcp` promouvables en PTY complet, le transfert de fichiers, la lecture et l'écriture du registre Windows, et l'énumération jusqu'aux empreintes de mots de passe, avec une attaque par dictionnaire proposée contre elles.
* **Contournement des filtres et des WAF** - scripts de falsification (tamper) combinables, appliqués dans un ordre déterministe - voir [filters bypass examples](https://github.com/commixproject/commix/wiki/Filters-bypass-examples).
* **Des cibles sous toutes les formes** - une URL, une exploration du site, des formulaires HTML, un sitemap, une description OpenAPI (Swagger), un journal de proxy, un fichier de cibles multiples, une requête HTTP brute ou une entrée `stdin` - voir [target options](https://github.com/commixproject/commix/wiki/Usage#target-options).
* **Reprenable et scriptable** - [fichiers de session par cible](https://github.com/commixproject/commix/wiki/Usage#resume-from-stored-session-data), sortie JSON/CSV/HAR, profils d'options réutilisables et `--proof`, qui prouve à nouveau chaque découverte par une expérience qui lui est propre.
* **Type Unix et Windows** - back-ends PHP, Python, Perl, Ruby, ASP.NET, JSP et CGI - voir
[Windows and Unix-like targets at a glance](https://github.com/commixproject/commix/wiki/Techniques#windows-and-unix-like-targets-at-a-glance)
pour la façon dont les charges utiles diffèrent.

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
$ python3 commix.py --url="http://commix-testbed/scenarios/regular/GET/classic.php?addr=127.0.0.1" --os-shell
```

Prouver l'exécution hors bande, lorsque la réponse ne renvoie rien :

```
$ python3 commix.py --url="http://commix-testbed/scenarios/regular/POST/blind.php" --data="addr=127.0.0.1" --oob
```

> [!NOTE]
> Le client est choisi selon ce dont la cible dispose : une machine dépourvue des clients HTTP
> habituels reste donc à portée - fixez-en un avec `--oob-transport` lorsque sa sortie réseau est
> déjà connue. La détection hors bande (OAST) avec `--oob` utilise par défaut le serveur interactsh
> public `oast.fun` : les métadonnées des interactions avec votre cible sortent donc de votre réseau.
> Pointez `--oob-server` vers une instance auto-hébergée pour les garder en interne. Pour un guide
> détaillé, consultez la page
> [**`out-of-band-oob-channel`**](https://github.com/commixproject/commix/wiki/Techniques#out-of-band-oob-channel) du wiki.

Analyser une liste de cibles sans surveillance et enregistrer les résultats dans un fichier :

```
$ python3 commix.py -m targets.txt --batch --report-json=results.json
```

Pour obtenir un aperçu des options, paramètres et concepts de base de commix, consultez les pages du wiki [**Utilisation**](https://github.com/commixproject/commix/wiki/Usage), [**Exemples d'utilisation**](https://github.com/commixproject/commix/wiki/Usage-examples) et [**Contournement des filtres**](https://github.com/commixproject/commix/wiki/Filters-bypass-examples).

## Liens

- Manuel utilisateur : [https://github.com/commixproject/commix/wiki](https://github.com/commixproject/commix/wiki)
- Suivi des problèmes : [https://github.com/commixproject/commix/issues](https://github.com/commixproject/commix/issues)
