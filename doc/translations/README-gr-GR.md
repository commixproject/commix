<p align="center">
  <img alt="CommixProject" src="https://commixproject.com/images/logo-header.png" height="120" />
</p>

<div align="center">

[`English`](../../README.md) • `Ελληνικά` • [`Español`](README-es-ES.md) • [`Français`](README-fr-FR.md) • [`فارسی`](README-fa-FA.md) • [`Bahasa Indonesia`](README-idn-IDN.md) • [`Türkçe`](README-tr-TR.md)

</div>

<p align="center">
  <a href="https://github.com/commixproject/commix/actions/workflows/builds.yml"><img alt="Builds Tests" src="https://img.shields.io/github/actions/workflow/status/commixproject/commix/builds.yml?branch=master&label=Builds%20Tests&style=for-the-badge&logo=githubactions&logoColor=white"></a>
  <a href="https://www.python.org/downloads/"><img alt="Python 3.7+" src="https://img.shields.io/badge/Python-3.7%2B-3776AB.svg?style=for-the-badge&logo=python&logoColor=white"></a>
  <a href="https://github.com/commixproject/commix/blob/master/LICENSE.txt"><img alt="GPLv3 License" src="https://img.shields.io/badge/License-GPLv3-6A1B9A.svg?style=for-the-badge&logo=gnu&logoColor=white"></a>
  <a href="https://x.com/commixproject"><img alt="Follow @commixproject" src="https://img.shields.io/badge/Follow-@commixproject-000000.svg?style=for-the-badge&logo=x&logoColor=white"></a>
</p>
To **commix** (συντομογραφία [**comm**]and [**i**]njection e[**x**]ploiter) είναι πρόγραμμα ανοιχτού κώδικα, γραμμένο από τον **[Anastasios Stasinopoulos](https://github.com/stasinopoulos)** (**[@ancst](https://x.com/ancst)**), που αυτοματοποιεί την εύρεση και εκμετάλλευση ευπαθειών τύπου **[command](https://owasp.org/www-community/attacks/Command_Injection)** (και **[code](https://owasp.org/www-community/attacks/Code_Injection)**) injection.

![Screenshot](https://commixproject.com/images/background.png)

Μπορείτε να επισκεφθείτε τη [συλλογή στιγμιότυπων](https://github.com/commixproject/commix/wiki/Screenshots) που παρουσιάζει μερικά από τα χαρακτηριστικά του, στο wiki.

> [!IMPORTANT]
> **Το έργο βρίσκεται υπό ενεργή ανάπτυξη.** Αναμένετε αλλαγές που ενδέχεται να σπάσουν τη
> συμβατότητα μεταξύ των εκδόσεων. Συμβουλευτείτε το
> [ιστορικό αλλαγών](https://github.com/commixproject/commix/blob/master/doc/CHANGELOG.md) πριν
> από κάθε ενημέρωση.
>
> Το commix έχει σχεδιαστεί κυρίως για χρήση ως αυτόνομο εργαλείο γραμμής εντολών και εκτελεί
> εντολές λειτουργικού συστήματος στα συστήματα που ελέγχει. **Η εκτέλεση του commix ως υπηρεσία
> ενδέχεται να ενέχει κινδύνους ασφαλείας.** Συνιστάται η χρήση του με προσοχή, και μόνο σε
> συστήματα που σας ανήκουν ή για τα οποία έχετε ρητή εξουσιοδότηση ελέγχου.

## Χαρακτηριστικά

* **Τέσσερις τεχνικές injection** – results-based, boolean-based, time-based και file-based, που επιλέγονται με `--technique` ή βάσει του τύπου που αναφέρουν με `--type` – δείτε τις [techniques](https://github.com/commixproject/commix/wiki/Techniques) για το τι απαιτεί η καθεμία από ένα target.
* **Out-of-band, όταν δεν επιστρέφει τίποτα** – το `--oob` αποδεικνύει την εκτέλεση και μεταφέρει το output της εντολής μέσω HTTP/S ή DNS, φτάνοντας στον server μέσω όποιου client τυχαίνει να διαθέτει το target – δείτε [out-of-band client](https://github.com/commixproject/commix/wiki/Usage#out-of-band-client) για το ποιους δοκιμάζει και πώς να ορίσετε έναν.
* **Code injection** – το [`--eval`](https://github.com/commixproject/commix/wiki/Usage#test-for-code-injection) ελέγχει ό,τι εκτελείται ως κώδικας από το target, σε PHP, Python, Ruby, JavaScript ή PowerShell, με τις ίδιες τεχνικές.
* **Όπου κι αν καταλήγει το input** – GET/POST parameters, [HTTP headers και cookies](https://github.com/commixproject/commix/wiki/Usage#request-options), JSON/XML/GraphQL bodies, καθώς και το `shellshock` module για CGI targets.
* **Από την απόδειξη στο shell** – [`--os-shell`](https://github.com/commixproject/commix/wiki/Getting-shells), ενσωματωμένα `reverse_tcp` και `bind_tcp` με αναβάθμιση σε πλήρες PTY, μεταφορά αρχείων, read/write στο Windows registry και enumeration μέχρι τα password hashes, με dictionary attack να προσφέρεται εναντίον τους.
* **Filter και WAF evasion** – συνδυάσιμα tamper scripts, που εφαρμόζονται με deterministic σειρά – δείτε [filters bypass examples](https://github.com/commixproject/commix/wiki/Filters-bypass-examples).
* **Targets σε κάθε μορφή** – URL, crawl, HTML forms, sitemap, OpenAPI (Swagger) description, proxy log, bulk file, raw HTTP request ή piped `stdin` – δείτε [target options](https://github.com/commixproject/commix/wiki/Usage#target-options).
* **Resumable και scriptable** – [session files ανά target](https://github.com/commixproject/commix/wiki/Usage#resume-from-stored-session-data), output σε JSON/CSV/HAR, επαναχρησιμοποιήσιμα profiles επιλογών και το `--proof`, που επαληθεύει εκ νέου κάθε εύρημα με δικό του πείραμα.
* **Unix-like και Windows** – PHP, Python, Perl, Ruby, ASP.NET, JSP και CGI back ends – δείτε το [Windows and Unix-like targets at a glance](https://github.com/commixproject/commix/wiki/Techniques#windows-and-unix-like-targets-at-a-glance) για τις διαφορές στα payloads.


## Εγκατάσταση

Μπορείτε να κατεβάσετε το commix σε κάθε πλατφόρμα κάνοντας κλώνο το επίσημο Git αποθετήριο:

    $ git clone https://github.com/commixproject/commix.git commix

Εναλλακτικά, μπορείτε να κατεβάσετε την τελευταία [tarball](https://github.com/commixproject/commix/tarball/master) ή [zipball](https://github.com/commixproject/commix/zipball/master).

> [!NOTE]
> H **[Python](https://www.python.org/downloads/)** (έκδοση **3.7** ή νεότερη) απαιτείται για την
> εκτέλεση του commix. Όλες οι υπόλοιπες εξαρτήσεις συνοδεύουν το πρόγραμμα, οπότε δεν απαιτείται
> κανένα επιπλέον βήμα εγκατάστασης.


## Χρήση

Για να λάβετε μια λίστα με όλες τις επιλογές και τους διακόπτες πατήστε: 

    $ python3 commix.py -h

Έλεγχος μιας ευπαθούς παραμέτρου και άμεση πρόσβαση σε κέλυφος στον στόχο :

    $ python3 commix.py --url="http://commix-testbed/scenarios/regular/GET/classic.php?addr=127.0.0.1" --os-shell

Απόδειξη εκτέλεσης εκτός ζώνης, όταν η απόκριση δεν επιστρέφει τίποτα :

    $ python3 commix.py --url="http://commix-testbed/scenarios/regular/POST/blind.php" --data="addr=127.0.0.1" --oob

> [!NOTE]
> Ο client επιλέγεται βάσει του τι διαθέτει ο στόχος, οπότε ένα μηχάνημα χωρίς τους συνηθισμένους
> HTTP clients παραμένει προσβάσιμο – ορίστε έναν με την `--oob-transport` όταν η εξερχόμενη
> κίνησή του είναι ήδη γνωστή. Η ανίχνευση εκτός ζώνης (OAST) με την επιλογή `--oob` χρησιμοποιεί
> από προεπιλογή τον δημόσιο διακομιστή interactsh `oast.fun`, οπότε μεταδεδομένα των
> αλληλεπιδράσεων με τον στόχο σας φεύγουν από το δίκτυό σας. Ορίστε την `--oob-server` σε μια δική
> σας εγκατάσταση, ώστε να παραμείνουν εσωτερικά. Για αναλυτικό οδηγό, συμβουλευτείτε τη σελίδα
> [**`out-of-band-oob-channel`**](https://github.com/commixproject/commix/wiki/Techniques#out-of-band-oob-channel) στο wiki.

Σάρωση λίστας στόχων χωρίς επίβλεψη και εγγραφή των αποτελεσμάτων σε αρχείο :

    $ python3 commix.py -m targets.txt --batch --report-json=results.json

Για να δείτε μια επισκόπηση των διαθέσιμων επιλογών, των διακοπτών ή / και βασικών ιδεών σχετικά με τον τρόπο χρήσης του commix, συμβουλευτείτε τις **[χρήση](https://github.com/commixproject/commix/wiki/Usage)**, **[παραδείγματα χρήσης](https://github.com/commixproject/commix/wiki/Usage-examples)** και **[παράκαμψη φίλτρων](https://github.com/commixproject/commix/wiki/Filters-bypass-examples)** wiki σελίδες.

## Σύνδεσμοι

* Εγχειρίδιο χρήστη: https://github.com/commixproject/commix/wiki
* Παρακολούθηση προβλημάτων: https://github.com/commixproject/commix/issues
