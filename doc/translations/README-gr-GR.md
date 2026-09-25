<p align="center">
  <img alt="CommixProject" src="https://commixproject.com/images/logo-header.png" height="120" />
</p>

<div align="center">

[`English`](../../README.md) • `Ελληνικά` • [`Español`](README-es-ES.md) • [`Français`](README-fr-FR.md) • [`فارسی`](README-fa-FA.md) • [`Bahasa Indonesia`](README-idn-IDN.md) • [`Türkçe`](README-tr-TR.md)

</div>

<p align="center">
  <a href="https://github.com/commixproject/commix/actions/workflows/builds.yml"><img alt="Builds Tests" src="https://github.com/commixproject/commix/actions/workflows/builds.yml/badge.svg"></a>
  <a href="https://www.python.org/downloads/"><img alt="Python 3.7+" src="https://img.shields.io/badge/python-3.7+-yellow.svg"></a>
  <a href="https://github.com/commixproject/commix/blob/master/LICENSE.txt"><img alt="GPLv3 License" src="https://img.shields.io/badge/license-GPLv3-red.svg"></a>
  <a href="https://x.com/commixproject"><img alt="X" src="https://img.shields.io/badge/x-@commixproject-blue.svg"></a>
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

* **Τέσσερις τεχνικές injection** – results-based (classic), time-based (blind), file-based (blind, με παραλλαγή βασισμένη σε προσωρινό αρχείο για targets με περιορισμούς εγγραφής) και out-of-band (OAST) μέσω HTTP/S και DNS. Επιλέγονται με `--technique` ή βάσει του τύπου που αναφέρουν με `--type`.
* **Code injection** – το `--eval` ελέγχει strings που εκτελούνται ως κώδικας από το target, σε PHP ή Python, χρησιμοποιώντας τις ίδιες τέσσερις τεχνικές.
* **Ευρεία κάλυψη injection επιφανειών** – GET/POST parameters, HTTP headers, cookies και JSON/XML request bodies, καθώς και το `shellshock` module για CGI targets.
* **Interactive shells** – `os_shell` στο target, ενσωματωμένα modes `reverse_tcp` και `bind_tcp`, καθώς και `download`/`upload` αρχείων μέσω του established shell.
* **Απόδειξη εκμετάλλευσης** – το `--proof` επαληθεύει εκ νέου κάθε εύρημα με δικό του πείραμα και αποθηκεύει το transcript δίπλα στο output του run. Το `--parse-errors` εμφανίζει τα error messages του shell όταν ένα payload έφτασε στο shell αλλά δεν έγινε κατανοητό.
* **Enumeration και πρόσβαση σε αρχεία** – current user, hostname, privileges, system information, users και password hashes, καθώς και ανάγνωση και εγγραφή αρχείων στο target host.
* **Filter και WAF evasion** – πολλαπλά συνδυάσιμα tamper scripts, τα οποία εφαρμόζονται με deterministic σειρά.
* **Ευέλικτο targeting** – υποστήριξη για single URL, crawl, HTML forms, sitemap, proxy log, bulk file, raw HTTP request file ή δεδομένα μέσω piped `stdin`.
* **Resumable scans και machine-readable output** – τα αποτελέσματα αποθηκεύονται ανά target σε session file και μπορούν να εξαχθούν σε JSON, CSV που περιλαμβάνει όλα τα tested targets ή HAR log με το HTTP traffic του run. Οι επιλογές ενός run μπορούν επίσης να αποθηκευτούν ως profile και να επαναχρησιμοποιηθούν.
* **Ευρεία υποστήριξη back-ends** – PHP, Python, Perl, Ruby, ASP.NET, JSP και CGI, με υποστήριξη τόσο για Unix-like όσο και για Windows targets. Δείτε το [Windows and Unix-like targets at a glance](https://github.com/commixproject/commix/wiki/Techniques#windows-and-unix-like-targets-at-a-glance) για τις διαφορές στα payloads.


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

    $ python3 commix.py --url="http://www.target.com/vuln.php?addr=127.0.0.1" --os-shell

Απόδειξη εκτέλεσης εκτός ζώνης, όταν η απόκριση δεν επιστρέφει τίποτα :

    $ python3 commix.py --url="http://www.target.com/vuln.php" --data="addr=127.0.0.1" --oob

> [!NOTE]
> Η ανίχνευση εκτός ζώνης (OAST) με την επιλογή `--oob` χρησιμοποιεί από προεπιλογή τον δημόσιο
> διακομιστή interactsh `oast.fun`, οπότε μεταδεδομένα των αλληλεπιδράσεων με τον στόχο σας φεύγουν
> από το δίκτυό σας. Ορίστε την `--oob-server` σε μια δική σας εγκατάσταση, ώστε να παραμείνουν
> εσωτερικά. Για αναλυτικό οδηγό, συμβουλευτείτε τη σελίδα
> [**`techniques`**](https://github.com/commixproject/commix/wiki/Techniques) στο wiki.

Σάρωση λίστας στόχων χωρίς επίβλεψη και εγγραφή των αποτελεσμάτων σε αρχείο :

    $ python3 commix.py -m targets.txt --batch --report-json=results.json

Για να δείτε μια επισκόπηση των διαθέσιμων επιλογών, των διακοπτών ή / και βασικών ιδεών σχετικά με τον τρόπο χρήσης του commix, συμβουλευτείτε τις **[χρήση](https://github.com/commixproject/commix/wiki/Usage)**, **[παραδείγματα χρήσης](https://github.com/commixproject/commix/wiki/Usage-examples)** και **[παράκαμψη φίλτρων](https://github.com/commixproject/commix/wiki/Filters-bypass-examples)** wiki σελίδες.

## Σύνδεσμοι

* Εγχειρίδιο χρήστη: https://github.com/commixproject/commix/wiki
* Παρακολούθηση προβλημάτων: https://github.com/commixproject/commix/issues
