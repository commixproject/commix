<p align="center">
  <img alt="CommixProject" src="https://commixproject.com/images/logo-header.png" height="120" />
</p>

<div align="center">

[`English`](../../README.md) • [`Ελληνικά`](README-gr-GR.md) • [`Español`](README-es-ES.md) • [`Français`](README-fr-FR.md) • [`فارسی`](README-fa-FA.md) • `Bahasa Indonesia` • [`Türkçe`](README-tr-TR.md)

</div>

<p align="center">
  <a href="https://github.com/commixproject/commix/actions/workflows/builds.yml"><img alt="Builds Tests" src="https://img.shields.io/github/actions/workflow/status/commixproject/commix/builds.yml?branch=master&label=Builds%20Tests&style=for-the-badge&logo=githubactions&logoColor=white"></a>
  <a href="https://www.python.org/downloads/"><img alt="Python 3.7+" src="https://img.shields.io/badge/Python-3.7%2B-3776AB.svg?style=for-the-badge&logo=python&logoColor=white"></a>
  <a href="https://github.com/commixproject/commix/blob/master/LICENSE.txt"><img alt="GPLv3 License" src="https://img.shields.io/badge/License-GPLv3-6A1B9A.svg?style=for-the-badge&logo=gnu&logoColor=white"></a>
  <a href="https://x.com/commixproject"><img alt="Follow @commixproject" src="https://img.shields.io/badge/Follow-@commixproject-000000.svg?style=for-the-badge&logo=x&logoColor=white"></a>
</p>

**Commix** (kependekan dari [**comm**]and [**i**]njection e[**x**]ploiter) adalah alat pengujian penetrasi open source, yang ditulis oleh **[Anastasios Stasinopoulos](https://github.com/stasinopoulos)** (**[@ancst](https://x.com/ancst)**), yang mengotomatiskan deteksi dan eksploitasi kerentanan **[command](https://owasp.org/www-community/attacks/Command_Injection)** (dan **[code](https://owasp.org/www-community/attacks/Code_Injection)**) injection.

![Screenshot](https://commixproject.com/images/background.png)

Anda dapat mengunjungi [koleksi dari tangkapan layar](https://github.com/commixproject/commix/wiki/Screenshots) yang menunjukkan beberapa fitur di wiki.

> [!IMPORTANT]
> **Proyek ini sedang dalam pengembangan aktif.** Perubahan yang dapat merusak kompatibilitas
> mungkin terjadi antar revisi. Periksa
> [catatan perubahan](https://github.com/commixproject/commix/blob/master/doc/CHANGELOG.md) sebelum
> memperbarui.
>
> Commix terutama dibuat untuk digunakan sebagai alat baris perintah mandiri, dan alat ini
> menjalankan perintah sistem operasi pada target yang diujinya. **Menjalankan commix sebagai sebuah
> layanan dapat menimbulkan risiko keamanan.** Gunakan dengan hati-hati, dan hanya terhadap sistem
> milik Anda sendiri atau yang Anda memiliki izin tertulis untuk mengujinya.

## Fitur

* **Empat teknik injeksi** - results-based, boolean-based, time-based dan file-based, dipilih dengan `--technique` atau berdasarkan tipe yang mereka laporkan dengan `--type` - lihat [techniques](https://github.com/commixproject/commix/wiki/Techniques) untuk apa yang dituntut masing-masing dari sebuah target.
* **Out-of-band, ketika tidak ada yang kembali** - `--oob` membuktikan eksekusi dan membawa keluaran perintah melalui HTTP/S atau DNS, mencapai server lewat klien apa pun yang kebetulan dimiliki target - lihat [out-of-band client](https://github.com/commixproject/commix/wiki/Usage#out-of-band-client) untuk klien yang dicoba dan cara menetapkan salah satunya.
* **Injeksi kode** - [`--eval`](https://github.com/commixproject/commix/wiki/Usage#test-for-code-injection) menguji apa yang dievaluasi target sebagai kode, dalam PHP, Python, Ruby, JavaScript, atau PowerShell, dengan teknik yang sama.
* **Di mana pun masukan mendarat** - parameter GET/POST, [header HTTP dan cookie](https://github.com/commixproject/commix/wiki/Usage#request-options), body JSON/XML/GraphQL, serta modul `shellshock` untuk target CGI.
* **Dari bukti ke shell** - [`--os-shell`](https://github.com/commixproject/commix/wiki/Getting-shells), mode bawaan `reverse_tcp` dan `bind_tcp` yang dapat ditingkatkan menjadi PTY penuh, transfer berkas, baca/tulis registry Windows, dan enumerasi hingga hash kata sandi, dengan serangan kamus yang ditawarkan terhadapnya.
* **Pengelakan filter dan WAF** - skrip tamper yang dapat dikombinasikan, diterapkan dalam urutan yang deterministik - lihat [filters bypass examples](https://github.com/commixproject/commix/wiki/Filters-bypass-examples).
* **Target dalam bentuk apa pun** - satu URL, penelusuran situs, formulir HTML, sitemap, deskripsi OpenAPI (Swagger), log proxy, berkas berisi banyak target, permintaan HTTP mentah, atau masukan `stdin` - lihat [target options](https://github.com/commixproject/commix/wiki/Usage#target-options).
* **Dapat dilanjutkan dan diskripkan** - [berkas sesi per target](https://github.com/commixproject/commix/wiki/Usage#resume-from-stored-session-data), keluaran JSON/CSV/HAR, profil opsi yang dapat digunakan kembali, dan `--proof`, yang membuktikan kembali setiap temuan dengan percobaannya sendiri.
* **Unix maupun Windows** - back-end PHP, Python, Perl, Ruby, ASP.NET, JSP dan CGI - lihat
[Windows and Unix-like targets at a glance](https://github.com/commixproject/commix/wiki/Techniques#windows-and-unix-like-targets-at-a-glance)
untuk perbedaan muatannya.

## Instalasi

Anda dapat mengunduh commix di platform apa pun dengan mengkloning repositori resmi Git:

    $ git clone https://github.com/commixproject/commix.git commix

Atau, Anda dapat mengunduh [tarball](https://github.com/commixproject/commix/tarball/master) atau [zipball](https://github.com/commixproject/commix/zipball/master) terbaru.

> [!NOTE]
> **[Python](https://www.python.org/downloads/)** (versi **3.7** atau lebih baru) diperlukan untuk
> menjalankan commix. Semua dependensi lainnya sudah disertakan, sehingga tidak diperlukan langkah
> instalasi tambahan.


## Penggunaan

Untuk mendapatkan daftar semua opsi dan beralih gunakan:

    $ python3 commix.py -h

Menguji satu parameter yang dapat diinjeksi, lalu masuk ke shell pada target:

    $ python3 commix.py --url="http://commix-testbed/scenarios/regular/GET/classic.php?addr=127.0.0.1" --os-shell

Membuktikan eksekusi secara out-of-band, ketika respons tidak mengembalikan apa pun:

    $ python3 commix.py --url="http://commix-testbed/scenarios/regular/POST/blind.php" --data="addr=127.0.0.1" --oob

> [!NOTE]
> Klien dipilih berdasarkan apa yang dimiliki target, sehingga mesin tanpa klien HTTP yang biasa pun
> tetap terjangkau - tetapkan salah satu dengan `--oob-transport` bila jalur keluarnya sudah
> diketahui. Deteksi out-of-band (OAST) dengan `--oob` secara bawaan menggunakan server interactsh
> publik `oast.fun`, sehingga metadata interaksi dengan target Anda keluar dari jaringan Anda. Arahkan
> `--oob-server` ke instansi milik sendiri agar tetap berada di jaringan internal. Untuk panduan
> lengkap, lihat halaman
> [**`out-of-band-oob-channel`**](https://github.com/commixproject/commix/wiki/Techniques#out-of-band-oob-channel) di wiki.

Memindai daftar target tanpa pengawasan dan menyimpan hasilnya ke sebuah berkas:

    $ python3 commix.py -m targets.txt --batch --report-json=results.json

Untuk mendapatkan gambaran umum tentang opsi commix yang tersedia, beralih dan / atau ide dasar tentang cara menggunakan commix, periksa **[penggunaan](https://github.com/commixproject/commix/wiki/Usage)**, **[contoh penggunaan](https://github.com/commixproject/commix/wiki/Usage-examples)** dan **[bypass filter](https://github.com/commixproject/commix/wiki/Filters-bypass-examples)** halaman wiki.


## Link

* Panduan : https://github.com/commixproject/commix/wiki
* Pelacak masalah : https://github.com/commixproject/commix/issues
