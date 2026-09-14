<p align="center">
  <img alt="CommixProject" src="https://commixproject.com/images/logo-header.png" height="120" />
</p>

<div align="center">

[`English`](../../README.md) • [`Ελληνικά`](README-gr-GR.md) • [`Español`](README-es-ES.md) • [`Français`](README-fr-FR.md) • [`فارسی`](README-fa-FA.md) • `Bahasa Indonesia` • [`Türkçe`](README-tr-TR.md)

</div>

<p align="center">
  <a href="https://github.com/commixproject/commix/actions/workflows/builds.yml"><img alt="Builds Tests" src="https://github.com/commixproject/commix/actions/workflows/builds.yml/badge.svg"></a>
  <a href="https://www.python.org/downloads/"><img alt="Python 3.7+" src="https://img.shields.io/badge/python-3.7+-yellow.svg"></a>
  <a href="https://github.com/commixproject/commix/blob/master/LICENSE.txt"><img alt="GPLv3 License" src="https://img.shields.io/badge/license-GPLv3-red.svg"></a>
  <a href="https://x.com/commixproject"><img alt="X" src="https://img.shields.io/badge/x-@commixproject-blue.svg"></a>
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

* **Empat teknik injeksi** - classic (berbasis hasil), time-based (buta), file-based (setengah buta, dengan varian tempfile-based untuk target yang terbatas hak tulisnya) dan out-of-band (OAST) melalui HTTP/S dan DNS.
* **Injeksi kode** - `--eval` menguji string yang dievaluasi target sebagai kode, dalam PHP atau Python, dengan empat teknik yang sama.
* **Permukaan injeksi yang luas** - parameter GET/POST, header HTTP, cookie, dan body permintaan JSON/XML, serta modul `shellshock` untuk target CGI.
* **Shell interaktif** - `os_shell` pada target, mode bawaan `reverse_tcp` dan `bind_tcp`, serta transfer berkas (`download`/`upload`) melalui shell yang telah terbentuk.
* **Enumerasi dan akses berkas** - pengguna saat ini, nama host, hak akses, informasi sistem, daftar pengguna dan hash kata sandi; membaca dan menulis berkas pada target.
* **Pengelakan filter dan WAF** - Beberapa skrip tamper yang dapat dikombinasikan, diterapkan dalam urutan yang deterministik.
* **Penentuan target yang fleksibel** - satu URL, penelusuran situs, formulir HTML, sitemap, log proxy, berkas berisi banyak target, berkas permintaan HTTP mentah, atau masukan `stdin`.
* **Pemindaian yang dapat dilanjutkan** - hasil disimpan per target dalam berkas sesi dan dapat diekspor ke JSON.
* **Dukungan back-end yang luas** - PHP, Python, Perl, Ruby, ASP.NET, JSP dan CGI.

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

    $ python3 commix.py --url="http://www.target.com/vuln.php?addr=127.0.0.1" --os-shell

Membuktikan eksekusi secara out-of-band, ketika respons tidak mengembalikan apa pun:

    $ python3 commix.py --url="http://www.target.com/vuln.php" --data="addr=127.0.0.1" --oob

> [!NOTE]
> Deteksi out-of-band (OAST) dengan `--oob` secara bawaan menggunakan server interactsh publik
> `oast.fun`, sehingga metadata interaksi dengan target Anda keluar dari jaringan Anda. Arahkan
> `--oob-server` ke instansi milik sendiri agar tetap berada di jaringan internal. Untuk panduan
> lengkap, lihat halaman
> [**`techniques`**](https://github.com/commixproject/commix/wiki/Techniques) di wiki.

Memindai daftar target tanpa pengawasan dan menyimpan hasilnya ke sebuah berkas:

    $ python3 commix.py -m targets.txt --batch --report-json=results.json

Untuk mendapatkan gambaran umum tentang opsi commix yang tersedia, beralih dan / atau ide dasar tentang cara menggunakan commix, periksa **[penggunaan](https://github.com/commixproject/commix/wiki/Usage)**, **[contoh penggunaan](https://github.com/commixproject/commix/wiki/Usage-examples)** dan **[bypass filter](https://github.com/commixproject/commix/wiki/Filters-bypass-examples)** halaman wiki.


## Link

* Panduan : https://github.com/commixproject/commix/wiki
* Pelacak masalah : https://github.com/commixproject/commix/issues
