<p align="center">
  <img alt="CommixProject" src="https://commixproject.com/images/logo-header.png" height="120" />
</p>

<div align="center">

[`English`](../../README.md) • [`Ελληνικά`](README-gr-GR.md) • [`Español`](README-es-ES.md) • [`Français`](README-fr-FR.md) • [`فارسی`](README-fa-FA.md) • [`Bahasa Indonesia`](README-idn-IDN.md) • `Türkçe`

</div>

<p align="center">
  <a href="https://github.com/commixproject/commix/actions/workflows/builds.yml"><img alt="Builds Tests" src="https://img.shields.io/github/actions/workflow/status/commixproject/commix/builds.yml?branch=master&label=Builds%20Tests&style=for-the-badge&logo=githubactions&logoColor=white"></a>
  <a href="https://www.python.org/downloads/"><img alt="Python 3.7+" src="https://img.shields.io/badge/Python-3.7%2B-3776AB.svg?style=for-the-badge&logo=python&logoColor=white"></a>
  <a href="https://github.com/commixproject/commix/blob/master/LICENSE.txt"><img alt="GPLv3 License" src="https://img.shields.io/badge/License-GPLv3-6A1B9A.svg?style=for-the-badge&logo=gnu&logoColor=white"></a>
  <a href="https://x.com/commixproject"><img alt="Follow @commixproject" src="https://img.shields.io/badge/Follow-@commixproject-000000.svg?style=for-the-badge&logo=x&logoColor=white"></a>
</p>

**Commix** ([comm]and [i]njection e[x]ploiter'ın kısaltması), **[Anastasios Stasinopoulos](https://github.com/stasinopoulos)** (**[@ancst](https://x.com/ancst)**) tarafından yazılan ve **[Komut](https://owasp.org/www-community/attacks/Command_Injection)** (ve **[kod](https://owasp.org/www-community/attacks/Code_Injection)**) enjeksiyonu güvenlik açıklarının tespitini ve istismarını otomatikleştiren açık kaynaklı bir sızma testi aracıdır.

![Screenshot](https://commixproject.com/images/background.png)

Wiki'deki bazı özellikleri gösteren [ekran görüntüleri koleksiyonunu](https://github.com/commixproject/commix/wiki/Screenshots) ziyaret edebilirsiniz.

> [!IMPORTANT]
> **Bu proje aktif geliştirme aşamasındadır.** Sürümler arasında geriye dönük uyumluluğu bozan
> değişiklikler olabilir. Güncellemeden önce
> [değişiklik günlüğünü](https://github.com/commixproject/commix/blob/master/doc/CHANGELOG.md)
> inceleyin.
>
> Commix öncelikle bağımsız bir komut satırı aracı olarak kullanılmak üzere tasarlanmıştır ve test
> ettiği hedeflerde işletim sistemi komutları çalıştırır. **Commix'i bir servis olarak çalıştırmak
> güvenlik riskleri doğurabilir.** Dikkatli kullanılması ve yalnızca size ait olan ya da test etmek
> için açık yetkiye sahip olduğunuz sistemlerde kullanılması önerilir.

## Özellikler

* **Dört enjeksiyon tekniği** - results-based, boolean-based, time-based ve file-based; `--technique` ile ya da `--type` ile bildirildikleri türe göre seçilir - her birinin hedeften ne istediği için bkz. [techniques](https://github.com/commixproject/commix/wiki/Techniques).
* **Hiçbir şey geri dönmediğinde out-of-band** - `--oob` yürütmeyi kanıtlar ve komutun çıktısını HTTP/S ya da DNS üzerinden geri taşır; sunucuya hedefte hangi istemci varsa onunla ulaşır - hangilerini denediği ve nasıl sabitleneceği için bkz. [out-of-band client](https://github.com/commixproject/commix/wiki/Usage#out-of-band-client).
* **Kod enjeksiyonu** - [`--eval`](https://github.com/commixproject/commix/wiki/Usage#test-for-code-injection), hedefin kod olarak değerlendirdiğini PHP, Python, Ruby, JavaScript veya PowerShell olarak, aynı tekniklerle sınar.
* **Girdi nereye düşerse** - GET/POST parametreleri, [HTTP başlıkları ve çerezler](https://github.com/commixproject/commix/wiki/Usage#request-options), JSON/XML/GraphQL gövdeleri; ayrıca CGI hedefleri için `shellshock` modülü.
* **Kanıttan kabuğa** - [`--os-shell`](https://github.com/commixproject/commix/wiki/Getting-shells), tam PTY'ye yükseltilebilen yerleşik `reverse_tcp` ve `bind_tcp`, dosya aktarımı, Windows kayıt defteri okuma/yazma ve parola özetlerine kadar numaralandırma; bunlara karşı bir sözlük saldırısı da önerilir.
* **Filtre ve WAF atlatma** - birlikte kullanılabilen tamper betikleri, belirlenimci bir sırayla uygulanır - bkz. [filters bypass examples](https://github.com/commixproject/commix/wiki/Filters-bypass-examples).
* **Her biçimde hedef** - bir URL, site taraması, HTML formları, sitemap, bir OpenAPI (Swagger) tanımı, proxy günlüğü, çoklu hedef dosyası, ham HTTP isteği veya `stdin` girdisi - bkz. [target options](https://github.com/commixproject/commix/wiki/Usage#target-options).
* **Devam ettirilebilir ve betiklenebilir** - [hedef bazında oturum dosyaları](https://github.com/commixproject/commix/wiki/Usage#resume-from-stored-session-data), JSON/CSV/HAR çıktısı, yeniden kullanılabilir seçenek profilleri ve her bulguyu kendi deneyiyle yeniden kanıtlayan `--proof`.
* **Unix benzeri ve Windows** - PHP, Python, Perl, Ruby, ASP.NET, JSP ve CGI arka uçları - yüklerin nasıl farklılaştığı için bkz.
[Windows and Unix-like targets at a glance](https://github.com/commixproject/commix/wiki/Techniques#windows-and-unix-like-targets-at-a-glance).

## Kurulum

Resmi Git deposunu klonlayarak commix'i herhangi bir platformda indirebilirsiniz :


    $ git clone https://github.com/commixproject/commix.git commix

Alternatif olarak, en son [tarball](https://github.com/commixproject/commix/tarball/master) veya [zipball](https://github.com/commixproject/commix/zipball/master) olarak indirebilirsiniz.

> [!NOTE]
> Commix'i çalıştırmak için **[Python](https://www.python.org/downloads/)** (sürüm **3.7** veya
> üzeri) gereklidir. Diğer tüm bağımlılıklar programla birlikte gelir, bu nedenle ek bir kurulum
> adımına gerek yoktur.


## Kullanım

Seçeneklerinizi görmek ve yardım almak için aşağıdaki komutu girin:

    $ python3 commix.py -h

Tek bir enjekte edilebilir parametreyi test edip hedefte bir kabuk açmak için:

    $ python3 commix.py --url="http://commix-testbed/scenarios/regular/GET/classic.php?addr=127.0.0.1" --os-shell

Yanıtın hiçbir şey döndürmediği durumlarda çalıştırmayı bant dışı yöntemle kanıtlamak için:

    $ python3 commix.py --url="http://commix-testbed/scenarios/regular/POST/blind.php" --data="addr=127.0.0.1" --oob

> [!NOTE]
> İstemci, hedefte ne varsa ona göre seçilir; bu yüzden alışılmış HTTP istemcilerinden yoksun bir
> makine de erişilebilir kalır - çıkış trafiği zaten biliniyorsa `--oob-transport` ile birini
> sabitleyin. `--oob` ile yapılan bant dışı (OAST) tespit, varsayılan olarak herkese açık `oast.fun`
> interactsh sunucusunu kullanır; bu nedenle hedefinizle ilgili etkileşim meta verileri ağınızın
> dışına çıkar.
> Bunları kurum içinde tutmak için `--oob-server` seçeneğini kendi sunucunuza yönlendirin. Ayrıntılı
> rehber için wiki'deki
> [**`out-of-band-oob-channel`**](https://github.com/commixproject/commix/wiki/Techniques#out-of-band-oob-channel) sayfasına bakın.

Bir hedef listesini gözetimsiz taramak ve sonuçları bir dosyaya yazmak için:

    $ python3 commix.py -m targets.txt --batch --report-json=results.json

Mevcut commix seçenekleri veya commix'in nasıl kullanılacağına dair temel fikirler hakkında bilgi edinmek amacıyla **[kullanım kılavuzu](https://github.com/commixproject/commix/wiki/Usage)**, **[kullanım örnekleri](https://github.com/commixproject/commix/wiki/Usage-examples)** ve **[filtre bypassları](https://github.com/commixproject/commix/wiki/Filters-bypass-examples)**  wiki sayfalarını ziyaret edebilirsiniz.


## Linkler

* Kullanım kılavuzu: https://github.com/commixproject/commix/wiki
* Sorun takibi: https://github.com/commixproject/commix/issues
