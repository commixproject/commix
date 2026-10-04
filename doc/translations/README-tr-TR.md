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

* **Beş enjeksiyon tekniği** - results-based (classic), boolean-based (kör, yanıtı sayfadan okuyarak), time-based (kör), file-based (kör, yazma kısıtlı hedefler için tempfile-based varyantıyla birlikte) ve HTTP/S ile DNS üzerinden out-of-band (OAST). `--technique` ile ya da `--type` ile bildirildikleri türe göre seçilir.
* **Kod enjeksiyonu** - `--eval`, hedefin kod olarak değerlendirdiği dizgeyi PHP, Python, Ruby, JavaScript veya PowerShell olarak, aynı beş teknikle sınar.
* **Geniş enjeksiyon yüzeyi** - GET/POST parametreleri, HTTP başlıkları, çerezler ve JSON/XML istek gövdeleri; ayrıca CGI hedefleri için `shellshock` modülü.
* **Etkileşimli kabuklar ve sömürü sonrası** - hedef üzerinde `os_shell`, yerleşik `reverse_tcp` ve `bind_tcp` modları, kurulan kabuk üzerinden dosya aktarımı (`download`/`upload`) ve geçerli kullanıcı, makine adı, yetkiler, sistem bilgileri, kullanıcılar ile parola özetlerinin numaralandırılması. Her bulgu `--proof` ile yeniden kanıtlanabilir; bu, kendi deneyini çalıştırır ve dökümü taramanın diğer çıktılarının yanına yazar.
* **Filtre ve WAF atlatma** - birlikte kullanılabilen çok sayıda tamper betiği, belirlenimci bir sırayla uygulanır.
* **Esnek hedefleme** - tek bir URL, site taraması, HTML formları, sitemap, bir OpenAPI (Swagger) tanımı, proxy günlüğü, çoklu hedef dosyası, ham HTTP istek dosyası veya `stdin` girdisi.
* **Kaldığı yerden devam eden taramalar ve makine tarafından okunabilir çıktı** - sonuçlar hedef bazında bir oturum dosyasında saklanır ve JSON olarak, test edilen her hedefi kapsayan bir CSV olarak veya taramanın HTTP trafiğinin HAR kaydı olarak dışa aktarılabilir. Bir taramanın çalıştırıldığı seçenekler profil olarak kaydedilip yeniden kullanılabilir.
* **Geniş arka uç desteği** - PHP, Python, Perl, Ruby, ASP.NET, JSP ve CGI; hem Unix benzeri hem de Windows hedeflerine karşı çalışır - yüklerin nasıl farklılaştığı için bkz.
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
> `--oob` ile yapılan bant dışı (OAST) tespit, varsayılan olarak herkese açık `oast.fun` interactsh
> sunucusunu kullanır; bu nedenle hedefinizle ilgili etkileşim meta verileri ağınızın dışına çıkar.
> Bunları kurum içinde tutmak için `--oob-server` seçeneğini kendi sunucunuza yönlendirin. Ayrıntılı
> rehber için wiki'deki
> [**`techniques`**](https://github.com/commixproject/commix/wiki/Techniques) sayfasına bakın.

Bir hedef listesini gözetimsiz taramak ve sonuçları bir dosyaya yazmak için:

    $ python3 commix.py -m targets.txt --batch --report-json=results.json

Mevcut commix seçenekleri veya commix'in nasıl kullanılacağına dair temel fikirler hakkında bilgi edinmek amacıyla **[kullanım kılavuzu](https://github.com/commixproject/commix/wiki/Usage)**, **[kullanım örnekleri](https://github.com/commixproject/commix/wiki/Usage-examples)** ve **[filtre bypassları](https://github.com/commixproject/commix/wiki/Filters-bypass-examples)**  wiki sayfalarını ziyaret edebilirsiniz.


## Linkler

* Kullanım kılavuzu: https://github.com/commixproject/commix/wiki
* Sorun takibi: https://github.com/commixproject/commix/issues
