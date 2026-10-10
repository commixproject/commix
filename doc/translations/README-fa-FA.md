<p align="center">
  <img alt="CommixProject" src="https://commixproject.com/images/logo-header.png" height="120" />
</p>

<div align="center">

[`English`](../../README.md) • [`Ελληνικά`](README-gr-GR.md) • [`Español`](README-es-ES.md) • [`Français`](README-fr-FR.md) • `فارسی` • [`Bahasa Indonesia`](README-idn-IDN.md) • [`Türkçe`](README-tr-TR.md)

</div>

<p align="center">
  <a href="https://github.com/commixproject/commix/actions/workflows/builds.yml"><img alt="Builds Tests" src="https://img.shields.io/github/actions/workflow/status/commixproject/commix/builds.yml?branch=master&label=Builds%20Tests&style=for-the-badge&logo=githubactions&logoColor=white"></a>
  <a href="https://www.python.org/downloads/"><img alt="Python 3.7+" src="https://img.shields.io/badge/Python-3.7%2B-3776AB.svg?style=for-the-badge&logo=python&logoColor=white"></a>
  <a href="https://github.com/commixproject/commix/blob/master/LICENSE.txt"><img alt="GPLv3 License" src="https://img.shields.io/badge/License-GPLv3-6A1B9A.svg?style=for-the-badge&logo=gnu&logoColor=white"></a>
  <a href="https://x.com/commixproject"><img alt="Follow @commixproject" src="https://img.shields.io/badge/Follow-@commixproject-000000.svg?style=for-the-badge&logo=x&logoColor=white"></a>
</p>
**کامیکس** (مخفف [**کام**]ند ا[**ی**]نجکشن ا[**کس**]پلویتر) یک ابزار متن‌باز تست‌نفوذ است که توسط **[آناستاسیوس استاسینوپولوس](https://github.com/stasinopoulos)** (**[@ancst](https://x.com/ancst)**) نوشته شده است که فرایند کشف و بهره‌برداری از آسیپ پذیری های **[کامند](https://owasp.org/www-community/attacks/Command_Injection)** (و **[کد](https://owasp.org/www-community/attacks/Code_Injection)**) اینجکشن را خودکار می‌کند.


![Screenshot](https://commixproject.com/images/background.png)
می‌توانید از [مجموعه اسکرین‌ شات‌ها](https://github.com/commixproject/commix/wiki/Screenshots) که نشان‌دهنده بعضی از ویژگی‌ها است در صفحه ویکی دیدن کنید.

> [!IMPORTANT]
> **این پروژه در حال توسعه فعال است.** بین نسخه‌ها ممکن است تغییرات ناسازگار رخ دهد. پیش از
> به‌روزرسانی،
> [فهرست تغییرات](https://github.com/commixproject/commix/blob/master/doc/CHANGELOG.md) را مرور
> کنید.
>
> کامیکس در درجه اول برای استفاده به عنوان یک ابزار مستقل خط فرمان ساخته شده است و روی هدف‌هایی که
> آزمایش می‌کند دستورات سیستم‌عامل را اجرا می‌کند. **اجرای کامیکس به صورت یک سرویس ممکن است خطرات
> امنیتی به همراه داشته باشد.** توصیه می‌شود با احتیاط و تنها روی سامانه‌هایی استفاده شود که متعلق
> به شما هستند یا برای آزمودن آن‌ها مجوز صریح دارید.

## ویژگی‌ها

* **چهار تکنیک تزریق** - results-based، boolean-based، time-based و file-based، که با `--technique` یا بر پایه نوعی که با `--type` گزارش می‌کنند انتخاب می‌شوند - برای اینکه هر کدام چه چیزی از هدف می‌خواهد [techniques](https://github.com/commixproject/commix/wiki/Techniques) را ببینید.
* **out-of-band، وقتی هیچ چیز بازنمی‌گردد** - سوئیچ `--oob` اجرا را اثبات می‌کند و خروجی فرمان را روی HTTP/S یا DNS بازمی‌گرداند، و از راه هر کلاینتی که هدف داشته باشد به سرور می‌رسد - برای اینکه کدام‌ها را می‌آزماید و چگونه یکی را تثبیت کنید [out-of-band client](https://github.com/commixproject/commix/wiki/Usage#out-of-band-client) را ببینید.
* **تزریق کد** - سوئیچ [`--eval`](https://github.com/commixproject/commix/wiki/Usage#test-for-code-injection) آنچه را هدف به عنوان کد ارزیابی می‌کند، در PHP، Python، Ruby، JavaScript یا PowerShell و با همان تکنیک‌ها آزمایش می‌کند.
* **هر جا که ورودی فرود آید** - پارامترهای GET/POST، [سرآیندهای HTTP و کوکی‌ها](https://github.com/commixproject/commix/wiki/Usage#request-options)، بدنه‌های JSON/XML/GraphQL، به‌علاوه ماژول `shellshock` برای هدف‌های CGI.
* **از اثبات تا پوسته** - [`--os-shell`](https://github.com/commixproject/commix/wiki/Getting-shells)، حالت‌های داخلی `reverse_tcp` و `bind_tcp` با ارتقا به یک PTY کامل، انتقال فایل، خواندن و نوشتن رجیستری ویندوز، و شمارش تا درهم‌سازی گذرواژه‌ها، با پیشنهاد حمله دیکشنری علیه آن‌ها.
* **دور زدن فیلترها و WAF** - اسکریپت‌های tamper قابل ترکیب، که با ترتیبی قطعی اعمال می‌شوند - [filters bypass examples](https://github.com/commixproject/commix/wiki/Filters-bypass-examples) را ببینید.
* **هدف در هر شکلی** - یک URL، پویش سایت، فرم‌های HTML، sitemap، توصیف OpenAPI (Swagger)، گزارش پروکسی، فایل چندهدفی، درخواست خام HTTP یا ورودی `stdin` - [target options](https://github.com/commixproject/commix/wiki/Usage#target-options) را ببینید.
* **قابل ازسرگیری و اسکریپت‌پذیر** - [فایل‌های نشست به تفکیک هدف](https://github.com/commixproject/commix/wiki/Usage#resume-from-stored-session-data)، خروجی JSON/CSV/HAR، نمایه‌های گزینه قابل استفاده مجدد، و `--proof` که هر یافته را با آزمایشی از آنِ خود دوباره اثبات می‌کند.
* **شبه‌یونیکس و ویندوز** - بک‌اندهای PHP، Python، Perl، Ruby، ASP.NET، JSP و CGI - برای تفاوت بارها
[Windows and Unix-like targets at a glance](https://github.com/commixproject/commix/wiki/Techniques#windows-and-unix-like-targets-at-a-glance)
را ببینید.

## نصب و راه‌اندازی

در هر پلتفرمی می‌توانید با کلون کردن مخزن رسمی گیت کامیکس را دانلود کنید :

    $ git clone https://github.com/commixproject/commix.git commix

از سوی دیگر, می‌توانید جدیدترین [tarball](https://github.com/commixproject/commix/tarball/master) یا [zipball](https://github.com/commixproject/commix/zipball/master) را دانلود کیند.

> [!NOTE]
> **[پایتون](https://www.python.org/downloads/)** (نسخه **3.7** یا بالاتر) برای اجرای کامیکس مورد
> نیاز است. تمام وابستگی‌های دیگر همراه برنامه ارائه می‌شوند، بنابراین به مرحله نصب اضافی نیازی
> نیست.


## استفاده

برای دریافت لیستی از همه گزینه‌ها و سوئیچ‌ها از این دستور استفاده کنید:

    $ python3 commix.py -h

آزمودن یک پارامتر آسیب‌پذیر و سپس گرفتن پوسته روی هدف:

    $ python3 commix.py --url="http://commix-testbed/scenarios/regular/GET/classic.php?addr=127.0.0.1" --os-shell

اثبات اجرا به روش خارج از باند، هنگامی که پاسخ چیزی برنمی‌گرداند:

    $ python3 commix.py --url="http://commix-testbed/scenarios/regular/POST/blind.php" --data="addr=127.0.0.1" --oob

> [!NOTE]
> کلاینت بر پایه آنچه هدف دارد انتخاب می‌شود، بنابراین ماشینی که کلاینت‌های HTTP معمول را ندارد هم
> در دسترس می‌ماند - هنگامی که مسیر خروجی آن از پیش معلوم است، با `--oob-transport` یکی را تثبیت
> کنید. شناسایی خارج از باند (OAST) با `--oob` به‌صورت پیش‌فرض از سرور عمومی interactsh با نشانی
> `oast.fun` استفاده می‌کند، بنابراین فراداده تعامل‌های مربوط به هدف شما از شبکه‌تان خارج می‌شود.
> برای آنکه این داده‌ها درون‌سازمانی بماند، `--oob-server` را به نمونه‌ای که خودتان میزبانی می‌کنید
> اشاره دهید. برای راهنمای کامل، صفحه
> [**`out-of-band-oob-channel`**](https://github.com/commixproject/commix/wiki/Techniques#out-of-band-oob-channel) در ویکی را ببینید.

پویش فهرستی از هدف‌ها بدون نظارت و نوشتن نتایج در یک فایل:

    $ python3 commix.py -m targets.txt --batch --report-json=results.json

برای دریافت نمای کلی از گزینه‌های موجود, سوئیچ‌ها و/یا ایده‌های اساسی در مورد نحوه استفاده از کامیکس, بررسی **[استفاده](https://github.com/commixproject/commix/wiki/Usage)**, **[مثال‌های استفاده](https://github.com/commixproject/commix/wiki/Usage-examples)** و **[دور زدن فیلترها](https://github.com/commixproject/commix/wiki/Filters-bypass-examples)**, بخش [ویکی](https://github.com/commixproject/commix/wiki) را بررسی کنید.


## پیوندها

* راهنمای کاربر: https://github.com/commixproject/commix/wiki
* ردیاب مسائل: https://github.com/commixproject/commix/issues
