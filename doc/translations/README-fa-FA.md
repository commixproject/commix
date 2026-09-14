<p align="center">
  <img alt="CommixProject" src="https://commixproject.com/images/logo-header.png" height="120" />
</p>

<div align="center">

[`English`](../../README.md) • [`Ελληνικά`](README-gr-GR.md) • [`Español`](README-es-ES.md) • [`Français`](README-fr-FR.md) • `فارسی` • [`Bahasa Indonesia`](README-idn-IDN.md) • [`Türkçe`](README-tr-TR.md)

</div>

<p align="center">
  <a href="https://github.com/commixproject/commix/actions/workflows/builds.yml"><img alt="Builds Tests" src="https://github.com/commixproject/commix/actions/workflows/builds.yml/badge.svg"></a>
  <a href="https://www.python.org/downloads/"><img alt="Python 3.7+" src="https://img.shields.io/badge/python-3.7+-yellow.svg"></a>
  <a href="https://github.com/commixproject/commix/blob/master/LICENSE.txt"><img alt="GPLv3 License" src="https://img.shields.io/badge/license-GPLv3-red.svg"></a>
  <a href="https://x.com/commixproject"><img alt="X" src="https://img.shields.io/badge/x-@commixproject-blue.svg"></a>
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

* **چهار تکنیک تزریق** - classic (مبتنی بر نتیجه)، time-based (کور)، file-based (نیمه‌کور، به همراه گونه tempfile-based برای هدف‌هایی با محدودیت نوشتن) و out-of-band (OAST) روی HTTP/S و DNS.
* **تزریق کد** - سوئیچ `--eval` رشته‌ای را که هدف به عنوان کد ارزیابی می‌کند، در PHP یا Python و با همان چهار تکنیک آزمایش می‌کند.
* **سطح تزریق گسترده** - پارامترهای GET/POST، سرآیندهای HTTP، کوکی‌ها و بدنه درخواست‌های JSON/XML، به‌علاوه ماژول `shellshock` برای هدف‌های CGI.
* **پوسته‌های تعاملی** - یک `os_shell` روی هدف، حالت‌های داخلی `reverse_tcp` و `bind_tcp`، و انتقال فایل (`download`/`upload`) از طریق پوسته برقرارشده.
* **شمارش و دسترسی به فایل** - کاربر جاری، نام میزبان، سطوح دسترسی، اطلاعات سیستم، کاربران و درهم‌سازی گذرواژه‌ها؛ خواندن و نوشتن فایل روی هدف.
* **دور زدن فیلترها و WAF** - چندین اسکریپت tamper قابل ترکیب، که با ترتیبی قطعی اعمال می‌شوند.
* **هدف‌گذاری انعطاف‌پذیر** - یک URL، پویش سایت، فرم‌های HTML، sitemap، گزارش پروکسی، فایل چندهدفی، فایل درخواست خام HTTP یا ورودی `stdin`.
* **پویش‌های قابل ازسرگیری** - نتایج به تفکیک هدف در یک فایل نشست ذخیره می‌شوند و می‌توان آن‌ها را به JSON خروجی گرفت.
* **پشتیبانی گسترده از بک‌اند** - PHP، Python، Perl، Ruby، ASP.NET، JSP و CGI.

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

    $ python3 commix.py --url="http://www.target.com/vuln.php?addr=127.0.0.1" --os-shell

اثبات اجرا به روش خارج از باند، هنگامی که پاسخ چیزی برنمی‌گرداند:

    $ python3 commix.py --url="http://www.target.com/vuln.php" --data="addr=127.0.0.1" --oob

> [!NOTE]
> شناسایی خارج از باند (OAST) با `--oob` به‌صورت پیش‌فرض از سرور عمومی interactsh با نشانی
> `oast.fun` استفاده می‌کند، بنابراین فراداده تعامل‌های مربوط به هدف شما از شبکه‌تان خارج می‌شود.
> برای آنکه این داده‌ها درون‌سازمانی بماند، `--oob-server` را به نمونه‌ای که خودتان میزبانی می‌کنید
> اشاره دهید. برای راهنمای کامل، صفحه
> [**`techniques`**](https://github.com/commixproject/commix/wiki/Techniques) در ویکی را ببینید.

پویش فهرستی از هدف‌ها بدون نظارت و نوشتن نتایج در یک فایل:

    $ python3 commix.py -m targets.txt --batch --report-json=results.json

برای دریافت نمای کلی از گزینه‌های موجود, سوئیچ‌ها و/یا ایده‌های اساسی در مورد نحوه استفاده از کامیکس, بررسی **[استفاده](https://github.com/commixproject/commix/wiki/Usage)**, **[مثال‌های استفاده](https://github.com/commixproject/commix/wiki/Usage-examples)** و **[دور زدن فیلترها](https://github.com/commixproject/commix/wiki/Filters-bypass-examples)**, بخش [ویکی](https://github.com/commixproject/commix/wiki) را بررسی کنید.


## پیوندها

* راهنمای کاربر: https://github.com/commixproject/commix/wiki
* ردیاب مسائل: https://github.com/commixproject/commix/issues
