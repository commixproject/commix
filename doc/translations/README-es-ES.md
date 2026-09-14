<p align="center">
  <img alt="CommixProject" src="https://commixproject.com/images/logo-header.png" height="120" />
</p>

<div align="center">

[`English`](../../README.md) • [`Ελληνικά`](README-gr-GR.md) • `Español` • [`Français`](README-fr-FR.md) • [`فارسی`](README-fa-FA.md) • [`Bahasa Indonesia`](README-idn-IDN.md) • [`Türkçe`](README-tr-TR.md)

</div>

<p align="center">
  <a href="https://github.com/commixproject/commix/actions/workflows/builds.yml"><img alt="Builds Tests" src="https://github.com/commixproject/commix/actions/workflows/builds.yml/badge.svg"></a>
  <a href="https://www.python.org/downloads/"><img alt="Python 3.7+" src="https://img.shields.io/badge/python-3.7+-yellow.svg"></a>
  <a href="https://github.com/commixproject/commix/blob/master/LICENSE.txt"><img alt="GPLv3 License" src="https://img.shields.io/badge/license-GPLv3-red.svg"></a>
  <a href="https://x.com/commixproject"><img alt="X" src="https://img.shields.io/badge/x-@commixproject-blue.svg"></a>
</p>

**Commix** (abreviatura de [**comm**]and [**i**]njection e[**x**]ploiter) es una herramienta de pruebas de penetración de código abierto, escrita por **[Anastasios Stasinopoulos](https://github.com/stasinopoulos)** (**[@ancst](https://x.com/ancst)**), que automatiza la detección y explotación de vulnerabilidades de tipo **[command](https://owasp.org/www-community/attacks/Command_Injection)** (y **[code](https://owasp.org/www-community/attacks/Code_Injection)**) injection.

![Screenshot](https://commixproject.com/images/background.png)

Puede visitar la **[colección de capturas de pantalla](https://github.com/commixproject/commix/wiki/Screenshots)** que muestra algunas de las funcionalidades disponibles en el wiki.

> [!IMPORTANT]
> **Este proyecto está en desarrollo activo.** Es posible que se produzcan cambios incompatibles
> entre revisiones. Consulte el
> [registro de cambios](https://github.com/commixproject/commix/blob/master/doc/CHANGELOG.md) antes
> de actualizar.
>
> Commix está pensado principalmente para usarse como herramienta autónoma de línea de comandos, y
> ejecuta comandos del sistema operativo en los objetivos que analiza. **Ejecutar commix como un
> servicio puede suponer riesgos de seguridad.** Se recomienda usarlo con precaución, y únicamente
> contra sistemas de su propiedad o para los que cuente con autorización explícita.

## Características

* **Cuatro técnicas de inyección** - classic (basada en resultados), time-based (a ciegas), file-based (semi a ciegas, con una variante tempfile-based para objetivos con escritura restringida) y out-of-band (OAST) sobre HTTP/S y DNS.
* **Inyección de código** - `--eval` prueba la cadena que el objetivo evalúa como código, en PHP o Python, con las mismas cuatro técnicas.
* **Amplia superficie de inyección** - parámetros GET/POST, cabeceras HTTP, cookies y cuerpos de petición JSON/XML, además del módulo `shellshock` para objetivos CGI.
* **Shells interactivas** - una `os_shell` en el objetivo, los modos integrados `reverse_tcp` y `bind_tcp`, y transferencia de archivos (`download`/`upload`) a través de la shell establecida.
* **Enumeración y acceso a archivos** - usuario actual, nombre del host, privilegios, información del sistema, usuarios y hashes de contraseñas; lectura y escritura de archivos en el objetivo.
* **Evasión de filtros y WAF** - Múltiples scripts de manipulación (tamper) combinables, aplicados en un orden determinista.
* **Objetivos flexibles** - una única URL, un rastreo del sitio, formularios HTML, un sitemap, un registro de proxy, un archivo con varios objetivos, un archivo con una petición HTTP en bruto o entrada por `stdin`.
* **Análisis reanudables** - los resultados se almacenan por objetivo en un archivo de sesión y pueden exportarse a JSON.
* **Amplio soporte de back-end** - PHP, Python, Perl, Ruby, ASP.NET, JSP y CGI.

## Instalación

Puede descargar commix en cualquier plataforma clonando el repositorio Git oficial:

```
$ git clone https://github.com/commixproject/commix.git commix
```

Alternativamente, puede descargar la última **[versión tarball](https://github.com/commixproject/commix/tarball/master)** o **[versión zipball](https://github.com/commixproject/commix/zipball/master)**.

> [!NOTE]
> Se necesita **[Python](https://www.python.org/downloads/)** (versión **3.7** o posterior) para
> ejecutar commix. El resto de dependencias se incluyen con el programa, por lo que no hace falta
> ningún paso de instalación adicional.

## Uso

Para obtener una lista de todas las opciones y parámetros disponibles:

```
$ python3 commix.py -h
```

Probar un único parámetro inyectable y abrir una shell en el objetivo:

```
$ python3 commix.py --url="http://www.target.com/vuln.php?addr=127.0.0.1" --os-shell
```

Demostrar la ejecución fuera de banda, cuando la respuesta no devuelve nada:

```
$ python3 commix.py --url="http://www.target.com/vuln.php" --data="addr=127.0.0.1" --oob
```

> [!NOTE]
> La detección fuera de banda (OAST) con `--oob` utiliza de forma predeterminada el servidor
> interactsh público `oast.fun`, por lo que los metadatos de las interacciones con su objetivo salen
> de su red. Apunte `--oob-server` a una instancia propia para mantenerlos internos. Para una guía
> detallada, consulte la página
> [**`techniques`**](https://github.com/commixproject/commix/wiki/Techniques) del wiki.

Analizar una lista de objetivos de forma desatendida y guardar los resultados en un archivo:

```
$ python3 commix.py -m targets.txt --batch --report-json=results.json
```

Para obtener una visión general de las opciones, parámetros y conceptos básicos de uso de commix, consulte las páginas del wiki **[Uso](https://github.com/commixproject/commix/wiki/Usage)**, **[Ejemplos de uso](https://github.com/commixproject/commix/wiki/Usage-examples)** y **[Evasión de filtros](https://github.com/commixproject/commix/wiki/Filters-bypass-examples)**.

## Enlaces

- Manual de usuario: [https://github.com/commixproject/commix/wiki](https://github.com/commixproject/commix/wiki)
- Seguimiento de incidencias: [https://github.com/commixproject/commix/issues](https://github.com/commixproject/commix/issues)
