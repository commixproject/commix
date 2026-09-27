# Third-party code

Commix runs with nothing installed beyond Python itself. The libraries it needs are carried in the
tree under `src/thirdparty/`, and this file records what they are and the terms they come under.
Grouped by licence, each group followed by the licence in full, because the BSD and MIT terms below
require the notice to travel with the code.

| Library | Version | Where | What commix uses it for |
|---------|---------|-------|-------------------------|
| [Beautiful Soup](https://www.crummy.com/software/BeautifulSoup/) | 3.2.1 | `src/thirdparty/beautifulsoup/` | parsing pages while crawling, in `src/utils/crawler.py` |
| [chardet](https://github.com/chardet/chardet) | 4.0.0 | `src/thirdparty/chardet/` | working out a page's character encoding when the target does not say |
| [Colorama](https://github.com/tartley/colorama) | 0.3.9 | `src/thirdparty/colorama/` | coloured console output, on Windows as well |
| [flatten-json](https://github.com/amirziai/flatten) | - | `src/thirdparty/flatten_json/` | flattening a JSON body so each member can be named by the path it sits at |
| [PySocks](https://github.com/Anorov/PySocks) | 1.7.1 | `src/thirdparty/socks/` | SOCKS4/5 proxies, and reaching Tor directly |
| [six](https://github.com/benjaminp/six) | 1.16.0 | `src/thirdparty/six/` | the Python 2 and 3 compatibility layer the rest of the tree imports through |

`src/thirdparty/odict/` is not third-party code: it is a nine-line shim that hands back
`collections.OrderedDict`, falling back to the six version on interpreters too old to have it.

## BSD

* **Beautiful Soup**, under `src/thirdparty/beautifulsoup/`.
  Copyright (c) 2004-2010, Leonard Richardson.
* **Colorama**, under `src/thirdparty/colorama/`.
  Copyright (c) 2013, Jonathan Hartley.
* **PySocks**, under `src/thirdparty/socks/`.
  Copyright (c) 2006, Dan-Haim.

````
Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the copyright holder nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
````

## MIT

* **flatten-json**, under `src/thirdparty/flatten_json/`.
  Copyright (c) 2016, Amir Ziai.
* **six**, under `src/thirdparty/six/`.
  Copyright (c) 2010-2020, Benjamin Peterson.

````
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
````

## LGPL 2.1 or later

* **chardet**, under `src/thirdparty/chardet/`.
  The Universal Character Encoding Detector. The original code is Mozilla's universal charset
  detector; the initial developer is Netscape Communications Corporation, portions created by it
  being copyright (c) 2001. Shy Shalom wrote the original C code and Mark Pilgrim ported it to
  Python.

````
This library is free software; you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the Free
Software Foundation; either version 2.1 of the License, or (at your option)
any later version.

This library is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
details.

You should have received a copy of the GNU Lesser General Public License along
with this library; if not, write to the Free Software Foundation, Inc.,
51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
````

The full text of the GNU Lesser General Public License is at
<https://www.gnu.org/licenses/old-licenses/lgpl-2.1.txt>.

## Commix itself

Everything outside `src/thirdparty/` is commix's own and is licensed under the GNU General Public
License v3 - see [`LICENSE.txt`](../LICENSE.txt). That includes `src/utils/brotli.py`, which is a
Brotli decoder written for commix rather than a bundled library.
