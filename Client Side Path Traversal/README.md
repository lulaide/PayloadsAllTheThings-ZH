# 客户端路径遍历

> 客户端路径遍历 (CSPT)，有时也被称为“现场请求伪造”，是一种可以被利用作为 CSRF 或 XSS 攻击工具的漏洞。
> 它利用了客户端通过 fetch 发起请求的能力，这些请求的目标 URL 中可以注入多个 `../` 字符。经过规范化后，这些字符会将请求重定向到不同的 URL，可能导致安全漏洞。
> 由于每个请求都从应用程序的前端发起，浏览器会自动包含 Cookie 和其他身份验证机制，从而使这些攻击能够加以利用。

## 概述

* [工具](#工具)
* [方法论](#方法论)
    * [CSPT 转为 XSS](#cspt转为xss)
    * [CSPT 转为 CSRF](#cspt转为csrf)
* [实验室](#实验室)
* [参考文献](#参考文献)

## 工具

* [doyensec/CSPTBurpExtension](https://github.com/doyensec/CSPTBurpExtension) - CSPT 是一个开源的 Burp Suite 扩展，用于发现和利用客户端路径遍历漏洞。

## 方法论

### CSPT 转为 XSS

![cspt-query-param](https://matanber.com/images/blog/cspt-query-param.png)

页面在加载后调用 fetch 函数，向一个带有攻击者可控输入的 URL 发送请求。如果该输入未正确编码到路径中，则允许攻击者在路径中注入 `../` 序列，从而导致请求发送到任意端点。这种行为被称为 CSPT 漏洞。

**示例**：

* 页面 `https://example.com/static/cms/news.html` 接受 `newsitemid` 参数
* 然后获取 `https://example.com/newitems/<newsitemid>` 的内容
* 在 `https://example.com/pricing/default.js` 中还发现了通过 `cb` 参数的文本注入漏洞
* 最终载荷为 `https://example.com/static/cms/news.html?newsitemid=../pricing/default.js?cb=alert(document.domain)//`

### CSPT 转为 CSRF

CSPT 会重定向合法的 HTTP 请求，允许前端为 API 调用添加必要的令牌，例如身份验证或 CSRF 令牌。此功能可能会被利用来绕过现有的 CSRF 防护措施。

|                                              | CSRF               | CSPT2CSRF          |
| -------------------------------------------- | ------------------ | ------------------ |
| POST CSRF ?                                  | :white_check_mark: | :white_check_mark: |
| 能否控制主体？                              | :white_check_mark: | :x:                |
| 是否能与反 CSRF 令牌一起工作？               | :x:                | :white_check_mark: |
| 是否能与 Samesite=Lax 一起工作？             | :x:                | :white_check_mark: |
| GET / PATCH / PUT / DELETE CSRF ?            | :x:                | :white_check_mark: |
| 一键 CSRF ?                                  | :x:                | :white_check_mark: |
| 影响是否取决于源和接收器？                   | :x:                | :white_check_mark: |

现实场景：

* Rocket.Chat 中的一键 CSPT2CSRF
* CVE-2023-45316: Mattermost 中带 POST 接收器的 CSPT2CSRF：`/<team>/channels/channelname?telem_action=under_control&forceRHSOpen&telem_run_id=../../../../../../api/v4/caches/invalidate`
* CVE-2023-6458: Mattermost 中带 GET 接收器的 CSPT2CSRF
* [客户端路径操作 - erasec.be](https://www.erasec.be/blog/client-side-path-manipulation/)：CSPT2CSRF `https://example.com/signup/invite?email=foo%40bar.com&inviteCode=123456789/../../../cards/123e4567-e89b-42d3-a456-556642440000/cancel?a=`
* [CVE-2023-5123 : Grafana JSON API 插件中的 CSPT2CSRF](https://medium.com/@maxime.escourbiac/grafana-cve-2023-5123-write-up-74e1be7ef652)

## 实验室

* [doyensec/CSPTPlayground](https://github.com/doyensec/CSPTPlayground) - CSPTPlayground 是一个开源的实验平台，用于发现和利用客户端路径遍历 (CSPT)。
* [Root Me - CSPT - The Ruler](https://www.root-me.org/en/Challenges/Web-Client/CSPT-The-Ruler)

## 参考文献

* [利用客户端路径遍历执行跨站请求伪造 - 引入 CSPT2CSRF - Maxence Schmitt - 2024 年 7 月 2 日](https://blog.doyensec.com/2024/07/02/cspt2csrf.html)
* [利用客户端路径遍历 - CSRF 已死，长存 CSRF - 白皮书 - Maxence Schmitt - 2024 年 7 月 2 日](https://www.doyensec.com/resources/Doyensec_CSPT2CSRF_Whitepaper.pdf)
* [利用客户端路径遍历 - CSRF 已死，长存 CSRF - OWASP Global AppSec 2024 - Maxence Schmitt - 2024 年 6 月 24 日](https://www.doyensec.com/resources/Doyensec_CSPT2CSRF_OWASP_Appsec_Lisbon.pdf)
* [泄露 Jupyter 实例认证令牌链接 CVE-2023-39968、CVE-2024-22421 和一个 chromium bug - Davwwwx - 2023 年 8 月 30 日](https://blog.xss.am/2023/08/cve-2023-39968-jupyter-token-leak/)
* [现场请求伪造 - Dafydd Stuttard - 2007 年 5 月 3 日](https://portswigger.net/blog/on-site-request-forgery)
* [使用编码级别绕过 WAF 来利用 CSPT - Matan Berson - 2024 年 5 月 10 日](https://matanber.com/blog/cspt-levels)
* [自动化客户端路径遍历的发现 - Vitor Falcao - 2024 年 10 月 3 日](https://vitorfalcao.com/posts/automating-cspt-discovery/)
* [CSPT the Eval Villain Way! - Dennis Goodlett - 2024 年 12 月 3 日](https://blog.doyensec.com/2024/12/03/cspt-with-eval-villain.html)
* [绕过文件上传限制以利用客户端路径遍历 - Maxence Schmitt - 2025 年 1 月 9 日](https://blog.doyensec.com/2025/01/09/cspt-file-upload.html)