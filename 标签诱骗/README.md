# Tabnabbing

> 反向Tabnabbing是一种攻击方式，其中目标页面链接到的页面能够重写该页面，例如将其替换为钓鱼网站。由于用户最初是在正确的页面上，他们不太可能注意到页面已被替换为钓鱼网站，特别是如果钓鱼网站看起来与目标网站相同的话。如果用户在此新页面上进行身份验证，他们的凭据（或其他敏感数据）将被发送到钓鱼网站而不是合法网站。

## 概述

* [工具](#工具)
* [方法论](#方法论)
* [利用](#利用)
* [发现](#发现)
* [参考文献](#参考文献)

## 工具

* [PortSwigger/discovering-reversetabnabbing](https://portswigger.net/bappstore/80eb8fd46bf847b4b17861482c2f2a30) - 发现反向Tabnabbing

## 方法论

在进行Tabnabbing时，攻击者会寻找插入到网站中并受其控制的链接。例如，这些链接可能出现在论坛帖子中。一旦找到这种功能，就需要检查链接的`rel`属性是否不包含值`noopener`，并且`target`属性是否包含值`_blank`。如果是这种情况，则该网站容易受到Tabnabbing攻击。

## 利用

1. 攻击者发布一个指向他控制的网站的链接，该链接包含以下JS代码：`window.opener.location = "http://evil.com"`
2. 他诱使受害者访问该链接，该链接将在浏览器的新标签页中打开。
3. 同时，JS代码被执行，并且后台标签页被重定向到网站evil.com，这很可能是一个钓鱼网站。
4. 如果受害者再次打开后台标签页且没有查看地址栏，可能会发生他认为已登出的情况，因为例如出现登录页面。
5. 受害者尝试重新登录，攻击者接收到了凭据

## 发现

搜索以下链接格式：

```html
<a href="..." target="_blank" rel=""> 
<a href="..." target="_blank">
```

## 参考文献

* [反向Tabnabbing - OWASP - 2020年10月20日](https://owasp.org/www-community/attacks/Reverse_Tabnabbing)
* [Tabnabbing - 维基百科 - 2010年5月25日](https://en.wikipedia.org/wiki/Tabnabbing)