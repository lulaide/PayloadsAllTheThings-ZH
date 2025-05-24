# 不安全的反序列化

> 序列化是将某个对象转换为可以稍后恢复的数据格式的过程。人们常常会将对象序列化以便保存到存储中，或者作为通信的一部分发送出去。反序列化则是相反的过程——从某种格式的数据中重建对象 —— OWASP

## 概述

* [反序列化标识符](#反序列化标识符)
* [POP 小工具](#pop小工具)
* [实验室](#实验室)
* [参考文献](#参考文献)

## 反序列化标识符

检查以下子章节，它们位于其他章节中：

* [Java 反序列化：ysoserial, ...](Java.md)
* [PHP（对象注入）：phpggc, ...](PHP.md)
* [Ruby：universal rce 小工具, ...](Ruby.md)
* [Python：pickle, PyYAML, ...](Python.md)
* [.NET：ysoserial.net, ...](DotNET.md)

| 对象类型       | 头部 (十六进制) | 头部 (Base64) |
|---------------|----------------|--------------|
| Java 序列化   | AC ED          | rO            |
| .NET ViewState | FF 01          | /w            |
| Python Pickle  | 80 04 95       | gASV          |
| PHP 序列化    | 4F 3A          | Tz            |

## POP 小工具

> 一个 POP（面向属性编程）小工具是应用程序类中实现的一段代码，在反序列化过程中可以被调用。

POP 小工具的特点：

* 可以被序列化
* 具有公共/可访问的属性
* 实现特定的易受攻击的方法
* 能访问其他“可调用”的类

## 实验室

* [PortSwigger - 修改序列化对象](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects)
* [PortSwigger - 修改序列化数据类型](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-data-types)
* [PortSwigger - 使用应用程序功能来利用不安全的反序列化](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-using-application-functionality-to-exploit-insecure-deserialization)
* [PortSwigger - 在 PHP 中进行任意对象注入](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-arbitrary-object-injection-in-php)
* [PortSwigger - 利用 Apache Commons 来利用 Java 反序列化](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-java-deserialization-with-apache-commons)
* [PortSwigger - 使用预构建的小工具链来利用 PHP 反序列化](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-php-deserialization-with-a-pre-built-gadget-chain)
* [PortSwigger - 使用已记录的小工具链来利用 Ruby 反序列化](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-exploiting-ruby-deserialization-using-a-documented-gadget-chain)
* [PortSwigger - 为 Java 反序列化开发自定义小工具链](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-developing-a-custom-gadget-chain-for-java-deserialization)
* [PortSwigger - 为 PHP 反序列化开发自定义小工具链](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-developing-a-custom-gadget-chain-for-php-deserialization)
* [PortSwigger - 使用 PHAR 反序列化部署自定义小工具链](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-using-phar-deserialization-to-deploy-a-custom-gadget-chain)
* [NickstaDB - DeserLab](https://github.com/NickstaDB/DeserLab)

## 参考文献

* [ExploitDB 入门 - Abdelazim Mohammed(@intx0x80) - 2018 年 5 月 27 日](https://www.exploit-db.com/docs/english/44756-deserialization-vulnerability.pdf)
* [利用不安全的反序列化漏洞 - PortSwigger - 2020 年 7 月 25 日](https://portswigger.net/web-security/deserialization/exploiting)
* [Instagram 的百万美元漏洞 - Wesley Wineberg - 2015 年 12 月 17 日](http://www.exfiltrated.com/research-Instagram-RCE.php)