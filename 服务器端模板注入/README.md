# 服务器端模板注入

> 模板注入允许攻击者向现有（或不存在的）模板中插入模板代码。模板引擎通过使用静态模板文件使设计HTML页面更加容易，并在运行时用实际值替换HTML页面中的变量/占位符。

## 概要

- [工具](#工具)
- [方法论](#方法论)
    - [识别易受攻击的输入字段](#识别易受攻击的输入字段)
    - [注入模板语法](#注入模板语法)
    - [枚举模板引擎](#枚举模板引擎)
    - [提升到代码执行](#提升到代码执行)
- [实验室](#实验室)
- [参考文献](#参考文献)

## 工具

- [Hackmanit/TInjA](https://github.com/Hackmanit/TInjA) - 一种高效利用新型多语言的SSTI + CSTI扫描器

  ```bash
  tinja url -u "http://example.com/?name=Kirlia" -H "Authentication: Bearer ey..."
  tinja url -u "http://example.com/" -d "username=Kirlia"  -c "PHPSESSID=ABC123..."
  ```

- [epinna/tplmap](https://github.com/epinna/tplmap) - 服务端模板注入和代码注入检测与利用工具

  ```powershell
  python2.7 ./tplmap.py -u 'http://www.target.com/page?name=John*' --os-shell
  python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=*&comment=supercomment&link"
  python2.7 ./tplmap.py -u "http://192.168.56.101:3000/ti?user=InjectHere*&comment=A&link" --level 5 -e jade
  ```

- [vladko312/SSTImap](https://github.com/vladko312/SSTImap) - 基于[epinna/tplmap](https://github.com/epinna/tplmap)的交互式自动SSTI检测工具

  ```powershell
  python3 ./sstimap.py -u 'https://example.com/page?name=John' -s
  python3 ./sstimap.py -u 'https://example.com/page?name=Vulnerable*&message=My_message' -l 5 -e jade
  python3 ./sstimap.py -i -A -m POST -l 5 -H 'Authorization: Basic bG9naW46c2VjcmV0X3Bhc3N3b3Jk'
  ```

## 方法论

### 识别易受攻击的输入字段

攻击者首先定位一个输入字段、URL参数或应用程序中任何可由用户控制的部分，这些部分在未进行适当清理或转义的情况下传递到服务器端模板中。

例如，攻击者可能会发现一个Web表单、搜索栏或似乎基于动态用户输入返回结果的模板预览功能。

**提示**：生成的PDF文件、发票和电子邮件通常使用模板。

### 注入模板语法

攻击者通过注入特定于所用模板引擎的模板语法来测试已识别的输入字段。不同的Web框架使用不同的模板引擎（例如，Python中的Jinja2，PHP中的Twig，Java中的FreeMarker）。

常见的模板表达式：

- `{{7*7}}` 对于Jinja2（Python）。
- `#{7*7}` 对于Thymeleaf（Java）。

在相关技术页面（PHP、Python等）中可以找到更多模板表达式。

![SSTI速查表工作流程](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Images/serverside.png?raw=true)

在大多数情况下，这种多语言有效负载会在存在SSTI漏洞时触发错误：

```ps1
${{<%[%'"}}%\.
```

[Hackmanit/模板注入表](https://github.com/Hackmanit/template-injection-table) 是一个包含最有效的模板注入多语言的有效负载及其对44种最重要的模板引擎预期响应的交互式表格。

### 枚举模板引擎

根据成功的响应，攻击者确定正在使用的模板引擎。此步骤至关重要，因为不同的模板引擎具有不同的语法、特性和潜在的利用方式。攻击者可以通过尝试不同的有效负载来查看哪个有效负载执行成功，从而识别出引擎。

- **Python**：Django、Jinja2、Mako、...
- **Java**：FreeMarker、Jinjava、Velocity、...
- **Ruby**：ERB、Slim、...

[@0xAwali的《模板引擎注入101》文章](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756) 总结了JavaScript、Python、Ruby、Java和PHP中大多数模板引擎的语法和检测方法，以及如何区分使用相同语法的引擎。

### 提升到代码执行

一旦识别出模板引擎，攻击者就会注入更复杂的表达式，旨在执行服务器端命令或任意代码。

## 实验室

- [Root Me - Java - 服务器端模板注入](https://www.root-me.org/en/Challenges/Web-Server/Java-Server-side-Template-Injection)
- [Root Me - Python - 服务器端模板注入介绍](https://www.root-me.org/en/Challenges/Web-Server/Python-Server-side-Template-Injection-Introduction)
- [Root Me - Python - 盲SSTI过滤器绕过](https://www.root-me.org/en/Challenges/Web-Server/Python-Blind-SSTI-Filters-Bypass)

## 参考文献

- [渗透测试人员指南：服务器端模板注入（SSTI）- Busra Demir - 2020年12月24日](https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti)
- [利用服务器端模板注入（SSTI）获得Shell - David Valles - 2018年8月22日](https://medium.com/@david.valles/gaining-shell-using-server-side-template-injection-ssti-81e29bb8e0f9)
- [模板引擎注入101 - Mahmoud M. Awali - 2024年11月1日](https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756)
- [硬目标上的模板注入 - Lucas 'BitK' Philippe - 2022年9月28日](https://youtu.be/M0b_KA0OMFw)