# 正则表达式

> 正则表达式拒绝服务（ReDoS）是一种攻击类型，它利用了某些正则表达式需要极长时间来处理的事实，导致应用程序或服务变得无响应甚至崩溃。

## 概述

* [工具](#工具)
* [方法论](#方法论)
    * [邪恶的正则表达式](#邪恶的正则表达式)
    * [回溯限制](#回溯限制)
* [参考文献](#参考文献)

## 工具

* [tjenkinson/redos-detector](https://github.com/tjenkinson/redos-detector) - 一个命令行工具和库，可以确定地测试正则表达式模式是否免受ReDoS攻击。支持浏览器、Node.js和Deno。
* [doyensec/regexploit](https://github.com/doyensec/regexploit) - 查找易受ReDoS（正则表达式拒绝服务）攻击的正则表达式。
* [devina.io/redos-checker](https://devina.io/redos-checker) - 检查正则表达式是否存在潜在的拒绝服务漏洞。

## 方法论

### 邪恶的正则表达式

邪恶的正则表达式包含以下特征：

* 带有重复的分组
* 在重复的分组内：
    * 重复
    * 重叠的交替

**示例**：

* `(a+)+`
* `([a-zA-Z]+)*`
* `(a|aa)+`
* `(a|a?)+`
* `(.*a){x}` 其中 x > 10

这些正则表达式可以通过输入 `aaaaaaaaaaaaaaaaaaaaaaaa!`（20个'a'后跟一个'!'）来被利用。

```ps1
aaaaaaaaaaaaaaaaaaaa!
```

对于此输入，正则表达式引擎会在意识到匹配最终失败是因为'!'之前尝试所有可能的'a'字符分组方式。这会导致回溯尝试的爆炸性增长。

### 回溯限制

在正则表达式中，当正则表达式引擎尝试匹配模式并遇到不匹配时，就会发生回溯。然后引擎会回退到上一个匹配位置，并尝试另一条路径以找到匹配。这个过程可以重复多次，尤其是在复杂的模式和大的输入字符串的情况下。

**PHP PCRE配置选项**：

| 名称                 | 默认值        | 备注                |
|----------------------|---------------|---------------------|
| pcre.backtrack_limit | 1000000       | `PHP < 5.3.7`时为100000 |
| pcre.recursion_limit | 100000        | /                  |
| pcre.jit             | 1             | /                  |

有时，强制正则表达式超过100,000次递归将会导致ReDOS，并使`preg_match`返回false：

```php
$pattern = '/(a+)+$/';
$subject = str_repeat('a', 1000) . 'b';

if (preg_match($pattern, $subject)) {
    echo "匹配成功";
} else {
    echo "未匹配";
}
```

## 参考文献

* [Intigriti挑战1223 - 黑客手册 - 2023年12月21日](https://simones-organization-4.gitbook.io/hackbook-of-a-hacker/ctf-writeups/intigriti-challenges/1223)
* [MyBB管理面板RCE CVE-2023-41362 - SorceryIE - 2023年9月11日](https://blog.sorcery.ie/posts/mybb_acp_rce/)
* [OWASP验证正则表达式存储库 - OWASP - 2018年3月14日](https://wiki.owasp.org/index.php/OWASP_Validation_Regex_Repository)
* [PCRE > 安装/配置 - PHP手册 - 2008年5月3日](https://www.php.net/manual/en/pcre.configuration.php#ini.pcre.recursion-limit)
* [正则表达式拒绝服务 - ReDoS - Adar Weidman - 2019年12月4日](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)