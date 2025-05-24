# HTTP 隐藏参数

> Web 应用程序常常有隐藏或未公开的参数，这些参数在用户界面中不会暴露出来。模糊测试可以帮助发现这些参数，它们可能容易受到各种攻击。

## 概要

* [工具](#工具)
* [方法论](#方法论)
    * [暴力破解参数](#暴力破解参数)
    * [旧参数](#旧参数)
* [参考](#参考)

## 工具

* [PortSwigger/param-miner](https://github.com/PortSwigger/param-miner) - Burp 扩展工具，用于识别隐藏、未链接的参数。
* [s0md3v/Arjun](https://github.com/s0md3v/Arjun) - HTTP 参数发现套件
* [Sh1Yo/x8](https://github.com/Sh1Yo/x8) - 隐藏参数发现套件
* [tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls) - 获取 Wayback Machine 知道的所有域名的 URL
* [devanshbatham/ParamSpider](https://github.com/devanshbatham/ParamSpider) - 从 Web 存档的黑暗角落挖掘 URL，用于漏洞挖掘/模糊测试/进一步探测

## 方法论

### 暴力破解参数

* 使用常见的参数词表，并发送它们，观察后端是否出现意外行为。

    ```ps1
    x8 -u "https://example.com/" -w <词表>
    x8 -u "https://example.com/" -X POST -w <词表>
    ```

词表示例：

* [Arjun/large.txt](https://github.com/s0md3v/Arjun/blob/master/arjun/db/large.txt)
* [Arjun/medium.txt](https://github.com/s0md3v/Arjun/blob/master/arjun/db/medium.txt)
* [Arjun/small.txt](https://github.com/s0md3v/Arjun/blob/master/arjun/db/small.txt)
* [samlists/sam-cc-parameters-lowercase-all.txt](https://github.com/the-xentropy/samlists/blob/main/sam-cc-parameters-lowercase-all.txt)
* [samlists/sam-cc-parameters-mixedcase-all.txt](https://github.com/the-xentropy/samlists/blob/main/sam-cc-parameters-mixedcase-all.txt)

### 旧参数

浏览目标的所有 URL 来寻找旧参数。

* 浏览 [Wayback Machine](http://web.archive.org/)
* 查看 JS 文件以发现未使用的参数

## 参考

* [黑客工具：Arjun - 参数发现工具 - Intigriti - 2021 年 5 月 17 日](https://blog.intigriti.com/2021/05/17/hacker-tools-arjun-the-parameter-discovery-tool/)
* [参数发现：快速入门指南 - YesWeHack - 2022 年 4 月 20 日](http://web.archive.org/web/20220420123306/https://blog.yeswehack.com/yeswerhackers/parameter-discovery-quick-guide-to-start)