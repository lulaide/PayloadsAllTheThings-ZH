# HTTP 参数污染

> HTTP 参数污染（HPP）是一种Web攻击绕过技术，允许攻击者构造HTTP请求以操纵Web逻辑或获取隐藏的信息。这种绕过技术基于在具有相同名称的多个参数实例之间分割攻击向量（例如？param1=value&param1=value）。由于没有正式的HTTP参数解析方式，各个Web技术都有自己独特的URL参数解析和读取方法。有些技术会采用第一个出现的值，有些则采用最后一个出现的值，还有一些将它们视为数组。攻击者利用这种行为来绕过基于模式的安全机制。

## 概要

* [工具](#工具)
* [方法论](#方法论)
    * [参数污染表](#参数污染表)
    * [参数污染载荷](#参数污染载荷)
* [参考文献](#参考文献)

## 工具

* **Burp Suite**：手动修改请求以测试重复参数。
* **OWASP ZAP**：拦截并操作HTTP参数。

## 方法论

HTTP 参数污染（HPP）是一种Web安全漏洞，攻击者会在请求中注入多个相同的HTTP参数实例。服务器处理重复参数时的行为可能有所不同，可能导致意外或可被利用的行为。

HPP 可以针对两个级别：

* 客户端HPP：利用运行在客户端（浏览器）上的JavaScript代码。
* 服务端HPP：利用服务器如何处理具有相同名称的多个参数。

**示例**：

```ps1
/app?debug=false&debug=true
/transfer?amount=1&amount=5000
```

### 参数污染表

当存在 ?par1=a&par1=b 时

| 技术                                       | 解析结果           | 结果（par1=） |
| ------------------------------------------ | ------------------ | ------------- |
| ASP.NET/IIS                               | 所有出现值         | a,b           |
| ASP/IIS                                   | 所有出现值         | a,b           |
| Golang net/http - `r.URL.Query().Get("param")` | 第一个出现值       | a             |
| Golang net/http - `r.URL.Query()["param"]`   | 所有出现值为数组   | ['a','b']     |
| IBM HTTP Server                           | 第一个出现值       | a             |
| IBM Lotus Domino                          | 第一个出现值       | a             |
| JSP、Servlet/Tomcat                       | 第一个出现值       | a             |
| mod_wsgi（Python）/Apache                 | 第一个出现值       | a             |
| Node.js                                   | 所有出现值         | a,b           |
| Perl CGI/Apache                           | 第一个出现值       | a             |
| Perl CGI/Apache                           | 第一个出现值       | a             |
| PHP/Apache                                | 最后一个出现值     | b             |
| PHP/Zues                                  | 最后一个出现值     | b             |
| Python Django                             | 最后一个出现值     | b             |
| Python Flask                              | 第一个出现值       | a             |
| Python/Zope                               | 所有出现值为数组   | ['a','b']     |
| Ruby on Rails                             | 最后一个出现值     | b             |

### 参数污染载荷

* 重复参数：

    ```ps1
    param=value1&param=value2
    ```

* 数组注入：

    ```ps1
    param[]=value1
    param[]=value1&param[]=value2
    param[]=value1&param=value2
    param=value1&param[]=value2
    ```

* 编码注入：

    ```ps1
    param=value1%26other=value2
    ```

* 嵌套注入：

    ```ps1
    param[key1]=value1&param[key2]=value2
    ```

* JSON注入：

    ```ps1
    {
        "test": "user",
        "test": "admin"
    }
    ```

## 参考文献

* [如何检测HTTP参数污染攻击 - Acunetix - 2024年1月9日](https://www.acunetix.com/blog/whitepaper-http-parameter-pollution/)
* [HTTP参数污染 - Itamar Verta - 2023年12月20日](https://www.imperva.com/learn/application-security/http-parameter-pollution/)
* [11分钟了解HTTP参数污染 - PwnFunction - 2019年1月28日](https://www.youtube.com/watch?v=QVZBl8yxVX0&ab_channel=PwnFunction)