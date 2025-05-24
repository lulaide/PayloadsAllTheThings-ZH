# Google Web 工具包

> Google Web Toolkit（简称GWT），也称为GWT Web工具包，是一套开源工具，允许Web开发人员使用Java创建和维护JavaScript前端应用程序。它最初由Google开发，并于2006年5月16日首次发布。

## 概要

* [工具](#工具)
* [方法论](#方法论)
* [参考文献](#参考文献)

## 工具

* [FSecureLABS/GWTMap](https://github.com/FSecureLABS/GWTMap) - GWTMap 是一个工具，用于帮助映射基于 Google Web Toolkit (GWT) 的应用程序的攻击面。
* [GDSSecurity/GWT-Penetration-Testing-Toolset](https://github.com/GDSSecurity/GWT-Penetration-Testing-Toolset) - 一套用于协助对GWT应用程序进行渗透测试的工具。

## 方法论

* 通过其引导文件枚举远程应用程序的方法并通过代码（随机选择排列）创建本地备份：

    ```ps1
    ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --backup
    ```

* 通过特定代码排列枚举远程应用程序的方法：

    ```ps1
    ./gwtmap.py -u http://10.10.10.10/olympian/C39AB19B83398A76A21E0CD04EC9B14C.cache.js
    ```

* 在通过HTTP代理路由流量的同时枚举方法：

    ```ps1
    ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --backup -p http://127.0.0.1:8080
    ```

* 枚举任何给定排列的本地副本（文件）的方法：

    ```ps1
    ./gwtmap.py -F test_data/olympian/C39AB19B83398A76A21E0CD04EC9B14C.cache.js
    ```

* 将输出过滤到特定的服务或方法：

    ```ps1
    ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService.login
    ```

* 为过滤服务的所有方法生成RPC负载，并以彩色输出：

    ```ps1
    ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService --rpc --color
    ```

* 自动测试（探测）生成的RPC请求针对过滤服务方法的生成结果：

    ```ps1
    ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter AuthenticationService.login --rpc --probe
    ./gwtmap.py -u http://10.10.10.10/olympian/olympian.nocache.js --filter TestService.testDetails --rpc --probe
    ```

## 参考文献

* [从序列化到Shell :: 使用EL注入利用Google Web Toolkit - Steven Seeley - 2017年5月22日](https://srcincite.io/blog/2017/05/22/from-serialized-to-shell-auditing-google-web-toolkit-with-el-injection.html)
* [破解Google Web Toolkit应用 - thehackerish - 2021年4月22日](https://thehackerish.com/hacking-a-google-web-toolkit-application/)