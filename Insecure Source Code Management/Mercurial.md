# Mercurial

> Mercurial（也称为 hg，来自汞的化学符号）是一种分布式版本控制系统（DVCS），旨在高效且可扩展。由 Matt Mackall 开发并于 2005 年首次发布，Mercurial 以其速度、简洁性和处理大型代码库的能力而闻名。

## 概述

* [工具](#工具)
    * [rip-hg.pl](#rip-hgpl)
* [参考](#参考)

## 工具

### rip-hg.pl

* [kost/dvcs-ripper/master/rip-hg.pl](https://raw.githubusercontent.com/kost/dvcs-ripper/master/rip-hg.pl) - 提取可通过网络访问的（分布式）版本控制系统：SVN/GIT/HG...

    ```powershell
    docker run --rm -it -v /路径/到/主机/工作目录:/work:rw k0st/alpine-dvcs-ripper rip-hg.pl -v -u
    ```

## 参考

* [my-chemical-romance - siunam - Feb 13, 2023](https://siunam321.github.io/ctf/LA-CTF-2023/Web/my-chemical-romance/)