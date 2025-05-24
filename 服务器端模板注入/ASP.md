# 服务器端模板注入 - ASP.NET

> 服务器端模板注入（SSTI）是一类漏洞，攻击者可以将恶意输入注入到服务器端模板中，导致模板引擎在服务器上执行任意代码。在 ASP.NET 的上下文中，如果用户输入未经适当清理就直接嵌入到模板（如 Razor、ASPX 或其他模板引擎）中，则可能会发生 SSTI。

## 概述

- [ASP.NET Razor](#aspnet-razor)
    - [ASP.NET Razor - 基本注入](#aspnet-razor---基本注入)
    - [ASP.NET Razor - 命令执行](#aspnet-razor---命令执行)
- [参考](#参考)

## ASP.NET Razor

[官方文档](https://docs.microsoft.com/zh-cn/aspnet/web-pages/overview/getting-started/introducing-razor-syntax-c)

> Razor 是一种标记语法，允许您在网页中嵌入基于服务器的代码（Visual Basic 和 C#）。

### ASP.NET Razor - 基本注入

```powershell
@(1+2)
```

### ASP.NET Razor - 命令执行

```csharp
@{
  // C# 代码
}
```

## 参考

- [ASP.NET Razor 中的服务器端模板注入 (SSTI) - Clément Notin - 2020年4月15日](https://clement.notin.org/blog/2020/04/15/Server-Side-Template-Injection-(SSTI)-in-ASP.NET-Razor/)