# 不安全的源代码管理

> 不安全的源代码管理（SCM）可能导致Web应用程序和服务中出现多个关键漏洞。开发人员通常依赖Git和Subversion（SVN）等SCM系统来管理其源代码版本。然而，不良的安全实践，例如在生产环境中暴露.git和.svn文件夹到互联网上，可能带来重大风险。

## 概述

* [方法论](#方法论)
    * [Bazaar](./Bazaar.md)
    * [Git](./Git.md)
    * [Mercurial](./Mercurial.md)
    * [Subversion](./Subversion.md)
* [实验室](#实验室)
* [参考文献](#参考文献)

## 方法论

在Web服务器上暴露版本控制系统文件夹可能会导致严重的安全风险，包括：

* **源代码泄露**：攻击者可以下载整个源代码仓库，从而获取应用程序的逻辑。
* **敏感信息泄露**：代码库中可能包含嵌入的密钥、配置文件和凭据。
* **提交历史泄露**：攻击者可以查看过去的更改记录，揭示可能曾被公开并后来缓解的敏感信息。

第一步是收集目标应用程序的信息。这可以通过各种Web侦察工具和技术来完成。

* **手动检查**：通过导航到常见的SCM路径手动检查URL。
    * Git: `http://target.com/.git/`
    * SVN: `http://target.com/.svn/`

* **自动化工具**：参考特定技术的相关页面。

一旦识别出潜在的SCM文件夹，检查HTTP响应代码和内容。您可能需要绕过`.htaccess`或反向代理规则。

下面的NGINX规则在访问`/.git`端点时返回`403 (Forbidden)`响应，而不是`404 (Not Found)`。

```ps1
location /.git {
  deny all;
}
```

例如，在Git中，即使不能列出`.git`文件夹的内容（`http://target.com/.git/`），只要能够读取文件，仍然可以进行数据提取。

## 实验室

* [Root Me - 不安全的代码管理](https://www.root-me.org/fr/Challenges/Web-Serveur/Insecure-Code-Management)

## 参考文献

* [隐藏目录和文件作为Web应用程序敏感信息的来源 - 2017年4月30日](https://github.com/bl4de/research/tree/master/hidden_directories_leaks)