# 贡献指南

PayloadsAllTheThings 团队 :heart: 欢迎 Pull Request。

随时用你的 Payload 和技术来改进！

你也可以通过现实中的 :beers: 或使用 [赞助](https://github.com/sponsors/swisskyrepo) 按钮来贡献。

## Pull Request 规范

为了向社区提供最安全的 Payload，以下规则必须在 **每个** Pull Request 中遵循。

- Payload 必须经过清理
    - 使用 `id` 和 `whoami` 作为 RCE 的概念验证 (Proof of Concepts)
    - 当用户需要替换一个回调域名时，请使用 `[REDACTED]`。例如：XSSHunter、BurpCollaborator 等。
    - 如果 Payload 需要 IP 地址，请使用 `10.10.10.10` 和 `10.10.10.11`
    - 对于特权用户使用 `Administrator`，对于普通账户使用 `User`
    - 在示例中使用默认密码如 `P@ssw0rd`、`Password123`、`password`
    - 偏好使用常见的机器名称，例如 `DC01`、`EXCHANGE01`、`WORKSTATION01` 等
- 引用必须包含 `作者`、`标题`、`链接` 和 `日期`
    - 如果引用不可用，请使用 [Wayback Machine](https://web.archive.org/)
    - 日期格式应为 `月份 数字, 年份`，例如：`十二月 25, 2024`
    - 引用 GitHub 仓库的格式应为：`[作者/工具](https://github.com/URL) - 描述`

每个 Pull Request 都会通过 `markdownlint` 进行检查，以确保一致的书写和 Markdown 最佳实践。你可以使用以下 Docker 命令在本地验证文件：

```ps1
docker run -v $PWD:/workdir davidanson/markdownlint-cli2:v0.15.0 "**/*.md" --config .github/.markdownlint.json --fix
```

## 技术文件夹

每个部分应该包含以下文件，可以使用 `_template_vuln` 文件夹创建一个新的技术文件夹：

- **README.md**：漏洞描述及如何利用它，包括多个 Payload，详见下文
- **Intruder**：一组文件供 Burp Intruder 使用
- **Images**：README.md 中使用的图片
- **Files**：README.md 中引用的一些文件

## README.md 格式

使用示例文件夹 [_template_vuln/](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/_template_vuln/) 创建一个新的漏洞文档。主页面是 [README.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/_template_vuln/README.md)。它按章节组织，包括漏洞的标题和描述，并附有指向文档主要部分的目录摘要表。

- **工具**：列出相关的工具，附带其仓库链接和简短描述。
- **方法论**：提供所使用方法的快速概述，附带代码片段以演示利用步骤。
- **实验室**：引用可练习类似漏洞的在线平台，每个平台附带指向相应实验室的链接。
- **参考**：列出外部资源，如博客文章或文章，提供与该漏洞相关的额外背景或案例研究。