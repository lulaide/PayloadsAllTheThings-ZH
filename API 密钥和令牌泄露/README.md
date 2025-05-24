# API 密钥和令牌泄露

> API 密钥和令牌是常用的认证形式，用于管理对公共和私人服务的权限和访问。泄露这些敏感数据可能导致未经授权的访问、安全漏洞以及潜在的数据泄露。

## 概述

- [工具](#工具)
- [方法论](#方法论)
    - [常见的泄露原因](#常见的泄露原因)
    - [验证 API 密钥](#验证-api-密钥)
- [减少攻击面](#减少攻击面)
- [参考文献](#参考文献)

## 工具

- [aquasecurity/trivy](https://github.com/aquasecurity/trivy) - 通用漏洞和错误配置扫描器，也可以搜索 API 密钥/机密
- [blacklanternsecurity/badsecrets](https://github.com/blacklanternsecurity/badsecrets) - 一个用于检测多个平台上的已知或弱机密的库
- [d0ge/sign-saboteur](https://github.com/d0ge/sign-saboteur) - SignSaboteur 是 Burp Suite 的扩展，用于编辑、签名和验证各种签名的 Web 令牌
- [mazen160/secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) - 秘密模式数据库：最大的开源数据库，用于检测秘密、API 密钥、密码、令牌等
- [momenbasel/KeyFinder](https://github.com/momenbasel/KeyFinder) - 一个工具，可在浏览网页时查找密钥
- [streaak/keyhacks](https://github.com/streaak/keyhacks) - 一个仓库，展示了快速检查由漏洞赏金计划泄露的 API 密钥是否有效的方法
- [trufflesecurity/truffleHog](https://github.com/trufflesecurity/truffleHog) - 在各处查找凭据
- [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) - 使用这些模板测试 API 令牌对许多 API 服务端点的有效性

    ```powershell
    nuclei -t token-spray/ -var token=token_list.txt
    ```

## 方法论

- **API 密钥**: 用于验证与您的项目或应用程序相关的请求的唯一标识符。
- **令牌**: 授予访问受保护资源的安全令牌（如 OAuth 令牌）。

### 常见的泄露原因

- **硬编码在源代码中**: 开发人员可能无意中将 API 密钥或令牌直接留在源代码中。

    ```py
    # 硬编码 API 密钥的示例
    api_key = "1234567890abcdef"
    ```

- **公共存储库**: 不小心将敏感密钥和令牌提交到公开可访问的版本控制系统（如 GitHub）。

    ```ps1
    ## 扫描 Github 组织
    docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --org=trufflesecurity
    
    ## 扫描 GitHub 存储库及其问题和拉取请求
    docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --repo https://github.com/trufflesecurity/test_keys --issue-comments --pr-comments
    ```

- **硬编码在 Docker 镜像中**: API 密钥和凭据可能硬编码在 DockerHub 或私有注册表中的 Docker 镜像中。

    ```ps1
    # 扫描 Docker 镜像以查找已验证的秘密
    docker run --rm -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest docker --image trufflesecurity/secrets
    ```

- **日志和调试信息**: 在调试过程中可能会无意中记录或打印密钥和令牌。

- **配置文件**: 在公开可访问的配置文件中包含密钥和令牌（例如 .env 文件、config.json、settings.py 或 .aws/credentials）。

### 验证 API 密钥

如果需要帮助识别生成令牌的服务，可以查阅 [mazen160/secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db)。这是最大的开源数据库，用于检测秘密、API 密钥、密码、令牌等。该数据库包含各种秘密的正则表达式模式。

```yaml
patterns:
  - pattern:
      name: AWS API Gateway
      regex: '[0-9a-z]+.execute-api.[0-9a-z._-]+.amazonaws.com'
      confidence: low
  - pattern:
      name: AWS API Key
      regex: AKIA[0-9A-Z]{16}
      confidence: high
```

使用 [streaak/keyhacks](https://github.com/streaak/keyhacks) 或阅读服务文档，找到快速验证 API 密钥有效性的方法。

- **示例**: Telegram Bot API Token

    ```ps1
    curl https://api.telegram.org/bot<TOKEN>/getMe
    ```

## 减少攻击面

在将更改提交到 GitHub 仓库之前，请检查是否存在私钥或 AWS 凭据。

将以下行添加到您的 `.pre-commit-config.yaml` 文件中。

```yml
-   repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v3.2.0
    hooks:
    -   id: detect-aws-credentials
    -   id: detect-private-key
```

## 参考文献

- [发现隐藏的 API 密钥及如何使用它们 - Sumit Jain - 2019 年 8 月 24 日](https://web.archive.org/web/20191012175520/https://medium.com/@sumitcfe/finding-hidden-api-keys-how-to-use-them-11b1e5d0f01d)
- [介绍 SignSaboteur：轻松伪造签名的 Web 令牌 - Zakhar Fedotkin - 2024 年 5 月 22 日](https://portswigger.net/research/introducing-signsaboteur-forge-signed-web-tokens-with-ease)
- [由于缺乏访问控制导致的私有 API 密钥泄露 - yox - 2018 年 8 月 8 日](https://hackerone.com/reports/376060)
- [告别我最喜欢的五分钟 P1 - Allyson O'Malley - 2020 年 1 月 6 日](https://www.allysonomalley.com/2020/01/06/saying-goodbye-to-my-favorite-5-minute-p1/)