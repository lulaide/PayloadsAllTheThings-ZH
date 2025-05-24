# 依赖混淆

> 当软件安装脚本被诱骗从公共存储库拉取恶意代码文件而不是从内部存储库拉取同名的预期文件时，就会发生依赖混淆攻击或供应链替换攻击。

## 概述

* [工具](#工具)
* [方法论](#方法论)
    * [NPM 示例](#npm示例)
* [参考文献](#参考文献)

## 工具

* [visma-prodsec/confused](https://github.com/visma-prodsec/confused) - 用于检查多个包管理系统的依赖混淆漏洞的工具
* [synacktiv/DepFuzzer](https://github.com/synacktiv/DepFuzzer) - 用于查找依赖混淆或可以接管所有者电子邮件的项目的工具。

## 方法论

寻找 `npm`、`pip`、`gem` 包，方法相同：注册一个与公司使用的私有包同名的公共包，然后等待其被使用。

* **DockerHub**: Dockerfile 镜像
* **JavaScript** (npm): package.json
* **MVN** (maven): pom.xml
* **PHP** (composer): composer.json
* **Python** (pypi): requirements.txt

### NPM 示例

* 列出所有包（例如：package.json, composer.json, ...）
* 在 [www.npmjs.com](https://www.npmjs.com/) 上找到缺失的包
* 注册并创建一个同名的 **公共** 包
    * 包示例：[0xsapra/dependency-confusion-exploit](https://github.com/0xsapra/dependency-confusion-exploit)

## 参考文献

* [利用依赖混淆 - Aman Sapra (0xsapra) - 2021年7月2日](https://0xsapra.github.io/website//Exploiting-Dependency-Confusion)
* [依赖混淆：如何入侵苹果、微软和其他数十家公司 - Alex Birsan - 2021年2月9日](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
* [使用私有包存储库降低风险的三种方法 - 微软 - 2021年3月29日](https://web.archive.org/web/20210210121930/https://azure.microsoft.com/en-gb/resources/3-ways-to-mitigate-risk-using-private-package-feeds/)
* [$130,000+ 学习新的黑客技术 2021 - 依赖混淆 - Bug赏金报告解释 - 2021年2月22日](https://www.youtube.com/watch?v=zFHJwehpBrU)