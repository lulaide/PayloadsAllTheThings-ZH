# 不安全的管理接口

> 不安全的管理接口是指用于管理服务器、应用程序、数据库或网络设备的管理界面中存在漏洞。这些界面通常控制敏感设置，并对系统配置具有强大的访问权限，因此成为攻击者的主要目标。
> 不安全的管理接口可能缺乏适当的安全措施，例如强身份验证、加密或IP限制，允许未经授权的用户潜在地控制关键系统。常见问题包括使用默认凭据、未加密通信或向公共互联网暴露接口。

## 概要

* [方法论](#方法论)
* [参考文献](#参考文献)

## 方法论

当系统的管理界面或应用程序的管理界面未得到适当保护时，就会出现不安全的管理接口漏洞，这可能导致未经授权或恶意用户获得访问权限、修改配置或利用敏感操作。这些界面对于维护、监控和控制系统至关重要，必须严格保护。

* 缺乏身份验证或弱身份验证：
    * 可以在无需凭据的情况下访问的界面。
    * 使用默认或弱凭据（例如 admin/admin）。

    ```ps1
    nuclei -t http/default-logins -u https://example.com
    ```

* 向公共互联网暴露

    ```ps1
    nuclei -t http/exposed-panels -u https://example.com
    nuclei -t http/exposures -u https://example.com
    ```

* 敏感数据通过明文HTTP或其他未加密协议传输

**示例**：

* **网络设备**：带有默认凭据或未修补漏洞的路由器、交换机或防火墙。
* **Web 应用程序**：没有身份验证的管理面板或通过可预测URL暴露（例如，/admin）。
* **云服务**：没有适当身份验证的API端点或权限过于宽松的角色。

## 参考文献

* [CAPEC-121：利用非生产接口 - CAPEC - 2020年7月30日](https://capec.mitre.org/data/definitions/121.html)
* [利用Spring Boot Actuator - Michael Stepankin - 2019年2月25日](https://www.veracode.com/blog/research/exploiting-spring-boot-actuators)
* [Spring Boot - 官方文档 - 2024年5月9日](https://docs.spring.io/spring-boot/docs/current/reference/html/production-ready-endpoints.html)