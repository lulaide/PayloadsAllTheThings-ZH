# Linux - 持久化

:warning: 本页内容已迁移至 [InternalAllTheThings/redteam/persistence/linux-persistence](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/)

- [基本反向shell](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#basic-reverse-shell)
- [添加一个root用户](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#add-a-root-user)
- [Suid二进制文件](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#suid-binary)
- [Crontab - 反向shell](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#crontab---reverse-shell)
- [劫持用户的bash_rc](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#backdooring-a-users-bash_rc)
- [劫持启动服务](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#backdooring-a-startup-service)
- [劫持用户启动文件](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#backdooring-a-user-startup-file)
- [劫持登录提示信息](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#backdooring-message-of-the-day)
- [劫持驱动程序](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#backdooring-a-driver)
- [劫持APT](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#backdooring-the-apt)
- [劫持SSH](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#backdooring-the-ssh)
- [劫持Git](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#backdooring-git)
- [其他Linux持久化选项](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#additional-persistence-options)
- [参考文献](https://swisskyrepo.github.io/InternalAllTheThings/redteam/persistence/linux-persistence/#references)