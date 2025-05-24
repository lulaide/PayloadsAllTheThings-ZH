# Windows - 使用凭据

:warning: 本页内容已移至 [InternalAllTheThings/redteam/access/windows-using-credentials](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/)

- [获取凭据](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#get-credentials)
    - [创建您的凭据](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#create-your-credential)
    - [访客凭据](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#guest-credential)
    - [零售凭据](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#retail-credential)
    - [沙盒凭据](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#sandbox-credential)
- [NetExec](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#netexec)
- [Impacket](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#impacket)
    - [PSExec](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#psexec)
    - [WMIExec](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#wmiexec)
    - [SMBExec](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#smbexec)

- [RDP 远程桌面协议](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#rdp-remote-desktop-protocol)
- [PowerShell 远程协议](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#powershell-remoting-protocol)
    - [PowerShell 凭据](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#powershell-credentials)
    - [PowerShell PSSession](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#powershell-pssession)
    - [PowerShell 安全字符串](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#powershell-secure-strings)
- [SSH 协议](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#ssh-protocol)
- [WinRM 协议](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#winrm-protocol)
- [WMI 协议](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#wmi-protocol)

- [其他方法](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#other-methods)
    - [PsExec - Sysinternal](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#psexec-sysinternal)
    - [挂载远程共享](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#mount-a-remote-share)
    - [以其他用户身份运行](https://swisskyrepo.github.io/InternalAllTheThings/redteam/access/windows-using-credentials/#run-as-another-user)