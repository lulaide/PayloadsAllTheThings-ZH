# 批量分配

> 批量分配攻击是一种安全漏洞，当Web应用程序自动将用户提供的输入值分配给程序对象的属性或变量时会发生这种情况。如果用户能够修改他们不应访问的属性（如用户的权限或管理员标志），这可能会成为一个问题。

## 概述

* [方法论](#方法论)
* [实验室](#实验室)
* [参考文献](#参考文献)

## 方法论

批量分配漏洞在使用对象关系映射（ORM）技术或函数的Web应用程序中最常见，这些技术或函数将用户输入映射到对象属性，其中属性可以一次性更新而不是逐个更新。许多流行的Web开发框架（如Ruby on Rails、Django和Laravel(PHP)）都提供了这种功能。

例如，考虑一个使用ORM并具有`username`、`email`、`password`和`isAdmin`属性的用户对象的Web应用程序。在正常情况下，用户可能能够通过表单更新自己的用户名、电子邮件和密码，服务器随后将这些值分配给用户对象。

然而，攻击者可能会尝试向传入的数据中添加一个`isAdmin`参数，如下所示：

```json
{
    "username": "attacker",
    "email": "attacker@email.com",
    "password": "unsafe_password",
    "isAdmin": true
}
```

如果Web应用程序没有检查哪些参数允许以这种方式更新，则可能会根据用户提供的输入设置`isAdmin`属性，从而授予攻击者管理员权限。

## 实验室

* [PentesterAcademy - 批量分配 I](https://attackdefense.pentesteracademy.com/challengedetailsnoauth?cid=1964)
* [PentesterAcademy - 批量分配 II](https://attackdefense.pentesteracademy.com/challengedetailsnoauth?cid=1922)
* [Root Me - API - 批量分配](https://www.root-me.org/en/Challenges/Web-Server/API-Mass-Assignment)

## 参考文献

* [寻找批量分配漏洞 - Shivam Bathla - 2021年8月12日](https://blog.pentesteracademy.com/hunting-for-mass-assignment-56ed73095eda)
* [批量分配速查表 - OWASP - 2021年3月15日](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
* [什么是批量分配？攻击与安全提示 - Yoan MONTOYA - 2023年6月15日](https://www.vaadata.com/blog/what-is-mass-assignment-attacks-and-security-tips/)