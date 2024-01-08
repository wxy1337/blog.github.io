---
title: 'HTB: Bizness'
date: 2024-01-08 22:21:22
categories:
- Machines
- Lab
tags:
- HTB
- easy
- season4
---

![image-20240108222232805](../images/image-20240108222232805.png)

ip==10.10.11.252

```
┌──(root㉿kali)-[/home/kali/htb/Ouija]
└─# echo "10.10.11.252 bizness.htb" >> /etc/hosts
```

![image-20240108222342479](../images/image-20240108222342479.png)

![image-20240108223228038](../images/image-20240108223228038.png)

dirsearch后发现login

```
/control/login
```

![image-20240108225029785](../images/image-20240108225029785.png)

![image-20240108230028631](../images/image-20240108230028631.png)

![image-20240108230043066](../images/image-20240108230043066.png)

POC:

![image-20240108230109608](../images/image-20240108230109608.png)

https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass

![image-20240108230007696](../images/image-20240108230007696.png)

![image-20240108230150895](../images/image-20240108230150895.png)

user.txt

```
b8a20af294e45ce5f4ef00882c9da4a6
```

![image-20240108230741114](../images/image-20240108230741114.png)

```
<entity-engine-xml>
    <UserLogin userLoginId="@userLoginId@" currentPassword="{SHA}47ca69ebb4bdc9ae0adec130880165d2cc05db1a" requirePasswordChange="Y"/>
    <UserLoginSecurityGroup groupId="SUPER" userLoginId="@userLoginId@" fromDate="2001-01-01 12:00:00.0"/>
```

![image-20240108230958284](../images/image-20240108230958284.png)

解密（碰撞）即可

![image-20240108232109172](../images/image-20240108232109172.png)

![image-20240108232054920](../images/image-20240108232054920.png)
