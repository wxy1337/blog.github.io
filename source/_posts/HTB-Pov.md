---
title: 'HTB: Pov'
date: 2024-02-03 17:52:58
categories:
- Machines
- Lab
tags:
- HTB
- medium
- season4
---

![image-20240203175450020](../images/image-20240203175450020.png)

nmap扫描

```bash
└─$ nmap -sC -sV -T4 10.10.11.251 -oN nmap
Starting Nmap 7.92 ( https://nmap.org ) at 2024-02-03 04:50 EST
Nmap scan report for 10.10.11.251 (10.10.11.251)
Host is up (0.29s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: pov.htb
| http-methods: 
|_  Potentially risky methods: TRACE
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.49 seconds
```

访问页面

![image-20240203181543568](../images/image-20240203181543568.png)

![image-20240203181606029](../images/image-20240203181606029.png)

发现sfitz@pov.htb 和 dev.pov.htb

将dev.pov.htb加入hosts文件后进行访问

![image-20240203181803709](../images/image-20240203181803709.png)

![image-20240203182239958](../images/image-20240203182239958.png)

拦截download操作

![image-20240203182301633](../images/image-20240203182301633.png)

更改cv.pdf为其他参数

![image-20240203182423159](../images/image-20240203182423159.png)

https://book.hacktricks.xyz/pentesting-web/deserialization/exploiting-__viewstate-parameter?source=post_page-----7516c938c688--------------------------------

![image-20240203194457571](../images/image-20240203194457571.png)

![image-20240203194859231](../images/image-20240203194859231.png)

![image-20240203195009459](../images/image-20240203195009459.png)

![image-20240203195155945](../images/image-20240203195155945.png)

破解密码

![image-20240203195817695](../images/image-20240203195817695.png)

```
f8gQ8fynP44ek1m3
```

![image-20240203200017614](../images/image-20240203200017614.png)

![image-20240203200454549](../images/image-20240203200454549.png)

```
f3718df4539d90e69d26fe24ea34642f
```

Root

![image-20240203204848384](../images/image-20240203204848384.png)

![image-20240203210221735](../images/image-20240203210221735.png)

![image-20240203210830645](../images/image-20240203210830645.png)

![image-20240203210950694](../images/image-20240203210950694.png)

```
e5bf8b9e3b4aa1cf1537ba6fb2751279
```

![image-20240203211037563](../images/image-20240203211037563.png)
